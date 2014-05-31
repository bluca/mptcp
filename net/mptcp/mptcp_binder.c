#include <linux/module.h>

#include <net/mptcp.h>
#include <net/mptcp_v4.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <net/mptcp_v6.h>
#endif

#include <linux/route.h>
#include <linux/inet.h>
#include <linux/mroute.h>
#include <linux/spinlock_types.h>
#include <net/inet_ecn.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <net/compat.h>
#include <linux/slab.h>
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#include <net/transp_v6.h>
#include <linux/ipv6.h>
#endif

/* fprint of the list, to look it up set it available on socket close */
#define MPTCP_GW_MAX_LISTS	10
#define MPTCP_GW_LIST_MAX_LEN	6
#define MPTCP_GW_SYSCTL_MAX_LEN	(15 * MPTCP_GW_LIST_MAX_LEN * 	\
										MPTCP_GW_MAX_LISTS)
#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
#define MPTCP_GW_LIST_MAX_LEN6	1
#define MPTCP_GW6_SYSCTL_MAX_LEN	(40 * MPTCP_GW_LIST_MAX_LEN6 * \
										MPTCP_GW_MAX_LISTS)
#define MPTCP_OPT_V6_SIZE 24
#endif  /* CONFIG_MPTCP_BINDER_IPV6 */

struct mptcp_gw_list {
	struct in_addr list[MPTCP_GW_MAX_LISTS][MPTCP_GW_LIST_MAX_LEN];
	u8 len[MPTCP_GW_MAX_LISTS];
};

#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
struct mptcp_gw_list6 {
	struct in6_addr list[MPTCP_GW_MAX_LISTS][MPTCP_GW_LIST_MAX_LEN6];
	u8 len[MPTCP_GW_MAX_LISTS];
};
#endif /* CONFIG_MPTCP_BINDER_IPV6 */

struct binder_priv {
	/* Worker struct for subflow establishment */
	struct work_struct subflow_work;

	struct mptcp_cb *mpcb;

	spinlock_t *flow_lock;
};

static struct mptcp_gw_list * mptcp_gws = NULL;
static rwlock_t mptcp_gws_lock;

static int sysctl_mptcp_binder_ndiffports __read_mostly = 2;
static char sysctl_mptcp_binder_gateways[MPTCP_GW_SYSCTL_MAX_LEN] __read_mostly;

static struct kmem_cache *opt_slub_v4 = NULL;

#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
static struct mptcp_gw_list6 * mptcp_gws6 = NULL;
static rwlock_t mptcp_gws6_lock;

static char sysctl_mptcp_binder_gateways6[MPTCP_GW6_SYSCTL_MAX_LEN] __read_mostly;

static struct kmem_cache *opt_slub_v6 = NULL;
#endif /* CONFIG_MPTCP_BINDER_IPV6 */

static int mptcp_get_avail_list_ipv4(struct sock *sk, unsigned char *opt) {
	int i, j, sock_num, list_taken, opt_ret, opt_len;
	struct tcp_sock *tp;
	unsigned char *opt_ptr, *opt_end_ptr;
	
	for (i = 0; i < MPTCP_GW_MAX_LISTS; ++i) {
		if (mptcp_gws->len[i] == 0)
			goto error;
			
		mptcp_debug("mptcp_get_avail_list_ipv4: List %i\n", i);
		sock_num = 0;
		list_taken = 0;
		
		/* Loop through all sub-sockets in this connection */
		tp = tcp_sk(sk)->mpcb->connection_list->mptcp->next;
		while (tp != NULL) {
			mptcp_debug("mptcp_get_avail_list_ipv4: Next socket\n");
			sock_num++;
			
			/* Reset length and options buffer, then retrieve from socket */
			opt_len = MAX_IPOPTLEN;
			memset(opt, 0, MAX_IPOPTLEN);
			opt_ret = ip_getsockopt((struct sock *)tp, IPPROTO_IP,
				IP_OPTIONS, opt, &opt_len);
			if (opt_ret < 0) {
				mptcp_debug(KERN_ERR "%s: MPTCP subsocket getsockopt() IP_OPTIONS "
				"failed, error %d\n", __func__, opt_ret);
				goto error;
			}

			/* If socket has no options, it has no stake in this list */
			if (opt_len > 0) {
				/* Iterate options buffer */
				for (opt_ptr = &opt[0]; opt_ptr < &opt[opt_len]; opt_ptr++) {
										
					if (*opt_ptr == IPOPT_LSRR) {
						mptcp_debug("mptcp_get_avail_list_ipv4: LSRR options found\n");
						
						/* Pointer to the 2nd to last address */
						opt_end_ptr = opt_ptr+(*(opt_ptr+1))-4;
						
						/* Addresses start 3 bytes after type offset */
						opt_ptr += 3;
						j = 0;
						
						/* Different length lists cannot be the same */
						if ((opt_end_ptr-opt_ptr)/4 == mptcp_gws->len[i]) {
							/* Iterate if we are still inside options list and 
							 * sysctl list */
							while(opt_ptr < opt_end_ptr && j < mptcp_gws->len[i]) {
								/* If there is a different address, this list must 
								 * not be set on this socket */
								if (memcmp(&mptcp_gws->list[i][j], opt_ptr, 4))
									break;
								
								/* Jump 4 bytes to next address */
								opt_ptr += 4;
								j++;
							}
							
							/* Reached the end without a differing address,
							 * lists are therefore identical */
							if (j == mptcp_gws->len[i]) {
								mptcp_debug("mptcp_get_avail_list_ipv4: List "
										"already used\n");
								list_taken = 1;
							}
						}
						break;
					}
				}
			}
			
			/* List is taken so move on */
			if (list_taken)
				break;
				
			tp = tp->mptcp->next;
		}
		
		/* Free list found if not taken by a socket */
		if (! list_taken) {
			mptcp_debug("mptcp_get_avail_list_ipv4: List free\n");
			break;
		}
	}
	
	if (i >= MPTCP_GW_MAX_LISTS)
		goto error;

	return i;
error:
	return -1;
}

/*
 * The list of addresses is parsed each time a new connection is opened, to
 *  to make sure it's up to date. In case of error, all the lists are
 *  marked as unavailable and the subflow's fingerprint is set to 0.
 */
static void mptcp_v4_add_lsrr(struct sock *sk, struct in_addr rem)
{
	int i, j, ret;
	char * opt = NULL;
	struct tcp_sock * tp = tcp_sk(sk);
	struct binder_priv *fmp = (struct binder_priv *)&tp->mpcb->mptcp_pm[0];

	opt = kmem_cache_alloc(opt_slub_v4, GFP_KERNEL);
	if (!opt)
		goto error;
	/*
	 * Read lock: multiple sockets can read LSRR addresses at the same time,
	 * but writes are done in mutual exclusion.
	 * Spin lock: must search for free list for one socket at a time, or
	 * multiple sockets could take the same list.
	 */
	read_lock(&mptcp_gws_lock);
	spin_lock(fmp->flow_lock);

	i = mptcp_get_avail_list_ipv4(sk, (unsigned char *) opt);

	/*
	 * Execution enters here only if a free path is found.
	 */
	if (i >= 0) {
		memset(opt, 0, MAX_IPOPTLEN);
		opt[0] = IPOPT_NOP;
		opt[1] = IPOPT_LSRR;
		opt[2] = sizeof(mptcp_gws->list[i][0].s_addr) * (mptcp_gws->len[i] + 1)
				+ 3;
		opt[3] = IPOPT_MINOFF;
		for (j = 0; j < mptcp_gws->len[i]; ++j)
			memcpy(opt + 4 + (j * sizeof(mptcp_gws->list[i][0].s_addr)),
					&mptcp_gws->list[i][j].s_addr,
					sizeof(mptcp_gws->list[i][0].s_addr));
		/* Final destination must be part of IP_OPTIONS parameter. */
		memcpy(opt + 4 + (j * sizeof(rem.s_addr)), &rem.s_addr,
				sizeof(rem.s_addr));

		/*
		 * setsockopt must be inside the lock, otherwise another subflow could
		 * fail to see that we have taken a list.
		 */
		ret = ip_setsockopt(sk, IPPROTO_IP, IP_OPTIONS, opt,
				4 + sizeof(mptcp_gws->list[i][0].s_addr)
				* (mptcp_gws->len[i] + 1));

		if (ret < 0) {
			mptcp_debug(KERN_ERR "%s: MPTCP subsocket setsockopt() IP_OPTIONS "
			"failed, error %d\n", __func__, ret);
		}
	}

	spin_unlock(fmp->flow_lock);
	read_unlock(&mptcp_gws_lock);
	kmem_cache_free(opt_slub_v4, opt);

error:
	return;
}

/*
 *  Parses gateways string for a list of paths to different
 *  gateways, and stores them for use with the Loose Source Routing (LSRR)
 *  socket option. Each list must have "," separated addresses, and the lists
 *  themselves must be separated by "-". Returns -1 in case one or more of the
 *  addresses is not a valid ipv4/6 address.
 */
static int mptcp_parse_gateway_ipv4(char * gateways)
{
	int i, j, k, ret;
	char * tmp_string = NULL;
	struct in_addr tmp_addr;

	if ((tmp_string = kzalloc(16, GFP_KERNEL)) == NULL)
		return -ENOMEM;

	write_lock(&mptcp_gws_lock);

	memset(mptcp_gws, 0, sizeof(struct mptcp_gw_list));

	/*
	 * A TMP string is used since inet_pton needs a null terminated string but
	 * we do not want to modify the sysctl for obvious reasons.
	 * i will iterate over the SYSCTL string, j will iterate over the temporary string where
	 * each IP is copied into, k will iterate over the IPs in each list.
	 */
	for (i = j = k = 0; i < MPTCP_GW_SYSCTL_MAX_LEN && k < MPTCP_GW_MAX_LISTS; ++i) {
		if (gateways[i] == '-' || gateways[i] == ',' || gateways[i] == '\0') {
			/*
			 * If the temp IP is empty and the current list is empty, we are done.
			 */
			if (j == 0 && mptcp_gws->len[k] == 0)
				break;

			/*
			 * Terminate the temp IP string, then if it is non-empty parse the IP and copy it.
			 */
			tmp_string[j] = '\0';
			if (j > 0) {
				mptcp_debug("mptcp_parse_gateway_list tmp: %s i: %d \n",
						tmp_string, i);

				ret = in4_pton(tmp_string, strlen(tmp_string),
						(u8 *) &tmp_addr.s_addr, '\0', NULL);

				if (ret) {
					mptcp_debug("mptcp_parse_gateway_list ret: %d s_addr: %pI4\n",
							ret, &tmp_addr.s_addr);
					memcpy(&mptcp_gws->list[k][mptcp_gws->len[k]].s_addr,
							&tmp_addr.s_addr, sizeof(tmp_addr.s_addr));
					mptcp_gws->len[k]++;
					j = 0;
					tmp_string[j] = '\0';
					/*
					 * Since we can't impose a limit to what the user can input, make sure
					 * there are not too many IPs in the SYSCTL string.
					 */
					if (mptcp_gws->len[k] > MPTCP_GW_LIST_MAX_LEN) {
						mptcp_debug("mptcp_parse_gateway_list too many members in list %i: max %i\n",
							k, MPTCP_GW_LIST_MAX_LEN);
						goto error;
					}
				} else {
					goto error;
				}
			}

			if (gateways[i] == '-' || gateways[i] == '\0') {
				++k;
			}
		} else {
			tmp_string[j] = gateways[i];
			++j;
		}
	}

	sysctl_mptcp_binder_ndiffports = k+1;

	write_unlock(&mptcp_gws_lock);
	kfree(tmp_string);

	return 0;

error:
	memset(mptcp_gws, 0, sizeof(struct mptcp_gw_list));
	memset(gateways, 0, sizeof(char) * MPTCP_GW_SYSCTL_MAX_LEN);
	write_unlock(&mptcp_gws_lock);
	kfree(tmp_string);
	return -1;
}

#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
static int mptcp_get_avail_list_ipv6(struct sock *sk, unsigned char *opt)
{
	int i, sock_num, list_free, opt_ret, opt_len;
	struct tcp_sock *tp;

	for (i = 0; i < MPTCP_GW_MAX_LISTS; ++i) {
		if (mptcp_gws->len[i] == 0)
			goto error;

		mptcp_debug("mptcp_get_avail_list_ipv6: List %i\n", i);
		sock_num = 0;
		list_free = 0;

		/* Loop through all sub-sockets in this connection */
		tp = tcp_sk(sk)->mpcb->connection_list->mptcp->next;
		while (tp != NULL) {
			mptcp_debug("mptcp_get_avail_list_ipv6: Next socket\n");
			sock_num++;

			/* Reset length and options buffer, then retrieve from socket */
			memset(opt, 0, MPTCP_OPT_V6_SIZE);
			opt_ret = ipv6_getsockopt((struct sock *)tp, IPPROTO_IPV6,
					IPV6_RTHDR, opt, &opt_len);
			if (opt_ret < 0) {
				mptcp_debug(KERN_ERR "%s: MPTCP subsocket getsockopt() "
				"IP_OPTIONS failed, error %d\n", __func__, opt_ret);
				goto error;
			}

			/* If socket has no options, it has no stake in this list.
			 * The hop address will be in the socket dest address, NOT
			 * in the routing header.
			 */
			if (opt_len == 0 ||
					memcmp(&mptcp_gws->list[i][0], &sk->sk_v6_daddr, 8)) {
				list_free++;
			} else {
				/*
				 * One socket using the list is enough to make it unusable.
				 */
				break;
			}

			tp = tp->mptcp->next;
		}

		/* Free list found if all sockets agree */
		if (sock_num == list_free)
			break;
	}

	if (i >= MPTCP_GW_MAX_LISTS)
		goto error;

	return i;

error:
	return -1;
}

/*
 * The list of addresses is parsed each time a new connection is opened, to
 *  to make sure it's up to date. In case of error, all the lists are
 *  marked as unavailable.
 */
static void mptcp_v6_add_rh0(struct sock * sk, struct sockaddr_in6 *rem)
{
	int i, ret;
	char * opt = NULL;
	struct tcp_sock * tp = tcp_sk(sk);
	struct binder_priv *fmp = (struct binder_priv *)&tp->mpcb->mptcp_pm[0];

	opt = kmem_cache_alloc(opt_slub_v6, GFP_KERNEL);
	if (!opt)
		goto error;
	/*
	 * Read lock: multiple sockets can read RTH addresses at the same time,
	 * but writes are done in mutual exclusion.
	 * Spin lock: must search for free list for one socket at a time, or
	 * multiple sockets could take the same list.
	 */
	read_lock(&mptcp_gws6_lock);
	spin_lock(fmp->flow_lock);

	i = mptcp_get_avail_list_ipv6(sk, (unsigned char *) opt);

	/*
	 * Execution enters here only if a free path is found.
	 */
	if (i >= 0) {
		memset(opt, 0, MPTCP_OPT_V6_SIZE);
		opt[1] = 2; // Hdr Ext Len, from rfc2460: 2x addresses in the header.
		opt[2] = 0; // Routing Type
		opt[3] = 1; // Segments Left

		/*
		 * Insert dest address after 4 zero set bytes, following rfc2460
		 */
		memcpy(opt + 8, &rem->sin6_addr, sizeof(rem->sin6_addr));
		/*
		 * Change dest address to next hop address
		 */
		memcpy(&rem->sin6_addr, &mptcp_gws6->list[i][0].s6_addr,
				sizeof(mptcp_gws6->list[i][0].s6_addr));

		/*
		 * setsockopt must be inside the lock, otherwise another subflow could
		 * fail to see that we have taken a list.
		 */
		ret = ipv6_setsockopt(sk, IPPROTO_IPV6, IPV6_RTHDR, opt,
				MPTCP_OPT_V6_SIZE);

		if (ret < 0) {
			mptcp_debug(KERN_ERR "%s: MPTCP subsocket setsockopt() IPV6_RTHDR "
			"failed, error %d\n", __func__, ret);
		}
	}
	spin_unlock(fmp->flow_lock);
	read_unlock(&mptcp_gws6_lock);
	kmem_cache_free(opt_slub_v6, opt);

error:
	return;
}

/*
 *  Parses gateways string for a list of paths to different
 *  gateways, and stores them for use with the Routing Header Type 0
 *  socket option. Each list must have "," separated addresses, and the lists
 *  themselves must be separated by "-". Returns -1 in case one or more of the
 *  addresses is not a valid ipv6 address.
 */
static int mptcp_parse_gateway_ipv6(char * gateways)
{
	int i, j, k, ret;
	char * tmp_string = NULL;
	struct in6_addr tmp_addr;

	if ((tmp_string = kzalloc(40, GFP_KERNEL)) == NULL)
		return -ENOMEM;

	write_lock(&mptcp_gws6_lock);

	memset(mptcp_gws6, 0, sizeof(struct mptcp_gw_list6));

	/*
	 * A TMP string is used since inet_pton needs a null terminated string but
	 * we do not want to modify the sysctl for obvious reasons.
	 * i will iterate over the SYSCTL string, j will iterate over the temporary string where
	 * each IP is copied into, k will iterate over the IPs in each list.
	 */
	for (i = j = k = 0; i < MPTCP_GW6_SYSCTL_MAX_LEN && k < MPTCP_GW_MAX_LISTS; ++i) {
		if (gateways[i] == '-' || gateways[i] == ',' || gateways[i] == '\0') {
			/*
			 * If the temp IP is empty and the current list is empty, we are done.
			 */
			if (j == 0 && mptcp_gws6->len[k] == 0)
				break;

			/*
			 * Terminate the temp IP string, then if it is non-empty parse the IP and copy it.
			 */
			tmp_string[j] = '\0';

			if (j > 0) {
				mptcp_debug("mptcp_parse_gateway_list tmp: %s i: %d \n",
						tmp_string, i);

				ret = in6_pton(tmp_string, strlen(tmp_string),
						(u8 *) &tmp_addr.s6_addr, '\0', NULL);

				if (ret) {
					mptcp_debug("mptcp_parse_gateway_list ret: %d s_addr: %pI6\n",
							ret, &tmp_addr.s6_addr);
					memcpy(&mptcp_gws6->list[k][mptcp_gws6->len[k]].s6_addr,
							&tmp_addr.s6_addr, sizeof(tmp_addr.s6_addr));
					mptcp_gws6->len[k]++;
					j = 0;
					tmp_string[j] = '\0';
					/*
					 * Since we can't impose a limit to what the user can input, make sure
					 * there are not too many IPs in the SYSCTL string.
					 */
					if (mptcp_gws6->len[k] > MPTCP_GW_LIST_MAX_LEN6) {
						mptcp_debug("mptcp_parse_gateway_list too many members in list %i: max %i\n",
							k, MPTCP_GW_LIST_MAX_LEN);
						goto error;
					}
				} else {
					goto error;
				}
			}

			if (gateways[i] == '-' || gateways[i] == '\0') {
				++k;
			}
		} else {
			tmp_string[j] = gateways[i];
			++j;
		}
	}

	sysctl_mptcp_binder_ndiffports = k+1;

	write_unlock(&mptcp_gws6_lock);
	kfree(tmp_string);
	return 0;

error:
	memset(mptcp_gws6, 0, sizeof(struct mptcp_gw_list6));
	memset(gateways, 0, sizeof(char) * MPTCP_GW6_SYSCTL_MAX_LEN);
	write_unlock(&mptcp_gws6_lock);
	kfree(tmp_string);
	return -1;
}
#endif /* CONFIG_MPTCP_BINDER_IPV6 */

/**
 * Create all new subflows, by doing calls to mptcp_initX_subsockets
 *
 * This function uses a goto next_subflow, to allow releasing the lock between
 * new subflows and giving other processes a chance to do some work on the
 * socket and potentially finishing the communication.
 **/
static void create_subflow_worker(struct work_struct *work)
{
	struct binder_priv *pm_priv = container_of(work,
						     struct binder_priv,
						     subflow_work);
	struct mptcp_cb *mpcb = pm_priv->mpcb;
	struct sock *meta_sk = mpcb->meta_sk;
	int iter = 0;

next_subflow:
	if (iter) {
		release_sock(meta_sk);
		mutex_unlock(&mpcb->mpcb_mutex);

		yield();
	}
	mutex_lock(&mpcb->mpcb_mutex);
	lock_sock_nested(meta_sk, SINGLE_DEPTH_NESTING);

	iter++;

	if (sock_flag(meta_sk, SOCK_DEAD))
		goto exit;

	if (mpcb->master_sk &&
	    !tcp_sk(mpcb->master_sk)->mptcp->fully_established)
		goto exit;

	if (sysctl_mptcp_binder_ndiffports > iter &&
	    sysctl_mptcp_binder_ndiffports > mpcb->cnt_subflows) {
		if (meta_sk->sk_family == AF_INET ||
		    mptcp_v6_is_v4_mapped(meta_sk)) {
			struct mptcp_loc4 loc;

			loc.addr.s_addr = inet_sk(meta_sk)->inet_saddr;
			loc.loc4_id = 0;
			loc.low_prio = 0;

			mptcp_init4_subsockets(meta_sk, &loc, &mpcb->remaddr4[0]);
		} else {
#if IS_ENABLED(CONFIG_IPV6)
			struct mptcp_loc6 loc;

			loc.addr = inet6_sk(meta_sk)->saddr;
			loc.loc6_id = 0;
			loc.low_prio = 0;

			mptcp_init6_subsockets(meta_sk, &loc, &mpcb->remaddr6[0]);
#endif
		}
		goto next_subflow;
	}

exit:
	release_sock(meta_sk);
	mutex_unlock(&mpcb->mpcb_mutex);
	sock_put(meta_sk);
}

static void binder_new_session(struct sock *meta_sk, int index)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct binder_priv *fmp = (struct binder_priv *)&mpcb->mptcp_pm[0];
	static DEFINE_SPINLOCK(flow_lock);

	/* Initialize workqueue-struct */
	INIT_WORK(&fmp->subflow_work, create_subflow_worker);
	fmp->mpcb = mpcb;
	
	fmp->flow_lock = &flow_lock;
}

static void binder_create_subflows(struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct binder_priv *pm_priv = (struct binder_priv *)&mpcb->mptcp_pm[0];

	if (mpcb->infinite_mapping_snd || mpcb->infinite_mapping_rcv ||
	    mpcb->send_infinite_mapping ||
	    mpcb->server_side || sock_flag(meta_sk, SOCK_DEAD))
		return;

	if (!work_pending(&pm_priv->subflow_work)) {
		sock_hold(meta_sk);
		queue_work(mptcp_wq, &pm_priv->subflow_work);
	}
}

static int binder_get_local_index(sa_family_t family, union inet_addr *addr,
				  struct net *net)
{
	return 0;
}

/*
 * Callback functions, executed when syctl mptcp.mptcp_gateways is updated.
 * Inspired from proc_tcp_congestion_control().
 */
static int proc_mptcp_gateways(ctl_table *ctl, int write,
				       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	ctl_table tbl = {
		.maxlen = MPTCP_GW_SYSCTL_MAX_LEN,
	};

	if (write) {
		if ((tbl.data = kzalloc(MPTCP_GW_SYSCTL_MAX_LEN, GFP_KERNEL))
				== NULL)
			return -1;
		ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
		if (ret == 0) {
			ret = mptcp_parse_gateway_ipv4(tbl.data);
			memcpy(ctl->data, tbl.data, MPTCP_GW_SYSCTL_MAX_LEN);
		}
		kfree(tbl.data);
	} else {
		ret = proc_dostring(ctl, write, buffer, lenp, ppos);
	}


	return ret;
}

#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
/* ipv6 version of the callback */
static int proc_mptcp_gateways6(ctl_table *ctl, int write,
				       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	ctl_table tbl = {
		.maxlen = MPTCP_GW6_SYSCTL_MAX_LEN,
	};

	if (write) {
		if ((tbl.data = kzalloc(MPTCP_GW6_SYSCTL_MAX_LEN, GFP_KERNEL))
				== NULL)
			return -1;
		ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
		if (ret == 0) {
			ret = mptcp_parse_gateway_ipv6(tbl.data);
			memcpy(ctl->data, tbl.data, MPTCP_GW6_SYSCTL_MAX_LEN);
		}
		kfree(tbl.data);
	} else {
		ret = proc_dostring(ctl, write, buffer, lenp, ppos);
	}


	return ret;
}
#endif /* CONFIG_MPTCP_BINDER_IPV6 */

static struct mptcp_pm_ops binder __read_mostly = {
	.new_session = binder_new_session,
	.fully_established = binder_create_subflows,
	.get_local_index = binder_get_local_index,
	.get_local_id = binder_get_local_index,
	.init_subsocket_v4 = mptcp_v4_add_lsrr,
#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
	.init_subsocket_v6 = mptcp_v6_add_rh0,
#endif /* CONFIG_MPTCP_BINDER_IPV6 */
	.name = "binder",
	.owner = THIS_MODULE,
};

static struct ctl_table binder_table[] = {
	{
		.procname = "mptcp_binder_ndiffports",
		.data = &sysctl_mptcp_binder_ndiffports,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "mptcp_binder_gateways",
		.data = &sysctl_mptcp_binder_gateways,
		.maxlen = sizeof(char) * MPTCP_GW_SYSCTL_MAX_LEN,
 		.mode = 0644,
		.proc_handler = &proc_mptcp_gateways
 	},
#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
	{
		.procname = "mptcp_binder_gateways6",
		.data = &sysctl_mptcp_binder_gateways6,
		.maxlen = sizeof(char) * MPTCP_GW6_SYSCTL_MAX_LEN,
		.mode = 0644,
		.proc_handler = &proc_mptcp_gateways6
	},
#endif /* CONFIG_MPTCP_BINDER_IPV6 */
	{ }
};

struct ctl_table_header *mptcp_sysctl_binder;

/* General initialization of MPTCP_PM */
static int __init binder_register(void)
{
	mptcp_gws = kzalloc(sizeof(struct mptcp_gw_list), GFP_KERNEL);
	if (!mptcp_gws)
		return -ENOMEM;

	rwlock_init(&mptcp_gws_lock);

	opt_slub_v4 = kmem_cache_create("binder_v4", MAX_IPOPTLEN,
            0, 0, NULL);
	if (!opt_slub_v4)
		return -ENOMEM;

#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
	mptcp_gws6 = kzalloc(sizeof(struct mptcp_gw_list6), GFP_KERNEL);
	if (!mptcp_gws6)
		return -ENOMEM;

	rwlock_init(&mptcp_gws6_lock);

	opt_slub_v6 = kmem_cache_create("binder_v6", MPTCP_OPT_V6_SIZE,
            0, 0, NULL);
	if (!opt_slub_v6)
		return -ENOMEM;
#endif /* CONFIG_MPTCP_BINDER_IPV6 */

	BUILD_BUG_ON(sizeof(struct binder_priv) > MPTCP_PM_SIZE);

	mptcp_sysctl_binder = register_net_sysctl(&init_net, "net/mptcp", binder_table);
	if (!mptcp_sysctl_binder)
		goto exit;

	if (mptcp_register_path_manager(&binder))
		goto pm_failed;

	return 0;

pm_failed:
	unregister_net_sysctl_table(mptcp_sysctl_binder);
exit:
	return -1;
}

static void binder_unregister(void)
{
	mptcp_unregister_path_manager(&binder);
	unregister_net_sysctl_table(mptcp_sysctl_binder);
	kfree(mptcp_gws);
	if (opt_slub_v4)
		kmem_cache_destroy(opt_slub_v4);
#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
	kfree(mptcp_gws6);
	if (opt_slub_v6)
		kmem_cache_destroy(opt_slub_v6);
#endif /* CONFIG_MPTCP_BINDER_IPV6 */
}

module_init(binder_register);
module_exit(binder_unregister);

MODULE_AUTHOR("Luca Boccassi, Duncan Eastoe, Christoph Paasch (ndiffports)");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("BINDER MPTCP");
MODULE_VERSION("0.1");
