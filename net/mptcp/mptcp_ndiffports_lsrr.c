#include <linux/module.h>
#include <linux/inet.h>

#include <net/mptcp.h>
#include <net/mptcp_v4.h>

#define NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS 10
#define NDIFFPORTS_LSRR_GATEWAY_LIST_MAX_LEN 6
#define NDIFFPORTS_LSRR_GATEWAY_SYSCTL_MAX_LEN 15 * NDIFFPORTS_LSRR_GATEWAY_LIST_MAX_LEN * NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS
#define NDIFFPORTS_LSRR_GATEWAY_FP_SIZE 16

struct ndiffports_lsrr_gw_list {
	struct in_addr list[NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS][NDIFFPORTS_LSRR_GATEWAY_LIST_MAX_LEN];
	u64 timestamp;
	u8 gw_list_fingerprint[NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS][NDIFFPORTS_LSRR_GATEWAY_FP_SIZE];
	u8 len[NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS];
};

struct ndiffports_lsrr_gw_list_fps_and_disp {
	u64 timestamp;
	u8 gw_list_fingerprint[NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS][NDIFFPORTS_LSRR_GATEWAY_FP_SIZE];
	u8 gw_list_avail[NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS];
};

struct ndiffports_lsrr_used_gw {
	u8 gw_fingerprint[NDIFFPORTS_LSRR_GATEWAY_FP_SIZE];
	u8 gw_is_set;
};

struct ndiffports_lsrr_priv {
	/* Worker struct for subflow establishment */
	struct work_struct subflow_work;

	struct mptcp_cb *mpcb;
	
	struct ndiffports_lsrr_gw_list_fps_and_disp list_fingerprints;
};

char sysctl_ndiffports_lsrr_gateways[NDIFFPORTS_LSRR_GATEWAY_SYSCTL_MAX_LEN] __read_mostly;
struct ndiffports_lsrr_gw_list *mptcp_gws;
rwlock_t mptcp_gws_lock;
static int sysctl_mptcp_ndiffports_lsrr __read_mostly = 2;

/*
 * Updates the list of addresses contained in the meta-socket data structures
 */
int ndiffports_lsrr_update_mpcb_gateway_list_ipv4(struct mptcp_cb * mpcb) {
	int i, j;
	u8 * tmp_avail = NULL, * tmp_used = NULL;
	struct ndiffports_lsrr_priv *priv = ((struct ndiffports_lsrr_priv *) &mpcb->mptcp_pm[0]);

	if (priv->list_fingerprints.timestamp >= mptcp_gws->timestamp)
		return 0;

	if ((tmp_avail = kzalloc(sizeof(u8) * NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS,
			GFP_KERNEL)) == NULL)
		goto error;
	if ((tmp_used = kzalloc(sizeof(u8) * NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS,
			GFP_KERNEL)) == NULL)
		goto error;

	/*
	 * tmp_used: if any two lists are exactly equivalent then their fingerprint
	 * is also equivalent. This means that, without remembering which has
	 * already been seet, the following code would be broken, as only the first
	 * old value of gw_list_avail would be written on both the new variables.
	 */
	for (i = 0; i < NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS; ++i) {
		if (mptcp_gws->len[i] > 0) {
			tmp_avail[i] = 1;
			for (j = 0; j < NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS; ++j)
				if (!memcmp(&mptcp_gws->gw_list_fingerprint[i],
						&priv->list_fingerprints.gw_list_fingerprint[j],
						sizeof(u8) * NDIFFPORTS_LSRR_GATEWAY_FP_SIZE) && !tmp_used[j]) {
					tmp_avail[i] = priv->list_fingerprints.gw_list_avail[j];
					tmp_used[j] = 1;
					break;
				}
		}
	}

	memcpy(&priv->list_fingerprints.gw_list_fingerprint,
			&mptcp_gws->gw_list_fingerprint,
			sizeof(u8) * NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS * NDIFFPORTS_LSRR_GATEWAY_FP_SIZE);
	memcpy(&priv->list_fingerprints.gw_list_avail, tmp_avail,
			sizeof(u8) * NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS);
	priv->list_fingerprints.timestamp = mptcp_gws->timestamp;
	kfree(tmp_avail);
	kfree(tmp_used);

	return 0;

error:
	kfree(tmp_avail);
	kfree(tmp_used);
	memset(&priv->list_fingerprints, 0,
			sizeof(struct ndiffports_lsrr_gw_list_fps_and_disp));
	return -1;
}

/* Computes fingerprint of a list of IP addresses (4/16 bytes integers),
 * used to compare newly parsed sysctl variable with old one.
 * PAGE_SIZE is hard limit (1024 ipv4 or 256 ipv6 addresses per list) */
int ndiffports_lsrr_calc_fingerprint_gateway_list(u8 * fingerprint, u8 * data,
		size_t size)
{
	struct scatterlist * sg = NULL;
	struct crypto_hash * tfm = NULL;
	struct hash_desc desc;

	if (size > PAGE_SIZE)
		goto error;

	if ((sg = kmalloc(sizeof(struct scatterlist), GFP_KERNEL)) == NULL)
		goto error;

	if ((tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC)) == NULL)
		goto error;

	sg_init_one(sg, (u8 *)data, size);

	desc.tfm = tfm;
	if (crypto_hash_init(&desc) != 0)
		goto error;

	if (crypto_hash_digest(&desc, sg, size, fingerprint) != 0)
		goto error;

	crypto_free_hash(tfm);
	kfree(sg);

	return 0;

error:
	crypto_free_hash(tfm);
	kfree(sg);
	return -1;
}

/*
 *  Parses gateways string for a list of paths to different
 *  gateways, and stores them for use with the Loose Source Routing (LSRR)
 *  socket option. Each list must have "," separated addresses, and the lists
 *  themselves must be separated by "-". Returns -1 in case one or more of the
 *  addresses is not a valid ipv4/6 address.
 */
int ndiffports_lsrr_parse_gateway_ipv4(char * gateways)
{
	int i, j, k, ret;
	char * tmp_string = NULL;
	struct in_addr tmp_addr;

	write_lock(&mptcp_gws_lock);

	if ((tmp_string = kzalloc(16, GFP_KERNEL)) == NULL)
		goto error;

	memset(mptcp_gws, 0, sizeof(struct ndiffports_lsrr_gw_list));

	/*
	 * A TMP string is used since inet_pton needs a null terminated string but
	 * we do not want to modify the sysctl for obvious reasons.
	 * i will iterate over the SYSCTL string, j will iterate over the temporary string where
	 * each IP is copied into, k will iterate over the IPs in each list.
	 */
	for (i = j = k = 0; i < NDIFFPORTS_LSRR_GATEWAY_SYSCTL_MAX_LEN && k < NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS; ++i) {
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
					if (mptcp_gws->len[k] > NDIFFPORTS_LSRR_GATEWAY_LIST_MAX_LEN) {
						mptcp_debug("mptcp_parse_gateway_list too many members in list %i: max %i\n",
							k, NDIFFPORTS_LSRR_GATEWAY_LIST_MAX_LEN);
						goto error;
					}
				} else {
					goto error;
				}
			}

			/*
			 * If the list is over or the SYSCTL string is over, create a fingerprint.
			 */
			if (gateways[i] == '-' || gateways[i] == '\0') {
				if (ndiffports_lsrr_calc_fingerprint_gateway_list(
						(u8 *)&mptcp_gws->gw_list_fingerprint[k],
						(u8 *)&mptcp_gws->list[k][0],
						sizeof(mptcp_gws->list[k][0].s_addr) *
						mptcp_gws->len[k])) {
					goto error;
				}
				mptcp_debug("mptcp_parse_gateway_list fingerprint calculated for list %i\n", k);
				++k;
			}
		} else {
			tmp_string[j] = gateways[i];
			++j;
		}
	}

	mptcp_gws->timestamp = get_jiffies_64();
	kfree(tmp_string);
	write_unlock(&mptcp_gws_lock);

	return 0;

error:
	kfree(tmp_string);
	memset(mptcp_gws, 0, sizeof(struct ndiffports_lsrr_gw_list));
	memset(gateways, 0, sizeof(char) * NDIFFPORTS_LSRR_GATEWAY_SYSCTL_MAX_LEN);
	write_unlock(&mptcp_gws_lock);
	return -1;
}

/*
 * Callback functions, executed when syctl mptcp.mptcp_ndiffports_lsrr_gateways is updated.
 * Inspired from proc_tcp_congestion_control().
 */
static int proc_ndiffports_lsrr_gateways(ctl_table *ctl, int write,
				       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	ctl_table tbl = {
		.maxlen = NDIFFPORTS_LSRR_GATEWAY_SYSCTL_MAX_LEN,
	};

	if (write) {
		if ((tbl.data = kzalloc(NDIFFPORTS_LSRR_GATEWAY_SYSCTL_MAX_LEN, GFP_KERNEL))
				== NULL)
			return -1;
		ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
		if (ret == 0) {
			ret = ndiffports_lsrr_parse_gateway_ipv4(tbl.data);
			memcpy(ctl->data, tbl.data, NDIFFPORTS_LSRR_GATEWAY_SYSCTL_MAX_LEN);
		}
		kfree(tbl.data);
	} else {
		ret = proc_dostring(ctl, write, buffer, lenp, ppos);
	}


	return ret;
}

/**
 * Create all new subflows, by doing calls to mptcp_initX_subsockets
 *
 * This function uses a goto next_subflow, to allow releasing the lock between
 * new subflows and giving other processes a chance to do some work on the
 * socket and potentially finishing the communication.
 **/
static void create_subflow_worker(struct work_struct *work)
{
	struct ndiffports_lsrr_priv *pm_priv = container_of(work,
						     struct ndiffports_lsrr_priv,
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

	if (sysctl_mptcp_ndiffports_lsrr > iter &&
	    sysctl_mptcp_ndiffports_lsrr > mpcb->cnt_subflows) {
		if (meta_sk->sk_family == AF_INET ||
		    mptcp_v6_is_v4_mapped(meta_sk)) {
			struct mptcp_loc4 loc;

			loc.addr.s_addr = inet_sk(meta_sk)->inet_saddr;
			loc.id = 0;
			loc.low_prio = 0;

			mptcp_init4_subsockets(meta_sk, &loc, &mpcb->remaddr4[0]);
		}
		goto next_subflow;
	}

exit:
	release_sock(meta_sk);
	mutex_unlock(&mpcb->mpcb_mutex);
	sock_put(meta_sk);
}

static void ndiffports_lsrr_new_session(struct sock *meta_sk, u8 id)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct ndiffports_lsrr_priv *fmp = (struct ndiffports_lsrr_priv *)&mpcb->mptcp_pm[0];
	
	/*
	 * Allocates LSRR/Routing Header variables.
	 */
	memset(&fmp->list_fingerprints, 0,
			sizeof(struct ndiffports_lsrr_gw_list_fps_and_disp));

	/* Initialize workqueue-struct */
	INIT_WORK(&fmp->subflow_work, create_subflow_worker);
	fmp->mpcb = mpcb;
}

static void ndiffports_lsrr_create_subflows(struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct ndiffports_lsrr_priv *pm_priv = (struct ndiffports_lsrr_priv *)&mpcb->mptcp_pm[0];

	if (mpcb->infinite_mapping_snd || mpcb->infinite_mapping_rcv ||
	    mpcb->send_infinite_mapping ||
	    mpcb->server_side || sock_flag(meta_sk, SOCK_DEAD))
		return;

	if (!work_pending(&pm_priv->subflow_work)) {
		sock_hold(meta_sk);
		queue_work(mptcp_wq, &pm_priv->subflow_work);
	}
}

static int ndiffports_lsrr_get_local_id(sa_family_t family, union inet_addr *addr,
				  struct net *net)
{
	return 0;
}

static void ndiffports_lsrr_subsock_bind(struct sock *sk, struct mptcp_rem4 *rem) {
	int i, j, ret;
	char * opt = NULL;
	struct in_addr dest_addr = rem->addr;
	struct tcp_sock * tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;
	struct ndiffports_lsrr_priv *priv = ((struct ndiffports_lsrr_priv *) &mpcb->mptcp_pm[0]);
	struct ndiffports_lsrr_used_gw *used_gw = (struct ndiffports_lsrr_used_gw *)&tp->mptcp->mptcp_pm_sock[0];
	
	mptcp_debug("subsock_bind callback\n");

	/*
	 * Read lock: multiple sockets can read LSRR addresses at the same time,
	 * but writes are done in mutual exclusion.
	 */
	read_lock(&mptcp_gws_lock);

	if (ndiffports_lsrr_update_mpcb_gateway_list_ipv4(tp->mpcb))
		goto error;

	for (i = 0; i < NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS; ++i)
		if (priv->list_fingerprints.gw_list_avail[i] == 1
				&& mptcp_gws->len[i] > 0)
			break;

	/*
	 * Execution enters here only if a free path is found.
	 */
	if (i < NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS) {
		opt = kmalloc(MAX_IPOPTLEN, GFP_KERNEL);
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
		memcpy(opt + 4 + (j * sizeof(dest_addr)), &dest_addr,
				sizeof(dest_addr));

		ret = ip_setsockopt(sk, IPPROTO_IP, IP_OPTIONS, opt,
				4 + sizeof(mptcp_gws->list[i][0].s_addr)
				* (mptcp_gws->len[i] + 1));

		if (ret < 0) {
			mptcp_debug(KERN_ERR "%s: MPTCP subsocket setsockopt() IP_OPTIONS "
			"failed, error %d\n", __func__, ret);
			goto error;
		}

		priv->list_fingerprints.gw_list_avail[i] = 0;
		
		memcpy(&used_gw->gw_fingerprint,
				&priv->list_fingerprints.gw_list_fingerprint[i],
				sizeof(u8) * NDIFFPORTS_LSRR_GATEWAY_FP_SIZE);
		used_gw->gw_is_set = 1;
		
		kfree(opt);
		
	}

	read_unlock(&mptcp_gws_lock);
	return;

error:
	read_unlock(&mptcp_gws_lock);
	kfree(opt);
	return;
}

static void ndiffports_lsrr_sock_del(struct sock *sk) {
	int i;
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;
	struct ndiffports_lsrr_priv *priv = ((struct ndiffports_lsrr_priv *) &mpcb->mptcp_pm[0]);
	struct ndiffports_lsrr_used_gw *used_gw = (struct ndiffports_lsrr_used_gw *)&tp->mptcp->mptcp_pm_sock[0];
	
	mptcp_debug("sock_del callback\n");
	
	/*
	 * Sets the used path to GW as available again. We check if the match was
	 * actually claimed in case there are duplicates.
	 */
	if (used_gw->gw_is_set == 1) {
		if (sk->sk_family == AF_INET ||
				mptcp_v6_is_v4_mapped(sk)) {
			for (i = 0; i < NDIFFPORTS_LSRR_GATEWAY_MAX_LISTS; ++i) {
				if (priv->list_fingerprints.gw_list_avail[i] == 0
						&& !memcmp(&used_gw->gw_fingerprint,
						&priv->list_fingerprints.gw_list_fingerprint[i],
						sizeof(u8) * NDIFFPORTS_LSRR_GATEWAY_FP_SIZE)) {
					priv->list_fingerprints.gw_list_avail[i] = 1;
					break;
				}
			}
		}
	}
	
}

static struct mptcp_pm_ops ndiffports_lsrr __read_mostly = {
	.new_session = ndiffports_lsrr_new_session,
	.fully_established = ndiffports_lsrr_create_subflows,
	.get_local_id = ndiffports_lsrr_get_local_id,
	.subsock_bind = ndiffports_lsrr_subsock_bind,
	.sock_del = ndiffports_lsrr_sock_del,
	.name = "ndiffports_lsrr",
	.owner = THIS_MODULE,
};

static struct ctl_table ndiff_lsrr_table[] = {
	{
		.procname = "mptcp_ndiffports_lsrr",
		.data = &sysctl_mptcp_ndiffports_lsrr,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "mptcp_ndiffports_lsrr_gateways",
		.data = &sysctl_ndiffports_lsrr_gateways,
		.maxlen = sizeof(char) * NDIFFPORTS_LSRR_GATEWAY_SYSCTL_MAX_LEN,
 		.mode = 0644,
		.proc_handler = &proc_ndiffports_lsrr_gateways
 	},
	{ }
};

struct ctl_table_header *mptcp_sysctl_ndiffports_lsrr;

/* General initialization of MPTCP_PM */
static int __init ndiffports_lsrr_register(void)
{
	BUILD_BUG_ON(sizeof(struct ndiffports_lsrr_priv) > MPTCP_PM_SIZE);
	BUILD_BUG_ON(sizeof(struct ndiffports_lsrr_used_gw) > MPTCP_PM_SOCK_SIZE);

	mptcp_sysctl_ndiffports_lsrr = register_net_sysctl(&init_net, "net/mptcp", ndiff_lsrr_table);
	if (!mptcp_sysctl_ndiffports_lsrr)
		goto exit;

	if (mptcp_register_path_manager(&ndiffports_lsrr))
		goto pm_failed;

	mptcp_gws = kzalloc(sizeof(struct ndiffports_lsrr_gw_list), GFP_KERNEL);
	if (!mptcp_gws)
		return -ENOMEM;
	rwlock_init(&mptcp_gws_lock);

	return 0;

pm_failed:
	unregister_net_sysctl_table(mptcp_sysctl_ndiffports_lsrr);
exit:
	return -1;
}

static void ndiffports_lsrr_unregister(void)
{
	mptcp_unregister_path_manager(&ndiffports_lsrr);
	unregister_net_sysctl_table(mptcp_sysctl_ndiffports_lsrr);
	kfree(mptcp_gws);
}

module_init(ndiffports_lsrr_register);
module_exit(ndiffports_lsrr_unregister);

MODULE_AUTHOR("Luca Bocassi, Duncan Eastoe & Christoph Paasch (ndiffports)");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NDIFF-PORTS LSRR MPTCP");
MODULE_VERSION("0.88");
