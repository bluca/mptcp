#include <linux/module.h>

#include <net/mptcp.h>
#include <net/mptcp_v4.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <net/mptcp_v6.h>
#endif

#include <linux/jiffies.h>
#include <linux/route.h>
#include <linux/inet.h>
#include <linux/mroute.h>
#include <linux/cryptohash.h>
#include <net/inet_ecn.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <net/compat.h>
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#include <net/transp_v6.h>
#endif

#define MPTCP_GATEWAY_MAX_LISTS	10
#define MPTCP_GATEWAY_LIST_MAX_LEN	6
#define MPTCP_GATEWAY_SYSCTL_MAX_LEN	15 * MPTCP_GATEWAY_LIST_MAX_LEN * MPTCP_GATEWAY_MAX_LISTS
#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
#define MPTCP_GATEWAY_LIST_MAX_LEN6	1
#define MPTCP_GATEWAY6_SYSCTL_MAX_LEN	40 * MPTCP_GATEWAY_LIST_MAX_LEN6 * MPTCP_GATEWAY_MAX_LISTS
#endif  /* CONFIG_MPTCP_BINDER_IPV6 */

struct mptcp_gw_list {
	struct in_addr list[MPTCP_GATEWAY_MAX_LISTS][MPTCP_GATEWAY_LIST_MAX_LEN];
	u64 timestamp;
	u8 gw_list_fingerprint[MPTCP_GATEWAY_MAX_LISTS][MPTCP_BINDER_GATEWAY_FP_SIZE];
	u8 len[MPTCP_GATEWAY_MAX_LISTS];
};

#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
struct mptcp_gw_list6 {
	struct in6_addr list[MPTCP_GATEWAY_MAX_LISTS][MPTCP_GATEWAY_LIST_MAX_LEN6];
	u64 timestamp;
	u8 gw_list_fingerprint[MPTCP_GATEWAY_MAX_LISTS][MPTCP_BINDER_GATEWAY_FP_SIZE];
	u8 len[MPTCP_GATEWAY_MAX_LISTS];
};
#endif /* CONFIG_MPTCP_BINDER_IPV6 */

struct mptcp_gw_list_fps_and_disp {
#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
	u64 timestamp6;
	u8 gw_list_fingerprint6[MPTCP_GATEWAY_MAX_LISTS][MPTCP_BINDER_GATEWAY_FP_SIZE];
	u8 gw_list_avail6[MPTCP_GATEWAY_MAX_LISTS];
#endif /* CONFIG_MPTCP_BINDER_IPV6 */
	u64 timestamp;
	u8 gw_list_fingerprint[MPTCP_GATEWAY_MAX_LISTS][MPTCP_BINDER_GATEWAY_FP_SIZE];
	u8 gw_list_avail[MPTCP_GATEWAY_MAX_LISTS];
};

struct binder_priv {
	/* Worker struct for subflow establishment */
	struct work_struct subflow_work;

	struct mptcp_cb *mpcb;

	/* Lists of paths to gateways for LSRR, 0 if unavailabe/1 if available,
	 * and fingerprints for each list, to check on update from sysctl.
	 * */
	struct mptcp_gw_list_fps_and_disp list_fingerprints;
};

static struct mptcp_gw_list * mptcp_gws;
static rwlock_t mptcp_gws_lock;

static struct mptcp_gw_list * mptcp_gws;
static rwlock_t mptcp_gws_lock;

static int sysctl_mptcp_ndiffports __read_mostly = 2;
static char sysctl_mptcp_gateways[MPTCP_GATEWAY_SYSCTL_MAX_LEN] __read_mostly;

#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
static struct mptcp_gw_list6 * mptcp_gws6;
static rwlock_t mptcp_gws6_lock;

static struct mptcp_gw_list6 * mptcp_gws6;
static rwlock_t mptcp_gws6_lock;

static char sysctl_mptcp_gateways6[MPTCP_GATEWAY6_SYSCTL_MAX_LEN] __read_mostly;
#endif /* CONFIG_MPTCP_BINDER_IPV6 */

/* Computes fingerprint of a list of IP addresses (4/16 bytes integers),
 * used to compare newly parsed sysctl variable with old one.
 * PAGE_SIZE is hard limit (1024 ipv4 or 256 ipv6 addresses per list) */
static int mptcp_calc_fingerprint_gateway_list(u8 * fingerprint, u8 * data,
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
 * Sets the used path to GW as available again. We check if the match was
 * actually claimed in case there are duplicates.
 */
static void set_gateway_available(struct mptcp_cb *mpcb, struct tcp_sock *tp)
{
	int i;
	struct binder_priv *fmp = (struct binder_priv *)&mpcb->mptcp_pm[0];

	if (tp->mptcp->binder_gw_is_set == 1) {
		if (mpcb->meta_sk->sk_family == AF_INET || mptcp_v6_is_v4_mapped(mpcb->meta_sk)) {
			for (i = 0; i < MPTCP_GATEWAY_MAX_LISTS; ++i) {
				if (fmp->list_fingerprints.gw_list_avail[i] == 0 &&
						!memcmp(&tp->mptcp->binder_gw_fingerprint,
						&fmp->list_fingerprints.gw_list_fingerprint[i],
						sizeof(u8) * MPTCP_BINDER_GATEWAY_FP_SIZE)) {
					fmp->list_fingerprints.gw_list_avail[i] = 1;
					break;
				}
			}
		} else {
#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
			for (i = 0; i < MPTCP_GATEWAY_MAX_LISTS; ++i) {
				if (fmp->list_fingerprints.gw_list_avail6[i] == 0 &&
						!memcmp(&tp->mptcp->binder_gw_fingerprint,
						&fmp->list_fingerprints.gw_list_fingerprint6[i],
						sizeof(u8) * MPTCP_BINDER_GATEWAY_FP_SIZE)) {
					fmp->list_fingerprints.gw_list_avail6[i] = 1;
					break;
				}
			}
#endif /* CONFIG_MPTCP_BINDER_IPV6 */
		}
	}
}

/*
 * Updates the list of addresses contained in the meta-socket data structures
 */
static int mptcp_update_mpcb_gateway_list_ipv4(struct mptcp_cb * mpcb) {
	int i, j;
	u8 * tmp_avail = NULL, * tmp_used = NULL;
	struct binder_priv *fmp = (struct binder_priv *)&mpcb->mptcp_pm[0];

	if (fmp->list_fingerprints.timestamp >= mptcp_gws->timestamp)
		return 0;

	if ((tmp_avail = kzalloc(sizeof(u8) * MPTCP_GATEWAY_MAX_LISTS,
			GFP_KERNEL)) == NULL)
		goto error;
	if ((tmp_used = kzalloc(sizeof(u8) * MPTCP_GATEWAY_MAX_LISTS,
			GFP_KERNEL)) == NULL)
		goto error;

	/*
	 * tmp_used: if any two lists are exactly equivalent then their fingerprint
	 * is also equivalent. This means that, without remembering which has
	 * already been seet, the following code would be broken, as only the first
	 * old value of gw_list_avail would be written on both the new variables.
	 */
	for (i = 0; i < MPTCP_GATEWAY_MAX_LISTS; ++i) {
		if (mptcp_gws->len[i] > 0) {
			tmp_avail[i] = 1;
			for (j = 0; j < MPTCP_GATEWAY_MAX_LISTS; ++j)
				if (!memcmp(&mptcp_gws->gw_list_fingerprint[i],
						&fmp->list_fingerprints.gw_list_fingerprint[j],
						sizeof(u8) * MPTCP_BINDER_GATEWAY_FP_SIZE) && !tmp_used[j]) {
					tmp_avail[i] = fmp->list_fingerprints.gw_list_avail[j];
					tmp_used[j] = 1;
					break;
				}
		}
	}

	memcpy(&fmp->list_fingerprints.gw_list_fingerprint,
			&mptcp_gws->gw_list_fingerprint,
			sizeof(u8) * MPTCP_GATEWAY_MAX_LISTS * MPTCP_BINDER_GATEWAY_FP_SIZE);
	memcpy(&fmp->list_fingerprints.gw_list_avail, tmp_avail,
			sizeof(u8) * MPTCP_GATEWAY_MAX_LISTS);
	fmp->list_fingerprints.timestamp = mptcp_gws->timestamp;
	kfree(tmp_avail);
	kfree(tmp_used);

	return 0;

error:
	kfree(tmp_avail);
	kfree(tmp_used);
	memset(&fmp->list_fingerprints, 0,
			sizeof(struct mptcp_gw_list_fps_and_disp));
	return -1;
}

/*
 * The list of addresses is parsed each time a new connection is opened, to
 *  to make sure it's up to date. In case of error, all the lists are
 *  marked as unavailable and the subflow's fingerprint is set to 0.
 */
static void mptcp_v4_add_lsrr(struct sock * sk, struct in_addr rem)
{
	int i, j, ret;
	char * opt = NULL;
	struct tcp_sock * tp = tcp_sk(sk);
	struct binder_priv *fmp = (struct binder_priv *)&tp->mpcb->mptcp_pm[0];

	/*
	 * Read lock: multiple sockets can read LSRR addresses at the same time,
	 * but writes are done in mutual exclusion.
	 */
	read_lock(&mptcp_gws_lock);

	/*
	 * Added for main subflow support. If this socket is the first of a MPTCP
	 * connection, all the paths are free to take.
	 */
	if (tp->mpcb != NULL) {
		if (mptcp_update_mpcb_gateway_list_ipv4(tp->mpcb))
			goto error;

		for (i = 0; i < MPTCP_GATEWAY_MAX_LISTS; ++i)
			if (fmp->list_fingerprints.gw_list_avail[i] == 1
					&& mptcp_gws->len[i] > 0)
				break;
	} else {
		for (i = 0; i < MPTCP_GATEWAY_MAX_LISTS; ++i)
			if (mptcp_gws->len[i] > 0)
				break;
	}

	/*
	 * Execution enters here only if a free path is found.
	 */
	if (i < MPTCP_GATEWAY_MAX_LISTS) {
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
		memcpy(opt + 4 + (j * sizeof(rem.s_addr)), &rem.s_addr,
				sizeof(rem.s_addr));

		ret = ip_setsockopt(sk, IPPROTO_IP, IP_OPTIONS, opt,
				4 + sizeof(mptcp_gws->list[i][0].s_addr)
				* (mptcp_gws->len[i] + 1));

		if (ret < 0) {
			mptcp_debug(KERN_ERR "%s: MPTCP subsocket setsockopt() IP_OPTIONS "
			"failed, error %d\n", __func__, ret);
			goto error;
		}

		/*
		 * If first socket MPTCP data structures are not allocated yet, so copy
		 * data in the TCP data structure. Otherwise, uses MPTCP data.
		 */
		if (tp->mpcb != NULL) {
			fmp->list_fingerprints.gw_list_avail[i] = 0;
			memcpy(&tp->mptcp->binder_gw_fingerprint,
					&fmp->list_fingerprints.gw_list_fingerprint[0],
					sizeof(u8) * MPTCP_BINDER_GATEWAY_FP_SIZE);
			tp->mptcp->binder_gw_is_set = 1;
		} else {
			memcpy(&tp->mptcp->binder_gw_fingerprint, &mptcp_gws->gw_list_fingerprint[i],
					sizeof(u8) * MPTCP_BINDER_GATEWAY_FP_SIZE);
			tp->mptcp->binder_gw_is_set = 1;
		}
		kfree(opt);
	}

	read_unlock(&mptcp_gws_lock);
	return;

error:
	read_unlock(&mptcp_gws_lock);
	kfree(opt);
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

	write_lock(&mptcp_gws_lock);

	if ((tmp_string = kzalloc(16, GFP_KERNEL)) == NULL)
		goto error;

	memset(mptcp_gws, 0, sizeof(struct mptcp_gw_list));

	/*
	 * A TMP string is used since inet_pton needs a null terminated string but
	 * we do not want to modify the sysctl for obvious reasons.
	 * i will iterate over the SYSCTL string, j will iterate over the temporary string where
	 * each IP is copied into, k will iterate over the IPs in each list.
	 */
	for (i = j = k = 0; i < MPTCP_GATEWAY_SYSCTL_MAX_LEN && k < MPTCP_GATEWAY_MAX_LISTS; ++i) {
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
					if (mptcp_gws->len[k] > MPTCP_GATEWAY_LIST_MAX_LEN) {
						mptcp_debug("mptcp_parse_gateway_list too many members in list %i: max %i\n",
							k, MPTCP_GATEWAY_LIST_MAX_LEN);
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
				if (mptcp_calc_fingerprint_gateway_list(
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
	memset(mptcp_gws, 0, sizeof(struct mptcp_gw_list));
	memset(gateways, 0, sizeof(char) * MPTCP_GATEWAY_SYSCTL_MAX_LEN);
	write_unlock(&mptcp_gws_lock);
	return -1;
}

#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
/*
 * Updates the list of addresses contained in the meta-socket data structures
 */
static int mptcp_update_mpcb_gateway_list_ipv6(struct mptcp_cb * mpcb) {
	int i, j;
	u8 * tmp_avail = NULL, * tmp_used = NULL;
	struct binder_priv *fmp = (struct binder_priv *)&mpcb->mptcp_pm[0];

	if (fmp->list_fingerprints.timestamp >= mptcp_gws6->timestamp)
		return 0;

	if ((tmp_avail = kzalloc(sizeof(u8) * MPTCP_GATEWAY_MAX_LISTS,
			GFP_KERNEL)) == NULL)
		goto error;
	if ((tmp_used = kzalloc(sizeof(u8) * MPTCP_GATEWAY_MAX_LISTS,
			GFP_KERNEL)) == NULL)
		goto error;

	/*
	 * tmp_used: if any two lists are exactly equivalent then their fingerprint
	 * is also equivalent. This means that, without remembering which has
	 * already been seet, the following code would be broken, as only the first
	 * old value of gw_list_avail would be written on both the new variables.
	 */
	for (i = 0; i < MPTCP_GATEWAY_MAX_LISTS; ++i) {
		if (mptcp_gws6->len[i] > 0) {
			tmp_avail[i] = 1;
			for (j = 0; j < MPTCP_GATEWAY_MAX_LISTS; ++j)
				if (!memcmp(&mptcp_gws6->gw_list_fingerprint[i],
						&fmp->list_fingerprints.gw_list_fingerprint6[j],
						sizeof(u8) * MPTCP_BINDER_GATEWAY_FP_SIZE) && !tmp_used[j]) {
					tmp_avail[i] = fmp->list_fingerprints.gw_list_avail6[j];
					tmp_used[j] = 1;
					break;
				}
		}
	}

	memcpy(&fmp->list_fingerprints.gw_list_fingerprint6,
			&mptcp_gws6->gw_list_fingerprint,
			sizeof(u8) * MPTCP_GATEWAY_MAX_LISTS * MPTCP_BINDER_GATEWAY_FP_SIZE);
	memcpy(&fmp->list_fingerprints.gw_list_avail6, tmp_avail,
			sizeof(u8) * MPTCP_GATEWAY_MAX_LISTS);
	fmp->list_fingerprints.timestamp6 = mptcp_gws6->timestamp;
	kfree(tmp_avail);
	kfree(tmp_used);

	return 0;

error:
	kfree(tmp_avail);
	kfree(tmp_used);
	memset(&fmp->list_fingerprints, 0,
			sizeof(struct mptcp_gw_list_fps_and_disp));
	return -1;
}

/*
 * The list of addresses is parsed each time a new connection is opened, to
 *  to make sure it's up to date. In case of error, all the lists are
 *  marked as unavailable and the subflow's fingerprint is set to 0.
 */
static void mptcp_v6_add_rh0(struct sock * sk, struct sockaddr_in6 *rem)
{
	int i, ret;
	char * opt = NULL;
	struct tcp_sock * tp = tcp_sk(sk);
	struct binder_priv *fmp = (struct binder_priv *)&tp->mpcb->mptcp_pm[0];

	/*
	 * Read lock: multiple sockets can read LSRR addresses at the same time,
	 * but writes are done in mutual exclusion.
	 */
	read_lock(&mptcp_gws6_lock);

	/*
	 * Added for main subflow support. If this socket is the first of a MPTCP
	 * connection, all the paths are free to take.
	 */
	if (tp->mpcb != NULL) {
		if (mptcp_update_mpcb_gateway_list_ipv6(tp->mpcb))
			goto error;

		for (i = 0; i < MPTCP_GATEWAY_MAX_LISTS; ++i)
			if (fmp->list_fingerprints.gw_list_avail6[i] == 1
					&& mptcp_gws6->len[i] > 0)
				break;
	} else {
		for (i = 0; i < MPTCP_GATEWAY_MAX_LISTS; ++i)
			if (mptcp_gws6->len[i] > 0)
				break;
	}

	/*
	 * Execution enters here only if a free path is found.
	 */
	if (i < MPTCP_GATEWAY_MAX_LISTS) {
		opt = kzalloc(24, GFP_KERNEL);
		opt[1] = 2; // Hdr Ext Len
		opt[2] = 0; // Routing Type
		opt[3] = 1; // Segments Left
		
		/*
		 * Insert home address after 4 zero set bytes
		 */
		memcpy(opt + 8, &rem->sin6_addr, sizeof(rem->sin6_addr));
		memcpy(&rem->sin6_addr, &mptcp_gws6->list[0][0].s6_addr, sizeof(mptcp_gws6->list[0][0].s6_addr));
		
		ret = ipv6_setsockopt(sk, IPPROTO_IPV6, IPV6_RTHDR, opt, 24);

		if (ret < 0) {
			mptcp_debug(KERN_ERR "%s: MPTCP subsocket setsockopt() IPV6_RTHDR "
			"failed, error %d\n", __func__, ret);
			goto error;
		}

		/*
		 * If first socket MPTCP data structures are not allocated yet, so copy
		 * data in the TCP data structure. Otherwise, uses MPTCP data.
		 */
		if (tp->mpcb != NULL) {
			fmp->list_fingerprints.gw_list_avail6[i] = 0;
			memcpy(&tp->mptcp->binder_gw_fingerprint,
					&fmp->list_fingerprints.gw_list_fingerprint6[0],
					sizeof(u8) * MPTCP_BINDER_GATEWAY_FP_SIZE);
			tp->mptcp->binder_gw_is_set = 1;
		} else {
			memcpy(&tp->mptcp->binder_gw_fingerprint, &mptcp_gws6->gw_list_fingerprint[i],
					sizeof(u8) * MPTCP_BINDER_GATEWAY_FP_SIZE);
			tp->mptcp->binder_gw_is_set = 1;
		}
		kfree(opt);
	}

	read_unlock(&mptcp_gws6_lock);
	return;

error:
	read_unlock(&mptcp_gws6_lock);
	kfree(opt);
	return;
}

/*
 *  Parses gateways string for a list of paths to different
 *  gateways, and stores them for use with the Loose Source Routing (LSRR)
 *  socket option. Each list must have "," separated addresses, and the lists
 *  themselves must be separated by "-". Returns -1 in case one or more of the
 *  addresses is not a valid ipv4/6 address.
 */
static int mptcp_parse_gateway_ipv6(char * gateways)
{
	int i, j, k, ret;
	char * tmp_string = NULL;
	struct in6_addr tmp_addr;

	write_lock(&mptcp_gws6_lock);

	if ((tmp_string = kzalloc(40, GFP_KERNEL)) == NULL)
		goto error;

	memset(mptcp_gws6, 0, sizeof(struct mptcp_gw_list6));

	/*
	 * A TMP string is used since inet_pton needs a null terminated string but
	 * we do not want to modify the sysctl for obvious reasons.
	 * i will iterate over the SYSCTL string, j will iterate over the temporary string where
	 * each IP is copied into, k will iterate over the IPs in each list.
	 */
	for (i = j = k = 0; i < MPTCP_GATEWAY6_SYSCTL_MAX_LEN && k < MPTCP_GATEWAY_MAX_LISTS; ++i) {
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
					if (mptcp_gws6->len[k] > MPTCP_GATEWAY_LIST_MAX_LEN6) {
						mptcp_debug("mptcp_parse_gateway_list too many members in list %i: max %i\n",
							k, MPTCP_GATEWAY_LIST_MAX_LEN);
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
				if (mptcp_calc_fingerprint_gateway_list(
						(u8 *)&mptcp_gws6->gw_list_fingerprint[k],
						(u8 *)&mptcp_gws6->list[k][0],
						sizeof(mptcp_gws6->list[k][0].s6_addr) *
						mptcp_gws6->len[k])) {
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

	mptcp_gws6->timestamp = get_jiffies_64();
	kfree(tmp_string);
	write_unlock(&mptcp_gws6_lock);
	return 0;

error:
	kfree(tmp_string);
	memset(mptcp_gws6, 0, sizeof(struct mptcp_gw_list6));
	memset(gateways, 0, sizeof(char) * MPTCP_GATEWAY6_SYSCTL_MAX_LEN);
	write_unlock(&mptcp_gws6_lock);
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

	if (sysctl_mptcp_ndiffports > iter &&
	    sysctl_mptcp_ndiffports > mpcb->cnt_subflows) {
		if (meta_sk->sk_family == AF_INET ||
		    mptcp_v6_is_v4_mapped(meta_sk)) {
			struct mptcp_loc4 loc;

			loc.addr.s_addr = inet_sk(meta_sk)->inet_saddr;
			loc.id = 0;
			loc.low_prio = 0;

			mptcp_init4_subsockets(meta_sk, &loc, &mpcb->remaddr4[0]);
		} else {
#if IS_ENABLED(CONFIG_IPV6)
			struct mptcp_loc6 loc;

			loc.addr = inet6_sk(meta_sk)->saddr;
			loc.id = 0;
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

static void binder_new_session(struct sock *meta_sk, u8 id)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct binder_priv *fmp = (struct binder_priv *)&mpcb->mptcp_pm[0];

	/* Initialize workqueue-struct */
	INIT_WORK(&fmp->subflow_work, create_subflow_worker);
	fmp->mpcb = mpcb;

	/*
	 * Allocates and initialises LSRR/Routing Header variables.
	 */
	memset(&fmp->list_fingerprints, 0,
			sizeof(struct mptcp_gw_list_fps_and_disp));
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

static int binder_get_local_id(sa_family_t family, union inet_addr *addr,
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
		.maxlen = MPTCP_GATEWAY_SYSCTL_MAX_LEN,
	};

	if (write) {
		if ((tbl.data = kzalloc(MPTCP_GATEWAY_SYSCTL_MAX_LEN, GFP_KERNEL))
				== NULL)
			return -1;
		ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
		if (ret == 0) {
			ret = mptcp_parse_gateway_ipv4(tbl.data);
			memcpy(ctl->data, tbl.data, MPTCP_GATEWAY_SYSCTL_MAX_LEN);
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
		.maxlen = MPTCP_GATEWAY6_SYSCTL_MAX_LEN,
	};

	if (write) {
		if ((tbl.data = kzalloc(MPTCP_GATEWAY6_SYSCTL_MAX_LEN, GFP_KERNEL))
				== NULL)
			return -1;
		ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
		if (ret == 0) {
			ret = mptcp_parse_gateway_ipv6(tbl.data);
			memcpy(ctl->data, tbl.data, MPTCP_GATEWAY6_SYSCTL_MAX_LEN);
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
	.get_local_id = binder_get_local_id,
	.init_subsocket_v4 = mptcp_v4_add_lsrr,
	.init_subsocket_v6 = mptcp_v6_add_rh0,
	.del_subsocket = set_gateway_available,
	.name = "binder",
	.owner = THIS_MODULE,
};

static struct ctl_table binder_table[] = {
	{
		.procname = "mptcp_ndiffports",
		.data = &sysctl_mptcp_ndiffports,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "mptcp_gateways",
		.data = &sysctl_mptcp_gateways,
		.maxlen = sizeof(char) * MPTCP_GATEWAY_SYSCTL_MAX_LEN,
 		.mode = 0644,
		.proc_handler = &proc_mptcp_gateways
 	},
#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
	{
		.procname = "mptcp_gateways6",
		.data = &sysctl_mptcp_gateways6,
		.maxlen = sizeof(char) * MPTCP_GATEWAY6_SYSCTL_MAX_LEN,
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
	
#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
	mptcp_gws6 = kzalloc(sizeof(struct mptcp_gw_list6), GFP_KERNEL);
	if (!mptcp_gws6)
		return -ENOMEM;
		
	rwlock_init(&mptcp_gws6_lock);
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
#if IS_ENABLED(CONFIG_MPTCP_BINDER_IPV6)
	kfree(mptcp_gws6);
#endif /* CONFIG_MPTCP_BINDER_IPV6 */
}

module_init(binder_register);
module_exit(binder_unregister);

MODULE_AUTHOR("Luca Boccassi, Duncan Eastoe");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("BINDER MPTCP");
MODULE_VERSION("0.1");
