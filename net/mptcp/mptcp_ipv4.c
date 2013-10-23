/*
 *	MPTCP implementation - IPv4-specific functions
 *
 *	Initial Design & Implementation:
 *	Sébastien Barré <sebastien.barre@uclouvain.be>
 *
 *	Current Maintainer:
 *	Christoph Paasch <christoph.paasch@uclouvain.be>
 *
 *	Additional authors:
 *	Jaakko Korkeaniemi <jaakko.korkeaniemi@aalto.fi>
 *	Gregory Detal <gregory.detal@uclouvain.be>
 *	Fabien Duchêne <fabien.duchene@uclouvain.be>
 *	Andreas Seelinger <Andreas.Seelinger@rwth-aachen.de>
 *	Lavkesh Lahngir <lavkesh51@gmail.com>
 *	Andreas Ripke <ripke@neclab.eu>
 *	Vlad Dogaru <vlad.dogaru@intel.com>
 *	Octavian Purdila <octavian.purdila@intel.com>
 *	John Ronan <jronan@tssg.org>
 *	Catalin Nicutar <catalin.nicutar@gmail.com>
 *	Brandon Heller <brandonh@stanford.edu>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/export.h>
#include <linux/ip.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/tcp.h>

#include <net/inet_common.h>
#include <net/inet_connection_sock.h>
#include <net/mptcp.h>
#include <net/mptcp_pm.h>
#include <net/mptcp_v4.h>
#include <net/mptcp_v6.h>
#include <net/request_sock.h>
#include <net/tcp.h>

#include <linux/route.h>
#include <linux/inet.h>
#include <linux/mroute.h>
#include <net/inet_ecn.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <net/compat.h>
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#include <net/transp_v6.h>
#endif

#if IS_ENABLED(CONFIG_IPV6)
#define AF_INET_FAMILY(fam) ((fam) == AF_INET)
#else
#define AF_INET_FAMILY(fam) 1
#endif

u32 mptcp_v4_get_nonce(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
		       u32 seq)
{
	u32 hash[MD5_DIGEST_WORDS];

	hash[0] = (__force u32)saddr;
	hash[1] = (__force u32)daddr;
	hash[2] = ((__force u16)sport << 16) + (__force u16)dport;
	hash[3] = seq;

	md5_transform(hash, mptcp_secret);

	return hash[0];
}

u64 mptcp_v4_get_key(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	u32 hash[MD5_DIGEST_WORDS];

	hash[0] = (__force u32)saddr;
	hash[1] = (__force u32)daddr;
	hash[2] = ((__force u16)sport << 16) + (__force u16)dport;
	hash[3] = mptcp_key_seed++;

	md5_transform(hash, mptcp_secret);

	return *((u64 *)hash);
}


static void mptcp_v4_reqsk_destructor(struct request_sock *req)
{
	mptcp_reqsk_destructor(req);

	tcp_v4_reqsk_destructor(req);
}

/* Similar to tcp_request_sock_ops */
struct request_sock_ops mptcp_request_sock_ops __read_mostly = {
	.family		=	PF_INET,
	.obj_size	=	sizeof(struct mptcp_request_sock),
	.rtx_syn_ack	=	tcp_v4_rtx_synack,
	.send_ack	=	tcp_v4_reqsk_send_ack,
	.destructor	=	mptcp_v4_reqsk_destructor,
	.send_reset	=	tcp_v4_send_reset,
	.syn_ack_timeout =	tcp_syn_ack_timeout,
};

static void mptcp_v4_reqsk_queue_hash_add(struct sock *meta_sk,
					  struct request_sock *req,
					  unsigned long timeout)
{
	const u32 h = inet_synq_hash(inet_rsk(req)->rmt_addr,
				     inet_rsk(req)->rmt_port,
				     0, MPTCP_HASH_SIZE);

	inet_csk_reqsk_queue_hash_add(meta_sk, req, timeout);

	spin_lock(&mptcp_reqsk_hlock);
	list_add(&mptcp_rsk(req)->collide_tuple, &mptcp_reqsk_htb[h]);
	spin_unlock(&mptcp_reqsk_hlock);
}

/* Similar to tcp_v4_conn_request */
static void mptcp_v4_join_request(struct sock *meta_sk, struct sk_buff *skb)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct tcp_options_received tmp_opt;
	struct mptcp_options_received mopt;
	struct request_sock *req;
	struct inet_request_sock *ireq;
	struct mptcp_request_sock *mtreq;
	struct dst_entry *dst = NULL;
	u8 mptcp_hash_mac[20];
	__be32 saddr = ip_hdr(skb)->saddr;
	__be32 daddr = ip_hdr(skb)->daddr;
	__u32 isn = TCP_SKB_CB(skb)->when;
	int want_cookie = 0;

	tcp_clear_options(&tmp_opt);
	mptcp_init_mp_opt(&mopt);
	tmp_opt.mss_clamp = TCP_MSS_DEFAULT;
	tmp_opt.user_mss = tcp_sk(meta_sk)->rx_opt.user_mss;
	tcp_parse_options(skb, &tmp_opt, &mopt, 0, NULL);

	req = inet_reqsk_alloc(&mptcp_request_sock_ops);
	if (!req)
		return;

	tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;
	tcp_openreq_init(req, &tmp_opt, skb);

	ireq = inet_rsk(req);
	ireq->loc_addr = daddr;
	ireq->rmt_addr = saddr;
	ireq->no_srccheck = inet_sk(meta_sk)->transparent;
	ireq->opt = tcp_v4_save_options(skb);

	if (security_inet_conn_request(meta_sk, skb, req))
		goto drop_and_free;

	if (!want_cookie || tmp_opt.tstamp_ok)
		TCP_ECN_create_request(req, skb, sock_net(meta_sk));

	if (!isn) {
		struct flowi4 fl4;

		/* VJ's idea. We save last timestamp seen
		 * from the destination in peer table, when entering
		 * state TIME-WAIT, and check against it before
		 * accepting new connection request.
		 *
		 * If "isn" is not zero, this request hit alive
		 * timewait bucket, so that all the necessary checks
		 * are made in the function processing timewait state.
		 */
		if (tmp_opt.saw_tstamp &&
		    tcp_death_row.sysctl_tw_recycle &&
		    (dst = inet_csk_route_req(meta_sk, &fl4, req)) != NULL &&
		    fl4.daddr == saddr) {
			if (!tcp_peer_is_proven(req, dst, true)) {
				NET_INC_STATS_BH(sock_net(meta_sk), LINUX_MIB_PAWSPASSIVEREJECTED);
				goto drop_and_release;
			}
		}
		/* Kill the following clause, if you dislike this way. */
		else if (!sysctl_tcp_syncookies &&
			 (sysctl_max_syn_backlog - inet_csk_reqsk_queue_len(meta_sk) <
			  (sysctl_max_syn_backlog >> 2)) &&
			 !tcp_peer_is_proven(req, dst, false)) {
			/* Without syncookies last quarter of
			 * backlog is filled with destinations,
			 * proven to be alive.
			 * It means that we continue to communicate
			 * to destinations, already remembered
			 * to the moment of synflood.
			 */
			LIMIT_NETDEBUG(KERN_DEBUG pr_fmt("drop open request from %pI4/%u\n"),
				       &saddr, ntohs(tcp_hdr(skb)->source));
			goto drop_and_release;
		}

		isn = tcp_v4_init_sequence(skb);
	}
	tcp_rsk(req)->snt_isn = isn;
	tcp_rsk(req)->snt_synack = tcp_time_stamp;

	mtreq = mptcp_rsk(req);
	mtreq->mpcb = mpcb;
	INIT_LIST_HEAD(&mtreq->collide_tuple);
	mtreq->mptcp_rem_nonce = mopt.mptcp_recv_nonce;
	mtreq->mptcp_rem_key = mpcb->mptcp_rem_key;
	mtreq->mptcp_loc_key = mpcb->mptcp_loc_key;
	mtreq->mptcp_loc_nonce = mptcp_v4_get_nonce(saddr, daddr,
						    tcp_hdr(skb)->source,
						    tcp_hdr(skb)->dest, isn);
	mptcp_hmac_sha1((u8 *)&mtreq->mptcp_loc_key,
			(u8 *)&mtreq->mptcp_rem_key,
			(u8 *)&mtreq->mptcp_loc_nonce,
			(u8 *)&mtreq->mptcp_rem_nonce, (u32 *)mptcp_hash_mac);
	mtreq->mptcp_hash_tmac = *(u64 *)mptcp_hash_mac;
	mtreq->rem_id = mopt.rem_id;
	mtreq->low_prio = mopt.low_prio;
	tcp_rsk(req)->saw_mpc = 1;

	if (tcp_v4_send_synack(meta_sk, dst, req, skb_get_queue_mapping(skb), want_cookie))
		goto drop_and_free;

	/* Adding to request queue in metasocket */
	mptcp_v4_reqsk_queue_hash_add(meta_sk, req, TCP_TIMEOUT_INIT);

	return;

drop_and_release:
	dst_release(dst);
drop_and_free:
	reqsk_free(req);
	return;
}

int mptcp_v4_rem_raddress(struct mptcp_cb *mpcb, u8 id)
{
	int i;

	for (i = 0; i < MPTCP_MAX_ADDR; i++) {
		if (!((1 << i) & mpcb->rem4_bits))
			continue;

		if (mpcb->remaddr4[i].id == id) {
			/* remove address from bitfield */
			mpcb->rem4_bits &= ~(1 << i);

			return 0;
		}
	}

	return -1;
}

/* Based on function tcp_v4_conn_request (tcp_ipv4.c)
 * Returns -1 if there is no space anymore to store an additional
 * address
 */
int mptcp_v4_add_raddress(struct mptcp_cb *mpcb, const struct in_addr *addr,
			  __be16 port, u8 id)
{
	int i;
	struct mptcp_rem4 *rem4;

	mptcp_for_each_bit_set(mpcb->rem4_bits, i) {
		rem4 = &mpcb->remaddr4[i];

		/* Address is already in the list --- continue */
		if (rem4->id == id &&
		    rem4->addr.s_addr == addr->s_addr && rem4->port == port)
			return 0;

		/* This may be the case, when the peer is behind a NAT. He is
		 * trying to JOIN, thus sending the JOIN with a certain ID.
		 * However the src_addr of the IP-packet has been changed. We
		 * update the addr in the list, because this is the address as
		 * OUR BOX sees it.
		 */
		if (rem4->id == id && rem4->addr.s_addr != addr->s_addr) {
			/* update the address */
			mptcp_debug("%s: updating old addr:%pI4 to addr %pI4 with id:%d\n",
				    __func__, &rem4->addr.s_addr,
				    &addr->s_addr, id);
			rem4->addr.s_addr = addr->s_addr;
			rem4->port = port;
			mpcb->list_rcvd = 1;
			return 0;
		}
	}

	i = mptcp_find_free_index(mpcb->rem4_bits);
	/* Do we have already the maximum number of local/remote addresses? */
	if (i < 0) {
		mptcp_debug("%s: At max num of remote addresses: %d --- not adding address: %pI4\n",
			    __func__, MPTCP_MAX_ADDR, &addr->s_addr);
		return -1;
	}

	rem4 = &mpcb->remaddr4[i];

	/* Address is not known yet, store it */
	rem4->addr.s_addr = addr->s_addr;
	rem4->port = port;
	rem4->bitfield = 0;
	rem4->retry_bitfield = 0;
	rem4->id = id;
	mpcb->list_rcvd = 1;
	mpcb->rem4_bits |= (1 << i);

	return 0;
}

/* Sets the bitfield of the remote-address field
 * local address is not set as it will disappear with the global address-list
 */
void mptcp_v4_set_init_addr_bit(struct mptcp_cb *mpcb, __be32 daddr)
{
	int i;

	mptcp_for_each_bit_set(mpcb->rem4_bits, i) {
		if (mpcb->remaddr4[i].addr.s_addr == daddr) {
			/* It's the initial flow - thus local index == 0 */
			mpcb->remaddr4[i].bitfield |= 1;
			return;
		}
	}
}

/* We only process join requests here. (either the SYN or the final ACK) */
int mptcp_v4_do_rcv(struct sock *meta_sk, struct sk_buff *skb)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *child, *rsk = NULL;
	int ret;

	if (!(TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_JOIN)) {
		struct tcphdr *th = tcp_hdr(skb);
		const struct iphdr *iph = ip_hdr(skb);
		struct sock *sk;

		sk = inet_lookup_established(sock_net(meta_sk), &tcp_hashinfo,
					     iph->saddr, th->source, iph->daddr,
					     th->dest, inet_iif(skb));

		if (!sk) {
			kfree_skb(skb);
			return 0;
		}
		if (is_meta_sk(sk)) {
			WARN("%s Did not find a sub-sk - did found the meta!\n", __func__);
			kfree_skb(skb);
			sock_put(sk);
			return 0;
		}

		if (sk->sk_state == TCP_TIME_WAIT) {
			inet_twsk_put(inet_twsk(sk));
			kfree_skb(skb);
			return 0;
		}

		ret = tcp_v4_do_rcv(sk, skb);
		sock_put(sk);

		return ret;
	}
	TCP_SKB_CB(skb)->mptcp_flags = 0;

	/* Has been removed from the tk-table. Thus, no new subflows.
	 *
	 * Check for close-state is necessary, because we may have been closed
	 * without passing by mptcp_close().
	 *
	 * When falling back, no new subflows are allowed either.
	 */
	if (meta_sk->sk_state == TCP_CLOSE || !tcp_sk(meta_sk)->inside_tk_table ||
	    mpcb->infinite_mapping_rcv || mpcb->send_infinite_mapping)
		goto reset_and_discard;

	child = tcp_v4_hnd_req(meta_sk, skb);

	if (!child)
		goto discard;

	if (child != meta_sk) {
		sock_rps_save_rxhash(child, skb);
		/* We don't call tcp_child_process here, because we hold
		 * already the meta-sk-lock and are sure that it is not owned
		 * by the user.
		 */
		ret = tcp_rcv_state_process(child, skb, tcp_hdr(skb), skb->len);
		bh_unlock_sock(child);
		sock_put(child);
		if (ret) {
			rsk = child;
			goto reset_and_discard;
		}
	} else {
		if (tcp_hdr(skb)->syn) {
			struct mp_join *join_opt = mptcp_find_join(skb);
			/* Currently we make two calls to mptcp_find_join(). This
			 * can probably be optimized.
			 */
			if (mptcp_v4_add_raddress(mpcb,
						  (struct in_addr *)&ip_hdr(skb)->saddr,
						  0,
						  join_opt->addr_id) < 0)
				goto reset_and_discard;
			mpcb->list_rcvd = 0;

			mptcp_v4_join_request(meta_sk, skb);
			goto discard;
		}
		goto reset_and_discard;
	}
	return 0;

reset_and_discard:
	tcp_v4_send_reset(rsk, skb);
discard:
	kfree_skb(skb);
	return 0;
}

/* After this, the ref count of the meta_sk associated with the request_sock
 * is incremented. Thus it is the responsibility of the caller
 * to call sock_put() when the reference is not needed anymore.
 */
struct sock *mptcp_v4_search_req(const __be16 rport, const __be32 raddr,
				 const __be32 laddr, const struct net *net)
{
	struct mptcp_request_sock *mtreq;
	struct sock *meta_sk = NULL;

	spin_lock(&mptcp_reqsk_hlock);
	list_for_each_entry(mtreq,
			    &mptcp_reqsk_htb[inet_synq_hash(raddr, rport, 0,
							    MPTCP_HASH_SIZE)],
			    collide_tuple) {
		struct inet_request_sock *ireq = inet_rsk(rev_mptcp_rsk(mtreq));
		meta_sk = mtreq->mpcb->meta_sk;

		if (ireq->rmt_port == rport &&
		    ireq->rmt_addr == raddr &&
		    ireq->loc_addr == laddr &&
		    rev_mptcp_rsk(mtreq)->rsk_ops->family == AF_INET &&
		    net_eq(net, sock_net(meta_sk)))
			break;
		meta_sk = NULL;
	}

	if (meta_sk && unlikely(!atomic_inc_not_zero(&meta_sk->sk_refcnt)))
		meta_sk = NULL;
	spin_unlock(&mptcp_reqsk_hlock);

	return meta_sk;
}

/* Create a new IPv4 subflow.
 *
 * We are in user-context and meta-sock-lock is hold.
 */
int mptcp_init4_subsockets(struct sock *meta_sk, const struct mptcp_loc4 *loc,
			   struct mptcp_rem4 *rem)
{
	struct tcp_sock *tp;
	struct sock *sk;
	struct sockaddr_in loc_in, rem_in;
	struct socket sock;
	int ulid_size = 0, ret;

	/* Don't try again - even if it fails */
	rem->bitfield |= (1 << loc->id);

	/** First, create and prepare the new socket */

	sock.type = meta_sk->sk_socket->type;
	sock.state = SS_UNCONNECTED;
	sock.wq = meta_sk->sk_socket->wq;
	sock.file = meta_sk->sk_socket->file;
	sock.ops = NULL;

	ret = inet_create(sock_net(meta_sk), &sock, IPPROTO_TCP, 1);
	if (unlikely(ret < 0)) {
		mptcp_debug("%s inet_create failed ret: %d\n", __func__, ret);
		return ret;
	}

	sk = sock.sk;
	tp = tcp_sk(sk);

	/* All subsockets need the MPTCP-lock-class */
	lockdep_set_class_and_name(&(sk)->sk_lock.slock, &meta_slock_key, "slock-AF_INET-MPTCP");
	lockdep_init_map(&(sk)->sk_lock.dep_map, "sk_lock-AF_INET-MPTCP", &meta_key, 0);

	if (mptcp_add_sock(meta_sk, sk, rem->id, GFP_KERNEL))
		goto error;

	tp->mptcp->slave_sk = 1;
	tp->mptcp->low_prio = loc->low_prio;

	/* Initializing the timer for an MPTCP subflow */
	setup_timer(&tp->mptcp->mptcp_ack_timer, mptcp_ack_handler, (unsigned long)sk);

	/** Then, connect the socket to the peer */

	ulid_size = sizeof(struct sockaddr_in);
	loc_in.sin_family = AF_INET;
	rem_in.sin_family = AF_INET;
	loc_in.sin_port = 0;
	if (rem->port)
		rem_in.sin_port = rem->port;
	else
		rem_in.sin_port = inet_sk(meta_sk)->inet_dport;
	loc_in.sin_addr = loc->addr;
	rem_in.sin_addr = rem->addr;

	ret = sock.ops->bind(&sock, (struct sockaddr *)&loc_in, ulid_size);
	if (ret < 0) {
		mptcp_debug("%s: MPTCP subsocket bind() failed, error %d\n",
			    __func__, ret);
		goto error;
	}

	mptcp_debug("%s: token %#x pi %d src_addr:%pI4:%d dst_addr:%pI4:%d\n",
		    __func__, tcp_sk(meta_sk)->mpcb->mptcp_loc_token,
		    tp->mptcp->path_index, &loc_in.sin_addr,
		    ntohs(loc_in.sin_port), &rem_in.sin_addr,
		    ntohs(rem_in.sin_port));

	/* Adds loose source routing to the socket via IP_OPTION */
	mptcp_v4_add_lsrr(sk, rem->addr);

	ret = sock.ops->connect(&sock, (struct sockaddr *)&rem_in,
				ulid_size, O_NONBLOCK);
	if (ret < 0 && ret != -EINPROGRESS) {
		mptcp_debug("%s: MPTCP subsocket connect() failed, error %d\n",
			    __func__, ret);
		goto error;
	}

	sk_set_socket(sk, meta_sk->sk_socket);
	sk->sk_wq = meta_sk->sk_wq;

	return 0;

error:
	/* May happen if mptcp_add_sock fails first */
	if (!tp->mpc) {
		tcp_close(sk, 0);
	} else {
		local_bh_disable();
		mptcp_sub_force_close(sk);
		local_bh_enable();
	}
	return ret;
}

/*
 * Updates the list of addresses contained in the meta-socket data structures
 */
int mptcp_update_mpcb_gateway_list_ipv4(struct mptcp_cb * mpcb) {
	int i, j;
	u8 * tmp_avail = NULL, * tmp_used = NULL;

	if (mpcb->list_fingerprints.timestamp >= mptcp_gws->timestamp)
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
						&mpcb->list_fingerprints.gw_list_fingerprint[j],
						sizeof(u8) * MPTCP_GATEWAY_FP_SIZE) && !tmp_used[j]) {
					tmp_avail[i] = mpcb->list_fingerprints.gw_list_avail[j];
					tmp_used[j] = 1;
					break;
				}
		}
	}

	memcpy(&mpcb->list_fingerprints.gw_list_fingerprint,
			&mptcp_gws->gw_list_fingerprint,
			sizeof(u8) * MPTCP_GATEWAY_MAX_LISTS * MPTCP_GATEWAY_FP_SIZE);
	memcpy(&mpcb->list_fingerprints.gw_list_avail, tmp_avail,
			sizeof(u8) * MPTCP_GATEWAY_MAX_LISTS);
	mpcb->list_fingerprints.timestamp = mptcp_gws->timestamp;
	kfree(tmp_avail);
	kfree(tmp_used);

	return 0;

error:
	kfree(tmp_avail);
	kfree(tmp_used);
	memset(&mpcb->list_fingerprints, 0,
			sizeof(struct mptcp_gw_list_fps_and_disp));
	return -1;
}

/*
 * The list of addresses is parsed each time a new connection is opened, to
 *  to make sure it's up to date. In case of error, all the lists are
 *  marked as unavailable and the subflow's fingerprint is set to 0.
 */
void mptcp_v4_add_lsrr(struct sock * sk, struct in_addr rem)
{
	int i, j, ret;
	char * opt = NULL;
	struct tcp_sock * tp = tcp_sk(sk);

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
			if (tp->mpcb->list_fingerprints.gw_list_avail[i] == 1
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
			tp->mpcb->list_fingerprints.gw_list_avail[i] = 0;
			memcpy(&tp->mptcp->gw_fingerprint,
					&tp->mpcb->list_fingerprints.gw_list_fingerprint[0],
					sizeof(u8) * MPTCP_GATEWAY_FP_SIZE);
			tp->mptcp->gw_is_set = 1;
		} else {
			memcpy(&tp->gw_fingerprint, &mptcp_gws->gw_list_fingerprint[i],
					sizeof(u8) * MPTCP_GATEWAY_FP_SIZE);
			tp->gw_is_set = 1;
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
int mptcp_parse_gateway_ipv4(char * gateways)
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
							ret, tmp_addr.s_addr);
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

/****** IPv4-Address event handler ******/

/* React on IP-addr add/rem-events */
static int mptcp_pm_inetaddr_event(struct notifier_block *this,
				   unsigned long event, void *ptr)
{
	return mptcp_pm_addr_event_handler(event, ptr, AF_INET);
}

/* React on ifup/down-events */
static int mptcp_pm_netdev_event(struct notifier_block *this,
				 unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct in_device *in_dev;

	if (!(event == NETDEV_UP || event == NETDEV_DOWN ||
	      event == NETDEV_CHANGE))
		return NOTIFY_DONE;

	/* Iterate over the addresses of the interface, then we go over the
	 * mpcb's to modify them - that way we take tk_hash_lock for a shorter
	 * time at each iteration. - otherwise we would need to take it from the
	 * beginning till the end.
	 */
	rcu_read_lock();
	in_dev = __in_dev_get_rtnl(dev);

	if (in_dev) {
		for_primary_ifa(in_dev) {
			mptcp_pm_inetaddr_event(NULL, event, ifa);
		} endfor_ifa(in_dev);
	}

	rcu_read_unlock();
	return NOTIFY_DONE;
}

void mptcp_pm_addr4_event_handler(struct in_ifaddr *ifa, unsigned long event,
				  struct mptcp_cb *mpcb)
{
	int i;
	struct sock *sk, *tmpsk;

	if (ifa->ifa_scope > RT_SCOPE_LINK)
		return;

	/* Look for the address among the local addresses */
	mptcp_for_each_bit_set(mpcb->loc4_bits, i) {
		if (mpcb->locaddr4[i].addr.s_addr == ifa->ifa_local)
			goto found;
	}

	/* Not yet in address-list */
	if ((event == NETDEV_UP || event == NETDEV_CHANGE) &&
	    netif_running(ifa->ifa_dev->dev) &&
	    !(ifa->ifa_dev->dev->flags & IFF_NOMULTIPATH)) {
		i = __mptcp_find_free_index(mpcb->loc4_bits, 0, mpcb->next_v4_index);
		if (i < 0) {
			mptcp_debug("MPTCP_PM: NETDEV_UP Reached max number of local IPv4 addresses: %d\n",
				    MPTCP_MAX_ADDR);
			return;
		}

		/* update this mpcb */
		mpcb->locaddr4[i].addr.s_addr = ifa->ifa_local;
		mpcb->locaddr4[i].id = i;
		mpcb->loc4_bits |= (1 << i);
		mpcb->next_v4_index = i + 1;
		/* re-send addresses */
		mptcp_v4_send_add_addr(i, mpcb);
		/* re-evaluate paths */
		mptcp_create_subflows(mpcb->meta_sk);
	}
	return;
found:
	/* Address already in list. Reactivate/Deactivate the
	 * concerned paths.
	 */
	mptcp_for_each_sk_safe(mpcb, sk, tmpsk) {
		struct tcp_sock *tp = tcp_sk(sk);
		if (sk->sk_family != AF_INET ||
		    inet_sk(sk)->inet_saddr != ifa->ifa_local)
			continue;

		if (event == NETDEV_DOWN ||
		    (ifa->ifa_dev->dev->flags & IFF_NOMULTIPATH)) {
			mptcp_reinject_data(sk, 0);
			mptcp_sub_force_close(sk);
		} else if (event == NETDEV_CHANGE) {
			int new_low_prio = (ifa->ifa_dev->dev->flags & IFF_MPBACKUP) ?
						1 : 0;
			if (new_low_prio != tp->mptcp->low_prio)
				tp->mptcp->send_mp_prio = 1;
			tp->mptcp->low_prio = new_low_prio;
		}
	}

	if (event == NETDEV_DOWN ||
	    (ifa->ifa_dev->dev->flags & IFF_NOMULTIPATH)) {
		mpcb->loc4_bits &= ~(1 << i);

		/* Force sending directly the REMOVE_ADDR option */
		mpcb->remove_addrs |= (1 << mpcb->locaddr4[i].id);
		sk = mptcp_select_ack_sock(mpcb->meta_sk, 0);
		if (sk)
			tcp_send_ack(sk);

		mptcp_for_each_bit_set(mpcb->rem4_bits, i) {
			mpcb->remaddr4[i].bitfield &= mpcb->loc4_bits;
			mpcb->remaddr4[i].retry_bitfield &= mpcb->loc4_bits;
		}
	}
}

/* Send ADD_ADDR for loc_id on all available subflows */
void mptcp_v4_send_add_addr(int loc_id, struct mptcp_cb *mpcb)
{
	struct tcp_sock *tp;

	mptcp_for_each_tp(mpcb, tp)
		tp->mptcp->add_addr4 |= (1 << loc_id);
}

static struct notifier_block mptcp_pm_inetaddr_notifier = {
		.notifier_call = mptcp_pm_inetaddr_event,
};

static struct notifier_block mptcp_pm_netdev_notifier = {
		.notifier_call = mptcp_pm_netdev_event,
};

/****** End of IPv4-Address event handler ******/

/* General initialization of IPv4 for MPTCP */
int mptcp_pm_v4_init(void)
{
	int ret;
	struct request_sock_ops *ops = &mptcp_request_sock_ops;

	ops->slab_name = kasprintf(GFP_KERNEL, "request_sock_%s", "MPTCP");
	if (ops->slab_name == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	ops->slab = kmem_cache_create(ops->slab_name, ops->obj_size, 0,
				      SLAB_HWCACHE_ALIGN, NULL);

	if (ops->slab == NULL) {
		ret =  -ENOMEM;
		goto err_reqsk_create;
	}

	ret = register_inetaddr_notifier(&mptcp_pm_inetaddr_notifier);
	if (ret)
		goto err_reg_inetaddr;
	ret = register_netdevice_notifier(&mptcp_pm_netdev_notifier);
	if (ret)
		goto err_reg_netdev;

out:
	return ret;

err_reg_netdev:
	unregister_inetaddr_notifier(&mptcp_pm_inetaddr_notifier);
err_reg_inetaddr:
	kmem_cache_destroy(ops->slab);
err_reqsk_create:
	kfree(ops->slab_name);
	ops->slab_name = NULL;
	goto out;
}

void mptcp_pm_v4_undo(void)
{
	unregister_inetaddr_notifier(&mptcp_pm_inetaddr_notifier);
	unregister_netdevice_notifier(&mptcp_pm_netdev_notifier);
	kmem_cache_destroy(mptcp_request_sock_ops.slab);
	kfree(mptcp_request_sock_ops.slab_name);
}


