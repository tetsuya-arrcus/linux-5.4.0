// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  SR-IPv6 implementation
 *
 *  Author:
 *  David Lebrun <david.lebrun@uclouvain.be>
 */

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/ip_tunnels.h>
#include <net/lwtunnel.h>
#include <net/netevent.h>
#include <net/netns/generic.h>
#include <net/ip6_fib.h>
#include <net/route.h>
#include <net/seg6.h>
#include <linux/seg6.h>
#include <linux/seg6_iptunnel.h>
#include <net/addrconf.h>
#include <net/ip6_route.h>
#include <net/dst_cache.h>
#ifdef CONFIG_IPV6_SEG6_HMAC
#include <net/seg6_hmac.h>
#endif

static u16 srh_tagfield[256] = {
  /* 0 */
  0x0,
  /* 1 : Echo Request */
  0x0004,
  /* 2 : Echo Reply */
  0x0008,
  /* 3 - 7 */
  0x0, 0x0, 0x0, 0x0, 0x0,
  /* 8 - 15 */
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  /* 16 - 23 */
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  /* 24 - 25 */
  0x0, 0x0,
  /* 26 : Error Indication */
  0x0002,
  /* 27 - 31 */
  0x0, 0x0, 0x0, 0x0, 0x0,
  /* 32 - 247 */
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  /* 248 - 253 */
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  /* 254 : End Maker */
  0x0001,
  /* 255 : G_PDU */
  0x0
};

struct seg6_lwt {
	struct dst_cache cache;
	struct seg6_iptunnel_encap tuninfo[0];
};

static inline struct seg6_lwt *seg6_lwt_lwtunnel(struct lwtunnel_state *lwt)
{
	return (struct seg6_lwt *)lwt->data;
}

static inline struct seg6_iptunnel_encap *
seg6_encap_lwtunnel(struct lwtunnel_state *lwt)
{
	return seg6_lwt_lwtunnel(lwt)->tuninfo;
}

static const struct nla_policy seg6_iptunnel_policy[SEG6_IPTUNNEL_MAX + 1] = {
	[SEG6_IPTUNNEL_SRH]	= { .type = NLA_BINARY },
};

static int nla_put_srh(struct sk_buff *skb, int attrtype,
		       struct seg6_iptunnel_encap *tuninfo)
{
	struct seg6_iptunnel_encap *data;
	struct nlattr *nla;
	int len;

	len = SEG6_IPTUN_ENCAP_SIZE(tuninfo);

	nla = nla_reserve(skb, attrtype, len);
	if (!nla)
		return -EMSGSIZE;

	data = nla_data(nla);
	memcpy(data, tuninfo, len);

	return 0;
}

static void set_tun_src(struct net *net, struct net_device *dev,
			struct in6_addr *daddr, struct in6_addr *saddr)
{
	struct seg6_pernet_data *sdata = seg6_pernet(net);
	struct in6_addr *tun_src;

	rcu_read_lock();

	tun_src = rcu_dereference(sdata->tun_src);

	if (!ipv6_addr_any(tun_src)) {
		memcpy(saddr, tun_src, sizeof(struct in6_addr));
	} else {
		ipv6_dev_get_saddr(net, dev, daddr, IPV6_PREFER_SRC_PUBLIC,
				   saddr);
	}

	rcu_read_unlock();
}

/* Compute flowlabel for outer IPv6 header */
static __be32 seg6_make_flowlabel(struct net *net, struct sk_buff *skb,
				  struct ipv6hdr *inner_hdr)
{
	int do_flowlabel = net->ipv6.sysctl.seg6_flowlabel;
	__be32 flowlabel = 0;
	u32 hash;

	if (do_flowlabel > 0) {
		hash = skb_get_hash(skb);
		hash = rol32(hash, 16);
		flowlabel = (__force __be32)hash & IPV6_FLOWLABEL_MASK;
	} else if (!do_flowlabel && skb->protocol == htons(ETH_P_IPV6)) {
		flowlabel = ip6_flowlabel(inner_hdr);
	}
	return flowlabel;
}

/* encapsulate an IPv6 packet within an outer IPv6 header with a given SRH */
int seg6_do_srh_encap(struct sk_buff *skb, struct ipv6_sr_hdr *osrh, int proto)
{
	struct dst_entry *dst = skb_dst(skb);
	struct net *net = dev_net(dst->dev);
	struct ipv6hdr *hdr, *inner_hdr;
	struct ipv6_sr_hdr *isrh;
	int hdrlen, tot_len, err;
	__be32 flowlabel;

	hdrlen = (osrh->hdrlen + 1) << 3;
	tot_len = hdrlen + sizeof(*hdr);

	err = skb_cow_head(skb, tot_len + skb->mac_len);
	if (unlikely(err))
		return err;

	inner_hdr = ipv6_hdr(skb);
	flowlabel = seg6_make_flowlabel(net, skb, inner_hdr);

	skb_push(skb, tot_len);
	skb_reset_network_header(skb);
	skb_mac_header_rebuild(skb);
	hdr = ipv6_hdr(skb);

	/* inherit tc, flowlabel and hlim
	 * hlim will be decremented in ip6_forward() afterwards and
	 * decapsulation will overwrite inner hlim with outer hlim
	 */

	if (skb->protocol == htons(ETH_P_IPV6)) {
		ip6_flow_hdr(hdr, ip6_tclass(ip6_flowinfo(inner_hdr)),
			     flowlabel);
		hdr->hop_limit = inner_hdr->hop_limit;
	} else {
		ip6_flow_hdr(hdr, 0, flowlabel);
		hdr->hop_limit = ip6_dst_hoplimit(skb_dst(skb));

		memset(IP6CB(skb), 0, sizeof(*IP6CB(skb)));

		/* the control block has been erased, so we have to set the
		 * iif once again.
		 * We read the receiving interface index directly from the
		 * skb->skb_iif as it is done in the IPv4 receiving path (i.e.:
		 * ip_rcv_core(...)).
		 */
		IP6CB(skb)->iif = skb->skb_iif;
	}

	hdr->nexthdr = NEXTHDR_ROUTING;

	isrh = (void *)hdr + sizeof(*hdr);
	memcpy(isrh, osrh, hdrlen);

	isrh->nexthdr = proto;

	hdr->daddr = osrh->segments[osrh->first_segment];
	set_tun_src(net, dst->dev, &hdr->daddr, &hdr->saddr);

#ifdef CONFIG_IPV6_SEG6_HMAC
	if (isrh && sr_has_hmac(isrh)) {
		err = seg6_push_hmac(net, &hdr->saddr, isrh);
		if (unlikely(err))
			return err;
	}
#endif

	skb_postpush_rcsum(skb, hdr, tot_len);

	return 0;
}
EXPORT_SYMBOL_GPL(seg6_do_srh_encap);

/* insert an SRH within an IPv6 packet, just after the IPv6 header */
int seg6_do_srh_inline(struct sk_buff *skb, struct ipv6_sr_hdr *osrh)
{
	struct ipv6hdr *hdr, *oldhdr;
	struct ipv6_sr_hdr *isrh;
	int hdrlen, err;

	hdrlen = (osrh->hdrlen + 1) << 3;

	err = skb_cow_head(skb, hdrlen + skb->mac_len);
	if (unlikely(err))
		return err;

	oldhdr = ipv6_hdr(skb);

	skb_pull(skb, sizeof(struct ipv6hdr));
	skb_postpull_rcsum(skb, skb_network_header(skb),
			   sizeof(struct ipv6hdr));

	skb_push(skb, sizeof(struct ipv6hdr) + hdrlen);
	skb_reset_network_header(skb);
	skb_mac_header_rebuild(skb);

	hdr = ipv6_hdr(skb);

	memmove(hdr, oldhdr, sizeof(*hdr));

	isrh = (void *)hdr + sizeof(*hdr);
	memcpy(isrh, osrh, hdrlen);

	isrh->nexthdr = hdr->nexthdr;
	hdr->nexthdr = NEXTHDR_ROUTING;

	isrh->segments[0] = hdr->daddr;
	hdr->daddr = isrh->segments[isrh->first_segment];

#ifdef CONFIG_IPV6_SEG6_HMAC
	if (sr_has_hmac(isrh)) {
		struct net *net = dev_net(skb_dst(skb)->dev);

		err = seg6_push_hmac(net, &hdr->saddr, isrh);
		if (unlikely(err))
			return err;
	}
#endif

	skb_postpush_rcsum(skb, hdr, sizeof(struct ipv6hdr) + hdrlen);

	return 0;
}
EXPORT_SYMBOL_GPL(seg6_do_srh_inline);

int seg6_do_gtp6_d(struct sk_buff *skb, struct seg6_iptunnel_encap *tinfo)
{
	struct gtp_sr_info *gtp_info;
	struct ip6_gtpu_header_t *hdr;
	struct ipv6hdr *ip6;
	struct ipv6_sr_hdr *srh;
	struct iphdr *ip;
	struct gtpu_pdu_session_t *sess = NULL;
	struct in6_addr src, dst, seg;
	__u8 gtpu_type;
	__u32 hdr_len = 0;
	__u32 teid = 0;
	__u16 seq = 0;
	__u8 qfi = 0;
	__u32 offset;
	int ie_size = 0;
	__u16 tlv_siz = 0;
	__u8 ie_buf[GTPU_IE_MAX_SIZ];

	if (skb->protocol != htons(ETH_P_IPV6)) {
		return -EINVAL;
	}

	gtp_info = tinfo->gtp_info;
	if (!gtp_info) {
		return -EINVAL;
	}

	hdr = (struct ip6_gtpu_header_t *)ipv6_hdr(skb);
	if (!hdr) {
		return -EINVAL;
	}

    if (hdr->ip6.version != 6 || hdr->ip6.nexthdr != IPPROTO_UDP) {
        return -EINVAL;
    }

    if (hdr->udp.source != htons(SRV6_GTP_UDP_DST_PORT)
     && hdr->udp.dest != htons(SRV6_GTP_UDP_DST_PORT)) {
        return -EINVAL;
    }

	hdr_len = sizeof(struct ip6_gtpu_header_t);

	teid = hdr->gtpu.teid;

	gtpu_type = hdr->gtpu.type;

	if (hdr->gtpu.ver_flags & (GTPU_EXTHDR_FLAG | GTPU_SEQ_FLAG)) {
		hdr_len += sizeof(struct gtpu_exthdr_t);

		seq = hdr->gtpu.ext->seq;

		if (hdr->gtpu.ext->nextexthdr == GTPU_EXTHDR_PDU_SESSION) {
			sess = (struct gtpu_pdu_session_t *)(((char *)hdr) + hdr_len);
			qfi = sess->u.val &~GTPU_PDU_SESSION_P_BIT_MASK;

			hdr_len += sizeof(struct gtpu_pdu_session_t);

			if (sess->u.val & GTPU_PDU_SESSION_P_BIT_MASK) {
				hdr_len += sizeof(struct gtpu_paging_policy_t);
			}
		}
	}

	src = hdr->ip6.saddr;
	dst = hdr->ip6.daddr;

	seg = gtp_info->gtp_sid;
	offset = gtp_info->gtp_sid_len / 8;

	qfi = ((qfi & GTPU_PDU_SESSION_QFI_MASK) << 2) |
			((qfi & GTPU_PDU_SESSION_R_BIT_MASK) >> 5);

	if (sess && sess->type) {
		qfi |= SRV6_PDU_SESSION_U_BIT_MASK;
	}

	seg.s6_addr[offset] = qfi;

	if (gtpu_type == GTPU_TYPE_ECHO_REQUEST
	 || gtpu_type == GTPU_TYPE_ECHO_REPLY
	 || gtpu_type == GTPU_TYPE_ERROR_INDICATION) {
		memcpy(&seg.s6_addr[offset + 1], &seq, 2);
	} else {
		memcpy(&seg.s6_addr[offset + 1], &teid, 4);
	}

	if (gtpu_type == GTPU_TYPE_ERROR_INDICATION) {
		__u16 payload_len;

		payload_len = ntohs(hdr->gtpu.length);
		if (payload_len != 0) {
			ie_size = payload_len - (hdr_len - sizeof(struct ip6_gtpu_header_t));
			if (ie_size > 0) {
				__u8 *ies;

				ies = (__u8 *) ((__u8 *)hdr + hdr_len);
				memcpy(ie_buf, ies, ie_size);
				hdr_len += ie_size;
			}
		}
	}

	if (!pskb_pull(skb, hdr_len)) {
		return -EINVAL;
	}

	skb_postpull_rcsum(skb, skb_network_header(skb), hdr_len);

	ip = (struct iphdr *)skb->data;

	hdr_len = sizeof(struct ipv6hdr);
	hdr_len += sizeof(struct ipv6_sr_hdr);
	hdr_len += sizeof(struct in6_addr);

	if (ie_size) {
		tlv_siz = sizeof(struct ip6_sr_tlv_t) + sizeof(struct user_plane_sub_tlv_t) + ie_size;

		tlv_siz = (tlv_siz & ~0x07) + (tlv_siz & ~0x07 ? 0x08 : 0x0);
		hdr_len += tlv_siz;
	}

	skb_push(skb, hdr_len);

	ip6 = (struct ipv6hdr *)skb->data;
	srh = (struct ipv6_sr_hdr *)(skb->data + sizeof(struct ipv6hdr));

	ip6->version = 6;
	ip6->daddr = seg;
	ip6->saddr = src;

	ip6->nexthdr = IPPROTO_ROUTING;

	if (gtpu_type != GTPU_TYPE_GTPU) {
		srh->nexthdr = IPPROTO_IP6_ETHERNET;
		srh->tag = htons(srh_tagfield[gtpu_type]);
	} else {
		srh->tag = 0;
		if (ip->version == 4) {
			srh->nexthdr = IPPROTO_IPIP;
		} else {
			srh->nexthdr = IPPROTO_IPV6;
		}
	}

	srh->type = IPV6_SRCRT_TYPE_4;

	srh->segments_left = 1;
	srh->first_segment = 0;

	srh->hdrlen = sizeof(struct in6_addr) / 8;
	srh->segments[0] = dst;

	if (ie_size) {
		struct ip6_sr_tlv_t *tlv;
		struct user_plane_sub_tlv_t *sub_tlv;

		tlv = (struct ip6_sr_tlv_t *)(skb->data + (hdr_len - tlv_siz));
		tlv->type = SRH_TLV_USER_PLANE_CONTAINER;
		tlv->length = (__u8) (tlv_siz - sizeof(struct ip6_sr_tlv_t));
		memset(tlv->value, 0, tlv->length);

		sub_tlv = (struct user_plane_sub_tlv_t *) tlv->value;
		sub_tlv->type = USER_PLANE_SUB_TLV_IE;
		sub_tlv->length = (__u8) ie_size;
		memcpy(sub_tlv->value, ie_buf, ie_size);

		srh->hdrlen += (__u8)(tlv_siz / 8);
	}

	ip6->payload_len = htons(skb->len - sizeof(struct ipv6hdr));

	ip6->hop_limit = 64;

	memset(IP6CB(skb), 0, sizeof(*IP6CB(skb)));

	skb_postpush_rcsum(skb, ip6, hdr_len);

	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb_mac_header_rebuild(skb);

	return 0;
}

int seg6_do_gtp4_d(struct sk_buff *skb, struct seg6_iptunnel_encap *tinfo)
{
	struct gtp_sr_info *gtp_info;
	struct ip4_gtpu_header_t *hdr;
	struct ipv6hdr *ip6;
	struct ipv6_sr_hdr *srh;
	struct iphdr *ip;
	struct gtpu_pdu_session_t *sess = NULL;
	struct in_addr src, dst;
	struct in6_addr seg, src6;
	__u8 gtpu_type;
	__u32 hdr_len = 0;
	__u32 teid = 0;
	__u16 seq = 0;
	__u8 qfi = 0;
	__u32 offset;
	int ie_size = 0;
	__u16 tlv_siz = 0;
	__u8 ie_buf[GTPU_IE_MAX_SIZ];

	if (skb->protocol != htons(ETH_P_IP)) {
		return -EINVAL;
	}

	gtp_info = tinfo->gtp_info;
	if (!gtp_info) {
		return -EINVAL;
	}

	hdr = (struct ip4_gtpu_header_t *)ip_hdr(skb);
	if (!hdr) {
		return -EINVAL;
	}

    if (hdr->ip4.version != 4 || hdr->ip4.protocol != IPPROTO_UDP) {
        return -EINVAL;
    }

    if (hdr->udp.source != htons(SRV6_GTP_UDP_DST_PORT)
     && hdr->udp.dest != htons(SRV6_GTP_UDP_DST_PORT)) {
        return -EINVAL;
    }

	hdr_len = sizeof(struct ip4_gtpu_header_t);

	teid = hdr->gtpu.teid;

	gtpu_type = hdr->gtpu.type;

	if (hdr->gtpu.ver_flags & (GTPU_EXTHDR_FLAG | GTPU_SEQ_FLAG)) {
		hdr_len += sizeof(struct gtpu_exthdr_t);

		seq = hdr->gtpu.ext->seq;

		if (hdr->gtpu.ext->nextexthdr == GTPU_EXTHDR_PDU_SESSION) {
			sess = (struct gtpu_pdu_session_t *)(((char *)hdr) + hdr_len);
			qfi = sess->u.val &~GTPU_PDU_SESSION_P_BIT_MASK;

			hdr_len += sizeof(struct gtpu_pdu_session_t);

			if (sess->u.val & GTPU_PDU_SESSION_P_BIT_MASK) {
				hdr_len += sizeof(struct gtpu_paging_policy_t);
			}
		}
	}

	src.s_addr = hdr->ip4.saddr;
	dst.s_addr = hdr->ip4.daddr;

	seg = gtp_info->gtp_sid;
	offset = gtp_info->gtp_sid_len / 8;

	memcpy(&seg.s6_addr[offset], &dst, 4);

	qfi = ((qfi & GTPU_PDU_SESSION_QFI_MASK) << 2) |
			((qfi & GTPU_PDU_SESSION_R_BIT_MASK) >> 5);

	if (sess && sess->type) {
		qfi |= SRV6_PDU_SESSION_U_BIT_MASK;
	}

	seg.s6_addr[offset + 4] = qfi;

	if (gtpu_type == GTPU_TYPE_ECHO_REQUEST
	 || gtpu_type == GTPU_TYPE_ECHO_REPLY
	 || gtpu_type == GTPU_TYPE_ERROR_INDICATION) {
		memcpy(&seg.s6_addr[offset + 5], &seq, 2);
	} else {
		memcpy(&seg.s6_addr[offset + 5], &teid, 4);
	}

	if (gtpu_type == GTPU_TYPE_ERROR_INDICATION) {
		__u16 payload_len;

		payload_len = ntohs(hdr->gtpu.length);
		if (payload_len != 0) {
			ie_size = payload_len - (hdr_len - sizeof(struct ip4_gtpu_header_t));
			if (ie_size > 0) {
				__u8 *ies;

				ies = (__u8 *) ((__u8 *)hdr + hdr_len);
				memcpy(ie_buf, ies, ie_size);
				hdr_len += ie_size;
			}
		}
	}

	src6 = gtp_info->source_prefix;

	offset = gtp_info->source_prefix_len / 8;

	memcpy(&src6.s6_addr[offset], &src, 4);

	if (!pskb_pull(skb, hdr_len)) {
		return -EINVAL;
	}

	skb_postpull_rcsum(skb, skb_network_header(skb), hdr_len);

	ip = (struct iphdr *)skb->data;

	hdr_len = sizeof(struct ipv6hdr);

	if (gtpu_type != GTPU_TYPE_GTPU) {
		hdr_len += sizeof(struct ipv6_sr_hdr);
		hdr_len += sizeof(struct in6_addr);

	    if (ie_size) {
		    tlv_siz = sizeof(struct ip6_sr_tlv_t) + sizeof(struct user_plane_sub_tlv_t) + ie_size;

		    tlv_siz = (tlv_siz & ~0x07) + (tlv_siz & ~0x07 ? 0x08 : 0x0);
		    hdr_len += tlv_siz;
        }
	}

	skb_push(skb, hdr_len);

	ip6 = (struct ipv6hdr *)skb->data;
	srh = (struct ipv6_sr_hdr *)(skb->data + sizeof(struct ipv6hdr));

	ip6->version = 6;
	ip6->daddr = seg;
	ip6->saddr = src6;

	if (gtpu_type != GTPU_TYPE_GTPU) {
		ip6->nexthdr = IPPROTO_ROUTING;

		srh->nexthdr = IPPROTO_IP6_ETHERNET;
		srh->tag = htons(srh_tagfield[gtpu_type]);

		srh->type = IPV6_SRCRT_TYPE_4;

		srh->segments_left = 0;
		srh->first_segment = 0;

		srh->hdrlen = sizeof(struct in6_addr) / 8;
		srh->segments[0] = seg;

	    if (ie_size) {
		    struct ip6_sr_tlv_t *tlv;
		    struct user_plane_sub_tlv_t *sub_tlv;

		    tlv = (struct ip6_sr_tlv_t *)(skb->data + (hdr_len - tlv_siz));
		    tlv->type = SRH_TLV_USER_PLANE_CONTAINER;
		    tlv->length = (__u8) (tlv_siz - sizeof(struct ip6_sr_tlv_t));
		    memset(tlv->value, 0, tlv->length);

		    sub_tlv = (struct user_plane_sub_tlv_t *) tlv->value;
		    sub_tlv->type = USER_PLANE_SUB_TLV_IE;
		    sub_tlv->length = (__u8) ie_size;
		    memcpy(sub_tlv->value, ie_buf, ie_size);

		    srh->hdrlen += (__u8)(tlv_siz / 8);
	    }
	} else {
		if (ip->version == 4) {
			ip6->nexthdr = IPPROTO_IPIP;
		} else {
			ip6->nexthdr = IPPROTO_IPV6;
		}
	}

	ip6->payload_len = htons(skb->len - sizeof(struct ipv6hdr));

	ip6->hop_limit = 64;

	memset(IP6CB(skb), 0, sizeof(*IP6CB(skb)));

	skb_postpush_rcsum(skb, ip6, hdr_len);

	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb_mac_header_rebuild(skb);

	return 0;
}

static int seg6_do_srh(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct seg6_iptunnel_encap *tinfo;
	int proto, err = 0;

	tinfo = seg6_encap_lwtunnel(dst->lwtstate);

	switch (tinfo->mode) {
	case SEG6_IPTUN_MODE_INLINE:
		if (skb->protocol != htons(ETH_P_IPV6))
			return -EINVAL;

		err = seg6_do_srh_inline(skb, tinfo->srh);
		if (err)
			return err;
		break;
	case SEG6_IPTUN_MODE_ENCAP:
	case SEG6_IPTUN_MODE_ENCAP_REDUCED:
		err = iptunnel_handle_offloads(skb, SKB_GSO_IPXIP6);
		if (err)
			return err;

		if (skb->protocol == htons(ETH_P_IPV6))
			proto = IPPROTO_IPV6;
		else if (skb->protocol == htons(ETH_P_IP))
			proto = IPPROTO_IPIP;
		else
			return -EINVAL;

		err = seg6_do_srh_encap(skb, tinfo->srh, proto);
		if (err)
			return err;

		skb_set_inner_transport_header(skb, skb_transport_offset(skb));
		skb_set_inner_protocol(skb, skb->protocol);
		skb->protocol = htons(ETH_P_IPV6);
		break;
	case SEG6_IPTUN_MODE_L2ENCAP:
		if (!skb_mac_header_was_set(skb))
			return -EINVAL;

		if (pskb_expand_head(skb, skb->mac_len, 0, GFP_ATOMIC) < 0)
			return -ENOMEM;

		skb_mac_header_rebuild(skb);
		skb_push(skb, skb->mac_len);

		err = seg6_do_srh_encap(skb, tinfo->srh, NEXTHDR_NONE);
		if (err)
			return err;

		skb->protocol = htons(ETH_P_IPV6);
		break;
	case SEG6_IPTUN_MODE_GTP4_D:
		err = seg6_do_gtp4_d(skb, tinfo);
		if (err)
			return err;

		skb->protocol = htons(ETH_P_IPV6);
		break;
	case SEG6_IPTUN_MODE_GTP6_D:
		err = seg6_do_gtp6_d(skb, tinfo);
		if (err)
			return err;

		skb->protocol = htons(ETH_P_IPV6);
		break;
	}

	ipv6_hdr(skb)->payload_len = htons(skb->len - sizeof(struct ipv6hdr));
	skb_set_transport_header(skb, sizeof(struct ipv6hdr));

	return 0;
}

static int seg6_route_input(struct sk_buff *skb) {
	struct net *net = dev_net(skb->dev);
	struct ipv6hdr *hdr = ipv6_hdr(skb);
	int flags = RT6_LOOKUP_F_HAS_SADDR;
	struct dst_entry *dst = NULL;
	struct rt6_info *rt;
	struct flowi6 fl6;
	struct fib6_table *table;

	memset(&fl6, 0, sizeof (struct flowi6));
	fl6.flowi6_iif = skb->dev->ifindex;
	fl6.daddr = hdr->daddr;
	fl6.saddr = hdr->saddr;
	fl6.flowlabel = ip6_flowinfo(hdr);
	fl6.flowi6_mark = skb->mark;
	fl6.flowi6_proto = hdr->nexthdr;

	/* get the main table */
	table = fib6_get_table(net, 0);
	if (!table) {
		goto out;
	}

	rt = ip6_pol_route(net, table, 0, &fl6, skb, flags);
	dst = &rt->dst;

	if (dst && dst->dev->flags & IFF_LOOPBACK && !dst->error) {
		dst_release(dst);
		dst = NULL;
	}

out:
    if (!dst) {
        rt = net->ipv6.ip6_blk_hole_entry;
        dst = &rt->dst;
        dst_hold(dst);
    }

    skb_dst_set(skb, dst);
    return dst->error;
}

static int seg6_input(struct sk_buff *skb)
{
	struct dst_entry *orig_dst = skb_dst(skb);
	struct dst_entry *dst = NULL;
	struct seg6_lwt *slwt;
	int err;

	err = seg6_do_srh(skb);
	if (unlikely(err)) {
		kfree_skb(skb);
		return err;
	}

	slwt = seg6_lwt_lwtunnel(orig_dst->lwtstate);

	preempt_disable();
	dst = dst_cache_get(&slwt->cache);
	preempt_enable();

	skb_dst_drop(skb);

	if (!dst) {
		err = seg6_route_input(skb);
		if (unlikely(err)) {
			kfree_skb(skb);
			return err;
		}

		dst = skb_dst(skb);
		preempt_disable();
		dst_cache_set_ip6(&slwt->cache, dst,
					  &ipv6_hdr(skb)->saddr);
		preempt_enable();
	} else {
		skb_dst_set(skb, dst);
	}

	err = skb_cow_head(skb, LL_RESERVED_SPACE(dst->dev));
	if (unlikely(err))
		return err;

	return dst_input(skb);
}

static int seg6_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct dst_entry *orig_dst = skb_dst(skb);
	struct dst_entry *dst = NULL;
	struct seg6_lwt *slwt;
	int err = -EINVAL;

	err = seg6_do_srh(skb);
	if (unlikely(err))
		goto drop;

	slwt = seg6_lwt_lwtunnel(orig_dst->lwtstate);

	preempt_disable();
	dst = dst_cache_get(&slwt->cache);
	preempt_enable();

	if (unlikely(!dst)) {
		struct ipv6hdr *hdr = ipv6_hdr(skb);
		struct flowi6 fl6;

		memset(&fl6, 0, sizeof(fl6));
		fl6.daddr = hdr->daddr;
		fl6.saddr = hdr->saddr;
		fl6.flowlabel = ip6_flowinfo(hdr);
		fl6.flowi6_mark = skb->mark;
		fl6.flowi6_proto = hdr->nexthdr;

		dst = ip6_route_output(net, NULL, &fl6);
		if (dst->error) {
			err = dst->error;
			dst_release(dst);
			goto drop;
		}

		preempt_disable();
		dst_cache_set_ip6(&slwt->cache, dst, &fl6.saddr);
		preempt_enable();
	}

	skb_dst_drop(skb);
	skb_dst_set(skb, dst);

	err = skb_cow_head(skb, LL_RESERVED_SPACE(dst->dev));
	if (unlikely(err))
		goto drop;

	return dst_output(net, sk, skb);
drop:
	kfree_skb(skb);
	return err;
}

static int seg6_build_state(struct nlattr *nla,
			    unsigned int family, const void *cfg,
			    struct lwtunnel_state **ts,
			    struct netlink_ext_ack *extack)
{
	struct nlattr *tb[SEG6_IPTUNNEL_MAX + 1];
	struct seg6_iptunnel_encap *tuninfo;
	struct lwtunnel_state *newts;
	int tuninfo_len, min_size;
	struct seg6_lwt *slwt;
	int err;

	if (family != AF_INET && family != AF_INET6)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, SEG6_IPTUNNEL_MAX, nla,
					  seg6_iptunnel_policy, extack);

	if (err < 0)
		return err;

	if (!tb[SEG6_IPTUNNEL_SRH])
		return -EINVAL;

	tuninfo = nla_data(tb[SEG6_IPTUNNEL_SRH]);
	tuninfo_len = nla_len(tb[SEG6_IPTUNNEL_SRH]);

	switch (tuninfo->mode) {
	case SEG6_IPTUN_MODE_INLINE:
		if (family != AF_INET6)
			return -EINVAL;

		break;
	case SEG6_IPTUN_MODE_ENCAP:
		break;
	case SEG6_IPTUN_MODE_ENCAP_REDUCED:
		break;
	case SEG6_IPTUN_MODE_L2ENCAP:
		break;
	case SEG6_IPTUN_MODE_GTP4_D:
		break;
	case SEG6_IPTUN_MODE_GTP6_D:
		break;
	default:
		return -EINVAL;
	}

	if (tuninfo->mode != SEG6_IPTUN_MODE_GTP4_D &&
		tuninfo->mode != SEG6_IPTUN_MODE_GTP6_D) {
		/* tuninfo must contain at least the iptunnel encap structure,
	 	 * the SRH and one segment
	 	 */
		min_size = sizeof(*tuninfo) + sizeof(struct ipv6_sr_hdr) +
			sizeof(struct in6_addr);
		if (tuninfo_len < min_size)
			return -EINVAL;

		/* verify that SRH is consistent */
		if (!seg6_validate_srh(tuninfo->srh, tuninfo_len - sizeof(*tuninfo)))
			return -EINVAL;
	}

	newts = lwtunnel_state_alloc(tuninfo_len + sizeof(*slwt));
	if (!newts)
		return -ENOMEM;

	slwt = seg6_lwt_lwtunnel(newts);

	err = dst_cache_init(&slwt->cache, GFP_ATOMIC);
	if (err) {
		kfree(newts);
		return err;
	}

	memcpy(&slwt->tuninfo, tuninfo, tuninfo_len);

	newts->type = LWTUNNEL_ENCAP_SEG6;
	newts->flags |= LWTUNNEL_STATE_INPUT_REDIRECT;

	if (tuninfo->mode != SEG6_IPTUN_MODE_L2ENCAP)
		newts->flags |= LWTUNNEL_STATE_OUTPUT_REDIRECT;

	newts->headroom = seg6_lwt_headroom(tuninfo);

	*ts = newts;

	return 0;
}

static void seg6_destroy_state(struct lwtunnel_state *lwt)
{
	dst_cache_destroy(&seg6_lwt_lwtunnel(lwt)->cache);
}

static int seg6_fill_encap_info(struct sk_buff *skb,
				struct lwtunnel_state *lwtstate)
{
	struct seg6_iptunnel_encap *tuninfo = seg6_encap_lwtunnel(lwtstate);

	if (nla_put_srh(skb, SEG6_IPTUNNEL_SRH, tuninfo))
		return -EMSGSIZE;

	return 0;
}

static int seg6_encap_nlsize(struct lwtunnel_state *lwtstate)
{
	struct seg6_iptunnel_encap *tuninfo = seg6_encap_lwtunnel(lwtstate);

	return nla_total_size(SEG6_IPTUN_ENCAP_SIZE(tuninfo));
}

static int seg6_encap_cmp(struct lwtunnel_state *a, struct lwtunnel_state *b)
{
	struct seg6_iptunnel_encap *a_hdr = seg6_encap_lwtunnel(a);
	struct seg6_iptunnel_encap *b_hdr = seg6_encap_lwtunnel(b);
	int len = SEG6_IPTUN_ENCAP_SIZE(a_hdr);

	if (len != SEG6_IPTUN_ENCAP_SIZE(b_hdr))
		return 1;

	return memcmp(a_hdr, b_hdr, len);
}

static const struct lwtunnel_encap_ops seg6_iptun_ops = {
	.build_state = seg6_build_state,
	.destroy_state = seg6_destroy_state,
	.output = seg6_output,
	.input = seg6_input,
	.fill_encap = seg6_fill_encap_info,
	.get_encap_size = seg6_encap_nlsize,
	.cmp_encap = seg6_encap_cmp,
	.owner = THIS_MODULE,
};

int __init seg6_iptunnel_init(void)
{
	return lwtunnel_encap_add_ops(&seg6_iptun_ops, LWTUNNEL_ENCAP_SEG6);
}

void seg6_iptunnel_exit(void)
{
	lwtunnel_encap_del_ops(&seg6_iptun_ops, LWTUNNEL_ENCAP_SEG6);
}
