/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 *  SR-IPv6 implementation
 *
 *  Author:
 *  David Lebrun <david.lebrun@uclouvain.be>
 *
 *
 *  This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _UAPI_LINUX_SEG6_IPTUNNEL_H
#define _UAPI_LINUX_SEG6_IPTUNNEL_H

#include <linux/seg6.h>		/* For struct ipv6_sr_hdr. */

#define SEG6_IE_HEADROOM    (sizeof(struct ip6_sr_tlv_t) + sizeof(struct user_plane_sub_tlv_t))

enum {
	SEG6_IPTUNNEL_UNSPEC,
	SEG6_IPTUNNEL_SRH,
	__SEG6_IPTUNNEL_MAX,
};
#define SEG6_IPTUNNEL_MAX (__SEG6_IPTUNNEL_MAX - 1)

struct gtp_sr_info {
	uint32_t function;
	uint32_t inner_vrf;

	struct in6_addr gtp_sid;
	uint8_t gtp_sid_len;

	struct in6_addr source_prefix;
	uint8_t source_prefix_len;
};

struct seg6_iptunnel_encap {
	int mode;
	struct ipv6_sr_hdr srh[0];
	struct gtp_sr_info gtp_info[0];
};

enum {
	SEG6_IPTUN_MODE_INLINE,
	SEG6_IPTUN_MODE_ENCAP,
	SEG6_IPTUN_MODE_L2ENCAP,
	SEG6_IPTUN_MODE_GTP4_D,
	SEG6_IPTUN_MODE_GTP6_D,
	SEG6_IPTUN_MODE_ENCAP_REDUCED,
};

static inline int SEG6_IPTUN_ENCAP_SIZE(struct seg6_iptunnel_encap *x)
{
	if (x->mode == SEG6_IPTUN_MODE_GTP4_D ||
		x->mode == SEG6_IPTUN_MODE_GTP6_D) {
		return ((sizeof(*x)) + sizeof(struct gtp_sr_info));
	} else {
		return ((sizeof(*x)) + (((x)->srh->hdrlen + 1) << 3));
	}
}

#ifdef __KERNEL__

static inline size_t seg6_lwt_headroom(struct seg6_iptunnel_encap *tuninfo)
{
	int head = 0;
	int hdrlen = 0;

	switch (tuninfo->mode) {
	case SEG6_IPTUN_MODE_INLINE:
		hdrlen = tuninfo->srh->hdrlen;
		break;
	case SEG6_IPTUN_MODE_ENCAP:
		hdrlen = tuninfo->srh->hdrlen;
		head = sizeof(struct ipv6hdr);
		break;
	case SEG6_IPTUN_MODE_ENCAP_REDUCED:
        if (tuninfo->srh->segments_left) {
			hdrlen = tuninfo->srh->hdrlen;
		} else {
			hdrlen = 0;
		}
		head = sizeof(struct ipv6hdr);
		break;
	case SEG6_IPTUN_MODE_GTP4_D:
		hdrlen = 2;
		head = sizeof(struct ipv6hdr) + SEG6_IE_HEADROOM;
		break;
	case SEG6_IPTUN_MODE_GTP6_D:
		hdrlen = 4;
		head = sizeof(struct ipv6hdr) + SEG6_IE_HEADROOM;
		break;
	case SEG6_IPTUN_MODE_L2ENCAP:
		return 0;
	}

	return ((hdrlen + 1) << 3) + head;
}

#endif

#endif
