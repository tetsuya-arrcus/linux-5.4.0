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

#ifndef _UAPI_LINUX_SEG6_H
#define _UAPI_LINUX_SEG6_H

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/in6.h>		/* For struct in6_addr. */
 
#ifdef __BIG_ENDIAN
#define BITALIGN2(A,B)          A; B
#define BITALIGN3(A,B,C)        A; B; C
#else
#define BITALIGN2(A,B)          B; A
#define BITALIGN3(A,B,C)        C; B; A
#endif

#ifndef IPPROTO_IP6_ETHERNET
#define IPPROTO_IP6_ETHERNET    143
#endif

#define SRV6_GTP_UDP_DST_PORT 2152

/*
 * SRH
 */
struct ipv6_sr_hdr {
	__u8	nexthdr;
	__u8	hdrlen;
	__u8	type;
	__u8	segments_left;
	__u8	first_segment; /* Represents the last_entry field of SRH */
	__u8	flags;
	__u16	tag;

	struct in6_addr segments[0];
};

struct gtpu_recovery_ie_t {
	__u8	type;
	__u8	restart_counter;
};

struct gtpu_paging_policy_t {
	BITALIGN2 (__u8 ppi:3,
			   __u8 spare:5);

	__u8	padding[3];
};

struct gtpu_pdu_session_t {
	__u8	exthdrlen;
	BITALIGN2 (__u8 type:4,
			   __u8 spare:4);

	union {
		struct gtpu_qfi_bits {
			BITALIGN3 (__u8 p:1,
					   __u8 r:1,
					   __u8 qfi:6);
		} bits;

		__u8 val;
	} u;

	struct gtpu_paging_policy_t	paging[0];
	__u8	nextexthdr;
};

struct gtpu_exthdr_t {
	__u16	seq;
	__u8	npdu_num;
	__u8	nextexthdr;
};

struct gtpu_header_t {
	__u8	ver_flags;
	__u8	type;
	__u16	length;
	__u32	teid;
	struct gtpu_exthdr_t	ext[0];
};

struct ip4_gtpu_header_t {
	struct iphdr			ip4;
	struct udphdr 			udp;
	struct gtpu_header_t	gtpu;
};

struct ip6_gtpu_header_t {
	struct ipv6hdr			ip6;
	struct udphdr			udp;
	struct gtpu_header_t	gtpu;
};

struct user_plane_sub_tlv_t {
	__u8	type;
	__u8	length;
	__u8	value[0];
};

struct ip6_sr_tlv_t {
	__u8	type;
	__u8	length;
	__u8	value[0];
};

#define GTPU_EXTHDR_FLAG			0x04
#define GTPU_SEQ_FLAG				0x02
#define GTPU_EXTHDR_PDU_SESSION		0x85

#define SRH_TAG_ECHO_REPLY			0x0008
#define SRH_TAG_ECHO_REQUEST		0x0004
#define SRH_TAG_ERROR_INDICATION	0x0002
#define SRH_TAG_END_MARKER			0x0001

#define GTPU_RECOVERY_IE_TYPE		0x0e

#define GTPU_IE_MAX_SIZ				256
#define SRH_TLV_USER_PLANE_CONTAINER	0x0a /* tentative */

#define GTPU_V1_VER					(1<<5)
#define GTPU_PT_GTP 				(1<<4)

#define USER_PLANE_SUB_TLV_IE		0x01

#define GTPU_TYPE_ECHO_REQUEST		1
#define GTPU_TYPE_ECHO_REPLY		2
#define GTPU_TYPE_ERROR_INDICATION	26
#define GTPU_TYPE_END_MARKER		254
#define GTPU_TYPE_GTPU				255

#define GTPU_PDU_SESSION_P_BIT_MASK	0x80
#define GTPU_PDU_SESSION_R_BIT_MASK 0x40
#define GTPU_PDU_SESSION_QFI_MASK  	0x3f

#define SRV6_PDU_SESSION_U_BIT_MASK	0x01
#define SRV6_PDU_SESSION_R_BIT_MASK	0x02
#define SRV6_PDU_SESSION_QFI_MASK	0xfc

#define SR6_FLAG1_PROTECTED	(1 << 6)
#define SR6_FLAG1_OAM		(1 << 5)
#define SR6_FLAG1_ALERT		(1 << 4)
#define SR6_FLAG1_HMAC		(1 << 3)

#define SR6_TLV_INGRESS		1
#define SR6_TLV_EGRESS		2
#define SR6_TLV_OPAQUE		3
#define SR6_TLV_PADDING		4
#define SR6_TLV_HMAC		5

#define sr_has_hmac(srh) ((srh)->flags & SR6_FLAG1_HMAC)

struct sr6_tlv {
	__u8 type;
	__u8 len;
	__u8 data[0];
};

struct sr6_usid_info {
	__u8 usid_block_len;
	__u8 usid_len;
};

#endif
