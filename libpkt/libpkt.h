/*
 * Copyright (c) 2016 Internet Initiative Japan, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _LIBPKT_H_
#define _LIBPKT_H_

#include <sys/param.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#ifdef __NetBSD__
#include <net/if_ether.h>
#elif defined(__OpenBSD__)
#include <netinet/if_ether.h>
#elif defined(__FreeBSD__)
#include <net/ethernet.h>
#define ether_addr_octet octet
#elif defined(__linux__)
#include <net/ethernet.h>
#define __packed	__attribute__((__packed__))
struct ether_vlan_header {
	uint8_t evl_dhost[ETHER_ADDR_LEN];
	uint8_t evl_shost[ETHER_ADDR_LEN];
	uint16_t evl_encap_proto;
	uint16_t evl_tag;
	uint16_t evl_proto;
} __packed;
#endif
#include <stdio.h>

#define LIBPKT_PKTBUFSIZE	2048

/* ethernet arp packet */
struct arppkt_l2 {
	struct ether_header eheader;
	struct {
		uint16_t ar_hrd;			/* +0x00 */
		uint16_t ar_pro;			/* +0x02 */
		uint8_t ar_hln;				/* +0x04 */
		uint8_t ar_pln;				/* +0x05 */
		uint16_t ar_op;				/* +0x06 */
		uint8_t ar_sha[ETHER_ADDR_LEN];		/* +0x08 */
		struct in_addr ar_spa;			/* +0x0e */
		uint8_t ar_tha[ETHER_ADDR_LEN];		/* +0x12 */
		struct in_addr ar_tpa;			/* +0x18 */
							/* +0x1c */
	} __packed arp;
} __packed;

/* without ether_header */
struct arppkt_l3 {
	struct {
		uint16_t ar_hrd;			/* +0x00 */
		uint16_t ar_pro;			/* +0x02 */
		uint8_t ar_hln;				/* +0x04 */
		uint8_t ar_pln;				/* +0x05 */
		uint16_t ar_op;				/* +0x06 */
		uint8_t ar_sha[ETHER_ADDR_LEN];		/* +0x08 */
		struct in_addr ar_spa;			/* +0x0e */
		uint8_t ar_tha[ETHER_ADDR_LEN];		/* +0x12 */
		struct in_addr ar_tpa;			/* +0x18 */
							/* +0x1c */
	} __packed arp;
} __packed;

struct ndpkt_l2 {
	struct ether_header eheader;
	struct ip6_hdr ip6;
	union {
		struct icmp6_hdr nd_icmp6;
		struct nd_neighbor_solicit nd_solicit;
		struct nd_neighbor_advert nd_advert;
	};
	uint8_t opt[8];
} __packed;

struct ndpkt_l3 {
	struct ip6_hdr ip6;
	union {
		struct icmp6_hdr nd_icmp6;
		struct nd_neighbor_solicit nd_solicit;
		struct nd_neighbor_advert nd_advert;
	};
	uint8_t opt[8];
} __packed;

/* pppoe packet */
struct pppoe_l2 {
	struct ether_header eheader;
	struct {
		uint8_t vertype;
#define PPPOE_VERTYPE	0x11
		uint8_t code;
#define PPPOE_CODE_PADI	0x09
#define PPPOE_CODE_PADO	0x07
#define PPPOE_CODE_PADR	0x19
#define PPPOE_CODE_PADS	0x65
#define PPPOE_CODE_PADT	0xa7
		uint16_t session;
		uint16_t plen;
	} __packed pppoe;
	/* struct pppoetag[], or struct pppoelcp follow here... */
} __packed;

struct pppoetag {
	uint16_t tag;
#define PPPOE_TAG_EOL		0x0000
#define PPPOE_TAG_SNAME		0x0101
#define PPPOE_TAG_ACNAME	0x0102
#define PPPOE_TAG_HUNIQUE	0x0103
#define PPPOE_TAG_ACCOOKIE	0x0104
#define PPPOE_TAG_VENDOR	0x0105
#define PPPOE_TAG_RELAYSID	0x0110
#define PPPOE_TAG_MAX_PAYLOAD	0x0120
#define PPPOE_TAG_SNAME_ERR	0x0201
#define PPPOE_TAG_ACSYS_ERR	0x0202
#define PPPOE_TAG_GENERIC_ERR	0x0203
	uint16_t len;
} __packed;

struct pppoeppp {
	uint16_t protocol;
#define PPP_IP		0x0021
#define PPP_IPV6	0x0057
#define PPP_IPCP	0x8021
#define PPP_IPV6CP	0x8057
#define PPP_LCP		0xc021
#define PPP_PAP		0xc023
#define PPP_CHAP	0xc223
	union {
		struct {
			uint8_t type;
#define CONF_REQ	1
#define CONF_ACK	2
#define CONF_NAK	3
#define CONF_REJ	4
#define TERM_REQ	5
#define TERM_ACK	6
#define CODE_REJ	7
#define PROTO_REJ	8
#define ECHO_REQ	9
#define ECHO_REPLY	10
#define DISC_REQ	11
#define PAP_REQ		1
#define PAP_ACK		2
#define PAP_NAK		3
#define CHAP_CHALLENGE	1
#define CHAP_RESPONSE	2
#define CHAP_SUCCESS	3
#define CHAP_FAILURE	4

			uint8_t id;
			uint16_t len;
			uint8_t data[];
#define LCP_OPT_MRU		1
#define LCP_OPT_AUTH_PROTO	3
#define LCP_OPT_MAGIC		5

#define IPCP_OPT_ADDRESS	3

#define CHAP_CHALLENGE		1
#define CHAP_RESPONSE		2
#define CHAP_SUCCESS		3
#define CHAP_FAILURE		4
		} ppp;
	} __packed;
} __packed;

static inline unsigned int align(unsigned int n, unsigned int a)
{
	return (n + a - 1) & (-a);
}

static inline unsigned int
reduce1(uint32_t sum)
{
	if (sum == 0)
		return 0xffff;

	sum = ((sum >> 16) & 0xffff) + (sum & 0xffff);
	sum &= 0xffff;
	if (sum == 0)
		sum++;
	return sum;
}

/* cksum.c */
unsigned int in4_cksum(struct in_addr, struct in_addr, int, char *, unsigned int);
unsigned int in6_cksum(struct in6_addr *, struct in6_addr *, int, char *, unsigned int);
unsigned int in_cksum(unsigned int, char *, unsigned int);

/* etherpkt.c */
int ethpkt_template(char *, unsigned int);
int ethpkt_type(char *, u_short);
int ethpkt_src(char *, const u_char *);
int ethpkt_dst(char *, const u_char *);

/* pppoepkt.c */
int pppoepkt_template(char *, uint16_t);

int pppoepkt_code(char *, uint8_t);
int pppoepkt_session(char *, uint16_t);
int pppoepkt_type(char *, uint16_t);
int pppoepkt_length(char *, uint16_t);
int pppoepkt_tag_extract(char *, uint16_t, void *, uint16_t *);
int pppoepkt_tag_add(char *, uint16_t, const void *, uint16_t);
int pppoepkt_ppp_set(char *, uint16_t, uint8_t, uint8_t);
int pppoepkt_ppp_extract_data(char *, int, void *, int);
int pppoepkt_ppp_add_data(char *, void *, uint16_t);

/* ip4pkt.c */
int ip4pkt_arpparse(char *, int *, struct ether_addr *, in_addr_t *, in_addr_t *);
int ip4pkt_arpquery(char *, const struct ether_addr *, in_addr_t, in_addr_t);
int ip4pkt_arpreply(char *, const char *, u_char *, in_addr_t, in_addr_t);
int ip4pkt_icmp_template(char *, unsigned int);
int ip4pkt_icmp_echoreply(char *, unsigned int, const char *, unsigned int);
int ip4pkt_icmp_type(char *, unsigned int, int);
int ip4pkt_udp_template(char *, unsigned int);
int ip4pkt_tcp_template(char *, unsigned int);
int ip4pkt_length(char *, unsigned int, unsigned int);
int ip4pkt_off(char *, unsigned int, uint16_t);
int ip4pkt_id(char *, unsigned int, uint16_t);
int ip4pkt_ttl(char *, unsigned int, unsigned int);
int ip4pkt_src(char *, unsigned int, in_addr_t);
int ip4pkt_dst(char *, unsigned int, in_addr_t);
int ip4pkt_srcport(char *, unsigned int, uint16_t);
int ip4pkt_dstport(char *, unsigned int, uint16_t);
int ip4pkt_payload(char *, unsigned int, char *, unsigned int);

int ip4pkt_icmptype(char *, unsigned int, uint8_t);
int ip4pkt_icmpcode(char *, unsigned int, uint8_t);
int ip4pkt_icmpid(char *, unsigned int, uint16_t);
int ip4pkt_icmpseq(char *, unsigned int, uint16_t);

int ip4pkt_tcpseq(char *, unsigned int, uint32_t);
int ip4pkt_tcpack(char *, unsigned int, uint32_t);
int ip4pkt_tcpflags(char *, unsigned int, int);
int ip4pkt_tcpwin(char *, unsigned int, uint16_t);
int ip4pkt_tcpurp(char *, unsigned int, uint16_t);

int ip4pkt_writedata(char *, unsigned int, unsigned int, char *, unsigned int);
int ip4pkt_readdata(char *, unsigned int, unsigned int, char *, unsigned int);
char *ip4pkt_getptr(char *, unsigned int, unsigned int);

int ip4pkt_test_cksum(char *, unsigned int, unsigned int);

/* ip6pkt.c */
int ip6pkt_neighbor_parse(char *, int *, struct in6_addr *, struct in6_addr *);
int ip6pkt_neighbor_solicit(char *, const struct ether_addr *, struct in6_addr *, struct in6_addr *);
int ip6pkt_neighbor_solicit_reply(char *, const char *, u_char *, struct in6_addr *);
int ip6pkt_icmp6_template(char *, unsigned int);
int ip6pkt_icmp6_echoreply(char *, unsigned int, const char *, unsigned int);
int ip6pkt_icmp6_type(char *, unsigned int, unsigned int);
int ip6pkt_udp_template(char *, unsigned int);
int ip6pkt_tcp_template(char *, unsigned int);
int ip6pkt_length(char *, unsigned int, unsigned int);
int ip6pkt_off(char *, unsigned int, uint16_t);
int ip6pkt_flowinfo(char *, unsigned int, uint32_t);
int ip6pkt_ttl(char *, unsigned int, int);
int ip6pkt_src(char *, unsigned int, const struct in6_addr *);
int ip6pkt_dst(char *, unsigned int, const struct in6_addr *);
int ip6pkt_srcport(char *, unsigned int, uint16_t);
int ip6pkt_dstport(char *, unsigned int, uint16_t);
int ip6pkt_payload(char *, unsigned int, char *, unsigned int);

int ip6pkt_icmptype(char *, unsigned int, uint8_t);
int ip6pkt_icmpcode(char *, unsigned int, uint8_t);
int ip6pkt_icmpid(char *, unsigned int, uint16_t);
int ip6pkt_icmpseq(char *, unsigned int, uint16_t);

int ip6pkt_tcpseq(char *, unsigned int, uint32_t);
int ip6pkt_tcpack(char *, unsigned int, uint32_t);
int ip6pkt_tcpflags(char *, unsigned int, int);
int ip6pkt_tcpwin(char *, unsigned int, uint16_t);
int ip6pkt_tcpurp(char *, unsigned int, uint16_t);

int ip6pkt_writedata(char *, unsigned int, unsigned int, char *, unsigned int);
int ip6pkt_readdata(char *, unsigned int, unsigned int, char *, unsigned int);
char *ip6pkt_getptr(char *, unsigned int, unsigned int);

int ip6pkt_test_cksum(char *, unsigned int, unsigned int);


/* debug */
#define DUMPSTR_FLAGS_CRLF	0x00000001
int fdumpstr(FILE *, const char *, size_t, int);
int dumpstr(const char *, size_t, int);

/* tcpdump file output utility */
int tcpdumpfile_open(const char *);
ssize_t tcpdumpfile_output(int, char *, int);
void tcpdumpfile_close(int);

#endif /* _LIBPKT_H_ */
