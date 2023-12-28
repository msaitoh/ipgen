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
#include "libpkt.h"

#include <string.h>
#ifdef __FreeBSD__
#include <sys/stddef.h>
#else
#include <stddef.h>
#endif
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>

/* XXX: from netinet6/in6.h */
#if BYTE_ORDER == BIG_ENDIAN
#define IPV6_ADDR_INT32_ONE		1
#define IPV6_ADDR_INT32_TWO		2
#define IPV6_ADDR_INT32_MNL		0xff010000
#define IPV6_ADDR_INT32_MLL		0xff020000
#define IPV6_ADDR_INT32_SMP		0x0000ffff
#define IPV6_ADDR_INT16_ULL		0xfe80
#define IPV6_ADDR_INT16_USL		0xfec0
#define IPV6_ADDR_INT16_MLL		0xff02
#elif BYTE_ORDER == LITTLE_ENDIAN
#define IPV6_ADDR_INT32_ONE		0x01000000
#define IPV6_ADDR_INT32_TWO		0x02000000
#define IPV6_ADDR_INT32_MNL		0x000001ff
#define IPV6_ADDR_INT32_MLL		0x000002ff
#define IPV6_ADDR_INT32_SMP		0xffff0000
#define IPV6_ADDR_INT16_ULL		0x80fe
#define IPV6_ADDR_INT16_USL		0xc0fe
#define IPV6_ADDR_INT16_MLL		0x02ff
#endif
#ifndef IPV6_VERSION
#define IPV6_VERSION          0x60
#endif
#ifndef IPV6_VERSION_MASK
#define IPV6_VERSION_MASK     0xf0
#endif
#ifndef IPV6_FLOWINFO_MASK
#define IPV6_FLOWINFO_MASK    0x0fffffff
#endif
#ifdef __linux__
#define s6_addr8  s6_addr
#endif
#ifndef s6_addr8
#define s6_addr8  __u6_addr.__u6_addr8
#endif
#ifndef s6_addr16
#define s6_addr16 __u6_addr.__u6_addr16
#endif
#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

int
ip6pkt_neighbor_solicit(char *buf, const struct ether_addr *sha, struct in6_addr *addr1, struct in6_addr *addr2)
{
	u_int8_t edst[ETHER_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };	/* XXX: should to use multicast address */
	struct ndpkt_l2 *ndpkt;
	unsigned int ip6len, protolen;
	int len;
	struct in6_addr daddr;

	ndpkt = (struct ndpkt_l2 *)buf;

	len = ip6pkt_icmp6_template(buf, sizeof(struct ndpkt_l2));
	ip6len = len - sizeof(struct ether_header);
	protolen = ip6len - sizeof(struct ip6_hdr);

	ethpkt_src(buf, (u_char *)sha);
	ethpkt_dst(buf, edst);

	memset(&daddr, 0, sizeof(daddr));
	daddr.s6_addr16[0] = IPV6_ADDR_INT16_MLL;
	daddr.s6_addr16[1] = 0;
	daddr.s6_addr32[1] = 0;
	daddr.s6_addr32[2] = IPV6_ADDR_INT32_ONE;
	daddr.s6_addr32[3] = addr2->s6_addr32[3];
	daddr.s6_addr8[12] = 0xff;

	ndpkt->ip6.ip6_src = *addr1;
	ndpkt->ip6.ip6_dst = daddr;
	ndpkt->nd_icmp6.icmp6_type = ND_NEIGHBOR_SOLICIT;
	memcpy(&ndpkt->opt[2], sha, ETHER_ADDR_LEN);
	memcpy(&ndpkt->nd_solicit.nd_ns_target, addr2, sizeof(struct in6_addr));
	ndpkt->opt[0] = 1;
	ndpkt->opt[1] = 1;

	ndpkt->nd_icmp6.icmp6_cksum = 0;
	ndpkt->nd_icmp6.icmp6_cksum = in6_cksum(&ndpkt->ip6.ip6_src, &ndpkt->ip6.ip6_dst, ndpkt->ip6.ip6_nxt, (char *)&ndpkt->nd_icmp6, protolen);

	return len;
}

int
ip6pkt_neighbor_parse(char *buf, int *type, struct in6_addr *src, struct in6_addr *tgt)
{
	struct ndpkt_l3 *ndpkt;

	ndpkt = (struct ndpkt_l3 *)buf;

	*type = ndpkt->nd_icmp6.icmp6_type;
	memcpy(src, &ndpkt->ip6.ip6_src, sizeof(struct in6_addr));

	switch (ndpkt->nd_icmp6.icmp6_type) {
	case ND_NEIGHBOR_SOLICIT:
		memcpy(tgt, &ndpkt->nd_solicit.nd_ns_target, sizeof(struct in6_addr));
		break;

	case ND_NEIGHBOR_ADVERT:
		memcpy(tgt, &ndpkt->nd_advert.nd_na_target, sizeof(struct in6_addr));
		break;

	default:
		/* XXX: notyet */
		break;
	}

	return 0;
}

int
ip6pkt_neighbor_solicit_reply(char *buf, const char *solicitbuf, u_char *eaddr, struct in6_addr *addr)
{
	struct ether_header *oeheader;
	struct ether_vlan_header *oevheader;
	struct ndpkt_l3 *ondpkt_l3;
	struct ndpkt_l2 *ndpkt_l2;
	unsigned int ip6len, protolen;
	int len;

	oeheader = (struct ether_header *)solicitbuf;
	ndpkt_l2 = (struct ndpkt_l2 *)buf;

	if (ntohs(oeheader->ether_type) == ETHERTYPE_VLAN) {
		ondpkt_l3 = (struct ndpkt_l3 *)(solicitbuf + sizeof(struct ether_vlan_header));
		oevheader = (struct ether_vlan_header *)oeheader;
	} else {
		ondpkt_l3 = (struct ndpkt_l3 *)(solicitbuf + sizeof(struct ether_header));
		oevheader = NULL;
	}


	len = ip6pkt_icmp6_template(buf, sizeof(struct ndpkt_l2));
	ip6len = len - sizeof(struct ether_header);
	protolen = ip6len - sizeof(struct ip6_hdr);

	ethpkt_src(buf, eaddr);
	ethpkt_dst(buf, oeheader->ether_shost);

	if (IN6_IS_ADDR_MULTICAST(&ondpkt_l3->ip6.ip6_dst))
		ndpkt_l2->ip6.ip6_src = ondpkt_l3->nd_solicit.nd_ns_target;
	else
		ndpkt_l2->ip6.ip6_src = ondpkt_l3->ip6.ip6_dst;

	ndpkt_l2->ip6.ip6_dst = ondpkt_l3->ip6.ip6_src;
	ndpkt_l2->nd_icmp6.icmp6_type = ND_NEIGHBOR_ADVERT;
	ndpkt_l2->nd_icmp6.icmp6_data32[0] = 
	    ND_NA_FLAG_SOLICITED |
	    ND_NA_FLAG_OVERRIDE;

	memcpy(&ndpkt_l2->opt[2], eaddr, ETHER_ADDR_LEN);
	memcpy(&ndpkt_l2->nd_advert.nd_na_target,
	    &ondpkt_l3->nd_solicit.nd_ns_target,
	    sizeof(struct in6_addr));
	ndpkt_l2->opt[0] = 2;
	ndpkt_l2->opt[1] = 1;

	ndpkt_l2->nd_icmp6.icmp6_cksum = 0;
	ndpkt_l2->nd_icmp6.icmp6_cksum = in6_cksum(&ndpkt_l2->ip6.ip6_src, &ndpkt_l2->ip6.ip6_dst, ndpkt_l2->ip6.ip6_nxt, (char *)&ndpkt_l2->nd_icmp6, protolen);

	if (oevheader != NULL) {
		/* insert VLAN tag */
		memmove(buf + sizeof(struct ether_vlan_header), buf + sizeof(struct ether_header),
		    ip6len);

		struct ether_vlan_header *evl = (struct ether_vlan_header *)buf;
		evl->evl_encap_proto = htons(ETHERTYPE_VLAN);
		evl->evl_tag = oevheader->evl_tag;
		evl->evl_proto = htons(ETHERTYPE_IPV6);

		return len + 4;
	}

	return len;
}

int
ip6pkt_icmp6_template(char *buf, unsigned int framelen)
{
	struct ether_header *eh;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	unsigned int ip6len, protolen;

	ip6len = framelen - sizeof(struct ether_header);
	protolen = ip6len - sizeof(struct ip6_hdr);

	memset(buf, 0, framelen);
	eh = (struct ether_header *)buf;
	eh->ether_type = htons(ETHERTYPE_IPV6);

	ip6 = (struct ip6_hdr *)(eh + 1);
	ip6->ip6_vfc = IPV6_VERSION;
/*	ip6->ip6_flow = 0;	*/
	ip6->ip6_plen = htons(protolen);
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = 255;

	icmp6 = (struct icmp6_hdr *)(ip6 + 1);
	icmp6->icmp6_type = 0;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_cksum = in6_cksum(&ip6->ip6_src, &ip6->ip6_dst, ip6->ip6_nxt, (char *)icmp6, protolen);

	return framelen;
}

int
ip6pkt_icmp6_echoreply(char *buf, unsigned int l3offset, const char *reqbuf, unsigned int framelen)
{
	struct ip6_hdr *ip6, *rip6;

	ip6 = (struct ip6_hdr *)(buf + l3offset);
	rip6 = (struct ip6_hdr *)(reqbuf + l3offset);

	memcpy(buf, reqbuf, framelen);
	memcpy(&ip6->ip6_src, &rip6->ip6_dst, sizeof(struct in6_addr));
	memcpy(&ip6->ip6_dst, &rip6->ip6_src, sizeof(struct in6_addr));
	ip6pkt_icmp6_type(buf, l3offset, ICMP6_ECHO_REPLY);

	return framelen;
}

int
ip6pkt_icmp6_type(char *buf, unsigned int l3offset, unsigned int type)
{
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	uint32_t sum;

	ip6 = (struct ip6_hdr *)(buf + l3offset);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return -1;

	icmp6 = (struct icmp6_hdr *)(ip6 + 1);	/* XXX: don't consider extension header */

	sum = ~icmp6->icmp6_cksum & 0xffff;
#if _BYTE_ORDER == _LITTLE_ENDIAN
	sum -= icmp6->icmp6_type;
	sum += type;
#else
	sum -= (icmp6->icmp6_type << 8);
	sum += type << 8;
#endif
	icmp6->icmp6_cksum = ~reduce1(sum);
	icmp6->icmp6_type = type;

	return 0;
}

int
ip6pkt_udp_template(char *buf, unsigned int framelen)
{
	struct ether_header *eh;
	struct ip6_hdr *ip6;
	struct udphdr *udp;
	unsigned int ip6len, protolen;

	ip6len = framelen - sizeof(struct ether_header);
	protolen = ip6len - sizeof(struct ip6_hdr);

	memset(buf, 0, framelen);
	eh = (struct ether_header *)buf;
	eh->ether_type = htons(ETHERTYPE_IPV6);

	ip6 = (struct ip6_hdr *)(eh + 1);
	ip6->ip6_vfc = IPV6_VERSION;
/*	ip6->ip6_flow = 0;	*/
	ip6->ip6_plen = htons(protolen);
	ip6->ip6_nxt = IPPROTO_UDP;
	ip6->ip6_hlim = 64;

	udp = (struct udphdr *)(ip6 + 1);
/*	udp->uh_sport = 0;	*/
/*	udp->uh_dport = 0;	*/
	udp->uh_ulen = htons(protolen);
	udp->uh_sum = in6_cksum(&ip6->ip6_src, &ip6->ip6_dst, ip6->ip6_nxt, (char *)udp, protolen);

	return framelen;
}

int
ip6pkt_tcp_template(char *buf, unsigned int framelen)
{
	struct ether_header *eh;
	struct ip6_hdr *ip6;
	struct tcphdr *tcp;
	unsigned int ip6len, protolen;

	ip6len = framelen - sizeof(struct ether_header);
	protolen = ip6len - sizeof(struct ip6_hdr);

	memset(buf, 0, framelen);
	eh = (struct ether_header *)buf;
	eh->ether_type = htons(ETHERTYPE_IPV6);

	ip6 = (struct ip6_hdr *)(eh + 1);
	ip6->ip6_vfc = IPV6_VERSION;
/*	ip6->ip6_flow = 0;	*/
	ip6->ip6_plen = htons(protolen);
	ip6->ip6_nxt = IPPROTO_TCP;
	ip6->ip6_hlim = 64;

	tcp = (struct tcphdr *)(ip6 + 1);
/*	tcp->th_sport = 0;	*/
/*	tcp->th_dport = 0;	*/
/*	tcp->th_seq = 0;	*/
/*	tcp->th_ack = 0;	*/
	tcp->th_off = sizeof(struct tcphdr) / 4;
/*	tcp->th_x2 = 0;	*/
/*	tcp->th_flags = 0;	*/
/*	tcp->th_win = 0;	*/
/*	tcp->th_sum = 0;	*/
/*	tcp->th_urp = 0;	*/
	tcp->th_sum = in6_cksum(&ip6->ip6_src, &ip6->ip6_dst, ip6->ip6_nxt, (char *)tcp, protolen);

	return framelen;
}

int
ip6pkt_length(char *buf, unsigned int l3offset, unsigned int ip6len)
{
	struct ip6_hdr *ip6;
	uint32_t sum;
	uint16_t oldlen;

	ip6 = (struct ip6_hdr *)(buf + l3offset);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return -1;

	oldlen = ip6->ip6_plen;	/* as network endian */
	ip6->ip6_plen = htons(ip6len - sizeof(struct ip6_hdr));

	switch (ip6->ip6_nxt) {
	case IPPROTO_UDP:
		{
			struct udphdr *udp = (struct udphdr *)(ip6 + 1);

			udp->uh_ulen = htons(ip6len - sizeof(struct ip6_hdr));
			sum = ~udp->uh_sum & 0xffff;
			sum -= oldlen;	/* for pseudo header */
			sum -= oldlen;	/* for udp->uh_ulen */
			sum += udp->uh_ulen;	/* for pseudo header */
			sum += udp->uh_ulen;	/* for udp->uh_ulen */
			udp->uh_sum = ~reduce1(sum);
		}
		break;
	case IPPROTO_TCP:
		{
			struct tcphdr *tcp = (struct tcphdr *)(ip6 + 1);

			sum = ~tcp->th_sum & 0xffff;
			sum -= oldlen;
			sum += ip6->ip6_plen;
			tcp->th_sum = ~reduce1(sum);
		}
		break;
	default:
		return -1;
	}

	return 0;
}

/*
 * XXX: NOTYET
 * TODO: support IPv6 extension header
 */
#if 0
int
ip6pkt_off(char *buf, unsigned int l3offset, uint16_t off)
{
	struct ip6_hdr *ip6;
//	uint32_t sum;

	ip6 = (struct ip6_hdr *)(buf + l3offset);
	(void)&ip6;

//	if (ip->ip_v != IPVERSION)
//		return -1;
//
//	off = htons(off);
//	sum = ~ip->ip_sum & 0xffff;
//	sum -= ip->ip_off & 0xffff;
//	sum += off & 0xffff;
//	ip->ip_sum = ~reduce1(sum);
//	ip->ip_off = off;

	return 0;
}
#endif

int
ip6pkt_flowinfo(char *buf, unsigned int l3offset, uint32_t flow)
{
	struct ip6_hdr *ip6;

	ip6 = (struct ip6_hdr *)(buf + l3offset);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return -1;

	ip6->ip6_flow &= IPV6_FLOWINFO_MASK;
	ip6->ip6_flow |= (flow & IPV6_FLOWINFO_MASK);
	return 0;
}

int
ip6pkt_ttl(char *buf, unsigned int l3offset, int ttl)
{
	struct ip6_hdr *ip6;

	ip6 = (struct ip6_hdr *)(buf + l3offset);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return -1;

	ip6->ip6_hlim = ttl;
	return 0;
}

static int
ip6pkt_srcdst(int srcdst, char *buf, unsigned int l3offset, const struct in6_addr *addr)
{
	struct ip6_hdr *ip6;
	uint16_t *sump;
	uint32_t sum;
	struct in6_addr old;

	ip6 = (struct ip6_hdr *)(buf + l3offset);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return -1;

	if (srcdst == 0) {
		old = ip6->ip6_src;
		ip6->ip6_src = *addr;
	} else {
		old = ip6->ip6_dst;
		ip6->ip6_dst= *addr;
	}

#ifndef s6_addr16
#define s6_addr16 __u6_addr.__u6_addr16
#endif

	switch (ip6->ip6_nxt) {
	case IPPROTO_UDP:
		{
			struct udphdr *udp = (struct udphdr *)(ip6 + 1);

			sum = ~udp->uh_sum & 0xffff;
			sump = &udp->uh_sum;
		}
		break;
	case IPPROTO_TCP:
		{
			struct tcphdr *tcp = (struct tcphdr *)(ip6 + 1);

			sum = ~tcp->th_sum & 0xffff;
			sump = &tcp->th_sum;
		}
		break;
	case IPPROTO_ICMPV6:
		{
			struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(ip6 + 1);

			sum = ~icmp6->icmp6_cksum & 0xffff;
			sump = &icmp6->icmp6_cksum;
		}
		break;
		break;
	default:
		return -1;
	}

	sum -= old.s6_addr16[0];
	sum -= old.s6_addr16[1];
	sum -= old.s6_addr16[2];
	sum -= old.s6_addr16[3];
	sum -= old.s6_addr16[4];
	sum -= old.s6_addr16[5];
	sum -= old.s6_addr16[6];
	sum -= old.s6_addr16[7];

	sum += addr->s6_addr16[0];
	sum += addr->s6_addr16[1];
	sum += addr->s6_addr16[2];
	sum += addr->s6_addr16[3];
	sum += addr->s6_addr16[4];
	sum += addr->s6_addr16[5];
	sum += addr->s6_addr16[6];
	sum += addr->s6_addr16[7];

	*sump = ~reduce1(sum);

	return 0;
}

int
ip6pkt_src(char *buf, unsigned int l3offset, const struct in6_addr *addr)
{
	return ip6pkt_srcdst(0, buf, l3offset, addr);
}

int
ip6pkt_dst(char *buf, unsigned int l3offset, const struct in6_addr *addr)
{
	return ip6pkt_srcdst(1, buf, l3offset, addr);
}

static inline int
ip6pkt_srcdstport(int srcdst, char *buf, unsigned int l3offset, uint16_t port)
{
	struct ip6_hdr *ip6;
	uint32_t sum;
	uint16_t oldport;

	ip6 = (struct ip6_hdr *)(buf + l3offset);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return -1;

	port = htons(port);
	switch (ip6->ip6_nxt) {
	case IPPROTO_UDP:
		{
			struct udphdr *udp = (struct udphdr *)(ip6 + 1);

			if (srcdst == 0) {
				/* change src */
				oldport = udp->uh_sport;
				udp->uh_sport = port;
			} else {
				/* change dst */
				oldport = udp->uh_dport;
				udp->uh_dport = port;
			}
			sum = ~udp->uh_sum & 0xffff;
			sum -= oldport;
			sum += port;
			udp->uh_sum = ~reduce1(sum);
		}
		break;
	case IPPROTO_TCP:
		{
			struct tcphdr *tcp = (struct tcphdr *)(ip6 + 1);

			if (srcdst == 0) {
				/* change src */
				oldport = tcp->th_sport;
				tcp->th_sport = port;
			} else {
				/* change dst */
				oldport =  tcp->th_dport;
				tcp->th_dport = port;
			}
			sum = ~tcp->th_sum & 0xffff;
			sum -= oldport;
			sum += port;
			tcp->th_sum = ~reduce1(sum);
		}
		break;
	default:
		return -1;
	}

	return 0;
}

int
ip6pkt_srcport(char *buf, unsigned int l3offset, uint16_t port)
{
	return ip6pkt_srcdstport(0, buf, l3offset, port);
}

int
ip6pkt_dstport(char *buf, unsigned int l3offset, uint16_t port)
{
	return ip6pkt_srcdstport(1, buf, l3offset, port);
}

int
ip6pkt_writedata(char *buf, unsigned int l3offset, unsigned int offset, char *data, unsigned int datalen)
{
	struct ip6_hdr *ip6;
	uint16_t *sump;
	char *datap;
	uint32_t sum;

	ip6 = (struct ip6_hdr *)(buf + l3offset);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return -1;

	switch (ip6->ip6_nxt) {
	case IPPROTO_UDP:
		{
			struct udphdr *udp = (struct udphdr *)(ip6 + 1);
			sump = &udp->uh_sum;
			datap = (char *)(udp + 1) + offset;
		}
		break;
	case IPPROTO_TCP:
		{
			struct tcphdr *tcp = (struct tcphdr *)(ip6 + 1);
			sump = &tcp->th_sum;
			datap = (char *)tcp + tcp->th_off * 4 + offset;
		}
		break;
	case IPPROTO_ICMPV6:
		{
			struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(ip6 + 1);
			sump = &icmp6->icmp6_cksum;
			datap = (char *)(icmp6->icmp6_data8) + offset;
		}
		break;
	default:
		return -1;
	}

	sum = ~*sump & 0xffff;
	{
		if (offset & 1) {
#if _BYTE_ORDER == _LITTLE_ENDIAN
			sum -= (*datap & 0xff) << 8;
			sum += (*data & 0xff) << 8;
#else
			sum -= (*datap & 0xff);
			sum += (*data & 0xff);
#endif
			sum = reduce1(sum);
			*datap++ = *data++;
			datalen--;
		}

		for (; datalen >= 2; datalen -= 2) {
			sum -= *(uint16_t *)datap;
			*(uint16_t *)datap = *(uint16_t *)data;
			sum += *(uint16_t *)data;
			sum = reduce1(sum);

			datap += 2;
			data += 2;
		}

		if (datalen > 0) {
#if _BYTE_ORDER == _LITTLE_ENDIAN
			sum -= (*datap & 0xff);
			sum += (*data & 0xff);
#else
			sum -= (*datap & 0xff) << 8;
			sum += (*data & 0xff) << 8;
#endif
			sum = reduce1(sum);
			*datap++ = *data++;
			datalen--;
		}
	}
	*sump = ~sum;

	return 0;
}

int
ip6pkt_readdata(char *buf, unsigned int l3offset, unsigned int offset, char *data, unsigned int datalen)
{
	struct ip6_hdr *ip6;
	char *datap;

	ip6 = (struct ip6_hdr *)(buf + l3offset);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return -1;

	switch (ip6->ip6_nxt) {
	case IPPROTO_UDP:
		{
			struct udphdr *udp = (struct udphdr *)(ip6 + 1);
			datap = (char *)(udp + 1) + offset;
		}
		break;
	case IPPROTO_TCP:
		{
			struct tcphdr *tcp = (struct tcphdr *)(ip6 + 1);
			datap = (char *)tcp + tcp->th_off * 4 + offset;
		}
		break;
	case IPPROTO_ICMPV6:
		{
			struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(ip6 + 1);
			datap = (char *)(icmp6->icmp6_data8) + offset;
		}
		break;
	default:
		datap = (char *)(ip6 + 1);
		break;
	}

	memcpy(data, datap, datalen);

	return 0;
}

char *
ip6pkt_getptr(char *buf, unsigned int l3offset, unsigned int offset)
{
	struct ip6_hdr *ip6;
	char *datap;

	ip6 = (struct ip6_hdr *)(buf + l3offset);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return NULL;

	switch (ip6->ip6_nxt) {
	case IPPROTO_UDP:
		{
			struct udphdr *udp = (struct udphdr *)(ip6 + 1);
			datap = (char *)(udp + 1) + offset;
		}
		break;
	case IPPROTO_TCP:
		{
			struct tcphdr *tcp = (struct tcphdr *)(ip6 + 1);
			datap = (char *)tcp + tcp->th_off * 4 + offset;
		}
		break;
	case IPPROTO_ICMP:
		{
			struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(ip6 + 1);
			datap = (char *)(icmp6->icmp6_data8) + offset;
		}
		break;
	default:
		datap = (char *)(ip6 + 1);
		break;
	}
	return datap;
}

static int
ip6pkt_icmp_uint8(char *buf, unsigned int l3offset, int icmpoffset, uint8_t data)
{
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	uint32_t sum;
	uint8_t olddata;

	ip6 = (struct ip6_hdr *)(buf + l3offset);
	(void)&ip6;

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return -1;
	icmp6 = (struct icmp6_hdr *)(ip6 + 1);

	olddata = *(uint8_t *)((char *)icmp6 + icmpoffset);
	*(uint8_t *)((char *)icmp6 + icmpoffset) = data;

	sum = ~icmp6->icmp6_cksum & 0xffff;
#if _BYTE_ORDER == _LITTLE_ENDIAN
	if (icmpoffset & 1) {
		sum -= (olddata << 8) & 0xffff;
		sum += (data << 8) & 0xffff;
	} else {
		sum -= olddata & 0xffff;
		sum += data & 0xffff;
	}
#else
	if (icmpoffset & 1) {
		sum -= olddata & 0xffff;
		sum += data & 0xffff;
	} else {
		sum -= (olddata << 8) & 0xffff;
		sum += (data << 8) & 0xffff;
	}
#endif
	icmp6->icmp6_cksum = ~reduce1(sum);

	return 0;
}

static int
ip6pkt_icmp_uint16(char *buf, unsigned int l3offset, int icmpoffset, uint16_t data)
{
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	uint32_t sum;
	uint16_t olddata;

	ip6 = (struct ip6_hdr *)(buf + l3offset);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return -1;
	icmp6 = (struct icmp6_hdr *)(ip6 + 1);

	data = htons(data);
	olddata = *(uint16_t *)((char *)icmp6 + icmpoffset);
	*(uint16_t *)((char *)icmp6 + icmpoffset) = data;

	sum = ~icmp6->icmp6_cksum & 0xffff;
	sum -= olddata & 0xffff;
	sum += data & 0xffff;
	icmp6->icmp6_cksum = ~reduce1(sum);

	return 0;
}

int
ip6pkt_icmptype(char *buf, unsigned int l3offset, uint8_t type)
{
	return ip6pkt_icmp_uint8(buf, l3offset, offsetof(struct icmp6_hdr, icmp6_type), type);
}

int
ip6pkt_icmpcode(char *buf, unsigned int l3offset, uint8_t code)
{
	return ip6pkt_icmp_uint8(buf, l3offset, offsetof(struct icmp6_hdr, icmp6_code), code);
}

int
ip6pkt_icmpid(char *buf, unsigned int l3offset, uint16_t id)
{
	return ip6pkt_icmp_uint16(buf, l3offset, offsetof(struct icmp6_hdr, icmp6_id), id);
}

int
ip6pkt_icmpseq(char *buf, unsigned int l3offset, uint16_t seq)
{
	return ip6pkt_icmp_uint16(buf, l3offset, offsetof(struct icmp6_hdr, icmp6_seq), seq);
}

//static int
//ip6pkt_udp_uint16(char *buf, unsigned int l3offset, int udpoffset, uint16_t data)
//{
//	struct ip6_hdr *ip6;
//	struct udphdr *udp;
//	uint32_t sum;
//	uint16_t old;
//
//	ip6 = (struct ip6_hdr *)(buf + l3offset);
//
//	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
//		return -1;
//
//	if (ip6->ip6_nxt != IPPROTO_UDP)
//		return -1;
//
//	udp = (struct udphdr *)(ip6 + 1);
//
//	data = htons(data);
//
//	old = *(uint16_t *)(((char *)udp) + udpoffset);
//	*(uint16_t *)(((char *)udp) + udpoffset) = data;
//
//	sum = ~udp->uh_sum & 0xffff;
//	sum -= old;
//	sum += data;
//	udp->uh_sum = ~reduce1(sum);
//
//	return 0;
//}

static int
ip6pkt_tcp_uint16(char *buf, unsigned int l3offset, int tcpoffset, uint16_t data)
{
	struct ip6_hdr *ip6;
	struct tcphdr *tcp;
	uint32_t sum;
	uint16_t old;

	ip6 = (struct ip6_hdr *)(buf + l3offset);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return -1;

	if (ip6->ip6_nxt != IPPROTO_TCP)
		return -1;

	tcp = (struct tcphdr *)(ip6 + 1);

	data = htons(data);

	old = *(uint16_t *)(((char *)tcp) + tcpoffset);
	*(uint16_t *)(((char *)tcp) + tcpoffset) = data;

	sum = ~tcp->th_sum & 0xffff;
	sum -= old;
	sum += data;
	tcp->th_sum = ~reduce1(sum);

	return 0;
}

static int
ip6pkt_tcp_uint32(char *buf, unsigned int l3offset, int tcpoffset, uint32_t data)
{
	struct ip6_hdr *ip6;
	struct tcphdr *tcp;
	uint32_t sum;
	uint32_t old;

	ip6 = (struct ip6_hdr *)(buf + l3offset);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return -1;

	if (ip6->ip6_nxt != IPPROTO_TCP)
		return -1;

	tcp = (struct tcphdr *)(ip6 + 1);

	data = htonl(data);

	old = *(uint32_t *)(((char *)tcp) + tcpoffset);
	*(uint32_t *)(((char *)tcp) + tcpoffset) = data;

	sum = ~tcp->th_sum & 0xffff;
	sum -= (old >> 16) & 0xffff;
	sum -= old & 0xffff;
	sum += (data >> 16) & 0xffff;
	sum += data & 0xffff;
	tcp->th_sum = ~reduce1(sum);

	return 0;
}

int
ip6pkt_tcpseq(char *buf, unsigned int l3offset, uint32_t seq)
{
	return ip6pkt_tcp_uint32(buf, l3offset, offsetof(struct tcphdr, th_seq), seq);
}

int
ip6pkt_tcpack(char *buf, unsigned int l3offset, uint32_t ack)
{
	return ip6pkt_tcp_uint32(buf, l3offset, offsetof(struct tcphdr, th_ack), ack);
}

int
ip6pkt_tcpflags(char *buf, unsigned int l3offset, int flags)
{
	struct ip6_hdr *ip6;
	struct tcphdr *tcp;
	uint32_t sum;
	uint8_t oldflags;

	ip6 = (struct ip6_hdr *)(buf + l3offset);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return -1;

	if (ip6->ip6_nxt != IPPROTO_TCP)
		return -1;

	tcp = (struct tcphdr *)(ip6 + 1);

	oldflags =  tcp->th_flags;
	tcp->th_flags = flags;

	sum = ~tcp->th_sum & 0xffff;
#if _BYTE_ORDER == _LITTLE_ENDIAN
	sum -= oldflags << 8;
	sum += flags << 8;
#else
	sum -= oldflags;
	sum += flags;
#endif
	tcp->th_sum = ~reduce1(sum);

	return 0;
}

int
ip6pkt_tcpwin(char *buf, unsigned int l3offset, uint16_t win)
{
	return ip6pkt_tcp_uint16(buf, l3offset, offsetof(struct tcphdr, th_win), win);
}

int
ip6pkt_tcpurp(char *buf, unsigned int l3offset, uint16_t urp)
{
	return ip6pkt_tcp_uint16(buf, l3offset, offsetof(struct tcphdr, th_urp), urp);
}

int
ip6pkt_test_cksum(char *buf, unsigned int l3offset, unsigned int maxframelen)
{
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	struct udphdr *udp;
	struct tcphdr *tcp;
	unsigned int protolen;

	if (maxframelen < sizeof(struct ether_header)) {
		fprintf(stderr, "packet buffer too short. cannot access ether header\n");
		return -1;
	}
	maxframelen -= sizeof(struct ether_header);

	if (maxframelen < sizeof(struct ip6_hdr)) {
		fprintf(stderr, "packet buffer too short. cannot access IPv6 header\n");
		return -1;
	}

	ip6 = (struct ip6_hdr *)(buf + l3offset);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) {
		fprintf(stderr, "no IPv6 header\n");
		return -1;
	}

	protolen = ip6->ip6_plen;
	maxframelen -= sizeof(struct ip6_hdr);

	if (maxframelen < protolen) {
		fprintf(stderr, "packet buffer too short. cannot access protocol data\n");
		return -1;
	}

	switch (ip6->ip6_nxt) {
	case IPPROTO_ICMPV6:
		icmp6 = (struct icmp6_hdr *)(ip6 + 1);
		if (in6_cksum(&ip6->ip6_src, &ip6->ip6_dst, IPPROTO_ICMPV6,
		    (char *)icmp6, protolen) != 0) {
			fprintf(stderr, "ICMP6 checksum error\n");
			return -IPPROTO_ICMPV6;
		}
		break;

	case IPPROTO_UDP:
		udp = (struct udphdr *)(ip6 + 1);
		if (protolen < ntohs(udp->uh_ulen)) {
			fprintf(stderr, "UDP packet is greater than packet\n");
			return -IPPROTO_ICMP;
		}
		if (in6_cksum(&ip6->ip6_src, &ip6->ip6_dst, IPPROTO_UDP,
		    (char *)udp, protolen) != 0) {
			fprintf(stderr, "UDP checksum error\n");
			return -IPPROTO_ICMP;
		}
		break;

	case IPPROTO_TCP:
		tcp = (struct tcphdr *)(ip6 + 1);
		if (in6_cksum(&ip6->ip6_src, &ip6->ip6_dst, IPPROTO_TCP,
		    (char *)tcp, protolen) != 0) {
			fprintf(stderr, "TCP checksum error\n");
			return -IPPROTO_TCP;
		}
		break;

	default:
		return -99999;	/* protocol not supported */
	}

	return 0;
}
