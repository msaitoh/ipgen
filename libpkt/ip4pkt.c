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
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>

#ifndef IPPROTO_IPV4
#define IPPROTO_IPV4	4
#endif

static int ip4pkt_icmp_uint8(char *, unsigned int, int, uint8_t);
static int ip4pkt_icmp_uint16(char *, unsigned int, int, uint16_t);

int
ip4pkt_arpparse(char *buf, int *op, struct ether_addr *sha, in_addr_t *spa, in_addr_t *tpa)
{
	struct arppkt_l3 *arp;

	arp = (struct arppkt_l3 *)buf;

	/* extract arp packet */
	*op = ntohs(arp->arp.ar_op);
	memcpy(sha, arp->arp.ar_sha, ETHER_ADDR_LEN);
	*spa = arp->arp.ar_spa.s_addr;
	*tpa = arp->arp.ar_tpa.s_addr;

	return 0;
}

int
ip4pkt_arpquery(char *buf, const struct ether_addr *sha, in_addr_t spa, in_addr_t tpa)
{
	static const uint8_t eth_broadcast[ETHER_ADDR_LEN] =
	    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	struct arppkt_l2 *aquery;

	aquery = (struct arppkt_l2 *)buf;

	/* build arp query packet */
	memset(aquery, 0, sizeof(*aquery));
	memcpy(aquery->eheader.ether_dhost, eth_broadcast, ETHER_ADDR_LEN);
	memcpy(aquery->eheader.ether_shost, sha, ETHER_ADDR_LEN);
	aquery->eheader.ether_type = htons(ETHERTYPE_ARP);
	aquery->arp.ar_hrd = htons(ARPHRD_ETHER);
	aquery->arp.ar_pro = htons(ETHERTYPE_IP);
	aquery->arp.ar_hln = ETHER_ADDR_LEN;
	aquery->arp.ar_pln = sizeof(struct in_addr);
	aquery->arp.ar_op = htons(ARPOP_REQUEST);
	memcpy(aquery->arp.ar_sha, sha, ETHER_ADDR_LEN);
	aquery->arp.ar_spa.s_addr = spa;
	aquery->arp.ar_tpa.s_addr = tpa;

	return sizeof(*aquery);
}

int
ip4pkt_arpreply(char *buf, const char *querybuf, u_char *eaddr, in_addr_t addr, in_addr_t mask)
{
	struct ether_header *eheader;
	struct ether_vlan_header *evheader = NULL;
	struct arppkt_l2 *aquery, *areply;
	uint16_t etype;

	eheader = (struct ether_header *)querybuf;
	aquery = (struct arppkt_l2 *)querybuf;
	areply = (struct arppkt_l2 *)buf;

	static const uint8_t eth_broadcast[ETHER_ADDR_LEN] =
	    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	etype = ntohs(eheader->ether_type);
	if (etype == ETHERTYPE_VLAN) {
		evheader = (struct ether_vlan_header *)eheader;
		etype = ntohs(evheader->evl_proto);
	}

	/* checking destination ether addr is broadcast */
	if ((etype != ETHERTYPE_ARP) ||
	    (memcmp(eheader->ether_dhost, eth_broadcast, ETHER_ADDR_LEN) != 0) ||
	    (ntohs(aquery->arp.ar_hrd) != ARPHRD_ETHER) ||
	    (ntohs(aquery->arp.ar_pro) != ETHERTYPE_IP) ||
	    (aquery->arp.ar_hln != ETHER_ADDR_LEN) ||
	    (aquery->arp.ar_pln != sizeof(struct in_addr)) ||
	    (ntohs(aquery->arp.ar_op) != ARPOP_REQUEST) ||
	    ((aquery->arp.ar_tpa.s_addr & mask) != (addr & mask)))
		return -1;	/* not an arp request packet for me */

	/* build arp reply packet */
	memset(areply, 0, sizeof(*areply));
	memcpy(areply->eheader.ether_dhost, aquery->arp.ar_sha, ETHER_ADDR_LEN);
	memcpy(areply->eheader.ether_shost, eaddr, ETHER_ADDR_LEN);
	areply->eheader.ether_type = htons(ETHERTYPE_ARP);
	areply->arp.ar_hrd = htons(ARPHRD_ETHER);
	areply->arp.ar_pro = htons(ETHERTYPE_IP);
	areply->arp.ar_hln = ETHER_ADDR_LEN;
	areply->arp.ar_pln = sizeof(struct in_addr);
	areply->arp.ar_op = htons(ARPOP_REPLY);
	memcpy(areply->arp.ar_sha, eaddr, ETHER_ADDR_LEN);
	memcpy(&areply->arp.ar_spa, &aquery->arp.ar_tpa, sizeof(struct in_addr));
	memcpy(areply->arp.ar_tha, aquery->arp.ar_sha, ETHER_ADDR_LEN);
	memcpy(&areply->arp.ar_tpa, &aquery->arp.ar_spa, sizeof(struct in_addr));

	if (evheader != NULL) {
		/* insert VLAN tag */
		memmove(buf + sizeof(*evheader), buf + sizeof(*eheader),
		    sizeof(struct arppkt_l3));

		struct ether_vlan_header *evl = (struct ether_vlan_header *)buf;
		evl->evl_encap_proto = htons(ETHERTYPE_VLAN);
		evl->evl_tag = evheader->evl_tag;
		evl->evl_proto = htons(ETHERTYPE_ARP);

		return sizeof(*areply) + 4;
	}

	return sizeof(*areply);
}

int
ip4pkt_icmp_template(char *buf, unsigned int framelen)
{
	struct ether_header *eh;
	struct ip *ip;
	struct icmp *icmp;
	unsigned int iplen;

	iplen = framelen - sizeof(struct ether_header);

	memset(buf, 0, framelen);
	eh = (struct ether_header *)buf;
	eh->ether_type = htons(ETHERTYPE_IP);

	ip = (struct ip *)(eh + 1);
	ip->ip_v = IPVERSION;
	ip->ip_hl = sizeof(struct ip) / 4;
/*	ip->ip_tos = 0;	*/
	ip->ip_len = htons(iplen);
/*	ip->ip_id = 0;	*/
/*	ip->ip_off = 0;	*/
	ip->ip_ttl = 8;
	ip->ip_p = IPPROTO_ICMP;
/*	ip->ip_src.s_addr = 0;	*/
/*	ip->ip_dst.s_addr = 0;	*/
	ip->ip_sum = in_cksum(0, (char *)ip, sizeof(struct ip));

	icmp = (struct icmp *)(ip + 1);
	icmp->icmp_type = 0;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0xffff;

	return framelen;
}

int
ip4pkt_icmp_echoreply(char *buf, unsigned int l3offset, const char *reqbuf, unsigned int framelen)
{
	struct ip *ip, *rip;

	ip = (struct ip *)(buf + l3offset);
	rip = (struct ip *)(reqbuf + l3offset);

	memcpy(buf, reqbuf, framelen);
	ip->ip_src = rip->ip_dst;
	ip->ip_dst = rip->ip_src;

	ip4pkt_icmp_type(buf, l3offset, ICMP_ECHOREPLY);

	return framelen;
}

int
ip4pkt_icmp_type(char *buf, unsigned int l3offset, int type)
{
	struct ip *ip;
	struct icmp *icmp;
	uint32_t sum;

	ip = (struct ip *)(buf + l3offset);
	if (ip->ip_v != IPVERSION)
		return -1;

	icmp = (struct icmp *)(ip + 1);

	sum = ~icmp->icmp_cksum & 0xffff;
#if _BYTE_ORDER == _LITTLE_ENDIAN
	sum -= icmp->icmp_type;
	sum += type;
#else
	sum -= (icmp->icmp_type << 8);
	sum += type << 8;
#endif
	icmp->icmp_cksum = ~reduce1(sum);
	icmp->icmp_type = type;

	return 0;
}

int
ip4pkt_udp_template(char *buf, unsigned int framelen)
{
	struct ether_header *eh;
	struct ip *ip;
	struct udphdr *udp;
	unsigned int iplen, protolen;

	iplen = framelen - sizeof(struct ether_header);
	protolen = iplen - sizeof(struct ip);

	memset(buf, 0, framelen);
	eh = (struct ether_header *)buf;
	eh->ether_type = htons(ETHERTYPE_IP);

	ip = (struct ip *)(eh + 1);
	ip->ip_v = IPVERSION;
	ip->ip_hl = sizeof(struct ip) / 4;
/*	ip->ip_tos = 0;	*/
	ip->ip_len = htons(iplen);
/*	ip->ip_id = 0;	*/
/*	ip->ip_off = 0;	*/
	ip->ip_ttl = 8;
	ip->ip_p = IPPROTO_UDP;
/*	ip->ip_src.s_addr = 0;	*/
/*	ip->ip_dst.s_addr = 0;	*/
	ip->ip_sum = in_cksum(0, (char *)ip, sizeof(struct ip));

	udp = (struct udphdr *)(ip + 1);
/*	udp->uh_sport = 0;	*/
/*	udp->uh_dport = 0;	*/
	udp->uh_ulen = htons(protolen);
	udp->uh_sum = in4_cksum(ip->ip_src, ip->ip_dst, ip->ip_p, (char *)udp, protolen);

	return framelen;
}

int
ip4pkt_tcp_template(char *buf, unsigned int framelen)
{
	struct ether_header *eh;
	struct ip *ip;
	struct tcphdr *tcp;
	unsigned int iplen, protolen;

	iplen = framelen - sizeof(struct ether_header);
	protolen = iplen - sizeof(struct ip);

	memset(buf, 0, framelen);
	eh = (struct ether_header *)buf;
	eh->ether_type = htons(ETHERTYPE_IP);

	ip = (struct ip *)(eh + 1);
	ip->ip_v = IPVERSION;
	ip->ip_hl = sizeof(struct ip) / 4;
/*	ip->ip_tos = 0;	*/
	ip->ip_len = htons(iplen);
/*	ip->ip_id = 0;	*/
/*	ip->ip_off = 0;	*/
	ip->ip_ttl = 8;
	ip->ip_p = IPPROTO_TCP;
/*	ip->ip_src.s_addr = 0;	*/
/*	ip->ip_dst.s_addr = 0;	*/
	ip->ip_sum = in_cksum(0, (char *)ip, sizeof(struct ip));

	tcp = (struct tcphdr *)(ip + 1);
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
	tcp->th_sum = in4_cksum(ip->ip_src, ip->ip_dst, ip->ip_p, (char *)tcp, protolen);

	return framelen;
}

int
ip4pkt_length(char *buf, unsigned int l3offset, unsigned int iplen)
{
	struct ip *ip;
	uint32_t sum;
	uint16_t oldlen;

	ip = (struct ip *)(buf + l3offset);
	if (ip->ip_v != IPVERSION)
		return -1;

	oldlen = ip->ip_len;
	ip->ip_len = htons(iplen);
	sum = ~ip->ip_sum & 0xffff;
	sum -= oldlen;
	sum += ip->ip_len;
	ip->ip_sum = ~reduce1(sum);

	switch (ip->ip_p) {
	case IPPROTO_UDP:
		{
			struct udphdr *udp = (struct udphdr *)((char *)ip + ip->ip_hl * 4);

			oldlen = udp->uh_ulen;
			udp->uh_ulen = htons(iplen - ip->ip_hl * 4);
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
			struct tcphdr *tcp = (struct tcphdr *)((char *)ip + ip->ip_hl * 4);

			oldlen = ntohs(oldlen) - ip->ip_hl * 4;
			sum = ~tcp->th_sum & 0xffff;
			sum -= htons(oldlen);
			sum += htons(iplen - ip->ip_hl * 4);
			tcp->th_sum = ~reduce1(sum);
		}
		break;
	case IPPROTO_ICMP:
		break;

	default:
		return -1;
	}

	return 0;
}

int
ip4pkt_off(char *buf, unsigned int l3offset, uint16_t off)
{
	struct ip *ip;
	uint32_t sum;

	ip = (struct ip *)(buf + l3offset);
	if (ip->ip_v != IPVERSION)
		return -1;

	off = htons(off);
	sum = ~ip->ip_sum & 0xffff;
	sum -= ip->ip_off & 0xffff;
	sum += off & 0xffff;
	ip->ip_sum = ~reduce1(sum);
	ip->ip_off = off;

	return 0;
}

int
ip4pkt_id(char *buf, unsigned int l3offset, uint16_t id)
{
	struct ip *ip;
	uint32_t sum;

	ip = (struct ip *)(buf + l3offset);
	if (ip->ip_v != IPVERSION)
		return -1;

	id = htons(id);
	sum = ~ip->ip_sum & 0xffff;
	sum -= ip->ip_id & 0xffff;
	sum += id & 0xffff;
	ip->ip_sum = ~reduce1(sum);
	ip->ip_id = id;

	return 0;
}

int
ip4pkt_ttl(char *buf, unsigned int l3offset, unsigned int ttl)
{
	struct ip *ip;
	uint32_t sum;

	ip = (struct ip *)(buf + l3offset);
	if (ip->ip_v != IPVERSION)
		return -1;

	sum = ~ip->ip_sum & 0xffff;
#if _BYTE_ORDER == _LITTLE_ENDIAN
	sum -= (ip->ip_ttl);
	sum += ttl;
#else
	sum -= (ip->ip_ttl << 8);
	sum += ttl << 8;
#endif
	ip->ip_sum = ~reduce1(sum);
	ip->ip_ttl = ttl;

	return 0;
}

static int
ip4pkt_srcdst(int srcdst, char *buf, unsigned int l3offset, in_addr_t addr)
{
	struct ip *ip;
	uint32_t sum;
	in_addr_t old;

	ip = (struct ip *)(buf + l3offset);
	if (ip->ip_v != IPVERSION)
		return -1;

	if (srcdst == 0)
		old = ip->ip_src.s_addr;
	else
		old = ip->ip_dst.s_addr;

	sum = ~ip->ip_sum & 0xffff;
	sum -= (old >> 16) & 0xffff;
	sum -= old & 0xffff;
	sum += (addr >> 16) & 0xffff;
	sum += addr & 0xffff;

	ip->ip_sum = ~reduce1(sum);
	if (srcdst == 0)
		ip->ip_src.s_addr = addr;
	else
		ip->ip_dst.s_addr = addr;

	if (ip->ip_p == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *)((char *)ip + ip->ip_hl * 4);
		sum = ~udp->uh_sum & 0xffff;
		sum -= (old >> 16) & 0xffff;
		sum -= old & 0xffff;
		sum += (addr >> 16) & 0xffff;
		sum += addr & 0xffff;
		udp->uh_sum = ~reduce1(sum);
	} else if (ip->ip_p == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *)((char *)ip + ip->ip_hl * 4);
		sum = ~tcp->th_sum & 0xffff;
		sum -= (old >> 16) & 0xffff;
		sum -= old & 0xffff;
		sum += (addr >> 16) & 0xffff;
		sum += addr & 0xffff;
		tcp->th_sum = ~reduce1(sum);
	}
	return 0;
}

int
ip4pkt_src(char *buf, unsigned int l3offset, in_addr_t addr)
{
	return ip4pkt_srcdst(0, buf, l3offset, addr);
}

int
ip4pkt_dst(char *buf, unsigned int l3offset, in_addr_t addr)
{
	return ip4pkt_srcdst(1, buf, l3offset, addr);
}

static inline int
ip4pkt_srcdstport(int srcdst, char *buf, unsigned int l3offset, uint16_t port)
{
	struct ip *ip;
	uint32_t sum;
	uint16_t oldport;

	ip = (struct ip *)(buf + l3offset);
	if (ip->ip_v != IPVERSION)
		return -1;

	port = htons(port);
	if (ip->ip_p == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *)((char *)ip + ip->ip_hl * 4);

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
	} else if (ip->ip_p == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *)((char *)ip + ip->ip_hl * 4);

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
	return 0;
}

int
ip4pkt_srcport(char *buf, unsigned int l3offset, uint16_t port)
{
	return ip4pkt_srcdstport(0, buf, l3offset, port);
}

int
ip4pkt_dstport(char *buf, unsigned int l3offset, uint16_t port)
{
	return ip4pkt_srcdstport(1, buf, l3offset, port);
}

int
ip4pkt_writedata(char *buf, unsigned int l3offset, unsigned int offset, char *data, unsigned int datalen)
{
	struct ip *ip;
	uint16_t *sump;
	char *datap;
	uint32_t sum;

	ip = (struct ip *)(buf + l3offset);
	switch (ip->ip_p) {
	case IPPROTO_UDP:
		{
			struct udphdr *udp = (struct udphdr *)((char *)ip + ip->ip_hl * 4);
			sump = &udp->uh_sum;
			datap = (char *)(udp + 1) + offset;
		}
		break;
	case IPPROTO_TCP:
		{
			struct tcphdr *tcp = (struct tcphdr *)((char *)ip + ip->ip_hl * 4);
			sump = &tcp->th_sum;
			datap = (char *)tcp + tcp->th_off * 4 + offset;
		}
		break;
	case IPPROTO_ICMP:
		{
			struct icmp *icmp = (struct icmp *)((char *)ip + ip->ip_hl * 4);
			sump = &icmp->icmp_cksum;
			datap = (char *)(icmp->icmp_data) + offset;
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
ip4pkt_readdata(char *buf, unsigned int l3offset, unsigned int offset, char *data, unsigned int datalen)
{
	struct ip *ip;
	char *datap;

	ip = (struct ip *)(buf + l3offset);
	switch (ip->ip_p) {
	case IPPROTO_UDP:
		{
			struct udphdr *udp = (struct udphdr *)((char *)ip + ip->ip_hl * 4);
			datap = (char *)(udp + 1) + offset;
		}
		break;
	case IPPROTO_TCP:
		{
			struct tcphdr *tcp = (struct tcphdr *)((char *)ip + ip->ip_hl * 4);
			datap = (char *)tcp + tcp->th_off * 4 + offset;
		}
		break;
	case IPPROTO_ICMP:
		{
			struct icmp *icmp = (struct icmp *)((char *)ip + ip->ip_hl * 4);
			datap = (char *)(icmp->icmp_data) + offset;
		}
		break;
	default:
		datap = (char *)ip + ip->ip_hl * 4 + offset;
		break;
	}

	memcpy(data, datap, datalen);

	return 0;
}

char *
ip4pkt_getptr(char *buf, unsigned int l3offset, unsigned int offset)
{
	struct ip *ip;
	char *datap;

	ip = (struct ip *)(buf + l3offset);
	switch (ip->ip_p) {
	case IPPROTO_UDP:
		{
			struct udphdr *udp = (struct udphdr *)((char *)ip + ip->ip_hl * 4);
			datap = (char *)(udp + 1) + offset;
		}
		break;
	case IPPROTO_TCP:
		{
			struct tcphdr *tcp = (struct tcphdr *)((char *)ip + ip->ip_hl * 4);
			datap = (char *)tcp + tcp->th_off * 4 + offset;
		}
		break;
	case IPPROTO_ICMP:
		{
			struct icmp *icmp = (struct icmp *)((char *)ip + ip->ip_hl * 4);
			datap = (char *)(icmp->icmp_data) + offset;
		}
		break;
	default:
		datap = (char *)ip + ip->ip_hl * 4 + offset;
		break;
	}

	return datap;
}

static int
ip4pkt_icmp_uint8(char *buf, unsigned int l3offset, int icmpoffset, uint8_t data)
{
	struct ip *ip;
	struct icmp *icmp;
	uint32_t sum;
	uint8_t olddata;

	ip = (struct ip *)(buf + l3offset);
	if (ip->ip_v != IPVERSION)
		return -1;
	icmp = (struct icmp *)((char *)ip + ip->ip_hl * 4);

	olddata = *(uint8_t *)((char *)icmp + icmpoffset);
	*(uint8_t *)((char *)icmp + icmpoffset) = data;

	sum = ~icmp->icmp_cksum & 0xffff;
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
	icmp->icmp_cksum = ~reduce1(sum);

	return 0;
}

static int
ip4pkt_icmp_uint16(char *buf, unsigned int l3offset, int icmpoffset, uint16_t data)
{
	struct ip *ip;
	struct icmp *icmp;
	uint32_t sum;
	uint16_t olddata;

	ip = (struct ip *)(buf + l3offset);
	if (ip->ip_v != IPVERSION)
		return -1;
	icmp = (struct icmp *)((char *)ip + ip->ip_hl * 4);

	data = htons(data);
	olddata = *(uint16_t *)((char *)icmp + icmpoffset);
	*(uint16_t *)((char *)icmp + icmpoffset) = data;

	sum = ~icmp->icmp_cksum & 0xffff;
	sum -= olddata & 0xffff;
	sum += data & 0xffff;
	icmp->icmp_cksum = ~reduce1(sum);

	return 0;
}

int
ip4pkt_icmptype(char *buf, unsigned int l3offset, uint8_t type)
{
	return ip4pkt_icmp_uint8(buf, l3offset, offsetof(struct icmp, icmp_type), type);
}

int
ip4pkt_icmpcode(char *buf, unsigned int l3offset, uint8_t code)
{
	return ip4pkt_icmp_uint8(buf, l3offset, offsetof(struct icmp, icmp_code), code);
}

int
ip4pkt_icmpid(char *buf, unsigned int l3offset, uint16_t id)
{
	return ip4pkt_icmp_uint16(buf, l3offset, offsetof(struct icmp, icmp_id), id);
}

int
ip4pkt_icmpseq(char *buf, unsigned int l3offset, uint16_t seq)
{
	return ip4pkt_icmp_uint16(buf, l3offset, offsetof(struct icmp, icmp_seq), seq);
}

//static int
//ip4pkt_udp_uint16(char *buf, int udpoffset, uint16_t data)
//{
//	struct ether_header *eh;
//	struct ip *ip;
//	struct udphdr *udp;
//	uint32_t sum;
//	uint16_t old;
//
//	eh = (struct ether_header *)buf;
//	ip = (struct ip *)(eh + 1);
//	if (ip->ip_v != IPVERSION)
//		return -1;
//	if (ip->ip_p != IPPROTO_UDP)
//		return -1;
//	udp = (struct udphdr *)((char *)ip + ip->ip_hl * 4);
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
ip4pkt_tcp_uint16(char *buf, unsigned int l3offset, int tcpoffset, uint16_t data)
{
	struct ip *ip;
	struct tcphdr *tcp;
	uint32_t sum;
	uint16_t old;

	ip = (struct ip *)(buf + l3offset);
	if (ip->ip_v != IPVERSION)
		return -1;
	if (ip->ip_p != IPPROTO_TCP)
		return -1;
	tcp = (struct tcphdr *)((char *)ip + ip->ip_hl * 4);

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
ip4pkt_tcp_uint32(char *buf, unsigned int l3offset, int tcpoffset, uint32_t data)
{
	struct ip *ip;
	struct tcphdr *tcp;
	uint32_t sum;
	uint32_t old;

	ip = (struct ip *)(buf + l3offset);
	if (ip->ip_v != IPVERSION)
		return -1;
	if (ip->ip_p != IPPROTO_TCP)
		return -1;
	tcp = (struct tcphdr *)((char *)ip + ip->ip_hl * 4);

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
ip4pkt_tcpseq(char *buf, unsigned int l3offset, uint32_t seq)
{
	return ip4pkt_tcp_uint32(buf, l3offset, offsetof(struct tcphdr, th_seq), seq);
}

int
ip4pkt_tcpack(char *buf, unsigned int l3offset, uint32_t ack)
{
	return ip4pkt_tcp_uint32(buf, l3offset, offsetof(struct tcphdr, th_ack), ack);
}

int
ip4pkt_tcpflags(char *buf, unsigned int l3offset, int flags)
{
	struct ip *ip;
	struct tcphdr *tcp;
	uint32_t sum;
	uint8_t oldflags;

	ip = (struct ip *)(buf + l3offset);
	if (ip->ip_v != IPVERSION)
		return -1;
	if (ip->ip_p != IPPROTO_TCP)
		return -1;
	tcp = (struct tcphdr *)((char *)ip + ip->ip_hl * 4);

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
ip4pkt_tcpwin(char *buf, unsigned int l3offset, uint16_t win)
{
	return ip4pkt_tcp_uint16(buf, l3offset, offsetof(struct tcphdr, th_win), win);
}

int
ip4pkt_tcpurp(char *buf, unsigned int l3offset, uint16_t urp)
{
	return ip4pkt_tcp_uint16(buf, l3offset, offsetof(struct tcphdr, th_urp), urp);
}

int
ip4pkt_test_cksum(char *buf, unsigned int l3offset, unsigned int maxframelen)
{
	struct ip *ip;
	struct icmp *icmp;
	struct udphdr *udp;
	struct tcphdr *tcp;
	unsigned int iplen, iphdrlen, protolen;

	if (maxframelen < sizeof(struct ether_header)) {
		fprintf(stderr, "packet buffer too short. cannot access ether header\n");
		return -1;
	}
	maxframelen -= sizeof(struct ether_header);

	if (maxframelen < sizeof(struct ip)) {
		fprintf(stderr, "packet buffer too short. cannot access IP header\n");
		return -1;
	}

	ip = (struct ip *)(buf + l3offset);
	if (ip->ip_v != IPVERSION) {
		fprintf(stderr, "IP header is not IPv4\n");
		return -1;
	}

	iphdrlen = ip->ip_hl * 4;
	if (in_cksum(0, (char *)ip, ip->ip_hl * 4) != 0) {
		fprintf(stderr, "IP header checksum error\n");
		return -IPPROTO_IPV4;
	}

	iplen = ntohs(ip->ip_len);
	protolen = iplen - iphdrlen;

	if (maxframelen < iphdrlen) {
		fprintf(stderr, "packet buffer too short. cannot access protocol header\n");
		return -1;
	}
	maxframelen -= iphdrlen;

	if (maxframelen < protolen) {
		fprintf(stderr, "packet buffer too short. cannot access protocol data\n");
		return -1;
	}

	switch (ip->ip_p) {
	case IPPROTO_ICMP:
		icmp = (struct icmp *)((char *)ip + iphdrlen);
		if (in4_cksum(ip->ip_src, ip->ip_dst, IPPROTO_ICMP,
		    (char *)icmp, protolen) != 0) {
			fprintf(stderr, "ICMP checksum error\n");
			return -IPPROTO_ICMP;
		}
		break;

	case IPPROTO_UDP:
		udp = (struct udphdr *)((char *)ip + iphdrlen);
		if (protolen < ntohs(udp->uh_ulen)) {
			fprintf(stderr, "UDP packet is greater than IP packet\n");
			return -IPPROTO_ICMP;
		}
		if (in4_cksum(ip->ip_src, ip->ip_dst, IPPROTO_UDP,
		    (char *)udp, protolen) != 0) {
			fprintf(stderr, "UDP checksum error\n");
			return -IPPROTO_ICMP;
		}
		break;

	case IPPROTO_TCP:
		tcp = (struct tcphdr *)((char *)ip + iphdrlen);
		if (in4_cksum(ip->ip_src, ip->ip_dst, IPPROTO_TCP,
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
