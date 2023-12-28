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
#include <sys/param.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef __linux__
#include <netinet/ether.h>
#include <openssl/md5.h>
#define MD5Init		MD5_Init
#define MD5Update	MD5_Update
#define MD5Final	MD5_Final
#define octet		ether_addr_octet
#else
#include <md5.h>
#endif

#include "libaddrlist.h"

static uint64_t
gcd(uint64_t a, uint64_t b)
{
	uint64_t t;
	while ((a % b) != 0) {
		t = b;
		b = a % b;
		a = t;
	}
	return b;
}

static unsigned int
lcm(uint64_t a, uint64_t b)
{
	return a * b / gcd(a, b);
}

struct addresslist *
addresslist_new(void)
{
	struct addresslist *adrlist;

	adrlist = malloc(sizeof(struct addresslist));
	if (adrlist != NULL)
		memset(adrlist, 0, sizeof(*adrlist));

	return adrlist;
}

void
addresslist_delete(struct addresslist *adrlist)
{
	if (adrlist->tuple != NULL)
		free(adrlist->tuple);
	free(adrlist);
}

static int
exists_in_addresses(int af, void *addr, struct address *addrlist, unsigned int addrlistnum)
{
	unsigned int i;

	for (i = 0; i < addrlistnum; i++) {
		if (addrlist[i].af == af) {
			switch (af) {
			case AF_INET:
				if (((struct in_addr *)addr)->s_addr == addrlist[i].a.addr4.s_addr)
					return 1;
				break;
			case AF_INET6:
				if (memcmp(addr, &addrlist[i].a, sizeof(struct in6_addr)) == 0)
					return 1;
				break;
			}
		}
	}
	return 0;
}

int
addresslist_exclude_saddr(struct addresslist *adrlist, struct in_addr addr)
{
	if (adrlist->exclude_saddr == NULL)
		adrlist->exclude_saddr = malloc(sizeof(struct address));
	else
		adrlist->exclude_saddr = realloc(adrlist->exclude_saddr, sizeof(struct address) * (adrlist->exclude_saddr_num + 1));

	if (adrlist->exclude_saddr == NULL) {
		fprintf(stderr, "Cannot allocate memory. number of exclude source address is %u\n", adrlist->exclude_saddr_num);
		return -1;
	}

	memset(&adrlist->exclude_saddr[adrlist->exclude_saddr_num], 0,
	    sizeof(adrlist->exclude_saddr[adrlist->exclude_saddr_num]));
	adrlist->exclude_saddr[adrlist->exclude_saddr_num].af = AF_INET;
	adrlist->exclude_saddr[adrlist->exclude_saddr_num].a.addr4.s_addr = addr.s_addr;

	adrlist->exclude_saddr_num++;

	return 0;
}

int
addresslist_exclude_daddr(struct addresslist *adrlist, struct in_addr addr)
{
	if (adrlist->exclude_daddr == NULL)
		adrlist->exclude_daddr = malloc(sizeof(struct address));
	else
		adrlist->exclude_daddr = realloc(adrlist->exclude_daddr, sizeof(struct address) * (adrlist->exclude_daddr_num + 1));

	if (adrlist->exclude_daddr == NULL) {
		fprintf(stderr, "Cannot allocate memory. number of exclude destination address is %u\n", adrlist->exclude_daddr_num);
		return -1;
	}

	memset(&adrlist->exclude_daddr[adrlist->exclude_daddr_num], 0,
	    sizeof(adrlist->exclude_daddr[adrlist->exclude_daddr_num]));
	adrlist->exclude_daddr[adrlist->exclude_daddr_num].af = AF_INET;
	adrlist->exclude_daddr[adrlist->exclude_daddr_num].a.addr4.s_addr = addr.s_addr;
	adrlist->exclude_daddr_num++;
	return 0;
}

int
addresslist_exclude_saddr6(struct addresslist *adrlist, struct in6_addr *addr6)
{
	if (adrlist->exclude_saddr == NULL)
		adrlist->exclude_saddr = malloc(sizeof(struct address));
	else
		adrlist->exclude_saddr = realloc(adrlist->exclude_saddr, sizeof(struct address) * (adrlist->exclude_saddr_num + 1));

	if (adrlist->exclude_saddr == NULL) {
		fprintf(stderr, "Cannot allocate memory. number of exclude source address is %u\n", adrlist->exclude_saddr_num);
		return -1;
	}

	memset(&adrlist->exclude_saddr[adrlist->exclude_saddr_num], 0,
	    sizeof(adrlist->exclude_saddr[adrlist->exclude_saddr_num]));
	adrlist->exclude_saddr[adrlist->exclude_saddr_num].af = AF_INET6;
	adrlist->exclude_saddr[adrlist->exclude_saddr_num].a.addr6 = *addr6;

	adrlist->exclude_saddr_num++;

	return 0;
}

int
addresslist_exclude_daddr6(struct addresslist *adrlist, struct in6_addr *addr6)
{
	if (adrlist->exclude_daddr == NULL)
		adrlist->exclude_daddr = malloc(sizeof(struct address));
	else
		adrlist->exclude_daddr = realloc(adrlist->exclude_daddr, sizeof(struct address) * (adrlist->exclude_daddr_num + 1));

	if (adrlist->exclude_daddr == NULL) {
		fprintf(stderr, "Cannot allocate memory. number of exclude destination address is %u\n", adrlist->exclude_daddr_num);
		return -1;
	}

	memset(&adrlist->exclude_daddr[adrlist->exclude_daddr_num], 0,
	    sizeof(adrlist->exclude_daddr[adrlist->exclude_daddr_num]));
	adrlist->exclude_daddr[adrlist->exclude_daddr_num].af = AF_INET6;
	adrlist->exclude_daddr[adrlist->exclude_daddr_num].a.addr6 = *addr6;
	adrlist->exclude_daddr_num++;
	return 0;
}


static char *
ip6_sprintf(struct in6_addr *addr)
{
	static char buf[8][INET6_ADDRSTRLEN];
	static int i;
	char *p = buf[i++ & 7];

	inet_ntop(AF_INET6, addr, p, sizeof(buf[0]));
	return p;
}

static char *
ip4_sprintf(struct in_addr *addr)
{
	static char buf[8][INET_ADDRSTRLEN];
	static int i;
	char *p = buf[i++ & 7];

	inet_ntop(AF_INET, addr, p, sizeof(buf[0]));
	return p;
}

static void
l2random(const void *data, unsigned int len, struct ether_addr *eaddr)
{
	MD5_CTX ctx;
	unsigned char digest[MD5_DIGEST_LENGTH];

	MD5Init(&ctx);
	MD5Update(&ctx, data, len);
	MD5Final(digest, &ctx);

	memcpy(eaddr->octet, digest, sizeof(eaddr->octet));
	eaddr->octet[0] &= 0xfc;
}

int
addresslist_append(struct addresslist *adrlist, uint8_t proto,
    struct in_addr saddr_begin, struct in_addr saddr_end,
    struct in_addr daddr_begin, struct in_addr daddr_end,
    uint16_t sport_begin, uint16_t sport_end,
    uint16_t dport_begin, uint16_t dport_end)
{
	struct address_tuple *newtuple;
	struct in_addr saddr, daddr;
	uint16_t sport, dport;
	uint64_t saddr_num, daddr_num, sport_num, dport_num;
	uint64_t addr_num, port_num;
	uint64_t tuple_num, n;

	saddr_num = ntohl(saddr_end.s_addr) - ntohl(saddr_begin.s_addr) + 1;
	daddr_num = ntohl(daddr_end.s_addr) - ntohl(daddr_begin.s_addr) + 1;
	sport_num = sport_end - sport_begin+ 1;
	dport_num = dport_end - dport_begin+ 1;

	addr_num = lcm(saddr_num, daddr_num);
	port_num = lcm(sport_num, dport_num);
	tuple_num = lcm(addr_num, port_num);

	if (adrlist->tuple_limit < (adrlist->ntuple + tuple_num)) {
		fprintf(stderr, "too large flowlist: %lu: %s-%s:%d-%d - %s-%s:%d-%d\n",
		    adrlist->ntuple + tuple_num,
		    ip4_sprintf(&saddr_begin), ip4_sprintf(&saddr_end),
		    sport_begin, sport_end,
		    ip4_sprintf(&daddr_begin), ip4_sprintf(&daddr_end),
		    dport_begin, dport_end);
		return -1;
	}


	if (adrlist->tuple == NULL) {
		newtuple = malloc(sizeof(struct address_tuple) * tuple_num);
		memset(newtuple, 0, sizeof(struct address_tuple) * tuple_num);
	} else {
		newtuple = realloc(adrlist->tuple, sizeof(struct address_tuple) * (adrlist->ntuple + tuple_num));
		memset(newtuple + adrlist->ntuple, 0, sizeof(struct address_tuple) * tuple_num);
	}

	if (newtuple == NULL) {
		fprintf(stderr, "Cannot allocate memory. number of session is %lu\n", adrlist->ntuple + tuple_num);
		return -1;
	}

	adrlist->tuple = newtuple;

	saddr.s_addr = saddr_begin.s_addr;
	daddr.s_addr = daddr_begin.s_addr;
	sport = sport_begin;
	dport = dport_begin;

	for (n = 0; n < tuple_num; ) {
		if (exists_in_addresses(AF_INET, &saddr, adrlist->exclude_saddr, adrlist->exclude_saddr_num) ||
		    exists_in_addresses(AF_INET, &daddr, adrlist->exclude_daddr, adrlist->exclude_daddr_num)) {
			tuple_num--;
		} else {
			newtuple[adrlist->ntuple + n].saddr.af = AF_INET;
			newtuple[adrlist->ntuple + n].saddr.a.addr4.s_addr = saddr.s_addr;
			newtuple[adrlist->ntuple + n].daddr.af = AF_INET;
			newtuple[adrlist->ntuple + n].daddr.a.addr4.s_addr = daddr.s_addr;
			newtuple[adrlist->ntuple + n].sport = sport;
			newtuple[adrlist->ntuple + n].dport = dport;
			newtuple[adrlist->ntuple + n].proto = proto;

			l2random(&newtuple[adrlist->ntuple + n].saddr.a.addr4,
			    sizeof(newtuple[adrlist->ntuple + n].saddr.a.addr4),
			    &newtuple[adrlist->ntuple + n].seaddr);
			l2random(&newtuple[adrlist->ntuple + n].daddr.a.addr4,
			    sizeof(newtuple[adrlist->ntuple + n].daddr.a.addr4),
			    &newtuple[adrlist->ntuple + n].deaddr);

			n++;
		}

		/* increment addresses and ports */
		if (saddr.s_addr == saddr_end.s_addr)
			saddr.s_addr = saddr_begin.s_addr;
		else
			saddr.s_addr = htonl(ntohl(saddr.s_addr) + 1);

		if (daddr.s_addr == daddr_end.s_addr)
			daddr.s_addr = daddr_begin.s_addr;
		else
			daddr.s_addr = htonl(ntohl(daddr.s_addr) + 1);

		if (sport == sport_end)
			sport = sport_begin;
		else
			sport++;

		if (dport == dport_end)
			dport = dport_begin;
		else
			dport++;
	}

	adrlist->ntuple += tuple_num;
	adrlist->sorted = 0;
	return 0;
}

static int
ipv6_equal(struct in6_addr *a, struct in6_addr *b)
{
	if (memcmp(a, b, sizeof(struct in6_addr)) == 0)
		return 1;
	return 0;
}

static void
ipv6_increment(struct in6_addr *a)
{
	if (++a->s6_addr[15] == 0)
		if (++a->s6_addr[14] == 0)
			if (++a->s6_addr[13] == 0)
				if (++a->s6_addr[12] == 0)
					if (++a->s6_addr[11] == 0)
						if (++a->s6_addr[10] == 0)
							if (++a->s6_addr[9] == 0)
								++a->s6_addr[8];
}

static uint64_t
ipv6_sub(struct in6_addr *a, struct in6_addr *b)
{
	uint64_t ax, bx;

	if (memcmp(&a->s6_addr[0], &b->s6_addr[0], 8) != 0)
		return UINT64_MAX;

	ax = a->s6_addr[8];
	ax = (ax << 8) + a->s6_addr[9];
	ax = (ax << 8) + a->s6_addr[10];
	ax = (ax << 8) + a->s6_addr[11];
	ax = (ax << 8) + a->s6_addr[12];
	ax = (ax << 8) + a->s6_addr[13];
	ax = (ax << 8) + a->s6_addr[14];
	ax = (ax << 8) + a->s6_addr[15];

	bx = b->s6_addr[8];
	bx = (bx << 8) + b->s6_addr[9];
	bx = (bx << 8) + b->s6_addr[10];
	bx = (bx << 8) + b->s6_addr[11];
	bx = (bx << 8) + b->s6_addr[12];
	bx = (bx << 8) + b->s6_addr[13];
	bx = (bx << 8) + b->s6_addr[14];
	bx = (bx << 8) + b->s6_addr[15];

	return ax - bx;
}

int
addresslist_append6(struct addresslist *adrlist, uint8_t proto,
    struct in6_addr *saddr_begin, struct in6_addr *saddr_end,
    struct in6_addr *daddr_begin, struct in6_addr *daddr_end,
    uint16_t sport_begin, uint16_t sport_end,
    uint16_t dport_begin, uint16_t dport_end)
{
	struct address_tuple *newtuple;
	struct in6_addr saddr, daddr;
	uint16_t sport, dport;
	uint64_t saddr_num, daddr_num, sport_num, dport_num;
	uint64_t addr_num, port_num;
	uint64_t tuple_num, n;

	saddr_num = ipv6_sub(saddr_end, saddr_begin) + 1;
	daddr_num = ipv6_sub(daddr_end, daddr_begin) + 1;
	sport_num = sport_end - sport_begin+ 1;
	dport_num = dport_end - dport_begin+ 1;

	if (saddr_num == 0) {
		 fprintf(stderr, "address range too large: %s - %s\n", ip6_sprintf(saddr_begin), ip6_sprintf(saddr_end));
		 return -1;
	}
	if (daddr_num == 0) {
		 fprintf(stderr, "address range too large: %s - %s\n", ip6_sprintf(daddr_begin), ip6_sprintf(daddr_end));
		 return -1;
	}

	addr_num = lcm(saddr_num, daddr_num);
	port_num = lcm(sport_num, dport_num);
	tuple_num = lcm(addr_num, port_num);

	if (adrlist->tuple_limit < (adrlist->ntuple + tuple_num)) {
		fprintf(stderr, "too large flowlist: %lu: [%s-%s]:%d-%d - [%s-%s]:%d-%d\n",
		    adrlist->ntuple + tuple_num,
		    ip6_sprintf(saddr_begin), ip6_sprintf(saddr_end),
		    sport_begin, sport_end,
		    ip6_sprintf(daddr_begin), ip6_sprintf(daddr_end),
		    dport_begin, dport_end);
		return -1;
	}

	if (adrlist->tuple == NULL) {
		newtuple = malloc(sizeof(struct address_tuple) * tuple_num);
		memset(newtuple, 0, sizeof(struct address_tuple) * tuple_num);
	} else {
		newtuple = realloc(adrlist->tuple, sizeof(struct address_tuple) * (adrlist->ntuple + tuple_num));
		memset(newtuple + adrlist->ntuple, 0, sizeof(struct address_tuple) * tuple_num);
	}

	if (newtuple == NULL) {
		fprintf(stderr, "Cannot allocate memory. number of session is %lu\n", adrlist->ntuple + tuple_num);
		return -1;
	}

	adrlist->tuple = newtuple;

	saddr = *saddr_begin;
	daddr = *daddr_begin;
	sport = sport_begin;
	dport = dport_begin;

	for (n = 0; n < tuple_num; ) {
		if (exists_in_addresses(AF_INET, &saddr, adrlist->exclude_saddr, adrlist->exclude_saddr_num) ||
		    exists_in_addresses(AF_INET, &daddr, adrlist->exclude_daddr, adrlist->exclude_daddr_num)) {
			tuple_num--;
		} else {
			newtuple[adrlist->ntuple + n].saddr.af = AF_INET6;
			newtuple[adrlist->ntuple + n].saddr.a.addr6 = saddr;
			newtuple[adrlist->ntuple + n].daddr.af = AF_INET6;
			newtuple[adrlist->ntuple + n].daddr.a.addr6 = daddr;
			newtuple[adrlist->ntuple + n].sport = sport;
			newtuple[adrlist->ntuple + n].dport = dport;
			newtuple[adrlist->ntuple + n].proto = proto;

			l2random(&newtuple[adrlist->ntuple + n].saddr.a.addr6,
			    sizeof(newtuple[adrlist->ntuple + n].saddr.a.addr6),
			    &newtuple[adrlist->ntuple + n].seaddr);
			l2random(&newtuple[adrlist->ntuple + n].daddr.a.addr6,
			    sizeof(newtuple[adrlist->ntuple + n].daddr.a.addr6),
			    &newtuple[adrlist->ntuple + n].deaddr);

			n++;
		}

		/* increment addresses and ports */
		if (ipv6_equal(&saddr, saddr_end))
			saddr = *saddr_begin;
		else
			ipv6_increment(&saddr);

		if (ipv6_equal(&daddr, daddr_end))
			daddr = *daddr_begin;
		else
			ipv6_increment(&daddr);

		if (sport == sport_end)
			sport = sport_begin;
		else
			sport++;

		if (dport == dport_end)
			dport = dport_begin;
		else
			dport++;
	}

	adrlist->ntuple += tuple_num;
	adrlist->sorted = 0;
	return 0;
}


static int
address_tuple_cmp(const void *a, const void *b)
{
	return memcmp(a, b, sizeof(struct address_tuple));
}

int
addresslist_rebuild(struct addresslist *adrlist)
{
	qsort(adrlist->tuple, adrlist->ntuple, sizeof(struct address_tuple),
	    address_tuple_cmp);
	adrlist->sorted = 1;
	return 0;
}

int
addresslist_tuple2id(struct addresslist *adrlist, struct address_tuple *tuple)
{
	struct address_tuple *found;

	if (adrlist->sorted == 0) {
		fprintf(stderr, "addresslist is not sorted. need to addresslist_rebuild\n");
		return -1;
	}

	found = bsearch(&tuple, adrlist->tuple, adrlist->ntuple, sizeof(struct address_tuple),
	    address_tuple_cmp);

	if (found != NULL)
		return (found - adrlist->tuple);

	return -1;
}

void
addresslist_setlimit(struct addresslist *adrlist, unsigned int limit)
{
	adrlist->tuple_limit = limit;
}

unsigned int
addresslist_get_tuplenum(struct addresslist *adrlist)
{
	return adrlist->ntuple;
}

unsigned int
addresslist_get_current_tupleid(struct addresslist *adrlist)
{
	return adrlist->curtuple;
}

void
addresslist_set_current_tupleid(struct addresslist *adrlist, unsigned int tupleid)
{
	if (tupleid >= adrlist->ntuple)
		tupleid = adrlist->ntuple - 1;

	adrlist->curtuple = tupleid;
}

const struct address_tuple *
addresslist_get_current_tuple(struct addresslist *adrlist)
{
	return &adrlist->tuple[adrlist->curtuple];
}

const struct address_tuple *
addresslist_get_tuple_next(struct addresslist *adrlist)
{
	const struct address_tuple *tuple;

	tuple = &adrlist->tuple[adrlist->curtuple];

	if (++adrlist->curtuple >= adrlist->ntuple)
		adrlist->curtuple = 0;

	return tuple;
}

int
addresslist_include_af(struct addresslist *adrlist, int af)
{
	struct address_tuple *tuple;
	unsigned int n;

	tuple = adrlist->tuple;
	if (tuple != NULL) {
		for (n = 0; n < adrlist->ntuple; n++) {
			if (tuple[n].saddr.af == af)
				return 1;
		}
	}
	return 0;
}

void
addresslist_dump(struct addresslist *adrlist)
{
	struct address_tuple *tuple;
	unsigned int n;
	char buf1[128], buf2[128];
	char ebuf1[sizeof("00:00:00:00:00:00")], ebuf2[sizeof("00:00:00:00:00:00")];
	const char *bracket_l, *bracket_r;

	printf("<addresslist p=%p sorted=%d ntuple=%u curtuple=%u>\n",
	    adrlist, adrlist->sorted,
	    adrlist->ntuple, adrlist->curtuple);

	tuple = adrlist->tuple;
	if (tuple != NULL) {
		printf("  <tuple>\n");
		for (n = 0; n < adrlist->ntuple; n++) {
			switch (tuple[n].saddr.af) {
			case AF_INET:
				inet_ntop(AF_INET, &tuple[n].saddr.a.addr4, buf1, sizeof(buf1));
				break;
			case AF_INET6:
				inet_ntop(AF_INET6, &tuple[n].saddr.a.addr6, buf1, sizeof(buf1));
				break;
			default:
				sprintf(buf1, "??? (family=%d)", tuple[n].saddr.af);
				break;
			}

			switch (tuple[n].daddr.af) {
			case AF_INET:
				inet_ntop(AF_INET, &tuple[n].daddr.a.addr4, buf2, sizeof(buf2));
				bracket_l = bracket_r = "";
				break;
			case AF_INET6:
				inet_ntop(AF_INET6, &tuple[n].daddr.a.addr6, buf2, sizeof(buf2));
				bracket_l = "[";
				bracket_r = "]";
				break;
			default:
				sprintf(buf1, "??? (family=%d)", tuple[n].daddr.af);
				break;
			}

			ether_ntoa_r(&tuple[n].seaddr, ebuf1);
			ether_ntoa_r(&tuple[n].deaddr, ebuf2);


			printf("    %d: %d %s%s%s:%d - %s%s%s:%d    (%s - %s)",
			    n, tuple[n].proto,
			    bracket_l, buf1, bracket_r,
			    tuple[n].sport,
			    bracket_l, buf2, bracket_r,
			    tuple[n].dport,
			    ebuf1, ebuf2);

			if (adrlist->sorted) {
				printf("   => id=%d",
				    addresslist_tuple2id(adrlist, &tuple[n]));
			}
			printf("\n");
		}
		printf("  </tuple>\n");
	}

	printf("</addresslist>\n");
}
