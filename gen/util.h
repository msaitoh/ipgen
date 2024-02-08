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
#ifndef _UTIL_H_
#define _UTIL_H_

#include <net/if.h>
#ifndef __linux__
#include <net/if_dl.h>
#include <net/if_types.h>
#endif
#include <ifaddrs.h>
#include <net/ethernet.h>

void chop(char *);
char *getword(char *str, char sep, char **save, char *buf, size_t bufsize);
char *timestamp(time_t);
int interface_is_active(const char *);
struct in_addr *getifipaddr(const char *, struct in_addr *, struct in_addr *);
struct in6_addr *getifip6addr(const char *, struct in6_addr *, struct in6_addr *);
uint8_t *getiflinkaddr(const char *, struct ether_addr *);
int listentcp(in_addr_t, uint16_t);
void interface_up(const char *);
uint64_t interface_get_baudrate(const char *);
void interface_promisc(const char *, int, int *);


char *ip4_sprintf(struct in_addr *);
char *ip6_sprintf(struct in6_addr *);
void prefix2in6addr(int, struct in6_addr *);
unsigned int in6addr2prefix(struct in6_addr *);
int ipv4_iszero(struct in_addr *);
int ipv6_iszero(struct in6_addr *);
int ipv6_not(struct in6_addr *, struct in6_addr *);
int ipv6_and(struct in6_addr *, struct in6_addr *, struct in6_addr *);
int ipv6_or(struct in6_addr *, struct in6_addr *, struct in6_addr *);

#endif /* _UTIL_H_ */
