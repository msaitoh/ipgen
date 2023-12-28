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
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libaddrlist/libaddrlist.h"
#include "flowparse.h"
#include "util.h"

/*
 * parse "12345-23456"
 *       "12345"
 */
int
parse_portrange(char *portrange, uint16_t *port_begin, uint16_t *port_end)
{
	char *p;

	p = portrange;
	*port_begin = strtol(p, &p, 10);
	if (*p == '\0') {
		*port_end = *port_begin;
		return 0;
	}

	if ((*p != ',') && (*p != '-'))
		return -1;

	p++;
	*port_end = strtol(p, &p, 10);
	return 0;
}

/*
 * parse "1.2.3.4-2.3.4.5"
 *       "1.2.3.4"
 */
int
parse_addrrange(char *addrrange, struct in_addr *addr_begin, struct in_addr *addr_end)
{
	char *p0, *p1, *tofree;
	int rc;

	tofree = strdup(addrrange);

	p0 = tofree;
	p1 = index(tofree, '-');

	if (p1 != NULL)
		*p1++ = '\0';

	if (inet_pton(AF_INET, p0, addr_begin) != 1) {
		rc = -1;
		goto done;
	}

	if (p1 == NULL) {
		memcpy(addr_end, addr_begin, sizeof(struct in_addr));
	} else {
		if (inet_pton(AF_INET, p1, addr_end) != 1) {
			rc = -1;
			goto done;
		}
	}
	rc = 0;

 done:
	free(tofree);
	return rc;
}

/*
 * parse  "fd00:1-fd00:100"
 *       "fd00:1:2:3"
 */
int
parse_addr6range(char *addrrange, struct in6_addr *addr_begin, struct in6_addr *addr_end)
{
	char *p0, *p1, *tofree;
	int rc;

	tofree = strdup(addrrange);

	p0 = tofree;
	p1 = index(tofree, '-');

	if (p1 != NULL)
		*p1++ = '\0';

	if (inet_pton(AF_INET6, p0, addr_begin) != 1) {
		rc = -1;
		goto done;
	}

	if (p1 == NULL) {
		memcpy(addr_end, addr_begin, sizeof(struct in6_addr));
	} else {
		if (inet_pton(AF_INET6, p1, addr_end) != 1) {
			rc = -1;
			goto done;
		}
	}
	rc = 0;

 done:
	free(tofree);
	return rc;
}

int
parse_addr_port(char *str, struct in_addr *addrstart, struct in_addr *addrend, uint16_t *portstart, uint16_t *portend)
{
	char *p0, *p;

	p0 = str;
	p = index(str, ':');
	if (p == NULL)
		return -1;
	*p++ = '\0';

	if (parse_addrrange(p0, addrstart, addrend) != 0)
		return -1;
	if (parse_portrange(p, portstart, portend) != 0)
		return -1;

	return 0;
}

static int
parse_addr6_port(char *str, struct in6_addr *addr6start, struct in6_addr *addr6end, uint16_t *portstart, uint16_t *portend)
{
	char *p0, *p;

	if (str[0] != '[')
		return -1;
	str++;

	p0 = str;
	p = index(str, ']');
	if (p == NULL)
		return -1;
	*p++ = '\0';
	if (*p != ':')
		return -1;
	*p++ = '\0';

	if (parse_addr6range(p0, addr6start, addr6end) != 0)
		return -1;
	if (parse_portrange(p, portstart, portend) != 0)
		return -1;

	return 0;
}

/*
 * parse flow strings:
 *  <address>[-<address>]:<port>[-<port>],<address>[-<address>]:<port>[-<port>]
 *
 * e.g.)
 *   10.0.0.1:9,10.0.0.2:100				(1 session)
 *   10.0.0.1:1024-65535,10.0.0.2:9			(64512 sessions)
 *   10.0.0.0-10.0.0.255:1024-65535,192.168.0.1:9	(5483519 sessions)
 */
int
parse_flowstr(struct addresslist *adrlist, int proto, const char *flowstr, int reverse)
{
	char *srcp, *dstp;
	char *str;
	struct in_addr sadr_start, sadr_end;
	struct in_addr dadr_start, dadr_end;
	struct in6_addr sadr6_start, sadr6_end;
	struct in6_addr dadr6_start, dadr6_end;
	uint16_t sport_start, sport_end;
	uint16_t dport_start, dport_end;
	int rc;

	str = strdup(flowstr);
	if (str == NULL)
		return -1;
	dstp = index(str, ',');
	if (dstp == NULL) {
		dstp = index(str, ' ');
		if (dstp == NULL) {
			dstp = index(str, '\t');
			if (dstp == NULL) {
				rc = -1;
				goto done;
			}
		}
	}
	*dstp++ = '\0';
	while ((*dstp == ' ') || (*dstp == '\t'))
		dstp++;
	srcp = str;


	if (srcp[0] == '[') {
		if (parse_addr6_port(srcp, &sadr6_start, &sadr6_end, &sport_start, &sport_end) != 0) {
			rc = -1;
			goto done;
		}
		if (parse_addr6_port(dstp, &dadr6_start, &dadr6_end, &dport_start, &dport_end) != 0) {
			rc = -1;
			goto done;
		}

		if (reverse) {
			addresslist_append6(adrlist, proto,
			    &dadr6_start, &dadr6_end, &sadr6_start, &sadr6_end,
			    dport_start, dport_end, sport_start, sport_end);
		} else {
			addresslist_append6(adrlist, proto,
			    &sadr6_start, &sadr6_end, &dadr6_start, &dadr6_end,
			    sport_start, sport_end, dport_start, dport_end);
		}
	} else {
		if (parse_addr_port(srcp, &sadr_start, &sadr_end, &sport_start, &sport_end) != 0) {
			rc = -1;
			goto done;
		}
		if (parse_addr_port(dstp, &dadr_start, &dadr_end, &dport_start, &dport_end) != 0) {
			rc = -1;
			goto done;
		}

		if (reverse) {
			addresslist_append(adrlist, proto,
			    dadr_start, dadr_end, sadr_start, sadr_end,
			    dport_start, dport_end, sport_start, sport_end);
		} else {
			addresslist_append(adrlist, proto,
			    sadr_start, sadr_end, dadr_start, dadr_end,
			    sport_start, sport_end, dport_start, dport_end);
		}
	}

	rc = 0;

 done:
	free(str);
	return rc;
}
