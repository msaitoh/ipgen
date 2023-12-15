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

int
ethpkt_template(char *buf, unsigned int framelen)
{
	struct ether_header *eh;

	memset(buf, 0, framelen);
	eh = (struct ether_header *)buf;
	eh->ether_type = htons(ETHERTYPE_IP);

	return framelen;
}

int
ethpkt_type(char *buf, u_short type)
{
	struct ether_header *eh;

	eh = (struct ether_header *)buf;
	eh->ether_type = htons(type);
	return 0;
}

int
ethpkt_src(char *buf, const u_char *eaddr)
{
	struct ether_header *eh;

	eh = (struct ether_header *)buf;
	memcpy(eh->ether_shost, eaddr, ETHER_ADDR_LEN);
	return 0;
}

int
ethpkt_dst(char *buf, const u_char *eaddr)
{
	struct ether_header *eh;

	eh = (struct ether_header *)buf;
	memcpy(eh->ether_dhost, eaddr, ETHER_ADDR_LEN);
	return 0;
}
