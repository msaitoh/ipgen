/*
 * Copyright (c) 2022 Internet Initiative Japan, Inc.
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
#include <string.h>

#include "libpkt.h"

int
pppoepkt_template(char *buf, uint16_t type)
{
	struct pppoe_l2 *pppoe;

	pppoe = (struct pppoe_l2 *)buf;
	memset(pppoe, 0, sizeof(*pppoe));

	pppoe->eheader.ether_type = htons(type);
	pppoe->pppoe.vertype = PPPOE_VERTYPE;

	return sizeof(*pppoe);
}

int
pppoepkt_code(char *buf, uint8_t code)
{
	struct pppoe_l2 *pppoe;

	pppoe = (struct pppoe_l2 *)buf;
	pppoe->pppoe.code = code;

	return sizeof(*pppoe);
}

int
pppoepkt_session(char *buf, uint16_t session)
{
	struct pppoe_l2 *pppoe;

	pppoe = (struct pppoe_l2 *)buf;
	pppoe->pppoe.session = session;

	return sizeof(*pppoe);
}

int
pppoepkt_type(char *buf, uint16_t type)
{
	struct pppoe_l2 *pppoe;
	uint16_t *tp;

	pppoe = (struct pppoe_l2 *)buf;
	tp = (uint16_t *)(pppoe + 1);
	*tp = htons(type);

	return sizeof(*pppoe) + 2;
}

int
pppoepkt_length(char *buf, uint16_t len)
{
	struct pppoe_l2 *pppoe;

	pppoe = (struct pppoe_l2 *)buf;
	pppoe->pppoe.plen = htons(len);

	return sizeof(*pppoe) + len;
}

int
pppoepkt_tag_extract(char *buf, uint16_t tag, void *data, uint16_t *datalen)
{
	struct pppoe_l2 *pppoe;
	struct pppoetag *pppoetag;
	uint16_t plen, rc;
	char *eop;

	pppoe = (struct pppoe_l2 *)buf;
	plen = ntohs(pppoe->pppoe.plen);
	eop = (char *)(pppoe + 1) + plen;

	pppoetag = (struct pppoetag *)(pppoe + 1);
	while ((char *)pppoetag < eop) {
		if (ntohs(pppoetag->tag) == tag) {
			uint16_t taglen = ntohs(pppoetag->len);
			if (data == NULL || datalen == NULL) {
				if (datalen != NULL)
					*datalen = taglen;
				return 0;
			}
			void *tagdata = (char *)pppoetag + sizeof(struct pppoetag);
			if (taglen > *datalen)
				rc = *datalen;
			else
				rc = taglen;
			memcpy(data, tagdata, rc);
			*datalen = taglen;
			return rc;
		}
		pppoetag = (struct pppoetag *)((char *)pppoetag + sizeof(struct pppoetag) + ntohs(pppoetag->len));
	}

	return -1;
}

int
pppoepkt_tag_add(char *buf, uint16_t tag, const void *data, uint16_t datalen)
{
	struct pppoe_l2 *pppoe;
	struct pppoetag *pppoetag;
	uint16_t plen;

	pppoe = (struct pppoe_l2 *)buf;
	plen = ntohs(pppoe->pppoe.plen);

	pppoetag = (struct pppoetag *)((char *)(pppoe + 1) + plen);
	pppoetag->tag = htons(tag);
	pppoetag->len = htons(datalen);
	memcpy(pppoetag + 1, data, datalen);
	pppoe->pppoe.plen = htons(plen + sizeof(struct pppoetag) + datalen);

	return sizeof(struct pppoe_l2) + ntohs(pppoe->pppoe.plen);
}

int
pppoepkt_ppp_set(char *buf, uint16_t proto, uint8_t type, uint8_t id)
{
	struct pppoe_l2 *pppoe;
	struct pppoeppp *ppp;

	pppoe = (struct pppoe_l2 *)buf;
	ppp = (struct pppoeppp *)(pppoe + 1);

	ppp->protocol = htons(proto);
	ppp->ppp.type = type;
	ppp->ppp.id = id;
	ppp->ppp.len = htons(4);	/* including .type, .id, .len */
	return pppoepkt_length(buf, sizeof(struct pppoeppp));
}

int
pppoepkt_ppp_extract_data(char *buf, int type, void *data, int datalen)
{
	struct pppoe_l2 *pppoe;
	struct pppoeppp *ppp;
	int plen;
	uint8_t *p;

	pppoe = (struct pppoe_l2 *)buf;
	ppp = (struct pppoeppp *)(pppoe + 1);
	plen = ntohs(ppp->ppp.len) - 4;

	p = ppp->ppp.data;
	while (plen > 0) {
		if (p[0] == type) {
			int len = p[1] - 2;
			if (len > datalen)
				datalen = len;
			memcpy(data, &p[2], datalen);
			return len;
		}
		p += p[1];
		plen -= p[1];
	}

	return -1;
}

int
pppoepkt_ppp_add_data(char *buf, void *data, uint16_t datalen)
{
	struct pppoe_l2 *pppoe;
	struct pppoeppp *ppp;
	int olen;

	pppoe = (struct pppoe_l2 *)buf;
	ppp = (struct pppoeppp *)(pppoe + 1);
	olen = ntohs(ppp->ppp.len) - 4;

	memcpy(ppp->ppp.data + olen, data, datalen);

	ppp->ppp.len = htons(4 + olen + datalen);
	return pppoepkt_length(buf, sizeof(struct pppoeppp) + olen + datalen);
}
