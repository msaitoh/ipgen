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
#ifdef __linux__
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>

#include "genscript.h"

static int
genscript_add_item(struct genscript *genscript, unsigned int cmd, unsigned int period, unsigned int pktsize, unsigned int pps)
{
	if (genscript->nalloc <= genscript->nitems) {
		struct genscript_item *p;
		unsigned int nn;

		nn = genscript->nalloc + 1024;

		if (genscript->items == NULL)
			p = malloc(nn * sizeof(struct genscript_item));
		else
			p = realloc(genscript->items, nn * sizeof(struct genscript_item));

		if (p == NULL)
			return -1;

		genscript->items = p;
		genscript->nalloc = nn;
	}

	genscript->items[genscript->nitems].cmd = cmd;
	genscript->items[genscript->nitems].period = period;
	genscript->items[genscript->nitems].pktsize = pktsize;
	genscript->items[genscript->nitems].pps = pps;
	genscript->nitems++;

	return 0;
}

struct genscript_item *
genscript_get_item(struct genscript *genscript, u_int idx)
{
	if (idx < 0 || idx >= genscript->nitems)
		return NULL;

	return &genscript->items[idx];
}

static char *
getword(char *src, char *dst, unsigned int dstlen)
{
	char c;
	unsigned int len;

	for (;; src++) {
		c = *src;
		if (c == '\0' || c == '\r' || c == '\n' || c == '#')
			return NULL;
		if (c == ' ' || c == '\t')
			continue;

		break;
	}

	for (len = 0; len + 1 < dstlen; ) {
		c = *src;
		if (c == '\0' || c == '\r' || c == '\n' || c == '#')
			break;
		if (c == ' ' || c == '\t')
			break;

		if ((len + 1) < dstlen) {
			*dst++ = c;
			len++;
		}
		src++;
	}

	*dst++ = '\0';


	return src;
}

static int
genscript_read(struct genscript *genscript, const char *path)
{
	FILE *fp;
	char buf[1024], wbuf[256], *p, *q;
	int lineno;
	int anyerror = 0;
	unsigned long cmd, period, pktsize, pps;
	unsigned long long bps;

	fp = fopen(path, "r");
	if (fp == NULL)
		return -1;

	for (lineno = 1;
	    (p = fgets(buf, sizeof(buf), fp)) != NULL;
	    lineno++) {

		cmd = period = pktsize = pps = 0;

		/* no parameter. empty line */
		if ((p = getword(p, wbuf, sizeof(wbuf))) == NULL)
			continue;
		period = strtoul(wbuf, NULL, 10);

		if ((p = getword(p, wbuf, sizeof(wbuf))) == NULL) {
			printf("%s:%d: command parameter is not exists\n", path, lineno);
			anyerror++;
			continue;
		}

		if (strcmp(wbuf, "reset") == 0) {
			cmd = GENITEM_CMD_RESET;
			goto end_of_param;
		} else if (strcmp(wbuf, "sleep") == 0 || strcmp(wbuf, "nop") == 0) {
			cmd = GENITEM_CMD_NOP;
			goto end_of_param;
		} else if (strcmp(wbuf, "tx0") == 0) {
			cmd = GENITEM_CMD_TX0SET;
		} else if (strcmp(wbuf, "tx1") == 0) {
			cmd = GENITEM_CMD_TX1SET;
		} else {
			printf("%s:%d: unknown command '%s'\n", path, lineno, wbuf);
			anyerror++;
			continue;
		}

		if ((p = getword(p, wbuf, sizeof(wbuf))) == NULL) {
			printf("%s:%d: pktsize parameter is not exists\n", path, lineno);
			anyerror++;
			continue;
		}
		pktsize = strtoul(wbuf, NULL, 10);

		if ((p = getword(p, wbuf, sizeof(wbuf))) == NULL) {
			printf("%s:%d: pps parameter is not exists\n", path, lineno);
			anyerror++;
			continue;
		}

#define	DEFAULT_IFG		12	/* Inter Packet Gap */
#define PKTSIZE2FRAMESIZE(pktsize, gap)	(8 /*PREAMBLE+SFD*/ + 14 /*ETHHDRSIZE*/ + (pktsize) + 4 /*FCS*/ + (gap))
		if ((q = strcasestr(wbuf, "gbps")) != NULL && strlen(q) == 4) {
			bps = strtoull(wbuf, NULL, 10);
			pps = bps * 1000000000ULL / 8 / PKTSIZE2FRAMESIZE(pktsize, DEFAULT_IFG);
		} else if ((q = strcasestr(wbuf, "mbps")) != NULL && strlen(q) == 4) {
			bps = strtoull(wbuf, NULL, 10);
			pps = bps * 1000000ULL / 8 / PKTSIZE2FRAMESIZE(pktsize, DEFAULT_IFG);
		} else if ((q = strcasestr(wbuf, "kbps")) != NULL && strlen(q) == 4) {
			bps = strtoull(wbuf, NULL, 10);
			pps = bps * 1000ULL / 8 / PKTSIZE2FRAMESIZE(pktsize, DEFAULT_IFG);
		} else if ((q = strcasestr(wbuf, "bps")) != NULL && strlen(q) == 3) {
			bps = strtoull(wbuf, NULL, 10);
			pps = bps / 8ULL / PKTSIZE2FRAMESIZE(pktsize, DEFAULT_IFG);
		} else {
			pps = strtoul(wbuf, NULL, 10);
		}

 end_of_param:
		if ((p = getword(p, wbuf, sizeof(wbuf))) != NULL) {
			printf("%s:%d: unexpected parameter: %s\n", path, lineno, wbuf);
			anyerror++;
		}
		genscript_add_item(genscript, cmd, period, pktsize, pps);
	}

	fclose(fp);

	if (anyerror)
		return -1;

	return 0;
}

void
genscript_dump_item(struct genscript_item *genitem, const char *prefix)
{
	printf("%s<item addr=%p cmd=%s period=%u pktsize=%u pps=%u />\n",
	    prefix,
	    genitem,
	    genscript_cmdname(genitem->cmd),
	    genitem->period,
	    genitem->pktsize,
	    genitem->pps);
}

void
genscript_dump(struct genscript *genscript)
{
	unsigned int i;

	printf("<genscript addr=%p>\n", genscript);
	for (i = 0; i < genscript->nitems; i++) {
		genscript_dump_item(&genscript->items[i], "  ");
	}
	printf("</genscript>\n");
}


struct genscript *
genscript_new(const char *path)
{
	struct genscript *genscript;

	genscript = malloc(sizeof(*genscript));
	if (genscript == NULL)
		return NULL;

	memset(genscript, 0, sizeof(*genscript));

	if (genscript_read(genscript, path) != 0) {
		free(genscript);
		return NULL;
	}

	return genscript;
}

void
genscript_delete(struct genscript *genscript)
{
	if (genscript->items == NULL)
		free(genscript->items);
	free(genscript);
}

#if 0
int
main(int argc, char *argv[])
{
	struct genscript *genscript;

	if (argc != 2) {
		printf("usage: genscript <genscript>\n");
		return 1;
	}

	genscript = genscript_new(argv[1]);
	if (genscript == NULL) {
		if (errno != 0)
			err(2, "genscript_read");
		return 3;
	}

	genscript_dump(genscript);
	genscript_delete(genscript);

	return 0;
}
#endif
