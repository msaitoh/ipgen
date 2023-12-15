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
#ifndef _GENSCRIPT_H_
#define _GENSCRIPT_H_

struct genscript {
	unsigned int nitems;
	unsigned int nalloc;
	struct genscript_item {
		unsigned int cmd;
#define GENITEM_CMD_RESET	0
#define GENITEM_CMD_NOP		1
#define GENITEM_CMD_TX0SET	2
#define GENITEM_CMD_TX1SET	3
#define GENITEM_CMD_NCMD	4
		unsigned int period;
		unsigned int pktsize;
		unsigned int pps;
	} *items;
};

static inline const char *
genscript_cmdname(unsigned int cmd)
{
	const char *cmd2cmdname[] = {
		"RESET", "NOP", "TX0", "TX1"
	};
	if (cmd >= GENITEM_CMD_NCMD)
		return "unknown";
	return cmd2cmdname[cmd];
}

struct genscript *genscript_new(const char *);
void genscript_delete(struct genscript *);
struct genscript_item *genscript_get_item(struct genscript *, int);

/* for debug */
void genscript_dump(struct genscript *);
void genscript_dump_item(struct genscript_item *, const char *);


#endif /* _GENSCRIPT_H_ */
