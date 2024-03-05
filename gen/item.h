/*
 * Copyright (c) 2015 Ryo Shimizu
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
#ifndef _ITEM_H_
#define _ITEM_H_

#include <curses.h>
#include <inttypes.h>

#define ITEMTYPE_STR		0x00000000
#define ITEMTYPE_UINT8		0x00000001
#define ITEMTYPE_UINT16		0x00000002
#define ITEMTYPE_UINT32		0x00000003
#define ITEMTYPE_UINT64		0x00000004
#define ITEMTYPE_DOUBLE		0x00000005
#define ITEMTYPE_NULL		0x0000000f

//#define ITEMFLAGS_HEX		0x00000010	/* when TYPE_UINTxx */
#define ITEMFLAGS_LEFTALIGN	0x00000080	/* default right aligned */
#define ITEMFLAGS_RADIO		0x01000000
#define ITEMFLAGS_BUTTON	0x02000000
#define ITEMFLAGS_EDITABLE	0x20000000
#define ITEMFLAGS_DISPLAYED	0x40000000	/* internal flag: displayed */
#define ITEMFLAGS_EDITING	0x80000000	/* internal flag: while editting */

struct itemlist;

union item_value {
	uint64_t num;
	double dbl;
	char str[128];	/* XXX */
};

struct item {
	int id;
	uint32_t type;
	uint32_t flags;
	int x, y, w;
	int (*cb_apply)(struct itemlist *, struct item *, void *);
	union item_value disp;
	union {
		void *ptr;
		uint64_t *n64;
		uint32_t *n32;
		uint16_t *n16;
		uint8_t *n8;
		double *dbl;
		char *str;
	} ref;
	char *buf;	/* for ref.str if needed */
	unsigned int buflen;
	intptr_t udata;
};


struct itemlist *itemlist_new(const char *, struct item *, int);
int itemlist_ttyhandler(struct itemlist *, int);
int itemlist_init_term(void);
int itemlist_fini_term(void);

void itemlist_register_item(struct itemlist *, int, int (*)(struct itemlist *, struct item *, void *), void *);
void itemlist_setvalue(struct itemlist *, int, const void *);
void itemlist_focus(struct itemlist *, int);
void itemlist_editable(struct itemlist *, int, int);

void itemlist_update(struct itemlist *, int);

#endif /* _ITEM_H_ */
