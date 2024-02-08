/*
 * Copyright (c) 2015 Ryo Shimizu <ryo@nerv.org>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <curses.h>
#include "item.h"

#undef ITEM_DEBUG

/* XXX: use termcap/terminfo */
#ifdef ITEM_DEBUG
#define	CLEAR()		(void)0
#define	LOCATE(x,y)	(void)0
#define	REFRESH()	(void)0
#define	PRINTF(format, args...)	printf(format, ## args)
#define	BEEP()		(void)0
#else
#define	CLEAR()		clear()
#define	LOCATE(x,y)	move(y,x)
#define	REFRESH()	refresh()
#define	PRINTF(format, args...)	printw(format, ## args)
#define	BEEP()		beep()
#endif

#define	REVERSE()	standout()
#define	NORMAL()	standend()


struct itemlist {
	int focus;
	int ready;

	const char *template;
	int nitems;
	struct item *items;

	/* line editor */
	int linebuffer_x, linebuffer_y;
	int linebuffer_cursor;
	char linebuf[128];
	union item_value save;
};

static void itemlist_update_cursor(struct itemlist *, int);
static int itemlist_status(struct itemlist *);
#define ITEMLIST_STATUS_NONE	0
#define ITEMLIST_STATUS_FOCUS	1
#define ITEMLIST_STATUS_EDITING	2

static void item_setvalue(struct item *, const void *);
static void itemlist_update_editing(struct itemlist *, int);
static int itemlist_editstart(struct itemlist *);
static int itemlist_editor(struct itemlist *, int c);
static int itemlist_editdone(struct itemlist *, int);
static void itemlist_focus_next(struct itemlist *);
static void itemlist_focus_prev(struct itemlist *);
static void itemlist_focus_up(struct itemlist *);
static void itemlist_focus_down(struct itemlist *);
static void itemlist_focus_horizontal(struct itemlist *, int);
static void itemlist_focus_vertical(struct itemlist *, int);
/* static void itemlist_unfocus(struct itemlist *itemlist); */
static void item_update(struct item *, int);


static int term_initted = 0;

int
itemlist_init_term(void)
{
	WINDOW *win;

	if (term_initted != 0)
		return 0;
	term_initted = 1;

	fflush(stdout);

#ifndef ITEM_DEBUG
	win = initscr();
	noecho();
	cbreak();
	keypad(win, TRUE);
#endif

	return 0;
}

int
itemlist_fini_term(void)
{
	if (term_initted == 0)
		return 0;
	term_initted = 0;

#ifndef ITEM_DEBUG
	refresh();
	endwin();
#endif

	return 0;
}

struct itemlist *
itemlist_new(const char *template, struct item *items, int nitems)
{
	struct itemlist *itemlist;

	itemlist = malloc(sizeof(struct itemlist));
	if (itemlist == NULL)
		return NULL;

	memset(itemlist, 0, sizeof(*itemlist));

	itemlist->template = template;
	itemlist->nitems = nitems;
	itemlist->items = items;
	itemlist->focus = -1;
	return itemlist;
}

static void
item_dump(struct item *item)
{
#ifdef ITEM_DEBUG
	printf("<item=%p x=%d y=%d w=%d>\n",
	    item, item->x, item->y, item->w);
#endif
}



static char *
double_fmt(double d, unsigned int w, int left)
{
	static char buf[32];

	unsigned int bw;
	if (d >= 10000000)
		bw = 8;
	else if (d >= 1000000)
		bw = 7;
	else if (d >= 100000)
		bw = 6;
	else if (d >= 10000)
		bw = 5;
	else if (d >= 1000)
		bw = 4;
	else if (d >= 100)
		bw = 3;
	else if (d >= 10)
		bw = 2;
	else
		bw = 1;

	if (w > bw)
		sprintf(buf, "%%%s.%df", left ? "-" : "", w - bw - 1);
	else
		sprintf(buf, "%%%s.1f", left ? "-" : "");
	return buf;
}

static void
item_update(struct item *item, int force)
{
	int changed = 0;

	if ((item->flags & ITEMFLAGS_DISPLAYED) == 0)
		force = 1;

	item_dump(item);

	/* autofetch? */
	if (item->ref.ptr != NULL) {
		switch (item->type) {
		case ITEMTYPE_STR:
			changed = strncmp(item->ref.str, item->disp.str, sizeof(item->disp.str));
			if (changed)
				strncpy(item->disp.str, item->ref.str, sizeof(item->disp.str));
			break;
		case ITEMTYPE_UINT8:
			changed = (*item->ref.n8 == item->disp.num) ? 0 : 1;
			if (changed)
				item->disp.num = *item->ref.n8;
			break;
		case ITEMTYPE_UINT16:
			changed = (*item->ref.n16 == item->disp.num) ? 0 : 1;
			if (changed)
				item->disp.num = *item->ref.n16;
			break;
		case ITEMTYPE_UINT32:
			changed = (*item->ref.n32 == item->disp.num) ? 0 : 1;
			if (changed)
				item->disp.num = *item->ref.n32;
			break;
		case ITEMTYPE_UINT64:
			changed = (*item->ref.n64 == item->disp.num) ? 0 : 1;
			if (changed)
				item->disp.num = *item->ref.n64;
			break;
		case ITEMTYPE_DOUBLE:
			changed = (*item->ref.dbl == item->disp.dbl) ? 0 : 1;
			if (changed)
				item->disp.dbl = *item->ref.dbl;
			break;
		}
	}

	/* display if needed */
	if (changed || force) {
		switch (item->type) {
		case ITEMTYPE_STR:
			LOCATE(item->x, item->y);
			if (item->flags & ITEMFLAGS_LEFTALIGN)
				PRINTF("%-*s", item->w, item->disp.str);
			else
				PRINTF("%*s", item->w, item->disp.str);
			break;
		case ITEMTYPE_UINT8:
		case ITEMTYPE_UINT16:
		case ITEMTYPE_UINT32:
		case ITEMTYPE_UINT64:
			LOCATE(item->x, item->y);
			if (item->flags & ITEMFLAGS_LEFTALIGN)
				PRINTF("%-*llu", item->w, (unsigned long long)item->disp.num);
			else
				PRINTF("%*llu", item->w, (unsigned long long)item->disp.num);
			break;
		case ITEMTYPE_DOUBLE:
			LOCATE(item->x, item->y);
			PRINTF(double_fmt(item->disp.dbl, item->w, item->flags & ITEMFLAGS_LEFTALIGN), item->w, item->disp.dbl);
			break;
		}
	}

	item->flags |= ITEMFLAGS_DISPLAYED;
}

static void
item_focus(struct item *item)
{
	if (item->flags & ITEMFLAGS_LEFTALIGN) {
		LOCATE(item->x, item->y);
	} else {
		LOCATE(item->x + item->w - 1, item->y);
	}
	REFRESH();
}

static int
itemlist_status(struct itemlist *itemlist)
{
	struct item *item;
	if (itemlist->focus < 0)
		return ITEMLIST_STATUS_NONE;
	item = &itemlist->items[itemlist->focus];
	if (item->flags & ITEMFLAGS_EDITING)
		return ITEMLIST_STATUS_EDITING;
	return ITEMLIST_STATUS_FOCUS;
}


/* focus */
static void
itemlist_focus_horizontal(struct itemlist *itemlist, int back)
{
	int i, n;
	struct item *item;
	int step;

	if (back)
		step = itemlist->nitems - 1;
	else
		step = 1;

	/* find next/previous focus */
	i = (itemlist->focus + step) % itemlist->nitems;
	for (n = 0; n <= itemlist->nitems; n++) {
		item = &itemlist->items[i];
		if (item->flags & ITEMFLAGS_EDITABLE) {
			itemlist->focus = i;
			break;
		}
		i = (i + step) % itemlist->nitems;
	}
	if (n >= itemlist->nitems) {
		itemlist->focus = -1;
	} else {
		item_focus(item);
	}
}

static int
itemlist_distance_item(struct itemlist *itemlist, int orig, int target)
{
	struct item *a, *b;
	int d;

	a = &itemlist->items[orig];
	b = &itemlist->items[target];

	if (a->x < b->x)
		d = b->x - a->x;
	else if (a->x < b->x + b->w)
		d = 0;
	else
		d = a->x - (b->x + b->w);

	return d + abs(a->y - b->y) * 256;
}

static void
itemlist_focus_vertical(struct itemlist *itemlist, int up)
{
	int step, i, orig, cur, cur_dist, candidate, candidate_dist;
	int targetline;

	orig = itemlist->focus;

	if (up)
		step = itemlist->nitems - 1;
	else
		step = 1;

	targetline = -1;
	candidate_dist = INT_MAX;
	candidate = -1;
	cur = itemlist->focus;
	for (i = 0; i < itemlist->nitems - 1; i++) {
		cur = (cur + step) % itemlist->nitems;

		if (((itemlist->items[cur].flags & ITEMFLAGS_EDITABLE) == 0) ||
		    (itemlist->items[cur].y == itemlist->items[orig].y))
			continue;

		if (targetline < 0)
			targetline = itemlist->items[cur].y;
		else if (targetline != itemlist->items[cur].y)
			continue;

		cur_dist = itemlist_distance_item(itemlist, orig, cur);

		if (candidate_dist > cur_dist) {
			candidate_dist = cur_dist;
			candidate = cur;
		}
	}

	if (candidate > 0) {
		itemlist->focus = candidate;
		item_focus(&itemlist->items[candidate]);
	}
}

static void
itemlist_focus_next(struct itemlist *itemlist)
{
	itemlist_focus_horizontal(itemlist, 0);
}

static void
itemlist_focus_prev(struct itemlist *itemlist)
{
	itemlist_focus_horizontal(itemlist, 1);
}

static void
itemlist_focus_up(struct itemlist *itemlist)
{
	itemlist_focus_vertical(itemlist, 1);
}

static void
itemlist_focus_down(struct itemlist *itemlist)
{
	itemlist_focus_vertical(itemlist, 0);
}

void
itemlist_focus(struct itemlist *itemlist, int id)
{
	itemlist->focus = id;
}

/*
static void
itemlist_unfocus(struct itemlist *itemlist)
{
	itemlist->focus = -1;
	itemlist_update_cursor(itemlist, 0);
}
*/

void
itemlist_editable(struct itemlist *itemlist, int id, int enable)
{
	struct item *item;

	item = &itemlist->items[id];
	if (enable)
		item->flags |= ITEMFLAGS_EDITABLE;
	else
		item->flags &= ~ITEMFLAGS_EDITABLE;
}

static void
itemlist_update_cursor(struct itemlist *itemlist, int force)
{
	struct item *item;

	/* update cursor */
	switch (itemlist_status(itemlist)) {
	case ITEMLIST_STATUS_NONE:
		itemlist_focus_next(itemlist);
		/* FALLTHRU */
	case ITEMLIST_STATUS_FOCUS:
		item = &itemlist->items[itemlist->focus];
		item_focus(item);
		break;
	case ITEMLIST_STATUS_EDITING:
		itemlist_update_editing(itemlist, force);
		break;
	}
	REFRESH();
}

#ifdef ITEM_DEBUG
static void
itemlist_dump(struct itemlist *itemlist)
{
	printf("<itemlist=%p>\n", itemlist);
	printf("  focus=%d\n", itemlist->focus);
	printf("  ready=%d\n", itemlist->ready);
	printf("  nitems=%d\n", itemlist->nitems);
	printf("  items=%p\n", itemlist->items);
	printf("</itemlist>\n");
	fflush(stdout);
}
#endif

void
itemlist_register_item(struct itemlist *itemlist, int id, int (*cb_apply)(struct itemlist *, struct item *, void *), void *refptr)
{
	itemlist->items[id].cb_apply = cb_apply;
	itemlist->items[id].ref.ptr = refptr;
}

static void
item_setvalue_str(struct item *item, const char *str)
{
	strncpy(item->disp.str, str, sizeof(item->disp.str));
}

static void
item_setvalue_num(struct item *item, uint64_t num)
{
	item->disp.num = num;
}

static void
item_setvalue_double(struct item *item, double dbl)
{
	item->disp.dbl = dbl;
}

static void
item_setvalue(struct item *item, const void *valueptr)
{
	if (valueptr == NULL) {
		item->disp.num = 0;
	} else {
		switch (item->type) {
		case ITEMTYPE_STR:
			item_setvalue_str(item, valueptr);
			break;
		case ITEMTYPE_UINT8:
			item_setvalue_num(item, *(const uint8_t *)valueptr);
			break;
		case ITEMTYPE_UINT16:
			item_setvalue_num(item, *(const uint16_t *)valueptr);
			break;
		case ITEMTYPE_UINT32:
			item_setvalue_num(item, *(const uint32_t *)valueptr);
			break;
		case ITEMTYPE_UINT64:
			item_setvalue_num(item, *(const uint64_t *)valueptr);
			break;
		case ITEMTYPE_DOUBLE:
			item_setvalue_double(item, *(const double *)valueptr);
			break;
		}
	}
	item_update(item, 1);
}

void
itemlist_setvalue(struct itemlist *itemlist, int id, const void *valueptr)
{
	struct item *item;

	item = &itemlist->items[id];
	item_setvalue(item, valueptr);
}

void
itemlist_update(struct itemlist *itemlist, int force)
{
	struct item *item;
	int i;

	if (!itemlist->ready) {
		itemlist->ready = 1;
		CLEAR();
		PRINTF("%s", itemlist->template);
	} else if (force)
		PRINTF("%s", itemlist->template);


#ifdef ITEM_DEBUG
	itemlist_dump(itemlist);
#endif

	for (i = 0, item = itemlist->items; i < itemlist->nitems; i++) {
		item_update(item++, force);
	}

	itemlist_update_cursor(itemlist, force);

}

static void
itemlist_update_editing(struct itemlist *itemlist, int force)
{
	int x, y;
	struct item *item;

	item = &itemlist->items[itemlist->focus];

	x = itemlist->linebuffer_x;
	y = itemlist->linebuffer_y;
	if (force) {
		LOCATE(x, y);
		REVERSE();
		PRINTF("%-*s", item->w, itemlist->linebuf);
		NORMAL();
	}

	/* lineeditor update */
	LOCATE(x + itemlist->linebuffer_cursor, y);
}

static int
itemlist_editstart(struct itemlist *itemlist)
{
	struct item *item;

	if (itemlist->focus < 0)
		return -1;

	item = &itemlist->items[itemlist->focus];
	if (item->flags & ITEMFLAGS_EDITING)
		return -2;
	if ((item->flags & ITEMFLAGS_EDITABLE) == 0)
		return -3;

	if (item->flags & (ITEMFLAGS_RADIO|ITEMFLAGS_BUTTON)) {
		int enable;

		if (item->flags & ITEMFLAGS_RADIO) {
			/* RADIO is toggle */
			if (strcmp(item->disp.str, "*") == 0) {
				item_setvalue(item, NULL);
				enable = 0;
			} else {
				item_setvalue(item, "*");
				enable = 1;
			}
		} else {
			/* BUTTON is set only */
			if (strcmp(item->disp.str, "*") == 0) {
				/* already enable */
				enable = 0;
			} else {
				item_setvalue(item, "*");
				enable = 1;
			}
		}

		if ((item->cb_apply == NULL) || (item->cb_apply(itemlist, item, &item->disp) == 0)) {
			item_focus(item);
			REFRESH();
		} else {
			/* revert */
			if (enable) {
				item_setvalue(item, NULL);
			} else {
				item_setvalue(item, "*");
			}
		}
		return 0;
	}

	item->flags |= ITEMFLAGS_EDITING;

	/* save for cancel */
	memcpy(&itemlist->save, &item->disp, sizeof(itemlist->save));

	switch (item->type) {
	case ITEMTYPE_STR:
		strncpy(itemlist->linebuf, item->disp.str, sizeof(itemlist->linebuf));
		break;
	case ITEMTYPE_DOUBLE:
		sprintf(itemlist->linebuf, "%.8f", item->disp.dbl);
		break;
	case ITEMTYPE_UINT8:
	case ITEMTYPE_UINT16:
	case ITEMTYPE_UINT32:
	case ITEMTYPE_UINT64:
		sprintf(itemlist->linebuf, "%llu", (unsigned long long)item->disp.num);
		break;
	}
	itemlist->linebuffer_x = item->x;
	itemlist->linebuffer_y = item->y;
	itemlist->linebuffer_cursor = strlen(itemlist->linebuf);

	itemlist_update_editing(itemlist, true);
	REFRESH();

	return 0;
}

static int
itemlist_editor(struct itemlist *itemlist, int c)
{
	struct item *item;
	int i;

	item = &itemlist->items[itemlist->focus];

	switch (c) {
	case 0x01:	/* ^A */
		if (itemlist->linebuffer_cursor != 0) {
			itemlist->linebuffer_cursor = 0;
			itemlist_update_editing(itemlist, true);
			REFRESH();
		}
		break;
	case KEY_LEFT:
	case 0x02:	/* ^B */
		if (itemlist->linebuffer_cursor != 0) {
			itemlist->linebuffer_cursor--;
			itemlist_update_editing(itemlist, true);
			REFRESH();
		}
		break;
	case 0x04:	/* ^D */
	case 0x7f:	/* DEL */
		if (itemlist->linebuf[itemlist->linebuffer_cursor] != '\0') {
			strcpy(&itemlist->linebuf[itemlist->linebuffer_cursor],
			    &itemlist->linebuf[itemlist->linebuffer_cursor + 1]);
			itemlist_update_editing(itemlist, true);
			REFRESH();
		}
		break;
	case 0x05:	/* ^E */
		i = strlen(itemlist->linebuf);
		if (itemlist->linebuffer_cursor < i) {
			itemlist->linebuffer_cursor = i;
			itemlist_update_editing(itemlist, true);
			REFRESH();
		}
	case 0x06:	/* ^F */
	case KEY_RIGHT:
		if (itemlist->linebuf[itemlist->linebuffer_cursor] != '\0') {
			itemlist->linebuffer_cursor++;
			itemlist_update_editing(itemlist, true);
			REFRESH();
		}
		break;
	case 0x0e:	/* ^N */
	case 0x10:	/* ^P */
		break;
	case 0x08:	/* ^H */
	case KEY_BACKSPACE:
		if (itemlist->linebuffer_cursor > 0) {
			strcpy(&itemlist->linebuf[itemlist->linebuffer_cursor - 1],
			    &itemlist->linebuf[itemlist->linebuffer_cursor]);
			itemlist->linebuffer_cursor--;
			itemlist_update_editing(itemlist, true);
			REFRESH();
		}
		break;
	case 0x0b:	/* ^K */
		if (itemlist->linebuf[itemlist->linebuffer_cursor] != '\0') {
			itemlist->linebuf[itemlist->linebuffer_cursor] = '\0';
			itemlist_update_editing(itemlist, true);
			REFRESH();
		}
		break;
	case 0x15:	/* ^U */
		if (itemlist->linebuf[0] != '\0') {
			itemlist->linebuf[0] = '\0';
			itemlist->linebuffer_cursor = 0;
			itemlist_update_editing(itemlist, true);
			REFRESH();
		}
		break;
	default:
		i = strlen(itemlist->linebuf);
		if ((i >= item->w) || (i >= sizeof(itemlist->linebuf))) {
			BEEP();
		} else {
			i = strlen(&itemlist->linebuf[itemlist->linebuffer_cursor]) + 1;
			memmove(&itemlist->linebuf[itemlist->linebuffer_cursor + 1],
			    &itemlist->linebuf[itemlist->linebuffer_cursor], i);
			itemlist->linebuf[itemlist->linebuffer_cursor++] = c;
			itemlist_update_editing(itemlist, true);
			REFRESH();
		}
		break;
	}
	return 0;
}

static uint64_t
eval_num(const char *p)
{
	long long int v;

	if (strncmp(p, "0x", 2) == 0)
		v = strtoll(p, NULL, 16);
	else
		v = strtoll(p, NULL, 10);

	return v;
}

static int
itemlist_editdone(struct itemlist *itemlist, int apply)
{
	struct item *item;

	if (itemlist->focus < 0)
		return -1;

	item = &itemlist->items[itemlist->focus];
	if ((item->flags & ITEMFLAGS_EDITING) == 0)
		return -2;

	if (apply) {
		// accept check callback -> ok? -> apply callback
		switch (item->type) {
		case ITEMTYPE_STR:
			item_setvalue_str(item, itemlist->linebuf);
			break;
		case ITEMTYPE_UINT8:
		case ITEMTYPE_UINT16:
		case ITEMTYPE_UINT32:
		case ITEMTYPE_UINT64:
			item_setvalue_num(item, eval_num(itemlist->linebuf));
			break;
		case ITEMTYPE_DOUBLE:
			item_setvalue_double(item, atof(itemlist->linebuf));
			break;
		}
	}

	if ((item->cb_apply == NULL) || (item->cb_apply(itemlist, item, &item->disp) == 0)) {
		if (item->ref.ptr != NULL) {
			switch (item->type) {
			case ITEMTYPE_STR:
				strncpy(item->ref.str, item->disp.str, sizeof(item->disp.str));
				break;
			case ITEMTYPE_UINT8:
				*item->ref.n8 = item->disp.num;
				break;
			case ITEMTYPE_UINT16:
				*item->ref.n16 = item->disp.num;
				break;
			case ITEMTYPE_UINT32:
				*item->ref.n32 = item->disp.num;
				break;
			case ITEMTYPE_UINT64:
				*item->ref.n64 = item->disp.num;
				break;
			case ITEMTYPE_DOUBLE:
				*item->ref.dbl = item->disp.dbl;
				break;
			}
		}
	} else {
		/* revert */
		memcpy(&item->disp, &itemlist->save, sizeof(item->disp));
	}
	item->flags &= ~ITEMFLAGS_EDITING;

	item_update(item, true);
	itemlist_update_cursor(itemlist, 1);
	return 0;
}

int
itemlist_ttyhandler(struct itemlist *itemlist, int c)
{
	int focus = 0;
	int editing = 0;
	int grabed = 0;

	switch (itemlist_status(itemlist)) {
	case ITEMLIST_STATUS_NONE:
		break;
	case ITEMLIST_STATUS_EDITING:
		editing = 1;
		/* FALLTHRU */
	case ITEMLIST_STATUS_FOCUS:
		focus = 1;
		break;
	}

	if (editing)
		grabed = 1;

	switch (c) {
	case 0x0c:	/* ^L */
		CLEAR();
		itemlist_update(itemlist, 1);
		grabed = 1;
		break;
	case 0x09:	/* TAB */
		if (!editing) {
			itemlist_focus_next(itemlist);
			grabed = 1;
		}
		break;
	case 0x0e:	/* ^N */
	case KEY_DOWN:
		if (!editing) {
			itemlist_focus_down(itemlist);
			grabed = 1;
		}
		break;
	case KEY_UP:
	case 0x10:	/* ^P */
		if (!editing) {
			itemlist_focus_up(itemlist);
			grabed = 1;
		}
		break;
	case 0x1b:	/* ESC */
		if (editing) {
			itemlist_editdone(itemlist, 0);
			grabed = 1;
		}
		break;
	case '\r':
	case '\n':
		if (editing)
			itemlist_editdone(itemlist, 1);
		else if (focus)
			itemlist_editstart(itemlist);
		grabed = 1;
		break;
	case KEY_RIGHT:
		if (editing)
			itemlist_editor(itemlist, c);
		else
			itemlist_focus_next(itemlist);
		grabed = 1;
		break;
	case KEY_LEFT:
		if (editing)
			itemlist_editor(itemlist, c);
		else
			itemlist_focus_prev(itemlist);
		grabed = 1;
		break;
	case 0x02:	/* ^B */
		if (editing)
			itemlist_editor(itemlist, c);
		else
			itemlist_focus_prev(itemlist);
		grabed = 1;
		break;
	case 0x06:	/* ^F */
		if (editing)
			itemlist_editor(itemlist, c);
		else
			itemlist_focus_next(itemlist);
		grabed = 1;
		break;
	case 0x01:	/* ^A */
	case 0x04:	/* ^D */
	case 0x05:	/* ^E */
	case 0x08:	/* ^H */
	case 0x0b:	/* ^K */
	case 0x15:	/* ^U */
	case 0x20 ... 0x7f:
	case KEY_BACKSPACE:
		if (editing) {
			itemlist_editor(itemlist, c);
			grabed = 1;
		}
		break;
	default:
		break;
	}

	return grabed;
}

#if 0
void
itemlist_message(struct itemlist *itemlist, int id, const char *message)
{
	struct item *item;
	unsigned int newlen;
	char *p;

	item = &itemlist->items[id];

	if ((item->buf == NULL) || (item->buflen < strlen(message))) {
		newlen = strlen(message);
		newlen = (newlen + 63) & -64;
		item->buflen = newlen;

		if (item->buf == NULL)
			p = malloc(item->buflen);
		else
			p = realloc(item->buf, item->buflen);

		if (p == NULL)
			return;
		item->buf = p;
	}

	strcpy(item->buf, message);
	item->ref.str = item->buf;
}
#endif
