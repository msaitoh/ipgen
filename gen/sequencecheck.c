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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "sequencecheck.h"

#if defined(__FreeBSD__) && defined(__x86_64__)
#include <machine/cpufunc.h>
#endif

struct sequencechecker {
	uint32_t sc_high;	/* upper 32bit internal counter */
	uint32_t sc_lastseq;	/* for checking reorder and extending 64bit */

	uint64_t sc_bitmap_start;
	uint64_t sc_bitmap_end;
	int sc_bitmap_baseidx;	/* sc_bitmap[sc_bitmap_base] = sc_bitmap_start */
	int sc_needinit;
#define SEQ_ARRAYSIZE		64	/* must be 2^n */
#define BIT_PER_DATA		(sizeof(uint64_t) * 8)
#define SEQ_MAXBIT		(BIT_PER_DATA * SEQ_ARRAYSIZE)
	uint64_t sc_bitmap[SEQ_ARRAYSIZE];

	struct sequencechecker *sc_parent;
	uint64_t sc_maxseq;
	uint64_t sc_nreceive;
	uint64_t sc_reorder;
	uint64_t sc_duplicate;
	uint64_t sc_outofrange;
	uint64_t sc_dropshift;
};
#define SEQ_NEXT_INDEX(i)	(((i) + 1) & (SEQ_ARRAYSIZE - 1))


static inline int
uint64bitcount(uint64_t x)
{
#if defined(__FreeBSD__) && defined(__x86_64__)
	uint64_t n;
	n = popcntq(x);
#else
	static const int n2nbit[16] = {
		0, 1, 1, 2, 1, 2, 2, 3,
		1, 2, 2, 3, 2, 3, 3, 4
	};
	int n;

	n = n2nbit[x & 15];
	n += n2nbit[(x >> 4) & 15];
	n += n2nbit[(x >> 8) & 15];
	n += n2nbit[(x >> 12) & 15];

	n += n2nbit[(x >> 16) & 15];
	n += n2nbit[(x >> 20) & 15];
	n += n2nbit[(x >> 24) & 15];
	n += n2nbit[(x >> 28) & 15];

	n += n2nbit[(x >> 32) & 15];
	n += n2nbit[(x >> 36) & 15];
	n += n2nbit[(x >> 40) & 15];
	n += n2nbit[(x >> 44) & 15];

	n += n2nbit[(x >> 48) & 15];
	n += n2nbit[(x >> 52) & 15];
	n += n2nbit[(x >> 56) & 15];
	n += n2nbit[(x >> 60) & 15];
#endif
	return n;
}

static void
seqcheck_init(struct sequencechecker *sc)
{
	memset(sc, 0, sizeof(*sc));
	sc->sc_bitmap_start = 0;
	sc->sc_bitmap_end = sc->sc_bitmap_start + SEQ_MAXBIT;
	sc->sc_maxseq = 0;
	sc->sc_needinit = 1;
}

void
seqcheck_clear(struct sequencechecker *sc)
{
	struct sequencechecker *parent;
	parent = sc->sc_parent;	/* save */

	seqcheck_init(sc);

	sc->sc_parent = parent;	/* restore */
}

static void
seqcheck_init2(struct sequencechecker *sc, uint64_t seq)
{
	struct sequencechecker *parent;

	parent = sc->sc_parent;	/* save */

	memset(sc, 0, sizeof(*sc));
	sc->sc_bitmap_start = seq;
	sc->sc_bitmap_end = sc->sc_bitmap_start + SEQ_MAXBIT;
	sc->sc_maxseq = seq;

	sc->sc_parent = parent;	/* restore */
}

struct sequencechecker *
seqcheck_new(void)
{
	struct sequencechecker *sc;

	sc = malloc(sizeof(struct sequencechecker));
	if (sc != NULL)
		seqcheck_init(sc);

	return sc;
}

void
seqcheck_setparent(struct sequencechecker *sc, struct sequencechecker *parent)
{
	sc->sc_parent = parent;
}

void
seqcheck_delete(struct sequencechecker *sc)
{
	free(sc);
}

static inline void
seqcheck_bit_set(struct sequencechecker *sc, unsigned int n)
{
	int idx;
	uint64_t bit;

	idx = (sc->sc_bitmap_baseidx + (n / BIT_PER_DATA)) & (SEQ_ARRAYSIZE - 1);
	bit = (1ULL << (n & (BIT_PER_DATA - 1)));
	if (sc->sc_bitmap[idx] & bit) {
		sc->sc_duplicate++;
		if (sc->sc_parent)
			sc->sc_parent->sc_duplicate++;
	} else {
		sc->sc_bitmap[idx] |= bit;
	}
}

#if 0
static inline int
seqcheck_bit_get(struct sequencechecker *sc, unsigned int n)
{
	int idx;

	idx = (sc->sc_bitmap_baseidx + (n / BIT_PER_DATA)) & (SEQ_ARRAYSIZE - 1);
	return !!(sc->sc_bitmap[idx] & (1ULL << (n & (BIT_PER_DATA - 1))));
}
#endif

uint64_t
seqcheck_receive(struct sequencechecker *sc, uint32_t seq)
{
	uint64_t seq64;
	uint64_t i, n, ndrop;
	uint64_t nskip;

	if (sc->sc_needinit) {
		seqcheck_init2(sc, seq);
		sc->sc_needinit = 0;
	}

	sc->sc_nreceive++;
	if (sc->sc_parent)
		sc->sc_parent->sc_nreceive++;


	/* extend 32bit counter to 64bit counter internally */
	uint32_t d = seq - sc->sc_lastseq;
	if (d < 0x80000000) {
		if (seq < sc->sc_lastseq) {
			/* overflow */
			sc->sc_high++;
		}
		seq64 = ((unsigned long long)sc->sc_high << 32) + seq;
	} else {
		if (seq > sc->sc_lastseq)
			sc->sc_high--;
		seq64 = ((unsigned long long)(sc->sc_high) << 32) + seq;

		/* reorder */
		sc->sc_reorder++;
		if (sc->sc_parent)
			sc->sc_parent->sc_reorder++;
	}
	sc->sc_lastseq = seq;


	if (sc->sc_maxseq < seq64) {
		nskip = seq64 - sc->sc_maxseq;
		sc->sc_maxseq = seq64;
	} else
		nskip = 0;

	if (sc->sc_bitmap_start > seq64) {
		sc->sc_outofrange++;
		if (sc->sc_parent)
			sc->sc_parent->sc_outofrange++;
		return 0;
	}
	if (sc->sc_bitmap_end > seq64) {
		seqcheck_bit_set(sc, seq64 - sc->sc_bitmap_start);
		return nskip;
	}

	/* bitmap shift */
	n = ((seq64 - sc->sc_bitmap_end) + BIT_PER_DATA) / BIT_PER_DATA;
	if (n > SEQ_ARRAYSIZE)
		n = SEQ_ARRAYSIZE;

	for (i = 0; i < n; i++) {
		ndrop = BIT_PER_DATA - uint64bitcount(sc->sc_bitmap[sc->sc_bitmap_baseidx]);
		sc->sc_dropshift += ndrop;
		if (sc->sc_parent)
			sc->sc_parent->sc_dropshift += ndrop;

		sc->sc_bitmap[sc->sc_bitmap_baseidx] = 0;

		/* shift bitmap */
		sc->sc_bitmap_baseidx = SEQ_NEXT_INDEX(sc->sc_bitmap_baseidx);
		sc->sc_bitmap_start += BIT_PER_DATA;
		sc->sc_bitmap_end += BIT_PER_DATA;
	}

	if (n >= SEQ_ARRAYSIZE) {
		n = ((seq64 - sc->sc_bitmap_end) + BIT_PER_DATA) / BIT_PER_DATA;

		sc->sc_dropshift += BIT_PER_DATA * n;
		if (sc->sc_parent)
			sc->sc_parent->sc_dropshift += BIT_PER_DATA * n;

		sc->sc_bitmap_end =
		    (seq64 + BIT_PER_DATA) & ~(BIT_PER_DATA - 1);
		sc->sc_bitmap_start = sc->sc_bitmap_end - SEQ_MAXBIT;
	}

	seqcheck_bit_set(sc, seq64 - sc->sc_bitmap_start);
	return nskip;
}

uint64_t
seqcheck_dupcount(struct sequencechecker *sc)
{
	return sc->sc_duplicate;
}

uint64_t
seqcheck_reordercount(struct sequencechecker *sc)
{
	return sc->sc_reorder;
}

uint64_t
seqcheck_dropcount(struct sequencechecker *sc)
{
#if 0
	uint64_t curdrop;
	int i;

	if (sc->sc_nreceive == 0)
		return 0;

	curdrop = 0;
	for (i = 0; i < SEQ_ARRAYSIZE; i++) {
		curdrop += BIT_PER_DATA - uint64bitcount(sc->sc_bitmap[i]);
	}
	curdrop -= ((sc->sc_bitmap_end - sc->sc_maxseq) - 1);

//printf("<dropshift=%llu, curdrop=%llu, maxseq=%llu>",
//  (unsigned long long)sc->sc_dropshift,
//  (unsigned long long)curdrop,
//  (unsigned long long)sc->sc_maxseq);

	return sc->sc_dropshift + curdrop;
#else
	return sc->sc_dropshift;
#endif
}

void
seqcheck_dump2(struct sequencechecker *sc)
{
	printf("nreceive   = %llu\n", (unsigned long long)sc->sc_nreceive);
	printf("reorder    = %llu\n", (unsigned long long)sc->sc_reorder);
	printf("outofrange = %llu\n", (unsigned long long)sc->sc_outofrange);
	printf("dropshift  = %llu\n", (unsigned long long)sc->sc_dropshift);
	printf("drop       = %llu\n", (unsigned long long)seqcheck_dropcount(sc));
}

void
seqcheck_dump(struct sequencechecker *sc)
{
	unsigned int i, j, n;
	uint64_t start, end;

	start = sc->sc_bitmap_start;
	end = sc->sc_bitmap_end;

	printf("lastseq    = 0x%llx\n", (unsigned long long)sc->sc_lastseq);
	printf("seq_high   = 0x%llx\n", (unsigned long long)sc->sc_high);

	printf("start      = 0x%llx\n", (unsigned long long)start);
	printf("end        = 0x%llx\n", (unsigned long long)end);
	printf("baseidx    = %llu\n", (unsigned long long)sc->sc_bitmap_baseidx);
	printf("max seq    = 0x%llx\n", (unsigned long long)sc->sc_maxseq);
	seqcheck_dump2(sc);

	i = sc->sc_bitmap_baseidx;
	for (n = 0; n < SEQ_ARRAYSIZE; n++) {
		if ((n & 1) == 0)
			printf("%10llu - %10llu: ",
			    (unsigned long long)start + (n * BIT_PER_DATA),
			    (unsigned long long)start + (n * BIT_PER_DATA) + BIT_PER_DATA * 2 - 1);

		for (j = 0; j < BIT_PER_DATA; j++) {
			printf("%d", (sc->sc_bitmap[i] & (1ULL << j)) ? 1 : 0);
		}

		if ((n & 1) == 1)
			printf("\n");
		else
			printf(" ");

		i = SEQ_NEXT_INDEX(i);
	}
	printf("\n");
}

#if 0	/* TEST */
int
main(int argc, char *argv[])
{
	uint32_t i;
	struct sequencechecker seqmap;

	(void)&argc;
	(void)&argv;


	seqcheck_init(&seqmap);
	seqcheck_dump(&seqmap);

	seqcheck_receive(&seqmap, 0);
	seqcheck_receive(&seqmap, 4097);
	seqcheck_dump(&seqmap);

	seqcheck_receive(&seqmap, 0x78000000);
	seqcheck_receive(&seqmap, 0x81000000);

	for (i = 0; i < 32; i++) {
		seqcheck_receive(&seqmap, 0xfffffff0 + i);
		seqcheck_dump(&seqmap);
	}

	printf("===================\n");
	for (i = 0; i < 32; i++) {
		seqcheck_receive(&seqmap, 0xfffffff0 + i);
		seqcheck_dump(&seqmap);
	}

	exit(1);

	seqcheck_receive(&seqmap, 16388);
	seqcheck_receive(&seqmap, 16387);
	seqcheck_dump(&seqmap);
	exit(1);

	seqcheck_receive(&seqmap, 16386 + 128);
	seqcheck_dump(&seqmap);
	exit(1);

	seqcheck_receive(&seqmap, 0);
	seqcheck_dump(&seqmap);

	seqcheck_receive(&seqmap, 1);
	seqcheck_receive(&seqmap, 2);
	seqcheck_receive(&seqmap, 3);
	seqcheck_dump(&seqmap);

	seqcheck_receive(&seqmap, 10);
	seqcheck_dump(&seqmap);

	seqcheck_receive(&seqmap, 64);
	seqcheck_dump(&seqmap);

	seqcheck_receive(&seqmap, 65);
	seqcheck_dump(&seqmap);

	seqcheck_receive(&seqmap, 100);
	seqcheck_dump(&seqmap);

	seqcheck_receive(&seqmap, 1000);
	seqcheck_dump(&seqmap);

	seqcheck_receive(&seqmap, 2000);
	seqcheck_dump(&seqmap);

	seqcheck_receive(&seqmap, 2048);
	seqcheck_dump(&seqmap);

	seqcheck_receive(&seqmap, 2049);
	seqcheck_dump(&seqmap);

	seqcheck_receive(&seqmap, 2050);
	seqcheck_dump(&seqmap);

	seqcheck_receive(&seqmap, 2051);
	seqcheck_dump(&seqmap);

	seqcheck_receive(&seqmap, 1999);
	seqcheck_receive(&seqmap, 1998);
	seqcheck_receive(&seqmap, 1997);
	seqcheck_receive(&seqmap, 1996);
	seqcheck_receive(&seqmap, 1995);

	seqcheck_receive(&seqmap, 10245);
	seqcheck_dump(&seqmap);
}
#endif
