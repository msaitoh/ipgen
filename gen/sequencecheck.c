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
#include <inttypes.h>
#include "gen.h"
#include "util.h"
#include "sequencecheck.h"
#include <pthread.h>

#if defined(__FreeBSD__) && defined(__x86_64__)
#include <machine/cpufunc.h>
#endif

#if defined(DEBUG) && defined(TEST)
#undef DEBUGLOG
#undef DEBUGLOG_CONT
#define DEBUGLOG(fmt, args...)	printf(fmt, ## args)
#define DEBUGLOG_CONT(fmt, args...) printf(fmt, ## args)
#endif

struct sequencechecker {
	pthread_mutex_t mtx;
	char sc_name[SCNAME_MAX];
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
	uint64_t sc_maxseq;	/* The max sequence number. */

	/* Statistics */
	uint64_t sc_nreceive;
	uint64_t sc_reorder;
	uint64_t sc_duplicate;
	uint64_t sc_outofrange;
	uint64_t sc_dropshift;
};
#define SEQ_NEXT_INDEX(i)	(((i) + 1) & (SEQ_ARRAYSIZE - 1))

#ifdef TEST
static void seqcheck_fullclear(struct sequencechecker *);
#endif

static uint64_t seqcheck_receive_locked(struct sequencechecker *, uint32_t);

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
	DEBUGLOG("%s: memset called\n", __func__);
	memset(sc, 0, sizeof(*sc));
	sc->sc_bitmap_start = 0;
	sc->sc_bitmap_end = sc->sc_bitmap_start + SEQ_MAXBIT;
	sc->sc_maxseq = 0;
	sc->sc_needinit = 1;
}

static void seqcheck_refresh(struct sequencechecker *);

#ifdef TEST
/*
 * ONLY FOR TEST!
 *
 * This functions fully clears sequencechecker. i.e. it clears not only
 * statistics but also the max sequence number and full bitmap.
 */
static void
seqcheck_fullclear(struct sequencechecker *sc)
{
	struct sequencechecker *parent;
	parent = sc->sc_parent;	/* save */

	DEBUGLOG("%s: called\n", __func__);

	seqcheck_init(sc);

	sc->sc_parent = parent;	/* restore */
}
#endif

/* Not locked */
void
seqcheck_clear(struct sequencechecker *sc)
{
	struct sequencechecker *parent;
	parent = sc->sc_parent;	/* save */

	DEBUGLOG("%s: clear %s\n", __func__, sc->sc_name);
	pthread_mutex_lock(&sc->mtx);
	seqcheck_refresh(sc);
	sc->sc_needinit = 1;
	pthread_mutex_unlock(&sc->mtx);
	sc->sc_parent = parent;	/* restore */
}

/* Locked */
static void
seqcheck_refresh(struct sequencechecker *sc)
{
	struct sequencechecker *parent;
	u_int idx, i, n;
	uint64_t seqhead;

	parent = sc->sc_parent;	/* save */

	pthread_mutex_lock(&sc->mtx);
	DEBUGLOG("%s: %s: called\n", __func__, sc->sc_name);


	/* Calculate number of bitmap array to be modified. */
	n = ((sc->sc_maxseq - sc->sc_bitmap_start) + BIT_PER_DATA) / BIT_PER_DATA;
//	printf("XXX n       = %u\n", n);

	idx = sc->sc_bitmap_baseidx;
	seqhead = sc->sc_bitmap_start;
//	printf("XXX idx     = %u\n", idx);
//	printf("XXX seqhead = %"PRIu64"\n", seqhead);
	/* Mark */
	for (i = 0; i < n; i++) {
		if ((sc->sc_maxseq - seqhead) >= BIT_PER_DATA) {
			sc->sc_bitmap[idx] = ~0; /* Mark all bits */
//			printf("XXX %2d: mark all of sc_bitmap[%u]\n", i, idx);
		} else {
#if 0
			printf("XXX %2d: partial sc_bitmap[%u], seqhead = %"PRIu64", maxsed = %"PRIu64"\n",
			    i, idx, sc->sc_maxseq, seqhead);
#endif
			for (u_int j = 0; j <= (sc->sc_maxseq - seqhead); j++) {
//				printf("%2d: Set bit %u (%"PRIx64")\n", j, j, 1UL << j);
				sc->sc_bitmap[idx] |= 1UL << j;
			}
		}
		idx = SEQ_NEXT_INDEX(idx);
		seqhead += BIT_PER_DATA;
	}

	/* Clear statistics. */
	sc->sc_nreceive = 0;
	sc->sc_reorder = 0;
	sc->sc_duplicate = 0;
	sc->sc_outofrange = 0;
	sc->sc_dropshift = 0;

	if (sc->sc_parent)
		seqcheck_refresh(sc->sc_parent);

	sc->sc_parent = parent;	/* restore */
	pthread_mutex_unlock(&sc->mtx);
}

/* Start from seq64 */
/* Locked */
static void
seqcheck_init2(struct sequencechecker *sc, uint64_t seq64)
{
	struct sequencechecker *parent;

	parent = sc->sc_parent;	/* save */

	DEBUGLOG("%s: %s: sc_maxseq = %"PRIu64"(%"PRIx64"), "
	    "lastseq = %u(%x), "
	    "seq64 = %"PRIu64"(%"PRIx64")\n",
	    __func__, sc->sc_name,
	    sc->sc_maxseq, sc->sc_maxseq,
	    sc->sc_lastseq, sc->sc_lastseq,
	    seq64, seq64);
	sc->sc_needinit = 0;
	if (seq64 != 0) {
		/* Force state before clear. */
#if 0
		DEBUGLOG("%s: clear up to = %"PRIu64"(%"PRIx64")\n", __func__,
		    seq64 -1 , seq64 - 1);
#endif
		if ((sc->sc_lastseq) != (uint32_t)(seq64 - 1))
			DEBUGLOG("INIT2: %u(%x) != (uint32)(%"PRIu64"(%"PRIx64") - 1)\n", sc->sc_lastseq, sc->sc_lastseq, seq64, seq64);
		seqcheck_receive_locked(sc, (uint32_t)(seq64 - 1));
//		DEBUGLOG("goto reqcheck_refresh()");
		seqcheck_refresh(sc);
//		seqcheck_dump(sc);
	}

	sc->sc_parent = parent;	/* restore */
}

struct sequencechecker *
seqcheck_new(char *name)
{
	struct sequencechecker *sc;

	sc = malloc(sizeof(struct sequencechecker));
	if (sc != NULL) {
		seqcheck_init(sc);
		strncpy(sc->sc_name, name, sizeof(sc->sc_name));
		DEBUGLOG("%s: name=%s\n", __func__, sc->sc_name);
		pthread_mutex_init(&sc->mtx, NULL);
	}

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
#if 0
		DEBUGLOG("DUP: %s: n = %u, idx=%d, bit=%"PRIx64"\n",
		    sc->sc_name, n, idx, bit);
#endif
		seqcheck_dump(sc);
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
	uint64_t rv;

	pthread_mutex_lock(&sc->mtx);
	rv = seqcheck_receive_locked(sc, seq);
	pthread_mutex_unlock(&sc->mtx);

	return rv;
}

static uint64_t
seqcheck_receive_locked(struct sequencechecker *sc, uint32_t seq)
{
	uint64_t seq64;
#if 0
	uint64_t oldmaxseq;
#endif
	uint64_t i, n, ndrop;
	uint64_t nskip;

//	DEBUGLOG("seqcheck_receive(%u)\n", seq);
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

	if (sc->sc_needinit) {
		seqcheck_init2(sc, seq64);
	}

	sc->sc_nreceive++;
	if (sc->sc_parent)
		sc->sc_parent->sc_nreceive++;


	sc->sc_lastseq = seq;
//	oldmaxseq = sc->sc_maxseq;

	/*
	 * seq64 --------><-------------------------><-----------
	 *         (A)                (B)                 (C)
	 *     outofrange
	 *
	 * ---------------|--------------------|-----|----------->
	 *                bitmap_start      maxseq    bitmap_end
	 */

	if (sc->sc_maxseq < seq64) {
		nskip = seq64 - sc->sc_maxseq;	/* Number of advanced seq */
		sc->sc_maxseq = seq64;		/* Update maxseq */
	} else
		nskip = 0;			/* Not advanced */

	if ((sc->sc_lastseq) != (uint32_t)sc->sc_maxseq)
		DEBUGLOG("RCV(%s): (uint32)(%"PRIu64"(%"PRIx64")) != %u(%x), seq64 = %"PRIu64"(%"PRIx64")\n",
		    sc->sc_name,
		    sc->sc_maxseq, sc->sc_maxseq,
		    sc->sc_lastseq, sc->sc_lastseq,
		    seq64, seq64);

	if (sc->sc_bitmap_start > seq64) {
		/* (A) Out of range */
		sc->sc_outofrange++;
		if (sc->sc_parent)
			sc->sc_parent->sc_outofrange++;
		return 0;
	}
	if (sc->sc_bitmap_end > seq64) {
		/*
		 * (B) Set the bit corresponding to that sequence number.
		 * The duplicate check is also done in this function.
		 */
		seqcheck_bit_set(sc, seq64 - sc->sc_bitmap_start);
		return nskip;
	}

	/* (C) The bitmap array is shifted to set new sequence. */
	/*
	 * 1.
	 * Count the number of bitmap array which will be flushed.
	 */
	n = ((seq64 - sc->sc_bitmap_end) + BIT_PER_DATA) / BIT_PER_DATA;
	if (n > SEQ_ARRAYSIZE) {
		/*
		 * Limit for the next for-loop. The remain will be resolved
		 * later.
		 */
		n = SEQ_ARRAYSIZE;
	}

#if 0
	DEBUGLOG("bms   = %"PRIu64"\n", sc->sc_bitmap_start);
	DEBUGLOG("s64   = %"PRIu64"\n", seq64);
	DEBUGLOG("omsq  = %"PRIu64"\n", oldmaxseq);
	DEBUGLOG("msq   = %"PRIu64"\n", sc->sc_maxseq);
	DEBUGLOG("bme   = %"PRIu64"\n", sc->sc_bitmap_end);
	DEBUGLOG("flush = %"PRIu64"\n", n);
#endif
	/* The drop count is calculated when an bitmap becomes out of range. */
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
#if 0
		DEBUGLOG("ndrop[%"PRIu64"] = %"PRIu64", bs = %"PRIu64", be = %"PRIu64"\n",
		    i, ndrop, sc->sc_bitmap_start, sc->sc_bitmap_end);
#endif
	}
//	DEBUGLOG("dropshift = %"PRIu64"\n", sc->sc_dropshift);
//	DEBUGLOG("bms(C)    = %"PRIu64"\n", sc->sc_bitmap_start);

	/* The sequence advanced more than whole bitmap entries. */
	if (n >= SEQ_ARRAYSIZE) {
		/* Re-calculate remains after finishing the above for loop. */
//		DEBUGLOG("s64 = %"PRIu64"\n", seq64);
//		DEBUGLOG("bme = %"PRIu64"\n", sc->sc_bitmap_end);
		n = ((seq64 - sc->sc_bitmap_end) + BIT_PER_DATA) / BIT_PER_DATA;
//		DEBUGLOG("new n = %"PRIu64"\n", n);

		sc->sc_dropshift += BIT_PER_DATA * n;
		if (sc->sc_parent)
			sc->sc_parent->sc_dropshift += BIT_PER_DATA * n;

		sc->sc_bitmap_end =
		    (seq64 + BIT_PER_DATA) & ~(BIT_PER_DATA - 1);
		sc->sc_bitmap_start = sc->sc_bitmap_end - SEQ_MAXBIT;
	}
//	DEBUGLOG("dropshift2= %"PRIu64"\n", sc->sc_dropshift);

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

uint64_t
seqcheck_outofrangecount(struct sequencechecker *sc)
{
	return sc->sc_outofrange;
}

#if 0
void
seqcheck_dump2(struct sequencechecker *sc)
{
	printf("nreceive   = %llu\n", (unsigned long long)sc->sc_nreceive);
	printf("reorder    = %llu\n", (unsigned long long)sc->sc_reorder);
	printf("duplicate  = %llu\n", (unsigned long long)sc->sc_duplicate);
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
#else
void
seqcheck_dump2(struct sequencechecker *sc)
{
	DEBUGLOG("nreceive   = %llu\n", (unsigned long long)sc->sc_nreceive);
	DEBUGLOG("reorder    = %llu\n", (unsigned long long)sc->sc_reorder);
	DEBUGLOG("duplicate  = %llu\n", (unsigned long long)sc->sc_duplicate);
	DEBUGLOG("outofrange = %llu\n", (unsigned long long)sc->sc_outofrange);
	DEBUGLOG("dropshift  = %llu\n", (unsigned long long)sc->sc_dropshift);
	DEBUGLOG("drop       = %llu\n", (unsigned long long)seqcheck_dropcount(sc));
}

void
seqcheck_dump(struct sequencechecker *sc)
{
	unsigned int i, j, n;
#ifdef DEBUG
	uint64_t start, end;

	start = sc->sc_bitmap_start;
	end = sc->sc_bitmap_end;
#endif

	DEBUGLOG("lastseq    = 0x%llx\n", (unsigned long long)sc->sc_lastseq);
	DEBUGLOG("seq_high   = 0x%llx\n", (unsigned long long)sc->sc_high);

	DEBUGLOG("start      = 0x%llx\n", (unsigned long long)start);
	DEBUGLOG("end        = 0x%llx\n", (unsigned long long)end);
	DEBUGLOG("baseidx    = %llu\n", (unsigned long long)sc->sc_bitmap_baseidx);
	DEBUGLOG("max seq    = 0x%llx\n", (unsigned long long)sc->sc_maxseq);
	seqcheck_dump2(sc);

	i = sc->sc_bitmap_baseidx;
	for (n = 0; n < SEQ_ARRAYSIZE; n++) {
		if ((n & 1) == 0)
			DEBUGLOG("%10llu - %10llu: ",
			    (unsigned long long)start + (n * BIT_PER_DATA),
			    (unsigned long long)start + (n * BIT_PER_DATA) + BIT_PER_DATA * 2 - 1);

		for (j = 0; j < BIT_PER_DATA; j++) {
			DEBUGLOG_CONT("%d", (sc->sc_bitmap[i] & (1ULL << j)) ? 1 : 0);
		}

		if ((n & 1) == 1)
			DEBUGLOG_CONT("\n");
		else
			DEBUGLOG_CONT(" ");

		i = SEQ_NEXT_INDEX(i);
	}
	DEBUGLOG("\n");
}
#endif

#ifdef TEST
#include "seqcheck_test.c"
#endif
