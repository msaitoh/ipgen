/*
 * Copyright (c) 1982, 1986, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
 *
 *      @(#)time.h      8.5 (Berkeley) 5/4/95
 */

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
#ifndef _GEN_H_
#define _GEN_H_

#include <time.h>
#include <stdbool.h>

#ifndef timespeccmp
#define	timespeccmp(tvp, uvp, cmp)					\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?				\
	    ((tvp)->tv_nsec cmp (uvp)->tv_nsec) :			\
	    ((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif
#ifndef timespecadd
#define	timespecadd(tsp, usp, vsp)					\
	do {								\
		(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec >= 1000000000L) {			\
			(vsp)->tv_sec++;				\
			(vsp)->tv_nsec -= 1000000000L;			\
		}							\
	} while (0)
#endif
#ifndef timespecsub
#define	timespecsub(tsp, usp, vsp)					\
	do {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} while (0)
#endif


const char *getifname(int);
unsigned long getpps(int);
int setpps(int, unsigned long);
unsigned int getpktsize(int);
int setpktsize(int, unsigned int);
void transmit_set(int, int);
int statistics_clear(void);

extern struct timespec currenttime;
extern bool use_curses;

#define DEBUG 1

#ifdef DEBUG
extern FILE *debugfh;
#define DEBUGOPEN(file)							\
	do {								\
		debugfh = fopen(file, "w");				\
		if (debugfh == NULL)					\
			err(2, "Failed to open %s", file);		\
	} while (0)
/* Log to ipgen-debug.log with timestamp. */
#define DEBUGLOG(fmt, args...)						 \
	do {								 \
		struct timespec realtime_now;				 \
									 \
		clock_gettime(CLOCK_REALTIME, &realtime_now);		 \
		if (!use_curses) {					 \
			printf("%s ", timestamp(realtime_now.tv_sec));	 \
			printf(fmt, ## args); fflush(stdout);		 \
		}							 \
		fprintf(debugfh, "%s ", timestamp(realtime_now.tv_sec)); \
		fprintf(debugfh, fmt, ## args); fflush(debugfh);	 \
	} while (0)
/*
 * Log to ipgen-debug.log without timestamp.
 * Used to write multiple debuglog as one line.
 */
#define DEBUGLOG_CONT(fmt, args...)					\
	do {								\
		fprintf(debugfh, fmt, ## args); fflush(debugfh);	\
	} while (0)
#define DEBUGCLOSE()		fclose(debugfh)
#else
#define DEBUGOPEN(file)		((void)0)
#define DEBUGLOG(args...)	((void)0)
#define DEBUGCLOSE()		((void)0)
#endif

#endif /* _GEN_H_ */
