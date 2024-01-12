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

static void seqcheck_testinit(const char *, struct sequencechecker *);

static int test0(void);
static int test1(void);
static int test1b(void);
static int test2(void);
static int test3(void);
static int test4(void);
static int test5(void);

/*
 * Print the banner with the function name and initialize seqmap.
 * Must be called in the beginning of each test function.
 */
static void
seqcheck_testinit(const char *funcname, struct sequencechecker *seqmapp)
{

	printf("====================== %s ======================\n", funcname);
	seqcheck_init(seqmapp);
}

static int
test0(void)
{
	struct sequencechecker seqmap;

	seqcheck_testinit(__func__, &seqmap);
	seqcheck_dump(&seqmap);

	return 0;
}

static int
test1(void)
{
	struct sequencechecker seqmap;

	seqcheck_testinit(__func__, &seqmap);

	seqcheck_receive(&seqmap, 0);
	seqcheck_receive(&seqmap, 4097);

	/*
	 * Seqno 0 and 4097 are received. From 1 to 4096 are not received.
	 * nreceived = 2.
	 * Receiving 4097 makes seqno 0-63 out of range. baseidx becomes to 1.
	 * Seqno 0 was received, so 1-63 are regarded as dropped.
	 * The total drop count must be 63.
	 */

	seqcheck_dump(&seqmap);

	return 0;
}

static int
test1b(void)
{
	struct sequencechecker seqmap;

	seqcheck_init(&seqmap);

	seqcheck_receive(&seqmap, 0);
	seqcheck_dump(&seqmap);
	seqcheck_receive(&seqmap, 31);
	seqcheck_dump(&seqmap);
	seqcheck_receive(&seqmap, 64);
	seqcheck_dump(&seqmap);
	seqcheck_receive(&seqmap, 4097);
	seqcheck_dump(&seqmap);
	seqcheck_receive(&seqmap, 4097+4096);
	seqcheck_dump(&seqmap);
	printf("XXX clear\n");
	seqcheck_clear(&seqmap);
	seqcheck_dump(&seqmap);
	printf("XXX jump 100\n");
	seqcheck_receive(&seqmap, 4097+4096+100);
	seqcheck_dump(&seqmap);
	printf("XXX clear2\n");
	seqcheck_clear(&seqmap);
	seqcheck_dump(&seqmap);

	return 0;
}

static int
test2(void)
{
	struct sequencechecker seqmap;

	seqcheck_testinit(__func__, &seqmap);

	seqcheck_receive(&seqmap, 0x78000000);
	seqcheck_dump(&seqmap);

	/*
	 * Seqno 0x78000000 was received.
	 * nreceive must be 1.
	 * dropcount must be 2013265920. (currently broken).
	 */

	seqcheck_receive(&seqmap, 0x81000000);

	seqcheck_dump(&seqmap);

	return 0;
}

static int
test3(void)
{
	struct sequencechecker seqmap;
	uint32_t i;

	seqcheck_testinit(__func__, &seqmap);

	for (i = 0; i < 32; i++) {
		seqcheck_receive(&seqmap, 0xfffffff0 + i);
		seqcheck_dump(&seqmap);
	}

	printf("===================\n");
	for (i = 0; i < 32; i++) {
		seqcheck_receive(&seqmap, 0xfffffff0 + i);
		seqcheck_dump(&seqmap);
	}

	return 0;
}

static int
test4(void)
{
	struct sequencechecker seqmap;

	seqcheck_testinit(__func__, &seqmap);

	seqcheck_receive(&seqmap, 16388); /* XXX SEQ_MAXBIT WAS 16384 now 4096 */
	seqcheck_receive(&seqmap, 16387);
	seqcheck_receive(&seqmap, 16386 + 128);

	seqcheck_dump(&seqmap);

	return 0;
}

static int
test5(void)
{
	struct sequencechecker seqmap;

	seqcheck_testinit(__func__, &seqmap);

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

	return 0;
}

struct testtab {
	int (*func)(void);
} tests[] = {
	{ test0 },
	{ test1 },
	{ test1b },
	{ test2 },
	{ test3 },
	{ test4 },
	{ test5 },
};

static int
doeachtest(u_int i)
{

	return tests[i].func();
}

int
main(int argc, char *argv[])
{
	uint32_t i;
	int rv = 0;

	if (argc == 2) {
		i = strtol(argv[1], NULL, 10);
		return doeachtest(i);
	}
	(void)&argv;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++)
		rv |= doeachtest(i);

	return rv;
}
