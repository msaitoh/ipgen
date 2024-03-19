static int test0(void);
static int test1(void);
static int test2(void);
static int test3(void);
static int test4(void);
static int test5(void);


static int
test0(void)
{
	struct sequencechecker seqmap;

	seqcheck_init(&seqmap);
	seqcheck_dump(&seqmap);

	return 0;
}

static int
test1(void)
{
	struct sequencechecker seqmap;

	seqcheck_init(&seqmap);

	seqcheck_receive(&seqmap, 0);
	seqcheck_receive(&seqmap, 4097);

	/*
	 * Seqno 0 and 4097 are received. From 1 to 4096 are not received. nreceived = 2.
	 * Receiving 4097 makes seqno 0-63 out of range. baseidx becomes to 1.
	 * Seqno 0 was received, so 1-63 are regarded as dropped.
	 * The total drop count must be 63.
	 */

	seqcheck_dump(&seqmap);

	return 0;
}

static int
test2(void)
{
	struct sequencechecker seqmap;

	seqcheck_init(&seqmap);

	seqcheck_receive(&seqmap, 0x78000000);
	seqcheck_dump(&seqmap);

	seqcheck_receive(&seqmap, 0x81000000);

	seqcheck_dump(&seqmap);

	return 0;
}

static int
test3(void)
{
	struct sequencechecker seqmap;
	uint32_t i;

	seqcheck_init(&seqmap);

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

	seqcheck_init(&seqmap);

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

	seqcheck_init(&seqmap);

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
	{ test2 },
	{ test3 },
	{ test4 },
	{ test5 },
};

static int
doeachtest(u_int i)
{

	printf("====================== test%u ======================\n", i);
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
