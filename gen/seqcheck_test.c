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

	exit(0);

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
