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
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "libpkt.h"

#define L3OFFSET	sizeof(struct ether_header)



int
main(int argc, char *argv[])
{
	char buf[1514];
	int len, fd;

	const struct ether_addr sha = { 1,2,3,4,5,6 };
	in_addr_t s, t;

	fd = tcpdumpfile_open(NULL);


	memset(buf, 0, sizeof(buf));

	s = htonl(0x01020304);
	t = htonl(0x0a0b0c0d);

#if 0
	/* 16bit checksum pattern test */
	{
		int x, y;

		len = ip4pkt_tcp_template(buf, 128);

		ip4pkt_srcport(buf, L3OFFSET, 0);
		tcpdumpfile_output(fd, buf, len);
		if (ip4pkt_test_cksum(buf, L3OFFSET, sizeof(buf)) != 0)
			fprintf(stderr, "cksum error\n");

		ip4pkt_srcport(buf, L3OFFSET, 255);
		tcpdumpfile_output(fd, buf, len);
		if (ip4pkt_test_cksum(buf, L3OFFSET, sizeof(buf)) != 0)
			fprintf(stderr, "cksum error\n");

		ip4pkt_srcport(buf, L3OFFSET, 0);
		tcpdumpfile_output(fd, buf, len);
		if (ip4pkt_test_cksum(buf, L3OFFSET, sizeof(buf)) != 0)
			fprintf(stderr, "cksum error\n");
	}
	exit(1);
#endif


#if 0
	/* 16bit checksum pattern test */
	{
		int x, y;

		len = ip4pkt_tcp_template(buf, 128);

		for (y = 0; y < 65536; y++) {
			fprintf(stderr, "%d/%d\r", y, 65536);
			ip4pkt_srcport(buf, L3OFFSET, y);
			for (x = 0; x < 65536; x++) {
				ip4pkt_srcport(buf, L3OFFSET, x);
				if (ip4pkt_test_cksum(buf, L3OFFSET, sizeof(buf)) != 0)
					fprintf(stderr, "cksum error\n");
			}
		}
	}
	exit(1);
#endif


#if 0
	{
		len = ip4pkt_icmp_template(buf, sizeof(buf));
		ip4pkt_ttl(buf, L3OFFSET, 4);
		ip4pkt_src(buf, L3OFFSET, inet_addr("10.0.0.2"));
		ip4pkt_dst(buf, L3OFFSET, inet_addr("255.255.255.255"));
		ip4pkt_dst(buf, L3OFFSET, inet_addr("0.0.0.0"));
		ip4pkt_icmptype(buf, L3OFFSET, 8);
		ip4pkt_icmpcode(buf, L3OFFSET, 1);
		ip4pkt_icmpid(buf, L3OFFSET, 0x1234);
		ip4pkt_icmpseq(buf, L3OFFSET, 0x5678);
	}
	tcpdumpfile_output(fd, buf, len);
	tcpdumpfile_output(fd, buf, len);
	tcpdumpfile_output(fd, buf, len);
#endif


#if 0
	{
		len = ip4pkt_tcp_template(buf, 58 + 14);
		ip4pkt_src(buf, L3OFFSET, inet_addr("10.0.0.1"));
		ip4pkt_dst(buf, L3OFFSET, inet_addr("10.1.0.1"));
		ip4pkt_id(buf, L3OFFSET, 1);
		ip4pkt_srcport(buf, L3OFFSET, 9);
		ip4pkt_dstport(buf, L3OFFSET, 9);
//		ip4pkt_tcpflags(buf, L3OFFSET, 0);
//		ip4pkt_tcpseq(buf, L3OFFSET, 0);
//		ip4pkt_tcpack(buf, L3OFFSET, 0);
//		ip4pkt_tcpwin(buf, L3OFFSET, 0);

//		ip4pkt_tcpflags(buf, L3OFFSET, 0x10);
//		ip4pkt_tcpseq(buf, L3OFFSET, 10000001);
//		ip4pkt_tcpack(buf, L3OFFSET, 99999999);
//		ip4pkt_tcpwin(buf, L3OFFSET, 0x4444);

//		ip4pkt_length(buf, L3OFFSET, 58);

#if 0
		char x[] = {
			0x02, 0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00
		};
		ip4pkt_writedata(buf, L3OFFSET, 0, x, sizeof(x));
#endif
	}
	tcpdumpfile_output(fd, buf, len);
#endif


#if 0
	{
		len = ip4pkt_udp_template(buf, sizeof(buf));
		ip4pkt_src(buf, L3OFFSET, inet_addr("10.0.0.2"));
		ip4pkt_dst(buf, L3OFFSET, inet_addr("255.255.255.255"));
		ip4pkt_dst(buf, L3OFFSET, inet_addr("0.0.0.0"));
		ip4pkt_srcport(buf, L3OFFSET, 1234);
		ip4pkt_dstport(buf, L3OFFSET, 5678);
		ip4pkt_length(buf, L3OFFSET, 65535);
		ip4pkt_length(buf, L3OFFSET, 100);

		ip4pkt_tcpwin(buf, L3OFFSET, 0xb0);
		ip4pkt_tcpwin(buf, L3OFFSET, 0);

//		char *x = "HELLO";
//		ip4pkt_writedata(buf, L3OFFSET, 0, x, 5);

#if 1
		char *x = "\xff\xff\xff\xff\xff";
		char *z = "\0\0\0\0\0";
		ip4pkt_writedata(buf, L3OFFSET, 1, x, 5);
//		ip4pkt_writedata(buf, L3OFFSET, 1, z, 4);
#endif
	}

	tcpdumpfile_output(fd, buf, len);
#endif


#if 1
	{
		int i;
		struct in6_addr addr;

		inet_pton(AF_INET6, "ff01::1", &addr);

		len = ip6pkt_udp_template(buf, 100);
		tcpdumpfile_output(fd, buf, len);

		for (i = 100; i < 1400; i+= 13) {
			addr.s6_addr[15] = i;

			len = i;
			ip6pkt_length(buf, L3OFFSET, len);
			ip6pkt_src(buf, L3OFFSET, &addr);
			ip6pkt_srcport(buf, L3OFFSET, i);
			ip6pkt_dstport(buf, L3OFFSET, i);

			tcpdumpfile_output(fd, buf, len + 14);
		}
	}
#endif


	return 0;
}
