/*
 * Copyright (c) 2013 Ryo Shimizu <ryo@nerv.org>
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
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/if_arp.h>
#ifdef __FreeBSD__
#include <net/ethernet.h>
#else
#include <net/if_ether.h>
#endif
#include <net/bpf.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>
#include <err.h>

#include "libpkt/libpkt.h"


#include "arpresolv.h"

static int bpfread_and_exec(int (*)(void *, unsigned char *, int, const char *), void *, int, const char *, unsigned char *, int);

static int bpfslot(void);
static void arpquery(int, const char *, struct ether_addr *, int, struct in_addr *, struct in_addr *);
static void ndsolicit(int, const char *, struct ether_addr *, int, struct in6_addr *, struct in6_addr *);
static int bpfopen(const char *, int, unsigned int *);
static void bpfclose(int);
static int bpf_arpfilter(int, int);
static int bpf_ndpfilter(int, int);
static int getifinfo(const char *, int *, uint8_t *);


/* for compatibility */
#ifdef __FreeBSD__
#define ether_addr_octet octet
#endif

#define TIMESPECADD(tsp, usp, vsp)					\
	do {								\
		(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec >= 1000000000L) {			\
			(vsp)->tv_sec++;				\
			(vsp)->tv_nsec -= 1000000000L;			\
		}							\
	} while (/* CONSTCOND */ 0)
#define TIMESPECSUB(tsp, usp, vsp)					\
	do {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} while (/* CONSTCOND */ 0)

#ifdef STANDALONE_TEST
#define	__testused
#else
#define	__testused	__unused
#endif

struct recvarp_arg {
	struct in_addr src;
	struct ether_addr src_eaddr;
};

struct recvnd_arg {
	struct in6_addr src;
	struct ether_addr src_eaddr;
};

struct bpf_insn arp_reply_filter[] = {
	/* check ethertype */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, ETHER_ADDR_LEN * 2),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_ARP, 0, 5),

	/* check ar_hrd == ARPHDR_ETHER && ar_pro == ETHERTYPE_IP */
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ETHER_HDR_LEN),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
	    (ARPHRD_ETHER << 16) + ETHERTYPE_IP, 0, 3),
	/* check ar_hln, ar_pln, ar_op */
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ETHER_HDR_LEN + 4),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
	    (ETHER_ADDR_LEN << 24) + (sizeof(struct in_addr) << 16) +
	    ARPOP_REPLY, 0, 1),

	BPF_STMT(BPF_RET + BPF_K, -1),	/* return -1 */
	BPF_STMT(BPF_RET + BPF_K, 0),	/* return 0 */
};


#define VLAN_TAG_SIZE	4
struct bpf_insn arp_reply_filter_vlan[] = {
	/* check ethertype */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, ETHER_ADDR_LEN * 2 + VLAN_TAG_SIZE),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_ARP, 0, 5),

	/* check ar_hrd == ARPHDR_ETHER && ar_pro == ETHERTYPE_IP */
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ETHER_HDR_LEN + VLAN_TAG_SIZE),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
	    (ARPHRD_ETHER << 16) + ETHERTYPE_IP, 0, 3),
	/* check ar_hln, ar_pln, ar_op */
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ETHER_HDR_LEN + VLAN_TAG_SIZE + 4),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
	    (ETHER_ADDR_LEN << 24) + (sizeof(struct in_addr) << 16) +
	    ARPOP_REPLY, 0, 1),

	BPF_STMT(BPF_RET + BPF_K, -1),	/* return -1 */
	BPF_STMT(BPF_RET + BPF_K, 0),	/* return 0 */
};

struct bpf_insn nd_filter[] = {
	/* check ethertype */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, ETHER_ADDR_LEN * 2),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IPV6, 0, 8),

	/* fetch ip6_hdr->ip6_nxt */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETHER_HDR_LEN + 6),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_ICMPV6, 0, 6),

	/* fetch icmp6_hdr->icmp6_type */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETHER_HDR_LEN + sizeof(struct ip6_hdr)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_ROUTER_SOLICIT, 3, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_ROUTER_ADVERT, 2, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_SOLICIT, 1, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_ADVERT, 0, 1),

	BPF_STMT(BPF_RET + BPF_K, -1),	/* return -1 (whole of packet) */
	BPF_STMT(BPF_RET + BPF_K, 0),	/* return 0 (nomatch) */
};

struct bpf_insn nd_filter_vlan[] = {
	/* check ethertype */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, ETHER_ADDR_LEN * 2 + VLAN_TAG_SIZE),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IPV6, 0, 8),

	/* fetch ip6_hdr->ip6_nxt */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETHER_HDR_LEN + 6),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_ICMPV6, 0, 6),

	/* fetch icmp6_hdr->icmp6_type */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETHER_HDR_LEN + VLAN_TAG_SIZE + sizeof(struct ip6_hdr)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_ROUTER_SOLICIT, 3, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_ROUTER_ADVERT, 2, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_SOLICIT, 1, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_ADVERT, 0, 1),

	BPF_STMT(BPF_RET + BPF_K, -1),	/* return -1 (whole of packet) */
	BPF_STMT(BPF_RET + BPF_K, 0),	/* return 0 (nomatch) */
};

#define BPFBUFSIZE	(1024 * 4)
static unsigned char bpfbuf[BPFBUFSIZE];
static unsigned int bpfbuflen = BPFBUFSIZE;

#ifdef STANDALONE_TEST
static int
usage(void)
{
	fprintf(stderr, "usage: arpresolv <interface> <ipv4address>\n");
	fprintf(stderr, "usage: ndresolv <interface> <ipv6address>\n");
	return 99;
}

static int
getaddr(const char *ifname, const struct in_addr *dstaddr, struct in_addr *srcaddr)
{
	int rc;
	struct ifaddrs *ifa0, *ifa;
	struct in_addr src, mask;
	struct in_addr curmask;

	curmask.s_addr = 0;
	src.s_addr = 0;

	rc = getifaddrs(&ifa0);
	ifa = ifa0;
	for (; ifa != NULL; ifa = ifa->ifa_next) {
		if ((strcmp(ifa->ifa_name, ifname) == 0) &&
		    (ifa->ifa_addr->sa_family == AF_INET)) {

			if (src.s_addr == 0)
				src = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;

			/* lookup addr with netmask */
			if (dstaddr != NULL) {
				mask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
				if ((ntohl(mask.s_addr) > ntohl(curmask.s_addr)) &&
				    ((((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr & mask.s_addr) ==
				    (dstaddr->s_addr & mask.s_addr))) {
					src = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
					curmask = mask;
				}
			}
		}
	}

	if (ifa0 != NULL)
		freeifaddrs(ifa0);

	*srcaddr = src;

	return (src.s_addr == 0);
}

static inline int
ip6_iszero(struct in6_addr *addr)
{
	int i;
	for (i = 0; i < 16; i++) {
		if (addr->s6_addr[0] != 0)
			return 0;
	}
	return 1;
}

static int
getaddr6(const char *ifname, const struct in6_addr *dstaddr, struct in6_addr *srcaddr)
{
	int rc;
	struct ifaddrs *ifa0, *ifa;
	struct in6_addr src;

	memset(&src, 0, sizeof(src));

	rc = getifaddrs(&ifa0);
	ifa = ifa0;
	for (; ifa != NULL; ifa = ifa->ifa_next) {
		if ((strcmp(ifa->ifa_name, ifname) == 0) &&
		    (ifa->ifa_addr->sa_family == AF_INET6)) {

			if (ip6_iszero(&src))
				src = ((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;

			/* lookup address that has same prefix */
			if (dstaddr != NULL) {
				if (memcmp(&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, dstaddr, 8) == 0) {
					memcpy(&src, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, 16);
				}
			}
		}
	}

	if (ifa0 != NULL)
		freeifaddrs(ifa0);

	*srcaddr = src;

	return ip6_iszero(&src);
}

int
main(int argc, char *argv[])
{
	int rc;
	char *ifname;
	struct in_addr src, dst;
	struct in6_addr src6, dst6;
	struct ether_addr *eth;
	char buf[INET6_ADDRSTRLEN];
	int vlan;

	if (argc != 3 && argc != 4)
		return usage();

	vlan = 0;
	if (argc == 4) {
		vlan = strtol(argv[3], NULL, 10);
	}

	ifname = argv[1];
	if (inet_pton(AF_INET, argv[2], &dst) == 1) {
		rc = getaddr(ifname, &dst, &src);
		if (rc != 0) {
			fprintf(stderr, "%s: %s: source address is unknown\n",
			    ifname, inet_ntoa(dst));
			return 3;
		}
		eth = arpresolv(ifname, vlan, &src, &dst);
	} else if (inet_pton(AF_INET6, argv[2], &dst6) == 1) {
		rc = getaddr6(ifname, &dst6, &src6);
		if (rc != 0) {
			fprintf(stderr, "%s: %s: source address is unknown\n",
			    ifname, inet_ntop(AF_INET6, &dst6, buf, sizeof(buf)));
			return 3;
		}
		eth = ndpresolv(ifname, vlan, &src6, &dst6);
	} else {
		printf("%s: invalid host\n", argv[2]);
		return 2;
	}

	if (eth != NULL) {
		printf("%s\n", ether_ntoa(eth));
		return 0;
	}
	return 1;
}
#endif

static int
recv_arpreply(void *arg, unsigned char *buf, int buflen, const char *ifname __testused)
{
	struct arppkt_l2 *arppkt;
	struct recvarp_arg *recvarparg;

#ifdef STANDALONE_TEST
	fprintf(stderr, "recv_arpreply: %s\n", ifname);
	dumpstr((const char *)buf, buflen, 0);
#endif

	recvarparg = (struct recvarp_arg *)arg;
	arppkt = (struct arppkt_l2 *)buf;

	if (ntohs(arppkt->eheader.ether_type) == ETHERTYPE_VLAN) {
		/* XXX: adjust for vlan. don't access arppkt->eheader anymore */
		arppkt = (struct arppkt_l2 *)((char *)arppkt + 4);
	}

	if (arppkt->arp.ar_spa.s_addr != recvarparg->src.s_addr)
		return 0;

	memcpy(&recvarparg->src_eaddr, (struct ether_addr *)(arppkt->arp.ar_sha), sizeof(struct ether_addr));

	return 1;
}

static int
recv_nd(void *arg, unsigned char *buf, int buflen, const char *ifname __testused)
{
	struct ndpkt_l2 *ndpkt_l2;
	struct recvnd_arg *recvndarg;

#ifdef STANDALONE_TEST
	fprintf(stderr, "recv_nd: %s\n", ifname);
	dumpstr((const char *)buf, buflen, 0);
#endif

	recvndarg = (struct recvnd_arg *)arg;
	ndpkt_l2 = (struct ndpkt_l2 *)buf;

	if (ntohs(ndpkt_l2->eheader.ether_type) == ETHERTYPE_VLAN) {
		/* XXX: adjust for vlan. don't access ndpkt->eheader anymore */
		ndpkt_l2 = (struct ndpkt_l2 *)((char *)ndpkt_l2 + 4);
	}

	if (ndpkt_l2->nd_icmp6.icmp6_type != ND_NEIGHBOR_ADVERT)
		return 0;

	memcpy(&recvndarg->src_eaddr, &ndpkt_l2->opt[2], sizeof(struct ether_addr));

	return 1;
}

struct ether_addr *
arpresolv(const char *ifname, int vlan, struct in_addr *src, struct in_addr *dst)
{
	fd_set rfd;
	struct timespec end, lim, now;
	struct timeval tlim;
	struct ether_addr macaddr;
	struct ether_addr *found;
	int fd, rc, mtu, nretry;

	found = NULL;

	fd = bpfopen(ifname, 0, &bpfbuflen);
	if (fd < 0) {
		warn("open: %s", ifname);
		return NULL;
	}

	bpf_arpfilter(fd, vlan);

	rc = getifinfo(ifname, &mtu, macaddr.ether_addr_octet);
	if (rc != 0) {
		warn("%s", ifname);
		return NULL;
	}

	for (nretry = 3; nretry > 0; nretry--) {
		arpquery(fd, ifname, &macaddr, vlan, src, dst);

		lim.tv_sec = 1;
		lim.tv_nsec = 0;
		clock_gettime(CLOCK_MONOTONIC, &end);

		TIMESPECADD(&lim, &end, &end);

		for (;;) {
			clock_gettime(CLOCK_MONOTONIC, &now);
			TIMESPECSUB(&end, &now, &lim);
			if (lim.tv_sec < 0)
				break;

			TIMESPEC_TO_TIMEVAL(&tlim, &lim);

			FD_ZERO(&rfd);
			FD_SET(fd, &rfd);
			rc = select(fd + 1, &rfd, NULL, NULL, &tlim);
			if (rc < 0) {
				err(1, "select");
				break;
			}

			if (rc == 0) {
				char buf[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, dst, buf, sizeof(buf));
				fprintf(stderr, "%s: %s: arp timeout\n", ifname, buf);
				break;
			}
			if (FD_ISSET(fd, &rfd)) {
				static struct recvarp_arg arg;
				memset(&arg, 0, sizeof(arg));
				arg.src = *dst;

				rc = bpfread_and_exec(recv_arpreply, (void *)&arg, fd, ifname, bpfbuf, bpfbuflen);
				if (rc != 0) {
					found = &arg.src_eaddr;
					break;
				}
			}
		}
		if (found != NULL)
			break;
	}

	bpfclose(fd);

	return found;
}

struct ether_addr *
ndpresolv(const char *ifname, int vlan, struct in6_addr *src, struct in6_addr *dst)
{
	fd_set rfd;
	struct timespec end, lim, now;
	struct timeval tlim;
	struct ether_addr macaddr;
	struct ether_addr *found;
	int fd, rc, mtu, nretry;

	found = NULL;

	fd = bpfopen(ifname, 0, &bpfbuflen);
	if (fd < 0) {
		warn("open: %s", ifname);
		return NULL;
	}

	bpf_ndpfilter(fd, vlan);

	rc = getifinfo(ifname, &mtu, macaddr.ether_addr_octet);
	if (rc != 0) {
		warn("%s", ifname);
		return NULL;
	}

	for (nretry = 3; nretry > 0; nretry--) {
		ndsolicit(fd, ifname, &macaddr, vlan, src, dst);

		lim.tv_sec = 1;
		lim.tv_nsec = 0;
		clock_gettime(CLOCK_MONOTONIC, &end);

		TIMESPECADD(&lim, &end, &end);

		for (;;) {
			clock_gettime(CLOCK_MONOTONIC, &now);
			TIMESPECSUB(&end, &now, &lim);
			if (lim.tv_sec < 0)
				break;

			TIMESPEC_TO_TIMEVAL(&tlim, &lim);

			FD_ZERO(&rfd);
			FD_SET(fd, &rfd);
			rc = select(fd + 1, &rfd, NULL, NULL, &tlim);
			if (rc < 0) {
				err(1, "select");
				break;
			}

			if (rc == 0) {
				char buf[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, dst, buf, sizeof(buf));
				fprintf(stderr, "%s: [%s]: neighbor solicit timeout\n", ifname, buf);
				break;
			}
			if (FD_ISSET(fd, &rfd)) {
				static struct recvnd_arg arg;
				memset(&arg, 0, sizeof(arg));
				arg.src = *dst;

				rc = bpfread_and_exec(recv_nd, (void *)&arg, fd, ifname, bpfbuf, bpfbuflen);
				if (rc != 0) {
					found = &arg.src_eaddr;
					break;
				}
			}
		}
		if (found != NULL)
			break;
	}

	bpfclose(fd);

	return found;
}

static int
bpfslot(void)
{
	int fd, i;

#ifdef _PATH_BPF
	fd = open(_PATH_BPF, O_RDWR);
#else
	char devbpf[PATH_MAX + 1];

	memset(devbpf, 0, sizeof(devbpf));
	i = 0;
	do {
		snprintf(devbpf, sizeof(devbpf), "/dev/bpf%d", i++);
		fd = open(devbpf, O_RDWR);
	} while ((fd < 0) && (errno == EBUSY));
#endif

	return fd;
}

static int
bpf_arpfilter(int fd, int vlan)
{
	struct bpf_program bpfprog;
	int rc;

	memset(&bpfprog, 0, sizeof(bpfprog));

	if (vlan) {
		bpfprog.bf_len = nitems(arp_reply_filter_vlan);
		bpfprog.bf_insns = arp_reply_filter_vlan;
	} else {
		bpfprog.bf_len = nitems(arp_reply_filter);
		bpfprog.bf_insns = arp_reply_filter;
	}

	rc = ioctl(fd, BIOCSETF, &bpfprog);
	if (rc != 0)
		warn("ioctl: BIOCSETF (arp filter)");

	return rc;
}

static int
bpf_ndpfilter(int fd, int vlan)
{
	struct bpf_program bpfprog;
	int rc;

	memset(&bpfprog, 0, sizeof(bpfprog));
	if (vlan) {
		bpfprog.bf_len = nitems(nd_filter_vlan);
		bpfprog.bf_insns = nd_filter_vlan;
	} else {
		bpfprog.bf_len = nitems(nd_filter);
		bpfprog.bf_insns = nd_filter;
	}

	rc = ioctl(fd, BIOCSETF, &bpfprog);
	if (rc != 0)
		warn("ioctl: BIOCSETF (ndp filter)");

	return rc;
}

static int
bpfopen(const char *ifname, int promisc, unsigned int *buflen)
{
	int fd, flag, rc;
	struct ifreq ifr;
	struct bpf_version bv;

	rc = 0;
	fd = bpfslot();
	if (fd < 0) {
		warn("open: bpf");
		rc = -1;
		goto bpfopen_err;
	}

	if (ioctl(fd, BIOCVERSION, (caddr_t)&bv) < 0) {
		warn("ioctl: BIOCVERSION");
		rc = -1;
		goto bpfopen_err;
	}

	if (bv.bv_major != BPF_MAJOR_VERSION ||
	    bv.bv_minor < BPF_MINOR_VERSION) {
		fprintf(stderr, "kernel bpf filter out of date");
		rc = -1;
		goto bpfopen_err;
	}

	memset(&ifr, 0, sizeof(ifr));
	if (ifname != NULL) {
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
			warn("ioctl: %s: BIOCSETIF", ifname);
			rc = -2;
			goto bpfopen_warn;
		}
	}

	flag = 1;
	ioctl(fd, BIOCIMMEDIATE, &flag);

	if (promisc) {
		if (ioctl(fd, BIOCPROMISC, 0) != 0) {
			warn("ioctl: BIOCPROMISC: %s", ifname);
		}
	}

	ioctl(fd, BIOCSBLEN, buflen);
	ioctl(fd, BIOCGBLEN, buflen);	/* return value for caller */

	return fd;

 bpfopen_warn:
 bpfopen_err:
	if (fd >= 0)
		close(fd);

	return rc;
}

static void
bpfclose(int fd)
{
	close(fd);
}

static int
getifinfo(const char *ifname, int *mtu, uint8_t *hwaddr)
{
	int mib[6] = {
		CTL_NET,
		AF_ROUTE,
		0,
		AF_LINK,
		NET_RT_IFLIST,
		0
	};
	uint8_t *buf, *end, *msghdr;
	struct if_msghdr *ifm;
	struct if_data *ifd = NULL;
	struct sockaddr_dl *sdl;
	size_t len;
	int rc;

	rc = -1;
	buf = NULL;
	if (sysctl(mib, 6, NULL, &len, NULL, 0) == -1) {
		fprintf(stderr, "sysctl: %s: cannot get iflist size",
		    strerror(errno));
		goto getifinfo_done;
	}
	if ((buf = malloc(len)) == NULL) {
		fprintf(stderr, "cannot allocate memory");
		goto getifinfo_done;
	}
	if (sysctl(mib, 6, buf, &len, NULL, 0) == -1) {
		fprintf(stderr, "sysctl: %s: cannot get iflist",
		    strerror(errno));
		goto getifinfo_done;
	}

	end = buf + len;
	for (msghdr = buf; msghdr < end; msghdr += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)msghdr;
		if (ifm->ifm_type == RTM_IFINFO) {
			sdl = (struct sockaddr_dl *)(ifm + 1);

			if (sdl->sdl_type != IFT_ETHER)
				continue;
			if (strncmp(&sdl->sdl_data[0], ifname, sdl->sdl_nlen)
			    != 0)
				continue;


			ifd = &ifm->ifm_data;
			if (mtu != NULL)
				*mtu = ifd->ifi_mtu;
			memcpy(hwaddr, LLADDR(sdl), ETHER_ADDR_LEN);
			rc = 0;
			break;
		}
	}
	if (rc != 0)
		fprintf(stderr,
		    "%s: Not a ethernet interface or no such interface",
		    ifname);

 getifinfo_done:
	if (buf != NULL)
		free(buf);

	return rc;
}

static char *
vlanize_malloc(int vlan, const char *pkt, unsigned int pktsize)
{
	char *p = malloc(pktsize + 4);
	struct ether_vlan_header *evl;

	if (p != NULL) {
		/* copy src/dst mac */
		memcpy(p, pkt, 12);

		/* insert vlan tag */
		evl = (struct ether_vlan_header *)p;
		evl->evl_encap_proto = htons(ETHERTYPE_VLAN);
		evl->evl_tag = htons(vlan);

		/* copy L2 payload */
		memcpy(p + 16, pkt + 12, pktsize - 12);
	}

	return p;
}

static void
arpquery(int fd, const char *ifname __testused, struct ether_addr *sha, int vlan, struct in_addr *src, struct in_addr *dst)
{
	struct arppkt_l2 aquery;
	static const uint8_t eth_broadcast[ETHER_ADDR_LEN] =
	    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	/* build arp reply packet */
	memset(&aquery, 0, sizeof(aquery));
	memcpy(&aquery.eheader.ether_dhost, eth_broadcast, ETHER_ADDR_LEN);
	memcpy(&aquery.eheader.ether_shost, sha->ether_addr_octet,
	    ETHER_ADDR_LEN);
	aquery.eheader.ether_type = htons(ETHERTYPE_ARP);
	aquery.arp.ar_hrd = htons(ARPHRD_ETHER);
	aquery.arp.ar_pro = htons(ETHERTYPE_IP);
	aquery.arp.ar_hln = ETHER_ADDR_LEN;
	aquery.arp.ar_pln = sizeof(struct in_addr);
	aquery.arp.ar_op = htons(ARPOP_REQUEST);
	memcpy(&aquery.arp.ar_sha, sha->ether_addr_octet,
	    ETHER_ADDR_LEN);
	memcpy(&aquery.arp.ar_spa, src, sizeof(struct in_addr));
	memcpy(&aquery.arp.ar_sha, sha->ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(&aquery.arp.ar_tpa, dst, sizeof(struct in_addr));

#ifdef STANDALONE_TEST
	fprintf(stderr, "send arp-query on %s\n", ifname);
	dumpstr((const char *)&aquery, sizeof(aquery), 0);
#endif

	/* send an arp-query via bpf */
	if (vlan) {
		char *p = vlanize_malloc(vlan, (const char *)&aquery, sizeof(aquery));
		write(fd, p, sizeof(aquery) + 4);
		free(p);
	} else {
		write(fd, &aquery, sizeof(aquery));
	}
}

static void
ndsolicit(int fd, const char *ifname __testused, struct ether_addr *sha, int vlan, struct in6_addr *src, struct in6_addr *dst)
{
	char pktbuf[LIBPKT_PKTBUFSIZE];
	unsigned int pktlen;

	pktlen = ip6pkt_neighbor_solicit(pktbuf, sha, src, dst);

#ifdef STANDALONE_TEST
	fprintf(stderr, "send nd-solicit on %s\n", ifname);
	dumpstr((const char *)pktbuf, pktlen, 0);
#endif

	/* send an arp-query via bpf */
	if (vlan) {
		char *p = vlanize_malloc(vlan, pktbuf, pktlen);
		write(fd, p, pktlen + 4);
		free(p);
	} else {
		write(fd, pktbuf, pktlen);
	}
}

static int
bpfread_and_exec(int (*recvcallback)(void *, unsigned char *, int, const char *),
    void *callbackarg, int fd, const char *ifname,
    unsigned char *buf, int buflen)
{
	ssize_t rc;

	rc = read(fd, buf, buflen);
	if (rc == 0) {
		fprintf(stderr, "read: bpf: no data\n");
		return -1;
	} else if (rc < 0) {
		warn("read");
		return -1;
	} else {
		uint8_t *p = buf;
		uint8_t *end = p + rc;

		rc = 0;
		while (p < end) {
			unsigned int perpacketsize =
			    ((struct bpf_hdr*)p)->bh_hdrlen +
			    ((struct bpf_hdr*)p)->bh_caplen;

#ifdef STANDALONE_TEST
			fprintf(stderr, "Received packet on %s\n", ifname);
			dumpstr(
			    (const char *)p + ((struct bpf_hdr*)p)->bh_hdrlen,
			    ((struct bpf_hdr*)p)->bh_datalen, 0);
#endif

			rc = recvcallback(callbackarg,
			    ((uint8_t *)p + ((struct bpf_hdr*)p)->bh_hdrlen),
			    ((struct bpf_hdr*)p)->bh_datalen, ifname);

			if (rc != 0)
				break;

			p += BPF_WORDALIGN(perpacketsize);
		}
	}

	return rc;
}
