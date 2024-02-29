/*
 * Copyright (c) 2022 Ryo Shimizu
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
#include <sys/random.h>
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
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <err.h>

#include "libpkt/libpkt.h"
#include "pppoe.h"

static int bpfread_and_exec(int (*)(void *, int, char *, int, const char *), void *, int, const char *, unsigned char *, int);

static int bpfslot(void);
static int bpfopen(const char *, int, unsigned int *);
static void bpfclose(int);
static int bpf_pppoefilter(int);
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

struct bpf_insn pppoe_filter[] = {
	/* check ethertype */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, ETHER_ADDR_LEN * 2),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_PPPOEDISC, 1, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_PPPOE, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, -1),	/* return -1 */
	BPF_STMT(BPF_RET + BPF_K, 0),	/* return 0 */
};

#define BPFBUFSIZE	(1024 * 4)
static unsigned char bpfbuf[BPFBUFSIZE];
static unsigned int bpfbuflen = BPFBUFSIZE;

static char *
strmacaddr(const uint8_t *eth)
{
	static char buf[3 * ETHER_ADDR_LEN];

	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
	    eth[0], eth[1],
	    eth[2], eth[3],
	    eth[4], eth[5]);

	return buf;
}

const static char *
strpppoecode(uint8_t code)
{
	static char buf[sizeof("0x00")];

	switch (code) {
	case PPPOE_CODE_PADI:
		return "PADI";
	case PPPOE_CODE_PADO:
		return "PADO";
	case PPPOE_CODE_PADR:
		return "PADR";
	case PPPOE_CODE_PADS:
		return "PADS";
	case PPPOE_CODE_PADT:
		return "PADT";
	}

	snprintf(buf, sizeof(buf), "0x%02x", code & 0xff);
	return buf;
}

const static char *
strpppproto(uint16_t proto)
{
	static char buf[sizeof("0x0000")];

	switch (proto) {
	case PPP_IP:
		return "IP";
	case PPP_IPV6:
		return "IPV6";
	case PPP_IPCP:
		return "IPCP";
	case PPP_IPV6CP:
		return "IPV6CP";
	case PPP_LCP:
		return "LCP";
	case PPP_PAP:
		return "PAP";
	case PPP_CHAP:
		return "CHAP";
	default:
		snprintf(buf, sizeof(buf), "0x%04x", proto);
		return buf;
	}
	return NULL;
}

const static char *
strlcptype(uint8_t type)
{
	static char buf[sizeof("0x0000")];

	switch (type) {
	case CONF_REQ:
		return "CONF_REQ";
	case CONF_ACK:
		return "CONF_ACK";
	case CONF_NAK:
		return "CONF_NAK";
	case CONF_REJ:
		return "CONF_REJ";
	case TERM_REQ:
		return "TERM_REQ";
	case TERM_ACK:
		return "TERM_ACK";
	case CODE_REJ:
		return "CODE_REJ";
	case PROTO_REJ:
		return "PROTO_REJ";
	case ECHO_REQ:
		return "ECHO_REQ";
	case ECHO_REPLY:
		return "ECHO_REPLY";
	case DISC_REQ:
		return "DISC_REQ";
	default:
		snprintf(buf, sizeof(buf), "0x%02x", type);
		return buf;
	}
	return NULL;
}

static void
pppdump(char *buf, const char *ifname)
{
	struct pppoe_l2 *req;
	struct pppoeppp *pppreq;
	uint16_t etype;
	int code;

	req = (struct pppoe_l2 *)buf;
	pppreq = (struct pppoeppp *)(req + 1);


	fprintf(stderr, "%s: ", ifname);
	fprintf(stderr, "%s -> ", strmacaddr(req->eheader.ether_shost));
	fprintf(stderr, "%s ", strmacaddr(req->eheader.ether_dhost));

	etype = ntohs(req->eheader.ether_type);
	code = req->pppoe.code;

	switch (etype) {
	case ETHERTYPE_PPPOEDISC:
		fprintf(stderr, "PPPoE-Discovery ");
		fprintf(stderr, "%s (0x%04x)\n",
		    strpppoecode(code),
		    ntohs(req->pppoe.session));
		break;
	case ETHERTYPE_PPPOE:
		fprintf(stderr, "PPPoE ");
		switch (ntohs(pppreq->protocol)) {
		case PPP_LCP:
		case PPP_IPCP:
			fprintf(stderr, "%s %s\n",
			    strpppproto(ntohs(pppreq->protocol)),
			    strlcptype(pppreq->ppp.type));
			break;
		case PPP_CHAP:
			fprintf(stderr, "CHAP\n");
			break;
		case PPP_PAP:
			fprintf(stderr, "PAP\n");
			break;
		default:
			fprintf(stderr, "%04x\n", ntohs(pppreq->protocol));
			break;
		}
		break;
	}
}

static int
recv_pppoe(void *arg, int fd, char *buf, int buflen, const char *ifname)
{
	struct pppoe_softc *sc;
	struct pppoe_l2 *req;
	char pktbuf[2048];
	unsigned char pppopt[128];
	uint16_t etype;
	int code, pktlen;

	sc = (struct pppoe_softc *)arg;

#if 0
	fprintf(stderr, "%s: %s\n", __func__, ifname);
	dumpstr((const char *)buf, buflen, 0);
#endif

	req = (struct pppoe_l2 *)buf;

	/* ignore packets sent by itself */
	if (memcmp(&sc->srcmac, req->eheader.ether_shost, ETHER_ADDR_LEN) == 0)
		return 0;

	etype = ntohs(req->eheader.ether_type);
	code = req->pppoe.code;

	pppdump(buf, ifname);

#if 0
	fprintf(stderr, "ver=%d,type=%d, Code=%s, Session=0x%08x, len=%d\n",
	    req->pppoe.vertype >> 4,
	    req->pppoe.vertype & 0xf,
	    strpppoecode(code),
	    ntohs(req->pppoe.session),
	    ntohs(req->pppoe.plen));
#endif

	switch (etype) {
	case ETHERTYPE_PPPOEDISC:
		switch (code) {
		case PPPOE_CODE_PADT:
			sc->pppoe_result = -1;
			break;

		case PPPOE_CODE_PADI:
			sc->hunique_len = sizeof(sc->hunique);
			pppoepkt_tag_extract((void *)req, PPPOE_TAG_HUNIQUE, sc->hunique, &sc->hunique_len);

			memcpy(&sc->dstmac, req->eheader.ether_shost, ETHER_ADDR_LEN);

			memset(pktbuf, 0, sizeof(pktbuf));
			pppoepkt_template(pktbuf, ETHERTYPE_PPPOEDISC);
			ethpkt_src(pktbuf, sc->srcmac.octet);
			ethpkt_dst(pktbuf, req->eheader.ether_shost);
			pppoepkt_code(pktbuf, PPPOE_CODE_PADO);

			pktlen = pppoepkt_tag_add(pktbuf, PPPOE_TAG_SNAME, NULL, 0);
			pktlen = pppoepkt_tag_add(pktbuf, PPPOE_TAG_ACNAME, "IIJipgen", 8);
			pktlen = pppoepkt_tag_add(pktbuf, PPPOE_TAG_HUNIQUE, sc->hunique, sc->hunique_len);

			write(fd, pktbuf, pktlen);
			pppdump(pktbuf, ifname);
			break;

		case PPPOE_CODE_PADR:
			memset(pktbuf, 0, sizeof(pktbuf));
			pppoepkt_template(pktbuf, ETHERTYPE_PPPOEDISC);
			ethpkt_src(pktbuf, sc->srcmac.octet);
			ethpkt_dst(pktbuf, req->eheader.ether_shost);
			pppoepkt_code(pktbuf, PPPOE_CODE_PADS);
			pppoepkt_session(pktbuf, sc->session);

			pppoepkt_tag_add(pktbuf, PPPOE_TAG_SNAME, NULL, 0);
			pppoepkt_tag_add(pktbuf, PPPOE_TAG_ACNAME, "IIJipgen", 8);
			pktlen = pppoepkt_tag_add(pktbuf, PPPOE_TAG_HUNIQUE, sc->hunique, sc->hunique_len);

			write(fd, pktbuf, pktlen);
			pppdump(pktbuf, ifname);
			sc->lcp_state = 1;	/* to send LCP CONF-REQ */

			break;
		}
		break;

	case ETHERTYPE_PPPOE:
		{
			struct pppoeppp *pppreq = (struct pppoeppp *)(req + 1);

			switch (ntohs(pppreq->protocol)) {
			case PPP_LCP:
				switch (pppreq->ppp.type) {
				case CONF_REQ:	/* LCP REQ */
					memset(pktbuf, 0, sizeof(pktbuf));
					pppoepkt_template(pktbuf, ETHERTYPE_PPPOE);
					ethpkt_src(pktbuf, sc->srcmac.octet);
					ethpkt_dst(pktbuf, req->eheader.ether_shost);
					pppoepkt_session(pktbuf, sc->session);

					pktlen = pppoepkt_ppp_set(pktbuf, PPP_LCP, CONF_ACK, pppreq->ppp.id);
					write(fd, pktbuf, pktlen);
					pppdump(pktbuf, ifname);

					break;

				case CONF_ACK:	/* LCP ACK */
					break;

				case ECHO_REQ:	/* LCP ECHO REQ */
					memset(pktbuf, 0, sizeof(pktbuf));
					pppoepkt_template(pktbuf, ETHERTYPE_PPPOE);
					ethpkt_src(pktbuf, sc->srcmac.octet);
					ethpkt_dst(pktbuf, req->eheader.ether_shost);
					pppoepkt_session(pktbuf, sc->session);
					pktlen = pppoepkt_ppp_set(pktbuf, PPP_LCP, ECHO_REPLY, pppreq->ppp.id);

					/* add a magic */
					memcpy(pppopt, &sc->magic, 4);
					pktlen = pppoepkt_ppp_add_data(pktbuf, pppopt, 4);

					write(fd, pktbuf, pktlen);
					pppdump(pktbuf, ifname);
					break;

				case TERM_REQ:	/* LCP TERM REQ */
					memset(pktbuf, 0, sizeof(pktbuf));
					pppoepkt_template(pktbuf, ETHERTYPE_PPPOE);
					ethpkt_src(pktbuf, sc->srcmac.octet);
					ethpkt_dst(pktbuf, req->eheader.ether_shost);
					pppoepkt_session(pktbuf, sc->session);
					pktlen = pppoepkt_ppp_set(pktbuf, PPP_LCP, TERM_ACK, pppreq->ppp.id);

					write(fd, pktbuf, pktlen);
					pppdump(pktbuf, ifname);

					sc->pppoe_result = -1;

					break;
				}
				break;

			case PPP_CHAP:	/* CHAP * */
				//XXX: notyet
				break;

			case PPP_PAP:
				switch (pppreq->ppp.type) {
				case PAP_REQ:
					memset(pktbuf, 0, sizeof(pktbuf));
					pppoepkt_template(pktbuf, ETHERTYPE_PPPOE);
					ethpkt_src(pktbuf, sc->srcmac.octet);
					ethpkt_dst(pktbuf, req->eheader.ether_shost);
					pppoepkt_session(pktbuf, sc->session);
					pktlen = pppoepkt_ppp_set(pktbuf, PPP_PAP, PAP_ACK, pppreq->ppp.id);

					/* need some data? */
					memset(pppopt, 0, 1);
					pktlen = pppoepkt_ppp_add_data(pktbuf, pppopt, 1);

					write(fd, pktbuf, pktlen);
					pppdump(pktbuf, ifname);

					break;
				}

				break;

			case PPP_IPCP:
				switch (pppreq->ppp.type) {
				case CONF_REQ:	/* IPCP REQ */
					if (sc->ipcp_state == 0)
						sc->ipcp_state = 1;

					{
						int ack_nack = CONF_ACK;
						struct in_addr *x = (struct in_addr *)pppopt;

						if (pppoepkt_ppp_extract_data(buf, IPCP_OPT_ADDRESS, pppopt, sizeof(pppopt)) < 0 ||
						    x->s_addr != sc->dstip.s_addr) {
							ack_nack = CONF_NAK;
						}

						memset(pktbuf, 0, sizeof(pktbuf));
						pppoepkt_template(pktbuf, ETHERTYPE_PPPOE);
						ethpkt_src(pktbuf, sc->srcmac.octet);
						ethpkt_dst(pktbuf, req->eheader.ether_shost);
						pppoepkt_session(pktbuf, sc->session);

						pktlen = pppoepkt_ppp_set(pktbuf, PPP_IPCP, ack_nack, pppreq->ppp.id);

						pppopt[0] = IPCP_OPT_ADDRESS;
						pppopt[1] = 2 + 4;
						memcpy(&pppopt[2], &sc->dstip, 4);
						pktlen = pppoepkt_ppp_add_data(pktbuf, pppopt, pppopt[1]);

						write(fd, pktbuf, pktlen);
						pppdump(pktbuf, ifname);

						if (ack_nack == CONF_ACK)
							sc->pppoe_result = 1;
					}

					break;

				case CONF_ACK:	/* IPCP ACK */
					break;
				}

				break;
			}
		}

		break;
	}

	if (sc->lcp_state == -1) {
		sc->pppoe_result = -1;

	} else if (sc->lcp_state == 1) {
		sc->lcp_state = 2;
		/* send conf-req */
		memset(pktbuf, 0, sizeof(pktbuf));
		pppoepkt_template(pktbuf, ETHERTYPE_PPPOE);
		ethpkt_src(pktbuf, sc->srcmac.octet);
		ethpkt_dst(pktbuf, req->eheader.ether_shost);
		pppoepkt_session(pktbuf, sc->session);
		pktlen = pppoepkt_ppp_set(pktbuf, PPP_LCP, CONF_REQ, 1);
#if 0
		pppopt[0] = LCP_OPT_MAGIC;
		pppopt[1] = 2 + 4;
		memcpy(&pppopt[2], &sc->magic, 4);
		pktlen = pppoepkt_ppp_add_data(pktbuf, pppopt, pppopt[1]);
#endif
#if 0
		/* CHAP */
		pppopt[0] = LCP_OPT_AUTH_PROTO;
		pppopt[1] = 2 + 3;
		pppopt[2] = 0xc2;
		pppopt[3] = 0x23;
		pppopt[4] = 0x05;
		pktlen = pppoepkt_ppp_add_data(pktbuf, pppopt, pppopt[1]);
#endif

		write(fd, pktbuf, pktlen);
		pppdump(pktbuf, ifname);
	}


	if (sc->ipcp_state == 1) {
		sc->ipcp_state = 2;

		/* send IPCP req */
		memset(pktbuf, 0, sizeof(pktbuf));
		pppoepkt_template(pktbuf, ETHERTYPE_PPPOE);
		ethpkt_src(pktbuf, sc->srcmac.octet);
		ethpkt_dst(pktbuf, req->eheader.ether_shost);
		pppoepkt_session(pktbuf, sc->session);
		pktlen = pppoepkt_ppp_set(pktbuf, PPP_IPCP, CONF_REQ, 1);

		pppopt[0] = IPCP_OPT_ADDRESS;
		pppopt[1] = 2 + 4;
		memcpy(&pppopt[2], &sc->srcip, 4);
		pktlen = pppoepkt_ppp_add_data(pktbuf, pppopt, pppopt[1]);

		write(fd, pktbuf, pktlen);
		pppdump(pktbuf, ifname);
	}

	if (sc->pppoe_result != 0)
		return sc->pppoe_result;

	return 0;
}

int
pppoe_server(const char *ifname, struct pppoe_softc *sc)
{
	fd_set rfd;
	struct timeval tlim;
	struct ether_addr macaddr;
	int fd, rc, mtu, error, established = 0;

	fd = bpfopen(ifname, 0, &bpfbuflen);
	if (fd < 0) {
		warn("open: %s", ifname);
		return -1;
	}

	bpf_pppoefilter(fd);

	rc = getifinfo(ifname, &mtu, macaddr.ether_addr_octet);
	if (rc != 0) {
		warn("%s", ifname);
		return -1;
	}

	memcpy(&sc->srcmac, &macaddr, ETHER_ADDR_LEN);
	sc->mtu = mtu;

	error = -1;
	for (;;) {
		if (established) {
			tlim.tv_sec = 5;
		} else {
			tlim.tv_sec = 10;
		}
		tlim.tv_usec = 0;

		FD_ZERO(&rfd);
		FD_SET(fd, &rfd);
		rc = select(fd + 1, &rfd, NULL, NULL, &tlim);
		if (rc < 0) {
			warn("select");
			break;
		}

		if (rc == 0) {
			if (established) {
				error = 1;
				break;
			}
			fprintf(stderr, "%s: pppoe timeout\n", ifname);
			errno = ETIMEDOUT;
			break;
		}
		if (FD_ISSET(fd, &rfd)) {
			rc = bpfread_and_exec(recv_pppoe, (void *)sc, fd, ifname, bpfbuf, bpfbuflen);
			if (rc > 0) {
				established = 1;
			} else if (rc < 0) {
				error = rc;
				break;
			}
		}
	}

	bpfclose(fd);

	return error;
}

#ifdef STANDALONE_TEST
static int
usage(void)
{
	fprintf(stderr, "usage: pppoe <interface>\n");
	return 99;
}

int
main(int argc, char *argv[])
{
	struct pppoe_softc pppoe_softc;
	const char *ifname;
	int rc;

	if (argc != 2)
		return usage();

	ifname = argv[1];

	memset(&pppoe_softc, 0, sizeof(pppoe_softc));
	pppoe_softc.ifname = ifname;
	inet_aton("10.1.0.1", &pppoe_softc.srcip);
	inet_aton("10.1.0.2", &pppoe_softc.dstip);
	pppoe_softc.session = getpid() & 0xffff;
	getrandom(&pppoe_softc.magic, sizeof(pppoe_softc.magic), 0);

	rc = pppoe_server(ifname, &pppoe_softc);

	printf("pppoe_server -> %d\n", rc);

	return 1;
}
#endif


static int
bpfslot(void)
{
	int fd;

#ifdef _PATH_BPF
	fd = open(_PATH_BPF, O_RDWR);
#else
	char devbpf[PATH_MAX + 1];

	memset(devbpf, 0, sizeof(devbpf));
	int i = 0;
	do {
		snprintf(devbpf, sizeof(devbpf), "/dev/bpf%d", i++);
		fd = open(devbpf, O_RDWR);
	} while ((fd < 0) && (errno == EBUSY));
#endif

	return fd;
}

static int
bpf_pppoefilter(int fd)
{
	struct bpf_program bpfprog;
	int rc;

	memset(&bpfprog, 0, sizeof(bpfprog));

	bpfprog.bf_len = nitems(pppoe_filter);
	bpfprog.bf_insns = pppoe_filter;

	rc = ioctl(fd, BIOCSETF, &bpfprog);
	if (rc != 0)
		warn("ioctl: BIOCSETF (arp filter)");

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

static int
bpfread_and_exec(int (*recvcallback)(void *, int, char *, int, const char *),
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

			rc = recvcallback(callbackarg, fd,
			    ((char *)p + ((struct bpf_hdr*)p)->bh_hdrlen),
			    ((struct bpf_hdr*)p)->bh_datalen, ifname);
			if (rc != 0)
				break;

			p += BPF_WORDALIGN(perpacketsize);
		}
	}

	return rc;
}
