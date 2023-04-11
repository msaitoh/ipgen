/*
 * Copyright (c) 2021 Ryota Ozaki <ozaki.ryota@gmail.com>
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
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <bsd/sys/param.h>

#include "af_xdp.h"

#define NUM_FRAMES	4096
#define FRAME_SIZE	XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE	64
#define NUM_DESCS	XSK_RING_PROD__DEFAULT_NUM_DESCS

struct ax_socket {
	struct xsk_ring_cons	rring; /* Rx ring */
	struct xsk_ring_prod	tring; /* Tx ring */
	struct xsk_ring_prod	fring; /* Fill ring */
	struct xsk_ring_cons	cring; /* Completion ring */
	struct xsk_socket	*xsk;
	struct xsk_umem		*umem;
	void			*umem_area;
	uint32_t		inflight_tx_pkts;
	/* current frame index in the umem_area */
	uint32_t		tx_frame_idx;
	bool			do_wakeup;
};

static struct ax_socket *
ax_setup_socket(const char *ifname, void *umem_area, size_t size)
{
	struct xsk_socket_config cfg;
	struct ax_socket *axs;
	int rc;

	axs = calloc(1, sizeof(*axs));
	if (axs == NULL)
		return NULL;

	rc = xsk_umem__create(&axs->umem, umem_area, size, &axs->fring, &axs->cring, NULL);
	if (rc != 0) {
		fprintf(stderr, "xsk_umem__create failed: %d\n", -rc);
		free(axs);
		return NULL;
	}
	axs->umem_area = umem_area;

	cfg.rx_size = NUM_DESCS;
	cfg.tx_size = NUM_DESCS;
	cfg.libbpf_flags = 0;
	cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
#ifdef USE_ZEROCOPY
	cfg.bind_flags = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY;
	axs->do_wakeup = true;
#else
	cfg.bind_flags = 0;
	axs->do_wakeup = false;
#endif

	rc = xsk_socket__create(&axs->xsk, ifname, 0 /* XXX */, axs->umem,
				 &axs->rring, &axs->tring, &cfg);
	if (rc != 0) {
		fprintf(stderr, "xsk_socket__create failed: %d\n", -rc);
		xsk_umem__delete(axs->umem);
		free(axs);
		return NULL;
	}
	if (cfg.bind_flags == 0)
		fprintf(stderr, "warning: zerocopy mode is NOT enabled on %s\n", ifname);

	return axs;
}

static inline void
ax_complete_tx0(struct ax_socket *axs, int batch_size)
{
	unsigned int done;
	uint32_t idx;

	if (axs->inflight_tx_pkts == 0)
		return;

	if (axs->do_wakeup) {
		if (xsk_ring_prod__needs_wakeup(&axs->tring))
			sendto(xsk_socket__fd(axs->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	} else {
		/* Tx needs wakeup anyway */
		sendto(xsk_socket__fd(axs->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	}

	done = xsk_ring_cons__peek(&axs->cring, batch_size, &idx);
	if (done > 0) {
		xsk_ring_cons__release(&axs->cring, done);
		axs->inflight_tx_pkts -= done;
	}
}

static int
ax_populate_fill_ring(struct ax_socket *axs)
{
	int rc, i;
	uint32_t idx;

	rc = xsk_ring_prod__reserve(&axs->fring, NUM_DESCS, &idx);
	if (rc != NUM_DESCS) {
		fprintf(stderr, "xsk_ring_prod__reserve failed: %d\n", rc);
		return -1;
	}
	for (i = 0; i < NUM_DESCS; i++) {
		/* Use second half for rx */
		*xsk_ring_prod__fill_addr(&axs->fring, idx++) =
			NUM_FRAMES * FRAME_SIZE + i * FRAME_SIZE;
	}
	xsk_ring_prod__submit(&axs->fring, NUM_DESCS);
	return 0;
}

unsigned int
ax_wait_for_packets(struct ax_desc *ax_desc, struct ax_rx_handle *handle)
{
	struct ax_socket *axs = ax_desc->axs;
	unsigned int npkts;
	int ret;

	npkts = xsk_ring_cons__peek(&axs->rring, BATCH_SIZE, &handle->rring_idx);
	if (npkts == 0) {
		if (axs->do_wakeup && xsk_ring_prod__needs_wakeup(&axs->fring)) {
			recvfrom(ax_desc->fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
		return 0;
	}
	/*
	 * Used receive buffers will be immediately set to the fill ring,
	 * so here we need to preserver the same number of entries as
	 * received packets.
	 */
	ret = xsk_ring_prod__reserve(&axs->fring, npkts, &handle->fring_idx);
	while (ret != npkts) {
		if (axs->do_wakeup && xsk_ring_prod__needs_wakeup(&axs->fring)) {
			recvfrom(ax_desc->fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
		ret = xsk_ring_prod__reserve(&axs->fring, npkts, &handle->fring_idx);
	}

	handle->npkts = npkts;
	return npkts;
}

void
ax_complete_rx(struct ax_desc *ax_desc, unsigned int n)
{
	struct ax_socket *axs = ax_desc->axs;

	xsk_ring_prod__submit(&axs->fring, n);
	xsk_ring_cons__release(&axs->rring, n);
}

char *
ax_get_rx_buf(struct ax_desc *ax_desc, uint32_t *lenp, struct ax_rx_handle *handle)
{
	struct ax_socket *axs = ax_desc->axs;
	const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&axs->rring, handle->rring_idx);

	/*
	 * XXX registering the buffer before accessing received data is racy
	 * but it's unlikely to be a problem if the number of descriptors is enough large.
	 */
	*xsk_ring_prod__fill_addr(&axs->fring, handle->fring_idx) = desc->addr;

	*lenp = desc->len;
	return (char *)xsk_umem__get_data(axs->umem_area, desc->addr);
}

uint32_t
ax_prepare_tx(struct ax_desc *ax_desc, unsigned int *npkts)
{
	struct ax_socket *axs = ax_desc->axs;
	uint32_t idx;

	*npkts = MIN(*npkts, BATCH_SIZE);

	while (xsk_ring_prod__reserve(&axs->tring, *npkts, &idx) < *npkts) {
		ax_complete_tx0(axs, *npkts);
	}

	return idx;
}

void
ax_complete_tx(struct ax_desc *ax_desc, unsigned int npkts)
{
	struct ax_socket *axs = ax_desc->axs;

	xsk_ring_prod__submit(&axs->tring, npkts);
	axs->inflight_tx_pkts += npkts;
	axs->tx_frame_idx += npkts;
	axs->tx_frame_idx %= NUM_FRAMES;
	ax_complete_tx0(axs, npkts);
}

char *
ax_get_tx_buf(struct ax_desc *ax_desc, uint32_t **lenp, uint32_t idx, int i)
{
	struct ax_socket *axs = ax_desc->axs;
	char *buf;
	struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&axs->tring, idx + i);

	tx_desc->addr = (axs->tx_frame_idx + i) * FRAME_SIZE;
	buf = xsk_umem__get_data(axs->umem_area, tx_desc->addr);

	*lenp = &tx_desc->len;
	return buf;
}

struct ax_desc *
ax_open(const char *ifname)
{
	void *umem_area;
	size_t mem_size;
	struct ax_socket *axs;
	struct ax_desc *ax_desc;
	int rc;

	ax_desc = malloc(sizeof(*ax_desc));
	if (ax_desc == NULL) {
		fprintf(stderr, "malloc failed: %s\n", strerror(errno));
		return NULL;
	}

	/* Allocate memory areas for tx and rx at once */
	mem_size = NUM_FRAMES * 2 * FRAME_SIZE;
	umem_area = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (umem_area == MAP_FAILED) {
		fprintf(stderr, "mmap failed: %s\n", strerror(errno));
		return NULL;
	}

	axs = ax_setup_socket(ifname, umem_area, mem_size);
	if (axs == NULL) {
		fprintf(stderr, "ax_setup_socket failed\n");
		return NULL;
	}

	rc = ax_populate_fill_ring(axs);
	if (rc != 0) {
		fprintf(stderr, "ax_populate_fill_ring failed\n");
		return NULL;
	}

	ax_desc->axs = axs;
	ax_desc->fd = xsk_socket__fd(axs->xsk);

	return ax_desc;
}

void
ax_close(struct ax_desc *desc)
{
	struct ax_socket *axs = desc->axs;

	xsk_umem__delete(axs->umem);
	xsk_socket__delete(axs->xsk);
}
