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
#ifndef _COMPAT_H_
#define _COMPAT_H_

#include <stdbool.h>

#ifdef __linux__
#define octet		ether_addr_octet
#endif

#ifndef IF_Mbps
#define IF_Mbps(n)	((uint64_t)(n) * 1000 * 1000)
#endif

#ifndef IF_Gbps
#define IF_Gbps(n)	(IF_Mbps(n) * 1000)
#endif

#ifndef IFNAMSIZ
#define IFNAMSIZ
#endif

#ifndef ETHERTYPE_FLOWCONTROL
#define ETHERTYPE_FLOWCONTROL	0x8808
#endif

#ifndef atomic_fetchadd_32
#define	atomic_fetchadd_32(t, v) __atomic_fetch_add(t, v, __ATOMIC_CONSUME)
#endif

#ifndef atomic_swap_32
#define	atomic_swap_32(t, v) __atomic_exchange_n(t, v, __ATOMIC_SEQ_CST)
#endif

#ifndef atomic_add_64
#define	atomic_add_64(t, v) __atomic_add_fetch(t, v, __ATOMIC_SEQ_CST)
#endif

#ifndef atomic_cmpset_32
static inline uint32_t
atomic_cmpset_32(volatile uint32_t *p, uint32_t cmpval, uint32_t newval)
{
	bool ret = __atomic_compare_exchange_n(p, &cmpval, newval, false, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
	return ret ? 1 : 0;
}
#endif

#endif /* _COMPAT_H_ */
