/*
 * Copyright (c) 2008 Ryo Shimizu
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include "libpkt.h"

int
fdumpstr(FILE *fp, const char *data, size_t len, int flags)
{
	char ascii[17];
	size_t i;
	const char *eol = (flags & DUMPSTR_FLAGS_CRLF) ? "\r\n" : "\n";

	ascii[16] = '\0';
	for (i = 0; i < len; i++) {
		unsigned char c;

		if ((i & 15) == 0)
			fprintf(fp, "%08x:", (unsigned int)i);

		c = *data++;
		fprintf(fp, " %02x", c);

		ascii[i & 15] = (0x20 <= c && c <= 0x7f) ? c : '.';

		if ((i & 15) == 15)
			fprintf(fp, " <%s>%s", ascii, eol);
	}
	ascii[len & 15] = '\0';

	if (len & 15) {
		const char *white = "                                                ";
		fprintf(fp, "%s <%s>%s", &white[(len & 15) * 3], ascii, eol);
	}

	return 0;
}

int
dumpstr(const char *str, size_t len, int flags)
{
	return fdumpstr(stdout, str, len, flags);
}
