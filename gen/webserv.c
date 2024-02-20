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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/errno.h>
#ifdef __linux__
#include <bsd/sys/queue.h>
#endif
#include <event.h>
#include "webserv.h"
#include "gen.h"
#include "compat.h"

static int webserv_output(struct webserv *, char *, int);
static int webserv_reply_errcode(struct webserv *, int, const char *);
static int webserv_stream(struct webserv *, char *, int);
static int webserv_read(struct webserv *);
static int webserv_connected(struct webserv *);
static int webserv_destroy(struct webserv *);

static int handler_index(struct webserv *, const char *path, int argc, char *argv[]);
static int handler_stat(struct webserv *, const char *path, int argc, char *argv[]);
static int handler_clear(struct webserv *, const char *path, int argc, char *argv[]);
static int handler_interface(struct webserv *, const char *path, int argc, char *argv[]);
static int pathhandler(struct webserv *, char *);


#ifndef HTDOCS
#define HTDOCS	"../htdocs/"
#endif
const char *htdocs;


#define	HTTP_FOUND_APPLICATION_JSON			\
	"HTTP/1.0 200 Found\r\n"			\
	"Content-Type: application/json\r\n"		\
	"\r\n"


/*
 * GET /interface/0/pktsize/1500
 * -> path = "/interface/0/pktsize/1500"
 *    argc = 3
 *    argv[0] = "0"
 *    argv[1] = "pktsize"
 *    argv[2] = "1500"
 */
struct urlhandler {
	const char *path;
	int (*func)(struct webserv *, const char *path, int argc, char *argv[]);
} urlhandler[] = {
	/* XXX: must be sorted by strlen! */
	{	"/interface/",			handler_interface		},
	{	"/clear/",			handler_clear			},
	{	"/stat/",			handler_stat			},
	{	"/",				handler_index			},
};

TAILQ_HEAD(, webserv) webserv_list;
TAILQ_HEAD(, webserv) webserv_broadcastlist;
unsigned int webserv_nclient;

static int
handler_index(struct webserv *web, const char *path __unused, int argc, char *argv[])
{
	char buf[1024 * 32];
	FILE *fh;
	size_t rc;

	if (argc == 1) {
		snprintf(buf, sizeof(buf), "%s/%s", htdocs, argv[0]);
		fh = fopen(buf, "r");

		if (fh != NULL) {
			fprintf(web->fh,
			    "HTTP/1.0 200 Found\r\n"
			    "Content-Type: text/html\r\n"
			    "\r\n");

			while ((rc = fread(buf, 1, sizeof(buf), fh)) > 0) {
				fwrite(buf, 1, rc, web->fh);
			}
			fclose(fh);

		} else {
			return webserv_reply_errcode(web, 404, "Not found");
		}

	} else if (argc == 0) {
		fprintf(web->fh,
		    "HTTP/1.0 200 Found\r\n"
		    "Content-Type: text/html\r\n"
		    "\r\n"
		    "<HTML>\n"
		    "<HEADER>\n"
		    "</HEADER>\n"
		    "<BODY>\n"
		    "ipgen web interface<br>\n"
		    "<a href=\"index.html\">ipgen web interface</a><br>\n"
		    "</BODY>\n"
		    "</HTML>\n"
		);
	} else {
		return webserv_reply_errcode(web, 404, "Not found");
	}

	return 0;
}

static int
handler_stat(struct webserv *web, const char *path __unused, int argc, char *argv[])
{
	char buf[1024];

	if (argc == 0) {
		;
	} else if ((argc == 1) && (strcmp(argv[0], "1") == 0)) {
		web->oneshot = 1;
	} else {
		return webserv_reply_errcode(web, 404, "Not found");
	}

	strcpy(buf, HTTP_FOUND_APPLICATION_JSON);
	webserv_output(web, buf, strlen(buf));
	web->streaming = 1;
	TAILQ_INSERT_TAIL(&webserv_broadcastlist, web, broadcastlist);

	return 0;
}

static int
handler_clear(struct webserv *web, const char *path __unused, int argc __unused, char *argv[] __unused)
{
	statistics_clear();

	fprintf(web->fh, HTTP_FOUND_APPLICATION_JSON
	    "{\"status\":0}\n");

	return 0;
}

static int
handler_interface(struct webserv *web, const char *path __unused, int argc, char *argv[])
{
	int ifno;
	unsigned int n;
	unsigned long nl;;

	if ((argc != 2) && (argc != 3))
		return webserv_reply_errcode(web, 404, "Not found");

	ifno = strtol(argv[0], NULL, 10);
	if ((ifno != 0) && (ifno != 1))
		return webserv_reply_errcode(web, 404, "Not found");

	if (strcmp(argv[1], "pktsize") == 0) {
		if (argc == 3) {
			n = strtol(argv[2], NULL, 10);
			setpktsize(ifno, n);
			fprintf(web->fh, HTTP_FOUND_APPLICATION_JSON
			    "{\"status\":0}\n");
		} else {
			n = getpktsize(ifno);
			fprintf(web->fh, HTTP_FOUND_APPLICATION_JSON
			    "{"
			    "\"interface\":\"%s\","
			    "\"packetsize\":%u"
			    "}\n",
			    getifname(ifno), n);
		}
	} else if (strcmp(argv[1], "pps") == 0) {
		if (argc == 3) {
			nl = strtol(argv[2], NULL, 10);
			setpps(ifno, nl);
			fprintf(web->fh, HTTP_FOUND_APPLICATION_JSON
			    "{\"status\":0}\n");
		} else {
			nl = getpps(ifno);
			fprintf(web->fh, HTTP_FOUND_APPLICATION_JSON
			    "{"
			    "\"interface\":\"%s\","
			    "\"TXppsconfig\":%lu"
			    "}\n",
			    getifname(ifno), nl);
		}
	} else {
		return webserv_reply_errcode(web, 404, "Not found");
	}
	return 0;
}

static int
pathhandler(struct webserv *web, char *path)
{
	struct urlhandler *match;
	const char *p;
	char *q;
	u_int i;
#define MAXARGV	32
	char *argv[MAXARGV];

	match = NULL;
	for (i = 0; i < sizeof(urlhandler) / sizeof(urlhandler[0]); i++) {
		p = urlhandler[i].path;
		q = path;

		for (;;) {
			if (*p == '\0') {
				match = &urlhandler[i];
				goto match;
			}
			if (*p++ != *q++) {
				/* treat "/path" as "/path/" */
				if ((q[-1] == '\0') && (p[-1] == '/') && (p[0] == '\0')) {
					match = &urlhandler[i];
					q--;
					goto match;
				}
				break;
			}
		}
	}

	if (match == NULL) {
		return -1;
	}

 match:
	i = 0;
	argv[i++] = q;
	for (;;) {
		if (*q == '\0') {
			break;
		} else if (*q == '/') {
			*q++ = '\0';
			argv[i++] = q;
			if (i >= MAXARGV)
				break;
		} else {
			q++;
		}
	}

	if ((i > 0) && (*argv[i - 1] == '\0')) {
		i--;
	}

	match->func(web, path, i, argv);

	return 0;
}

int
webserv_init(void)
{
	htdocs = getenv("IPGEN_HTDOCS");
	if (htdocs == NULL)
		htdocs = HTDOCS;

	TAILQ_INIT(&webserv_list);
	TAILQ_INIT(&webserv_broadcastlist);
	webserv_nclient = 0;
	return 0;
}

unsigned int
webserv_getclientnum(void)
{
	return webserv_nclient;
}

static void
evt_readable_client_callback(evutil_socket_t fd __unused, short event __unused, void *arg)
{
	struct webserv *web;

	web = (struct webserv *)arg;

	webserv_read(web);
	/* connection closed? */
	if (!webserv_connected(web))
		webserv_destroy(web);
}

struct webserv *
webserv_new(int fd)
{
	struct webserv *web;

	web = malloc(sizeof(struct webserv));
	memset(web, 0, sizeof(struct webserv));

	web->fd = fd;
	web->fh = fdopen(fd, "w");
	web->connected = 1;
	TAILQ_INSERT_TAIL(&webserv_list, web, list);
	webserv_nclient++;

	event_set(&web->event, fd, EV_READ | EV_PERSIST, evt_readable_client_callback, web);
	event_add(&web->event, NULL);

	return web;
}

static int
webserv_reply_errcode(struct webserv *web, int status, const char *string)
{
	fprintf(web->fh, "HTTP/1.0 %03d %s\r\n\r\n%03d %s\n",
	    status, string, status, string);

	return 0;
}

static int
webserv_proc_request(struct webserv *web)
{
	char *p, *q;
	int rc;

	if (web->status)
		return webserv_reply_errcode(web, web->status, web->status_string);

	/* parse HTTP request */
	p = web->request;

	if (strncmp("GET ", p, 4) != 0) {
		return webserv_reply_errcode(web, 405, "Method not allowed");
	}

	/* omit " HTTP/1.x" */
	for (q = p + 4; (*q != ' ') && (*q != '\0') && (*q != '\r') && (*q != '\n'); q++)
		;
	*q = '\0';

	rc = pathhandler(web, p + 4);
	if (rc < 0)
		return webserv_reply_errcode(web, 404, "Not found");
	return 0;
}

static int
webserv_read(struct webserv *web)
{
	ssize_t rc;
	char buf[1024 * 4];
	int i;
	char c;

	do
		rc = read(web->fd, buf, sizeof(buf));
	while ((rc < 0) && (errno == EINTR));

	if (rc < 0) {
		/* read error */
		web->connected = 0;
		return -1;
	} else if (rc == 0) {
		/* connection closed by foreign host */
		web->connected = 0;
		return 0;
	}

	for (i = 0; i < rc; i++) {
		if (web->requestlen >= BUFSIZE) {
			/* too long request */
			web->status = 414;
			strncpy(web->status_string, "Request-URI Too Long", sizeof(web->status_string));
			memcpy(web->request, &web->request[BUFSIZE / 2], BUFSIZE / 2);
			web->requestlen = BUFSIZE / 2;
		}

		web->request[web->requestlen++] = c = buf[i];
		if (c == '\n') {
			if (((web->requestlen >= 4) && (memcmp(&web->request[web->requestlen - 4], "\r\n\r\n", 4) == 0)) ||
			    ((web->requestlen >= 2) && (memcmp(&web->request[web->requestlen - 2], "\n\n", 2) == 0))) {
				web->request[web->requestlen] = '\0';
				webserv_proc_request(web);
				if (!web->streaming) {
					web->connected = 0;
				}
				web->requestlen = 0;
				fflush(web->fh);
			}
		}
	}

	return 0;
}

int
webserv_output(struct webserv *web, char *buf, int len)
{
	ssize_t rc;

	do
		rc = write(web->fd, buf, len);
	while ((rc < 0) && (errno == EINTR));

	if (rc != len)
		web->connected = 0;

	if (rc < 0)
		return -1;

	return 0;
}

static int
webserv_connected(struct webserv *web)
{
	return web->connected;
}

static int
webserv_stream(struct webserv *web, char *buf, int len)
{
	if (!web->connected || !web->streaming)
		return 0;

	webserv_output(web, buf, len);
	if (web->oneshot)
		shutdown(web->fd, SHUT_RDWR);

	return 0;
}

int
webserv_need_broadcast(void)
{
	if (TAILQ_EMPTY(&webserv_broadcastlist))
		return 0;
	return 1;
}

int
webserv_stream_broadcast(char *buf, int len)
{
	struct webserv *web, *tmp;

	TAILQ_FOREACH_SAFE(web, &webserv_broadcastlist, broadcastlist, tmp) {
		webserv_stream(web, buf, len);
	}
	return 0;
}

static int
webserv_destroy(struct webserv *web)
{
	fclose(web->fh);
	event_del(&web->event);

	TAILQ_REMOVE(&webserv_list, web, list);
	webserv_nclient--;
	if (web->streaming)
		TAILQ_REMOVE(&webserv_broadcastlist, web, broadcastlist);
	memset(web, 0, sizeof(struct webserv));
	free(web);
	return 0;
}
