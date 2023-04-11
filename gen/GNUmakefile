include ../Makefile.inc

PROG=		ipgen
SRCS=		gen.c util.c webserv.c pbuf.c sequencecheck.c seqtable.c item.c genscript.c flowparse.c pktgen_item.c
CFLAGS+=	-I.. -I/usr/local/include -g -Wall -DHTDOCS=\"${PREFIX}/share/ipgen/htdocs\"
LDADD=		-L../libpkt -lpkt -L../libaddrlist -L/usr/local/lib -laddrlist -lpthread -lc -lcurses -levent -lmd

ifeq ($(shell uname),Linux)
LDADD+=		-lbsd -lcrypto -lxdp
CFLAGS+=	-DIPG_HACK -DUSE_AF_XDP
SRCS+=		arpresolv_linux.c af_xdp.c
else
CFLAGS+=	-DIPG_HACK -DUSE_NETMAP
CFLAGS+=	-DSUPPORT_PPPOE
SRCS+=		arpresolv.c
SRCS+=		pppoe.c
endif

OBJS+=  $(patsubst %.S,%.o,$(SRCS:%.c=%.o))

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDADD)

pktgen_item.c: pktgen.layout
	perl layout_generator pktgen.layout

depend: pktgen_item.c $(SRCS)
	mkdep $(CFLAGS) $(SRCS)

clean:
	rm -f pktgen_item.[ch]
	rm -f $(PROG) $(OBJS)

cleandir: clean
	rm -f .depend GPATH GRTAGS GSYMS GTAGS

install:
	install -o root -g wheel -m 550 ipgen ${PREFIX}/bin/

-include .depend
