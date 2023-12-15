
TARGETLIB=	libpkt.a

SRCS+=		dumpstr.c
SRCS+=		etherpkt.c
SRCS+=		pppoepkt.c
SRCS+=		ip4pkt.c
SRCS+=		ip6pkt.c
SRCS+=		utils.c

CFLAGS+=	-O2
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith
CFLAGS+=	-Wno-address-of-packed-member

# x86
CFLAGS+=	-DUSE_CPU_IN_CKSUM
SRCS+=		in_cksum.c
SRCS+=		cpu_in_cksum.S


OBJS+=	$(patsubst %.S,%.o,$(SRCS:%.c=%.o))


.PHONY: clean

all: $(TARGETLIB)

$(TARGETLIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

depend:
	mkdep $(SRCS)

clean:
	rm -f $(TARGETLIB) $(OBJS)

cleandir: clean
	rm -f .depend GPATH GRTAGS GSYMS GTAGS

install:

-include .depend
