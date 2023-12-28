
TARGETLIB=	libaddrlist.a

SRCS+=		addresses.c

CFLAGS+=	-O2
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith
CFLAGS+=	-Wreturn-type -Wswitch -Wshadow
CFLAGS+=	-Wcast-qual -Wwrite-strings
CFLAGS+=	-Wno-address-of-packed-member

OBJS+=	$(SRCS:%.c=%.o)

.PHONY: clean

all: $(TARGETLIB)

$(TARGETLIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

test: libaddrlist.a
	cc test.c libaddrlist.a && ./a.out

depend:
	mkdep $(SRCS)

clean:
	rm -f $(TARGETLIB) $(OBJS)

cleandir: clean
	rm -f a.out
	rm -f .depend GPATH GRTAGS GSYMS GTAGS

install:

-include .depend
