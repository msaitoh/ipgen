
SUBDIRS := libpkt libaddrlist gen script htdocs
MKDEP := $(CURDIR)/mkdep

.PHONY: all $(SUBDIRS)

all clean cleandir depend install: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS) MKDEP=$(MKDEP)
