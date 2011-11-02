#### CONFIGURATION

ifndef PREFIX
PREFIX=/usr/local
endif
ifndef BINDIR
BINDIR=$(PREFIX)/bin
endif

CUSTOM_CFLAGS=
LIBS += -lz -lopcodes -lbfd -liberty -ldl

LD=ld

COMPRESS=bzip2 -9

### CONFIGURATION END

VER_MAJOR=0
VER_MINOR=9

CUSTOM_CFLAGS=-DVER_MAJOR=$(VER_MAJOR) -DVER_MINOR=$(VER_MINOR)

ifndef INSTALL
INSTALL=/usr/bin/install
endif

ifndef TAR
TAR=tar
endif

HDRS=kdumpid.h endian.h
SRC=main.c lkcd.c devmem.c diskdump.c elfdump.c util.c search.c \
	ppc.c ppc64.c s390.c x86.c
OBJS=$(addsuffix .o,$(basename $(SRC)))

DIST_EXTRA=Makefile Makefile.lib
DIST=$(HDRS) $(SRC) $(DIST_EXTRA)

PKGDIR=kdumpid-$(VER_MAJOR).$(VER_MINOR)
PKGNAME=$(PKGDIR).tar

all: kdumpid

kdumpid: $(OBJS)
	$(call cmd,link)

install:
	$(INSTALL) -D ./kdumpid $(DESTDIR)$(BINDIR)/kdumpid

clean:
	rm -f $(OBJS) kdumpid

dist:
	rm -rf $(PKGDIR)
	mkdir -p $(PKGDIR)
	$(INSTALL) -m 0644 $(DIST) $(PKGDIR)

package: dist
	rm -f $(PKGNAME)*
	tar cf $(PKGNAME) $(PKGDIR)
	$(COMPRESS) $(PKGNAME)
	rm -rf $(PKGDIR)

-include Makefile.lib
