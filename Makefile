#### CONFIGURATION

ifndef PREFIX
PREFIX=/usr/local
endif
ifndef BINDIR
BINDIR=$(PREFIX)/bin
endif
ifndef MANDIR
MANDIR=$(PREFIX)/man
endif

CUSTOM_CFLAGS=
LIBS += -lkdumpfile -laddrxlat -lz -lopcodes -lbfd -liberty -ldl

LD=ld

COMPRESS=bzip2 -9

### CONFIGURATION END

VER_MAJOR=1
VER_MINOR=2

CFLAGS=-DVER_MAJOR=$(VER_MAJOR) -DVER_MINOR=$(VER_MINOR)

ifndef INSTALL
INSTALL=/usr/bin/install
endif

ifndef TAR
TAR=tar
endif

HDRS=kdumpid.h endian.h
SRC=main.c util.c search.c ppc.c ppc64.c s390.c x86.c
OBJS=$(addsuffix .o,$(basename $(SRC)))

DIST_EXTRA=Makefile Makefile.lib kdumpid.1
DIST=$(HDRS) $(SRC) $(DIST_EXTRA)

PKGDIR=kdumpid-$(VER_MAJOR).$(VER_MINOR)
PKGNAME=$(PKGDIR).tar

all: kdumpid

kdumpid: $(OBJS)
	$(call cmd,link)

install:
	$(INSTALL) -D ./kdumpid $(DESTDIR)$(BINDIR)/kdumpid
	$(INSTALL) -m 0644 -D ./kdumpid.1 $(DESTDIR)$(MANDIR)/man1/kdumpid.1

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

.PHONY: all install clean dist package

-include Makefile.lib
