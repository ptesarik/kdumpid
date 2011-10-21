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

### CONFIGURATION END

ifndef INSTALL
INSTALL=/usr/bin/install
endif

OBJS=main.o lkcd.o devmem.o diskdump.o elfdump.o util.o search.o \
	ppc.o ppc64.o s390.o x86.o

all: kdumpid

kdumpid: $(OBJS)
	$(call cmd,link)

install:
	$(INSTALL) -D ./kdumpid $(DESTDIR)$(BINDIR)/hed

clean:
	rm -f $(OBJS) kdumpid

-include Makefile.lib
