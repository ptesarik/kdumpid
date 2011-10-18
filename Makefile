CFLAGS?=-ggdb -Wall -O0 -D_FILE_OFFSET_BITS=64
OBJS=main.o lkcd.o devmem.o diskdump.o elfdump.o util.o search.o \
	x86.o
LIBS=-lz -lopcodes -lbfd -liberty -ldl

kdumpid: $(OBJS)
	gcc $(CFLAGS) -o $@ $+ $(LIBS)

clean:
	rm $(OBJS) kdumpid
