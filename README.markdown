To compile this package, you'll need the following:

* [BFD](http://www.gnu.org/software/binutils/). Any version with
  disassemblers for x86, ppc and s390 will do. This usually comes with
  the distro packaged as binutils-devel or similar.
* [zlib](http://www.zlib.net/). You can usually find it in a zlib-devel
  package.
* [lzo](http://www.oberhumer.com/opensource/lzo/). Often found in a
  lzo-devel package.
* [snappy](https://code.google.com/p/snappy/). Often found in a snappy-devel
   package.
* [GNU C Library](http://www.gnu.org/software/libc/libc.html). Almost
  any version will do. Other C libraries may also work, but since there
  is no standard interface for byte-order macros, this may need some porting.
* [GCC](http://gcc.gnu.org/). The source uses a few construct specific
  to GCC (such as variable attributes). Porting should be easy, though.

Once you've got the prerequisites, simply unpack the tarball and run

	make
	make install

If you wish to install into another directory than `/usr/local/bin`, you
can tweak the location in `Makefile` before running `make install`.
