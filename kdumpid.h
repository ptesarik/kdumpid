#ifndef __KDUMPID_H
#define __KDUMPID_H

#include <stdint.h>
#include <endian.h>
#include <unistd.h>

#define VER_MAJOR	0
#define VER_MINOR	9

/* This should cover all possibilities:
 * - no supported architecture has less than 4K pages.
 * - PowerPC can have up to 256K large pages.
 */
#define MIN_PAGE_SIZE	(1UL << 12)
#define MAX_PAGE_SIZE	(1UL << 18)

#define INVALID_ADDR	((uint64_t)-1ULL)

enum arch {
	ARCH_UNKNOWN = 0,
	ARCH_ALPHA,
	ARCH_ARM,
	ARCH_IA64,
	ARCH_PPC,
	ARCH_PPC64,
	ARCH_S390,
	ARCH_S390X,
	ARCH_X86,
	ARCH_X86_64,
};

struct dump_desc;

typedef int (*readpage_fn)(struct dump_desc *, unsigned long);

struct dump_desc {
	const char *name;	/* file name */
	long flags;		/* see DIF_XXX below */
	int fd;			/* dump file descriptor */

	void *buffer;		/* temporary buffer */
	void *page;		/* page data buffer */
	size_t page_size;	/* target page size */
	readpage_fn read_page;	/* method to read dump pages */
	unsigned long max_pfn;	/* max PFN for read_page */
	unsigned long last_pfn;	/* last read PFN */

	enum arch arch;		/* architecture (if known) */
	int endian;		/* __LITTLE_ENDIAN or __BIG_ENDIAN */
	size_t ptr_size;	/* arch pointer size */
	uint64_t start_addr;	/* kernel start address */

	char format[32];	/* file format */
	char machine[66];	/* arch name (utsname machine) */
	char ver[66];		/* version (utsname release) */
	char banner[256];	/* Linux banner */

	char *cfg;		/* kernel configuration */
	size_t cfglen;

	uint64_t xen_start_info; /* address of Xen start info */

	void *priv;
};

/* Kdumpid flags */
#define DIF_FORCE	1
#define DIF_XEN		2
#define DIF_START_FOUND	4

/* LKCD */
int handle_lkcd_le(struct dump_desc *dd);
int handle_lkcd_be(struct dump_desc *dd);

/* diskdump/compressed kdump */
int handle_diskdump(struct dump_desc *dd);
int handle_kdump(struct dump_desc *dd);

/* ELF dumps */
int handle_elfdump(struct dump_desc *dd);

/* live sources */
int handle_devmem(struct dump_desc *dd);

/* Arch-specific helpers */
int looks_like_kcode_s390(struct dump_desc *dd, uint64_t addr);
int looks_like_kcode_x86(struct dump_desc *dd, uint64_t addr);

/* provide our own definition of new_utsname */
struct new_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

/* struct timeval has a different layout on 32-bit and 64-bit */
struct timeval_32 {
	int32_t tv_sec;
	int32_t tv_usec;
};
struct timeval_64 {
	int64_t tv_sec;
	int64_t tv_usec;
};

/* utils */

void copy_uts_string(char *dest, const char *src);
int uts_looks_sane(struct new_utsname *uts);

const size_t arch_ptr_size(enum arch arch);
const char *arch_name(enum arch arch);
enum arch get_machine_arch(const char *machine);

int get_version_from_banner(struct dump_desc *dd);
int need_explore(struct dump_desc *dd);

int read_page(struct dump_desc *dd, unsigned long pfn);
size_t dump_cpin(struct dump_desc *dd, void *buf, uint64_t paddr, size_t len);

int uncompress_config(struct dump_desc *dd, void *zcfg, size_t zsize);
uint64_t dump_search_range(struct dump_desc *dd,
			   uint64_t start, uint64_t end,
			   const unsigned char *needle, size_t len);

int explore_raw_data(struct dump_desc *dd);

int uncompress_rle(unsigned char *dst, size_t *pdstlen,
		   const unsigned char *src, size_t srclen);

/* Inline utility functions */

static inline unsigned
bitcount(unsigned x)
{
	return (uint32_t)((((x * 0x08040201) >> 3) & 0x11111111) * 0x11111111)
		>> 28;
}

static inline uint16_t
dump16toh(struct dump_desc *dd, uint16_t x)
{
	return dd->endian == __BIG_ENDIAN
		? be16toh(x)
		: le16toh(x);
}

static inline uint32_t
dump32toh(struct dump_desc *dd, uint32_t x)
{
	return dd->endian == __BIG_ENDIAN
		? be32toh(x)
		: le32toh(x);
}

static inline uint64_t
dump64toh(struct dump_desc *dd, uint64_t x)
{
	return dd->endian == __BIG_ENDIAN
		? be64toh(x)
		: le64toh(x);
}

#endif	/* __KDUMPID_H */
