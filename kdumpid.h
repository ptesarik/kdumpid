#ifndef __KDUMPID_H
#define __KDUMPID_H

#include <stdint.h>
#include <unistd.h>
#include <kdumpfile.h>

#include "endian.h"

#define INVALID_ADDR	((uint64_t)-1ULL)

struct dump_desc;

struct dump_desc {
	const char *name;	/* file name */
	long flags;		/* see DIF_XXX below */
	int fd;			/* dump file descriptor */
	kdump_ctx *ctx;		/* kdumpfile context */

	void *page;		/* page data buffer */
	size_t page_size;	/* target page size */
	unsigned long max_pfn;	/* max PFN for read_page */

	const char *arch;	/* architecture (if known) */
	int endian;		/* __LITTLE_ENDIAN or __BIG_ENDIAN */
	uint64_t start_addr;	/* kernel start address */

	char machine[66];	/* arch name (utsname machine) */
	char ver[66];		/* version (utsname release) */
	char banner[256];	/* Linux banner */

	char *cfg;		/* kernel configuration */
	size_t cfglen;

	uint64_t xen_start_info; /* address of Xen start info */

	void *priv;
};

/* Kdumpid flags */
#define DIF_VERBOSE	1
#define DIF_FORCE	2
#define DIF_START_FOUND	8

/* Arch-specific helpers */
int looks_like_kcode_ppc(struct dump_desc *dd, uint64_t addr);
int looks_like_kcode_ppc64(struct dump_desc *dd, uint64_t addr);
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

/* utils */

#ifdef KDUMPFILE_VER_MAJOR
static inline int
kdump_is_xen(kdump_ctx *ctx)
{
	return kdump_xen_type(ctx) != kdump_xen_none;
}
#endif

int get_version_from_banner(struct dump_desc *dd);
int need_explore(struct dump_desc *dd);

int read_page(struct dump_desc *dd, unsigned long pfn);
size_t dump_cpin(struct dump_desc *dd, void *buf, uint64_t paddr, size_t len);

int uncompress_config(struct dump_desc *dd, void *zcfg, size_t zsize);
uint64_t dump_search_range(struct dump_desc *dd,
			   uint64_t start, uint64_t end,
			   const unsigned char *needle, size_t len);

int explore_raw_data(struct dump_desc *dd);

#endif	/* __KDUMPID_H */
