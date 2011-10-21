/* 
 * lkcd.c 
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define _GNU_SOURCE

#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "kdumpid.h"

#define LKCD_DUMP_V1                  (0x1)  /* DUMP_VERSION_NUMBER */ 
#define LKCD_DUMP_V2                  (0x2)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V3                  (0x3)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V5                  (0x5)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V6                  (0x6)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V7                  (0x7)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V8                  (0x8)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V9                  (0x9)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V10                 (0xa)  /* DUMP_VERSION_NUMBER */

#define LKCD_DUMP_MCLX_V0            (0x80000000)   /* MCLX mod of LKCD */
#define LKCD_DUMP_MCLX_V1            (0x40000000)   /* Extra page header data */

#define LKCD_OFFSET_TO_FIRST_PAGE    (65536)

#define DUMP_PANIC_LEN 0x100

/* dump compression options */
#define DUMP_COMPRESS_NONE     0x0      /* don't compress this dump         */
#define DUMP_COMPRESS_RLE      0x1      /* use RLE compression              */
#define DUMP_COMPRESS_GZIP     0x2      /* use GZIP compression             */

/* common header fields for all versions */
struct dump_header_common {
	/* the dump magic number -- unique to verify dump is valid */
	uint64_t             dh_magic_number;

	/* the version number of this dump */
	uint32_t             dh_version;

	/* the size of this header (in case we can't read it) */
	uint32_t             dh_header_size;

	/* the level of this dump (just a header?) */
	uint32_t             dh_dump_level;

	/* the size of a Linux memory page (4K, 8K, 16K, etc.) */
	uint32_t             dh_page_size;

	/* the size of all physical memory */
	uint64_t             dh_memory_size;

	/* the start of physical memory */
	uint64_t             dh_memory_start;

	/* the end of physical memory */
	uint64_t             dh_memory_end;
} __attribute__((packed));

/* LKCDv1 32-bit variant */
struct dump_header_v1_32 {
	/* Known fields */
	struct dump_header_common common;

	/* the esp for i386 systems -- MOVE LATER */
	uint32_t             dh_esp;

	/* the eip for i386 systems -- MOVE LATER */
	uint32_t             dh_eip;

	/* the number of pages in this dump specifically */
	uint32_t             dh_num_pages;

	/* the panic string, if available */
	char                 dh_panic_string[DUMP_PANIC_LEN];

	/* the time of the system crash */
	struct timeval_32    dh_time;

	/* the utsname (uname) information */
	struct new_utsname   dh_utsname;

	/* alignment */
	char                 _pad2[2];

/* Other fields follow... */
} __attribute__((packed));

/* LKCDv1 64-bit variant */
struct dump_header_v1_64 {
	/* Known fields */
	struct dump_header_common common;

	/* the esp for i386 systems -- MOVE LATER */
	uint32_t             dh_esp;

	/* the eip for i386 systems -- MOVE LATER */
	uint32_t             dh_eip;

	/* the number of pages in this dump specifically */
	uint32_t             dh_num_pages;

	/* the panic string, if available */
	char                 dh_panic_string[DUMP_PANIC_LEN];

	/* alignment */
	char                 _pad1[4];

	/* the time of the system crash */
	struct timeval_64    dh_time;

	/* the utsname (uname) information */
	struct new_utsname   dh_utsname;

	/* alignment */
	char                 _pad2[2];

/* Other fields follow... */
} __attribute__((packed));

/* LKCDv2 .. LKCDv7 32-bit variant */
struct dump_header_v2_32 {
	/* Known fields */
	struct dump_header_common common;

	/* the number of pages in this dump specifically */
	uint32_t             dh_num_pages;

	/* the panic string, if available */
	char                 dh_panic_string[DUMP_PANIC_LEN];

	/* the time of the system crash */
	struct timeval_32    dh_time;

	/* the utsname (uname) information */
	struct new_utsname   dh_utsname;

	/* alignment */
	char                 _pad1[2];

	/* the address of current task */
	uint32_t             dh_current_task;

/* following fields only in LKCDv5+ */

	/* type of compression used in this dump */
	uint32_t             dh_dump_compress;

	/* any additional flags */
	uint32_t             dh_dump_flags;

	/* dump device */
	uint32_t             dh_dump_device;
} __attribute__((packed));

/* LKCDv2 .. LKCDv7 64-bit variant */
struct dump_header_v2_64 {
	/* Known fields */
	struct dump_header_common common;

	/* the number of pages in this dump specifically */
	uint32_t             dh_num_pages;

	/* the panic string, if available */
	char                 dh_panic_string[DUMP_PANIC_LEN];

	/* alignment */
	char                 _pad1[4];

	/* the time of the system crash */
	struct timeval_64    dh_time;

	/* the utsname (uname) information */
	struct new_utsname   dh_utsname;

	/* alignment */
	char                 _pad2[2];

	/* the address of current task */
	uint64_t             dh_current_task;

/* following fields only in LKCDv5+ */

	/* type of compression used in this dump */
	uint32_t             dh_dump_compress;

	/* any additional flags */
	uint32_t             dh_dump_flags;

	/* dump device */
	uint32_t             dh_dump_device;
} __attribute__((packed));

/* LKCDv8 unified variant */
struct dump_header_v8 {
	/* Known fields */
	struct dump_header_common common;

	/* the number of pages in this dump specifically */
	uint32_t             dh_num_pages;

	/* the panic string, if available */
	char                 dh_panic_string[DUMP_PANIC_LEN];

	/* timeval depends on architecture, two long values */
	struct {
		uint64_t tv_sec;
		uint64_t tv_usec;
	} dh_time; /* the time of the system crash */

	/* the utsname (uname) information */
	struct new_utsname   dh_utsname;

	/* the address of current task */
	uint64_t             dh_current_task;

	/* what type of compression we're using in this dump (if any) */
	uint32_t             dh_dump_compress;

	/* any additional flags */
	uint32_t             dh_dump_flags;

	/* any additional flags */
	uint32_t             dh_dump_device;

/* following fields only in LKCDv9+ */

	/* size of dump buffer */
	uint64_t             dh_dump_buffer_size;
} __attribute__((packed));

/* dump_page flags */
#define DUMP_RAW            0x1      /* raw page (no compression)        */
#define DUMP_COMPRESSED     0x2      /* page is compressed               */
#define DUMP_END            0x4      /* end marker on a full dump        */

struct dump_page {
	/* the address of this dump page */
        uint64_t             dp_address;

        /* the size of this dump page */
        uint32_t             dp_size;

        /* flags (currently DUMP_COMPRESSED, DUMP_RAW or DUMP_END) */
        uint32_t             dp_flags;
} __attribute__((packed));

/* Split the 32-bit PFN into 3 indices */
#define PFN_IDX1_BITS	10
#define PFN_IDX2_BITS	10
#define PFN_IDX3_BITS	12

#define PFN_IDX1_SIZE	((uint32_t)1 << PFN_IDX1_BITS)
#define PFN_IDX2_SIZE	((uint32_t)1 << PFN_IDX2_BITS)
#define PFN_IDX3_SIZE	((uint32_t)1 << PFN_IDX3_BITS)

#define pfn_idx1(pfn) \
	((uint32_t)(pfn) >> (PFN_IDX3_BITS + PFN_IDX2_BITS))
#define pfn_idx2(pfn) \
	(((uint32_t)(pfn) >> PFN_IDX3_BITS) & (PFN_IDX2_SIZE - 1))
#define pfn_idx3(pfn) \
	((uint32_t)(pfn) & (PFN_IDX3_SIZE - 1))

/* Level-3 tables contain only a 32-bit offset from the level-2 page
 * beginning, cutting their size by 50%. A 32-bit offset must be
 * enough, because max page shift is 18 and pfn_idx3 has 12 bits:
 * 18 + 12 = 30 and 30 < 32
 */

struct pfn_level2 {
	off_t off;
	uint32_t *pfn_level3;
};

struct lkcd_priv {
	off_t data_offset;	/* offset to 1st page */
	long version;
	uint32_t max_pfn;
	unsigned compression;
	struct pfn_level2 **pfn_level1;
};

static off_t
find_page(struct dump_desc *dd, off_t off, unsigned pfn, struct dump_page *dp)
{
	uint64_t addr = pfn * dd->page_size;

	for ( ;; ) {
		if (pread(dd->fd, dp, sizeof *dp, off) != sizeof *dp)
			return -1;
		dp->dp_address = dump64toh(dd, dp->dp_address);
		dp->dp_size = dump32toh(dd, dp->dp_size);
		if (dp->dp_address >= addr)
			break;
		off += sizeof(struct dump_page) + dp->dp_size;
	}

	dp->dp_flags = dump32toh(dd, dp->dp_flags);
	return off;
}

static int
fill_level1(struct dump_desc *dd, unsigned endidx)
{
	struct lkcd_priv *lkcdp = dd->priv;
	off_t off = lkcdp->data_offset;
	struct pfn_level2 **p;
	unsigned idx;

	for (p = lkcdp->pfn_level1, idx = 0; idx < endidx; ++p, ++idx) {
		if (!*p)
			break;
		off = (*p)->off;
	}

	for ( ; idx <= endidx; ++p, ++idx) {
		struct dump_page dp;
		uint32_t pfn;

		*p = calloc(PFN_IDX2_SIZE, sizeof(struct pfn_level2));
		if (!*p) {
			perror("Cannot allocate PFN mapping");
			return -1;
		}
		pfn = idx << (PFN_IDX3_BITS + PFN_IDX2_BITS);
		if ( (off = find_page(dd, off, pfn, &dp)) < 0)
			return -1;
		(*p)->off = off;
	}

	return 0;
}

static int
fill_level2(struct dump_desc *dd, unsigned idx1, unsigned endidx)
{
	struct lkcd_priv *lkcdp = dd->priv;
	struct pfn_level2 *p = lkcdp->pfn_level1[idx1];
	off_t off, baseoff;
	struct dump_page dp;
	uint32_t pfn;
	uint32_t *pp;
	unsigned idx;

	baseoff = p->off;
	for (idx = 0; idx <= endidx; ++p, ++idx) {
		if (!p->pfn_level3)
			break;
		baseoff = p->off;
	}

	pfn = ((idx1 << PFN_IDX2_BITS) + idx) << PFN_IDX3_BITS;
	for ( ; idx < endidx; ++p, ++idx) {
		if ( (baseoff = find_page(dd, baseoff, pfn, &dp)) < 0)
			return -1;
		p->off = baseoff;
		pfn += PFN_IDX3_SIZE;
	}
	if (idx) {
		if ( (baseoff = find_page(dd, baseoff, pfn, &dp)) < 0)
			return -1;
		p->off = baseoff;
	}

	pp = malloc(PFN_IDX3_SIZE * sizeof(uint32_t));
	if (!pp) {
		perror("Cannot allocate PFN mapping");
		return -1;
	}
	p->pfn_level3 = pp;
	memset(pp, -1, PFN_IDX3_SIZE * sizeof(uint32_t));

	off = baseoff;
	for (idx = 0; idx < PFN_IDX3_SIZE; ++idx, ++pp) {
		if ( (off = find_page(dd, off, pfn, &dp)) < 0)
			break;
		if (dp.dp_address == pfn * dd->page_size)
			*pp = off - baseoff;
		pfn++;
	}

	return 0;
}

static int 
lkcd_read_page(struct dump_desc *dd, unsigned long pfn)
{
	struct lkcd_priv *lkcdp = dd->priv;
	struct pfn_level2 *pfn_level2;
	uint32_t *pfn_level3;
	unsigned idx1, idx2, idx3;
	struct dump_page dp;
	unsigned type;
	off_t off;
	void *buf;

	if (pfn >= lkcdp->max_pfn)
		return -1;

	idx1 = pfn_idx1(pfn);
	if (!lkcdp->pfn_level1[idx1] &&
	    fill_level1(dd, idx1))
		return -1;
	pfn_level2 = lkcdp->pfn_level1[idx1];

	idx2 = pfn_idx2(pfn);
	if (!pfn_level2[idx2].pfn_level3 &&
	    fill_level2(dd, idx1, idx2))
		return -1;
	off = pfn_level2[idx2].off;
	pfn_level3 = pfn_level2[idx2].pfn_level3;

	idx3 = pfn_idx3(pfn);
	if (pfn_level3[idx3] == (uint32_t)-1)
		return -1;
	off += pfn_level3[idx3];

	if (find_page(dd, off, pfn, &dp) < 0)
		return -1;
	off += sizeof(struct dump_page);

	type = dp.dp_flags & (DUMP_COMPRESSED|DUMP_RAW);
	switch (type) {
	case DUMP_COMPRESSED:
		if (dp.dp_size > MAX_PAGE_SIZE)
			return -1;
		buf = dd->buffer;
		break;
	case DUMP_RAW:
		if (dp.dp_size != dd->page_size)
			return -1;
		buf = dd->page;
		break;
	default:
		fprintf(stderr, "WARNING: "
			"Unknown page type for PFN %lu: %u\n", pfn, type);
		return -1;
	}

	/* read page data */
	if (pread(dd->fd, buf, dp.dp_size, off) != dp.dp_size)
		return -1;

	if (type == DUMP_RAW)
		return 0;

	if (lkcdp->compression == DUMP_COMPRESS_RLE) {
		uLongf retlen = dd->page_size;
		int ret = uncompress(dd->page, &retlen,
				     buf, dp.dp_size);
		if ((ret != Z_OK) || (retlen != dd->page_size))
			return -1;
	} else if (lkcdp->compression = DUMP_COMPRESS_GZIP) {
		size_t retlen = dd->page_size;
		int ret = uncompress_rle(dd->page, &retlen,
					 buf, dp.dp_size);
		if (ret)
			return -1;
	} else
		return -1;

	return 0;
}

static inline long
base_version(int32_t version)
{
	return version & ~(LKCD_DUMP_MCLX_V0|LKCD_DUMP_MCLX_V1);
}

static int
init_v1(struct dump_desc *dd)
{
	struct lkcd_priv *lkcdp = dd->priv;
	struct dump_header_v1_32 *dh32 = dd->buffer;
	struct dump_header_v1_64 *dh64 = dd->buffer;

	if (!uts_looks_sane(&dh32->dh_utsname) &&
	    uts_looks_sane(&dh64->dh_utsname)) {
		copy_uts_string(dd->machine, dh64->dh_utsname.machine);
		copy_uts_string(dd->ver, dh64->dh_utsname.release);
		lkcdp->max_pfn = dump32toh(dd, dh64->dh_num_pages);
	} else {
		copy_uts_string(dd->machine, dh32->dh_utsname.machine);
		copy_uts_string(dd->ver, dh32->dh_utsname.release);
		lkcdp->max_pfn = dump32toh(dd, dh32->dh_num_pages);
	}
	lkcdp->compression = DUMP_COMPRESS_RLE;

	return 0;
}

static int
init_v2(struct dump_desc *dd)
{
	struct lkcd_priv *lkcdp = dd->priv;
	struct dump_header_v2_32 *dh32 = dd->buffer;
	struct dump_header_v2_64 *dh64 = dd->buffer;

	if (!uts_looks_sane(&dh32->dh_utsname) &&
	    uts_looks_sane(&dh64->dh_utsname)) {
		copy_uts_string(dd->machine, dh64->dh_utsname.machine);
		copy_uts_string(dd->ver, dh64->dh_utsname.release);
		lkcdp->max_pfn = dump32toh(dd, dh64->dh_num_pages);
		lkcdp->compression = (lkcdp->version >= LKCD_DUMP_V5)
			? dump32toh(dd, dh64->dh_dump_compress)
			: DUMP_COMPRESS_RLE;
	} else {
		copy_uts_string(dd->machine, dh32->dh_utsname.machine);
		copy_uts_string(dd->ver, dh32->dh_utsname.release);
		lkcdp->max_pfn = dump32toh(dd, dh32->dh_num_pages);
		lkcdp->compression = (lkcdp->version >= LKCD_DUMP_V5)
			? dump32toh(dd, dh32->dh_dump_compress)
			: DUMP_COMPRESS_RLE;
	}
	return 0;
}

static int
init_v8(struct dump_desc *dd)
{
	struct lkcd_priv *lkcdp = dd->priv;
	struct dump_header_v8 *dh = dd->buffer;

	copy_uts_string(dd->machine, dh->dh_utsname.machine);
	copy_uts_string(dd->ver, dh->dh_utsname.release);
	lkcdp->max_pfn = dump32toh(dd, dh->dh_num_pages);
	lkcdp->compression = dump32toh(dd, dh->dh_dump_compress);
	if (lkcdp->version >= LKCD_DUMP_V9)
		lkcdp->data_offset = dump64toh(dd, dh->dh_dump_buffer_size);

	return 0;
}

int
handle_common(struct dump_desc *dd)
{
	struct dump_header_common *dh = dd->buffer;
	struct lkcd_priv lkcdp;
	int32_t version;
	unsigned max_idx1;
	int res = -1;

	version = dump32toh(dd, dh->dh_version);
	lkcdp.version = base_version(version);
	snprintf(dd->format, sizeof(dd->format),
		 "LKCD v%ld", lkcdp.version);

	lkcdp.data_offset = LKCD_OFFSET_TO_FIRST_PAGE;

	dd->read_page = lkcd_read_page;
	dd->page_size = dump32toh(dd, dh->dh_page_size);
	dd->priv = &lkcdp;

	switch(lkcdp.version) {
	case LKCD_DUMP_V1:
		res = init_v1(dd);
		break;

	case LKCD_DUMP_V2:
	case LKCD_DUMP_V3:
	case LKCD_DUMP_V5:
	case LKCD_DUMP_V6:
	case LKCD_DUMP_V7:
		res = init_v2(dd);
		break;

	case LKCD_DUMP_V8:
	case LKCD_DUMP_V9:
	case LKCD_DUMP_V10:
		res = init_v8(dd);
		break;

	default:
		fprintf(stderr, "unsupported LKCD dump version: %ld (%lx)\n", 
			lkcdp.version, (long)version);
		return -1;
	}

	if (res)
		return res;
	if (dd->machine[0]) {
		dd->arch = get_machine_arch(dd->machine);
		if (dd->ver[0])
			return 0;
	}

	max_idx1 = pfn_idx1(lkcdp.max_pfn - 1) + 1;
	lkcdp.pfn_level1 = calloc(max_idx1, sizeof(struct pfn_level2*));
	if (!lkcdp.pfn_level1) {
		perror("Cannot allocate PFN mapping");
		return -1;
	}

	return explore_raw_data(dd);
}

int
handle_lkcd_le(struct dump_desc *dd)
{
	dd->endian = __LITTLE_ENDIAN;
	return handle_common(dd);
}

int
handle_lkcd_be(struct dump_desc *dd)
{
	dd->endian = __BIG_ENDIAN;
	return handle_common(dd);
}
