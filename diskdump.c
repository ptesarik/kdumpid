/* 
 * diskdump.c 
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

#include <stdlib.h>

#include <stdio.h>
#include <string.h>
#include <zlib.h>

#include "kdumpid.h"

#define SIG_LEN	8

/* The header is architecture-dependent, unfortunately */
struct disk_dump_header_32 {
	char			signature[SIG_LEN];	/* = "DISKDUMP" */
	int32_t			header_version; /* Dump header version */
	struct new_utsname	utsname;	/* copy of system_utsname */
	char			_pad1[2];	/* alignment */
	struct timeval_32	timestamp;	/* Time stamp */
	uint32_t		status; 	/* Above flags */
	int32_t			block_size;	/* Size of a block in byte */
	int32_t			sub_hdr_size;	/* Size of arch dependent
						   header in blocks */
	uint32_t		bitmap_blocks;	/* Size of Memory bitmap in
						   block */
	uint32_t		max_mapnr;	/* = max_mapnr */
	uint32_t		total_ram_blocks;/* Number of blocks should be
						   written */
	uint32_t		device_blocks;	/* Number of total blocks in
						 * the dump device */
	uint32_t		written_blocks; /* Number of written blocks */
	uint32_t		current_cpu;	/* CPU# which handles dump */
	int32_t			nr_cpus;	/* Number of CPUs */
	uint32_t		tasks[0];	/* "struct task_struct *" */
} __attribute__((packed));

/* The header is architecture-dependent, unfortunately */
struct disk_dump_header_64 {
	char			signature[SIG_LEN];	/* = "DISKDUMP" */
	int32_t			header_version; /* Dump header version */
	struct new_utsname	utsname;	/* copy of system_utsname */
	char			_pad1[6];	/* alignment */
	struct timeval_64	timestamp;	/* Time stamp */
	uint32_t		status; 	/* Above flags */
	int32_t			block_size;	/* Size of a block in byte */
	int32_t			sub_hdr_size;	/* Size of arch dependent
						   header in blocks */
	uint32_t		bitmap_blocks;	/* Size of Memory bitmap in
						   block */
	uint32_t		max_mapnr;	/* = max_mapnr */
	uint32_t		total_ram_blocks;/* Number of blocks should be
						   written */
	uint32_t		device_blocks;	/* Number of total blocks in
						 * the dump device */
	uint32_t		written_blocks; /* Number of written blocks */
	uint32_t		current_cpu;	/* CPU# which handles dump */
	int32_t			nr_cpus;	/* Number of CPUs */
	uint64_t		tasks[0];	/* "struct task_struct *" */
} __attribute__((packed));

/* descriptor of each page for vmcore */
struct page_desc {
	uint64_t	offset;		/* the offset of the page data*/
	uint32_t	size;		/* the size of this dump page */
	uint32_t	flags;		/* flags */
	uint64_t	page_flags;	/* page flags */
};

struct disk_dump_priv {
	unsigned char *bitmap;	/* for compressed dumps */
	off_t descoff;		/* position of page descriptor table */
};

/* flags */
#define DUMP_DH_COMPRESSED	0x1	/* page is compressed */

static inline int
page_is_dumpable(struct dump_desc *dd, unsigned int nr)
{
	struct disk_dump_priv *ddp = dd->priv;
	return ddp->bitmap[nr>>3] & (1 << (nr & 7));
}

static off_t
pfn_to_pdpos(struct dump_desc *dd, unsigned long pfn)
{
	struct disk_dump_priv *ddp = dd->priv;
	unsigned i, n;

	n = 0;
	for (i = 0; i < pfn >> 3; ++i)
		n += bitcount(ddp->bitmap[i]);
	for (i = 0; i < (pfn & 0x7); ++i)
		if (page_is_dumpable(dd, pfn - i))
		    ++n;

	return ddp->descoff + n * sizeof(struct page_desc);
}

static int
diskdump_read_page(struct dump_desc *dd, unsigned long pfn)
{
	struct page_desc pd;
	off_t pd_pos;
	void *buf;

	if (!page_is_dumpable(dd, pfn)) {
		memset(dd->page, 0, dd->page_size);
		return 0;
	}

	pd_pos = pfn_to_pdpos(dd, pfn);
	if (pread(dd->fd, &pd, sizeof pd, pd_pos) != sizeof pd)
		return -1;

	pd.offset = dump64toh(dd, pd.offset);
	pd.size = dump32toh(dd, pd.size);
	pd.flags = dump32toh(dd, pd.flags);
	pd.page_flags = dump64toh(dd, pd.page_flags);

	if (pd.flags & DUMP_DH_COMPRESSED) {
		if (pd.size > MAX_PAGE_SIZE)
			return -1;
		buf = dd->buffer;
	} else {
		if (pd.size != dd->page_size)
			return -1;
		buf = dd->page;
	}

	/* read page data */
	if (pread(dd->fd, buf, pd.size, pd.offset) != pd.size)
		return -1;

	if (pd.flags & DUMP_DH_COMPRESSED) {
		uLongf retlen = dd->page_size;
		int ret = uncompress(dd->page, &retlen,
				     buf, pd.size);
		if ((ret != Z_OK) || (retlen != dd->page_size))
			return -1;
	}

	return 0;
}

static int
sane_header_values(int32_t block_size, uint32_t bitmap_blocks,
		   uint32_t max_mapnr)
{
	unsigned maxcovered;

	/* Page size must be reasonable */
	if (block_size < MIN_PAGE_SIZE || block_size > MAX_PAGE_SIZE)
		return 0;

	/* It must be a power of 2 */
	if (block_size != (block_size & ~(block_size - 1)))
		return 0;

	/* Number of bitmap blocks should cover all pages in the system */
	maxcovered = 8 * bitmap_blocks * block_size;
	if (maxcovered < max_mapnr)
		return 0;

	/* basic sanity checks passed, return true: */
	return 1;
}

static int
header_looks_sane_32(struct disk_dump_header_32 *dh)
{
	if (sane_header_values(le32toh(dh->block_size),
			       le32toh(dh->bitmap_blocks),
			       le32toh(dh->max_mapnr)))
		return __LITTLE_ENDIAN;

	if (sane_header_values(be32toh(dh->block_size),
			       be32toh(dh->bitmap_blocks),
			       be32toh(dh->max_mapnr)))
		return __BIG_ENDIAN;

	return 0;
}

static int
header_looks_sane_64(struct disk_dump_header_64 *dh)
{
	if (sane_header_values(le32toh(dh->block_size),
			       le32toh(dh->bitmap_blocks),
			       le32toh(dh->max_mapnr)))
		return __LITTLE_ENDIAN;

	if (sane_header_values(be32toh(dh->block_size),
			       be32toh(dh->bitmap_blocks),
			       be32toh(dh->max_mapnr)))
		return __BIG_ENDIAN;

	return 0;
}

static inline int
read_bitmap(struct dump_desc *dd, int32_t sub_hdr_size,
	    int32_t bitmap_blocks, int32_t max_mapnr)
{
	struct disk_dump_priv *ddp = dd->priv;
	off_t off = (1 + sub_hdr_size) * dd->page_size;
	size_t bitmapsize;

	ddp->descoff = off + bitmap_blocks * dd->page_size;

	if (8 * bitmap_blocks * dd->page_size >= max_mapnr * 2) {
		/* partial dump */
		bitmap_blocks /= 2;
		off += bitmap_blocks * dd->page_size;
	}

	bitmapsize = bitmap_blocks * dd->page_size;
	if (! (ddp->bitmap = malloc(bitmapsize)) )
		return -1;

	dd->max_pfn = bitmapsize * 8;

	if (dd->flags & DIF_FORCE)
		memset(ddp->bitmap, 0xff, bitmapsize);
	else if (pread(dd->fd, ddp->bitmap, bitmapsize, off) != bitmapsize)
		return -1;

	return 0;
}

static int
handle_common(struct dump_desc *dd)
{
	struct disk_dump_header_32 *dh32 = dd->buffer;
	struct disk_dump_header_64 *dh64 = dd->buffer;
	struct disk_dump_priv ddp;

	dd->read_page = diskdump_read_page;
	dd->priv = &ddp;

	if (uts_looks_sane(&dh32->utsname)) {
		copy_uts_string(dd->machine, dh32->utsname.machine);
		copy_uts_string(dd->ver, dh32->utsname.release);
	} else if (uts_looks_sane(&dh64->utsname)) {
		copy_uts_string(dd->machine, dh64->utsname.machine);
		copy_uts_string(dd->ver, dh64->utsname.release);
	}

	if (!need_explore(dd))
		return 0;

	if ( (dd->endian = header_looks_sane_32(dh32)) ) {
		dd->page_size = dump32toh(dd, dh32->block_size);
		if (read_bitmap(dd,
				dump32toh(dd, dh32->sub_hdr_size),
				dump32toh(dd, dh32->bitmap_blocks),
				dump32toh(dd, dh32->max_mapnr)) ) {
			perror("Cannot read dumpable bitmap");
			return -1;
		}
		return explore_raw_data(dd);
	} else if ( (dd->endian = header_looks_sane_64(dh64)) ) {
		dd->page_size = dump32toh(dd, dh64->block_size);
		if (read_bitmap(dd,
				dump32toh(dd, dh64->sub_hdr_size),
				dump32toh(dd, dh64->bitmap_blocks),
				dump32toh(dd, dh64->max_mapnr)) ) {
			perror("Cannot read dumpable bitmap");
			return -1;
		}
		return explore_raw_data(dd);
	} else {
		fputs("Sorry, the file header looks damaged\n", stderr);
		return -1;
	}

	return 0;
}

int
handle_diskdump(struct dump_desc *dd)
{
	strcpy(dd->format, "diskdump");
	return handle_common(dd);
}

int
handle_kdump(struct dump_desc *dd)
{
	strcpy(dd->format, "compressed kdump");
	return handle_common(dd);
}
