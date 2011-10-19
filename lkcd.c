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

#include <endian.h>
#include <stdio.h>

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

#define DUMP_PANIC_LEN 0x100

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

	/* the time of the system crash */
	struct timeval_64    dh_time;

	/* the utsname (uname) information */
	struct new_utsname   dh_utsname;

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

/* Other fields follow... */
} __attribute__((packed));

/* LKCDv2 .. LKCDv7 64-bit variant */
struct dump_header_v2_64 {
	/* Known fields */
	struct dump_header_common common;

	/* the number of pages in this dump specifically */
	uint32_t             dh_num_pages;

	/* the panic string, if available */
	char                 dh_panic_string[DUMP_PANIC_LEN];

	/* the time of the system crash */
	struct timeval_64    dh_time;

	/* the utsname (uname) information */
	struct new_utsname   dh_utsname;

/* Other fields follow... */
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

/* Other fields follow... */
} __attribute__((packed));

static inline long
base_version(int32_t version)
{
	return version & ~(LKCD_DUMP_MCLX_V0|LKCD_DUMP_MCLX_V1);
}

static int
handle_v1(struct dump_desc *dd)
{
	struct dump_header_v1_32 *dh32 = dd->buffer;
	struct dump_header_v1_64 *dh64 = dd->buffer;

	if (!uts_looks_sane(&dh32->dh_utsname) &&
	    uts_looks_sane(&dh32->dh_utsname)) {
		copy_uts_string(dd->machine, dh64->dh_utsname.machine);
		copy_uts_string(dd->ver, dh64->dh_utsname.release);
	} else {
		copy_uts_string(dd->machine, dh32->dh_utsname.machine);
		copy_uts_string(dd->ver, dh32->dh_utsname.release);
	}
	return 0;
}

static int
handle_v2(struct dump_desc *dd)
{
	struct dump_header_v2_32 *dh32 = dd->buffer;
	struct dump_header_v2_64 *dh64 = dd->buffer;

	if (!uts_looks_sane(&dh32->dh_utsname) &&
	    uts_looks_sane(&dh32->dh_utsname)) {
		copy_uts_string(dd->machine, dh64->dh_utsname.machine);
		copy_uts_string(dd->ver, dh64->dh_utsname.release);
	} else {
		copy_uts_string(dd->machine, dh32->dh_utsname.machine);
		copy_uts_string(dd->ver, dh32->dh_utsname.release);
	}
	return 0;
}

static int
handle_v8(struct dump_desc *dd)
{
	struct dump_header_v8 *dh = dd->buffer;

	copy_uts_string(dd->machine, dh->dh_utsname.machine);
	copy_uts_string(dd->ver, dh->dh_utsname.release);
	return 0;
}

int
handle_common(struct dump_desc *dd)
{
	struct dump_header_common *dh = dd->buffer;
	int32_t version;

	version = dump32toh(dd, dh->dh_version);
	snprintf(dd->format, sizeof(dd->format),
		 "LKCD v%ld", base_version(version));

	switch(base_version(version)) {
	case LKCD_DUMP_V1:
		return handle_v1(dd);

	case LKCD_DUMP_V2:
	case LKCD_DUMP_V3:
	case LKCD_DUMP_V5:
	case LKCD_DUMP_V6:
	case LKCD_DUMP_V7:
		return handle_v2(dd);

	case LKCD_DUMP_V8:
	case LKCD_DUMP_V9:
	case LKCD_DUMP_V10:
		return handle_v8(dd);

	default:
		fprintf(stderr, "unsupported LKCD dump version: %ld (%lx)\n", 
			base_version(version), (long)version);
		return -1;
	}
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
