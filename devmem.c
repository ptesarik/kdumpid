/* 
 * devmem.c 
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

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "kdumpid.h"

static int
devmem_read_page(struct dump_desc *dd, unsigned long pfn)
{
	off_t pos = pfn * dd->page_size;
	if (pread(dd->fd, dd->page, dd->page_size, pos) != dd->page_size)
		return -1;
	return 0;
}

int
handle_devmem(struct dump_desc *dd)
{
	struct stat st;

	if (fstat(dd->fd, &st)) {
		perror("Cannot stat dump file");
		return -1;
	}

	if (S_ISCHR(st.st_mode) &&
	    (st.st_rdev == makedev(1, 1) ||
	     major(st.st_rdev) == 10)) {
		strcpy(dd->format, "live source");
		dd->page_size = sysconf(_SC_PAGESIZE);
		dd->read_page = devmem_read_page;
		return explore_raw_data(dd);
	}

	return 1;
}
