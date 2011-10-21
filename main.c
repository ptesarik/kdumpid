/* 
 * main.c 
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

#include "kdumpid.h"

typedef int (*handler_t)(struct dump_desc *dd);

struct crash_file {
	const char *magic;
	size_t magiclen;
	handler_t handler;
};

/* /dev/crash cannot handle reads larger than page size */
static int
paged_cpin(int fd, void *buffer, size_t size)
{
	long page_size = sysconf(_SC_PAGESIZE);
	while (size) {
		size_t chunksize = (size > page_size)
			? page_size
			: size;
		if (read(fd, buffer, chunksize) != chunksize)
			return size;

		buffer += chunksize;
		size -= chunksize;
	}
	return 0;
}

static const char magic_elfdump[] =
	{ '\177', 'E', 'L', 'F' };
static const char magic_kvm[] =
	{ 'Q', 'E', 'V', 'M' };
static const char magic_libvirt[] = 
	{ 'L', 'i', 'b', 'v' };
static const char magic_xc_save[] =
	{ 'L', 'i', 'n', 'u', 'x', 'G', 'u', 'e',
	  's', 't', 'R', 'e', 'c', 'o', 'r', 'd' };
static const char magic_xc_core[] =
	{ 0xed, 0xeb, 0x0f, 0xf0 };
static const char magic_xc_core_hvm[] =
	{ 0xee, 0xeb, 0x0f, 0xf0 };
static const char magic_diskdump[] =
	{ 'D', 'I', 'S', 'K', 'D', 'U', 'M', 'P' };
static const char magic_kdump[] =
	{ 'K', 'D', 'U', 'M', 'P', ' ', ' ', ' ' };
static const char magic_lkcd_le[] =
	{ 0xed, 0x23, 0x8f, 0x61, 0x73, 0x01, 0x19, 0xa8 };
static const char magic_lkcd_be[] =
	{ 0xa8, 0x19, 0x01, 0x73, 0x61, 0x8f, 0x23, 0xed };
static const char magic_mclxcd[] =
	{ 0xdd, 0xcc, 0x8b, 0x9a };
static const char magic_s390[] =
	{ 0xa8, 0x19, 0x01, 0x73, 0x61, 0x8f, 0x23, 0xfd };
static const char magic_devmem[0];

static int
handle_kvm(struct dump_desc *dd)
{
	fputs("KVM dump not yet implemented\n", stderr);
	return -1;
}

static int
handle_libvirt(struct dump_desc *dd)
{
	fputs("Libvirt dump not yet implemented\n", stderr);
	return -1;
}

static int
handle_xc_save(struct dump_desc *dd)
{
	fputs("Xen xc_save not yet implemented\n", stderr);
	return -1;
}

static int
handle_xc_core(struct dump_desc *dd)
{
	fputs("Xen xc_core not yet implemented\n", stderr);
	return -1;
}

static int
handle_xc_core_hvm(struct dump_desc *dd)
{
	fputs("Xen xc_core HVM not yet implemented\n", stderr);
	return -1;
}

static int
handle_mclxcd(struct dump_desc *dd)
{
	fputs("MCLXCD dump not yet implemented\n", stderr);
	return -1;
}

static int
handle_s390(struct dump_desc *dd)
{
	fputs("S/390 dump not yet implemented\n", stderr);
	return -1;
}

#define FORMAT(x)	{ magic_ ## x, sizeof(magic_ ## x), handle_ ## x }
static struct crash_file formats[] = {
	FORMAT(elfdump),
	FORMAT(kvm),
	FORMAT(libvirt),
	FORMAT(xc_save),
	FORMAT(xc_core),
	FORMAT(xc_core_hvm),
	FORMAT(diskdump),
	FORMAT(kdump),
	FORMAT(lkcd_le),
	FORMAT(lkcd_be),
	FORMAT(mclxcd),
	FORMAT(s390),
	FORMAT(devmem),
};

#define NFORMATS	(sizeof formats / sizeof formats[0])

static void
version(FILE *out, const char *progname)
{
	fprintf(out, "%s version %d.%d\n",
		basename(progname), VER_MAJOR, VER_MINOR);
}

static void
help(FILE *out, const char *progname)
{
	fprintf(out, "Usage: %s [-f] [-v] <dumpfile>\n",
		basename(progname));
}

#define SHORTOPTS	"fhv"

int
main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "force", no_argument, NULL, 'f' },
		{ "help", no_argument, NULL, 'h' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "version", no_argument, NULL, 256 },
		{0, 0, 0, 0}
	};
	struct dump_desc dd;
	int c, opt;
	int i;

	/* Initialize dd */
	memset(&dd, 0, sizeof dd);
	dd.last_pfn = -1;

	while ( (c = getopt_long(argc, argv, SHORTOPTS, opts, &opt)) != -1 )
		switch(c) {
		case 'f':
			dd.flags |= DIF_FORCE;
			break;
		case 'h':
			help(stdout, argv[0]);
			return 0;
		case 'v':
			dd.flags |= DIF_VERBOSE;
			break;
		case 256:
			version(stdout, argv[0]);
			return 0;
		}

	if (argc - optind != 1) {
		help(stderr, argv[0]);
		return 1;
	}
	dd.name = argv[optind];

	if ((dd.buffer = calloc(1, MAX_PAGE_SIZE)) == NULL) {
		perror("Buffer alloc");
		return 2;
	}

	if ((dd.fd = open(dd.name, O_RDONLY)) < 0) {
		perror(dd.name);
		return 2;
	}
	if (paged_cpin(dd.fd, dd.buffer, MAX_PAGE_SIZE)) {
		perror("Read header");
		return 2;
	}

	for (i = 0; i < NFORMATS; ++i) {
		if (!memcmp(dd.buffer,
			    formats[i].magic, formats[i].magiclen)) {
			if (!formats[i].handler(&dd))
				break;
		}
	}

	/* Intentionally ignore errors on close */
	close(dd.fd);

	if (i == NFORMATS) {
		fputs("Not a supported dump file format\n", stderr);
		return 1;
	}

	if (dd.arch == ARCH_UNKNOWN)
		dd.arch = get_machine_arch(dd.machine);
	if (!*dd.ver && *dd.banner)
		get_version_from_banner(&dd);

	printf("Format: %s%s\n", dd.format,
	       dd.flags & DIF_XEN ? ", Xen" : "");
	printf("Arch: %s\n", arch_name(dd.arch));
	printf("Version: %s\n", dd.ver);
	if (*dd.machine)
		printf("Machine: %s\n", dd.machine);
	if (*dd.banner)
		printf("Banner: %s\n", dd.banner);

	if (dd.cfg) {
		char *local = strstr(dd.cfg, "CONFIG_LOCALVERSION=");
		if (local) {
			char c, *end = strchr(local, '\n');
			if (end) {
				c = *end;
				*end = 0;
			}
			printf("Cfg release: %s\n", local + 20);
			if (end)
				*end = c;
		}
	}

	return 0;
}
