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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

#include "kdumpid.h"

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

static void
print_verbose(struct dump_desc *dd)
{
	const char *machine = kdump_machine(dd->ctx);
	if (!machine)
		machine = dd->machine;
	if (*machine)
		printf("Machine: %s\n", machine);
	if (*dd->banner)
		printf("Banner: %s\n", dd->banner);

	if (dd->cfg) {
		char *local = strstr(dd->cfg, "CONFIG_LOCALVERSION=");
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
}

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
	kdump_status status;
	int c, opt;
	int i;

	/* Initialize dd */
	memset(&dd, 0, sizeof dd);

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

	if ((dd.fd = open(dd.name, O_RDONLY)) < 0) {
		perror(dd.name);
		return 2;
	}
	status = kdump_fdopen(&dd.ctx, dd.fd);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot initialize %s: %s\n", dd.name,
			status == kdump_syserr
			? strerror(errno)
			: "libkdumpfile failure");
	}

	dd.page_size = kdump_pagesize(dd.ctx);

	if (need_explore(&dd))
		explore_raw_data(&dd);

	strcpy(dd.ver, kdump_release(dd.ctx));
	if (!*dd.ver)
		get_version_from_banner(&dd);

	printf("Format: %s%s\n", kdump_format(dd.ctx),
	       kdump_is_xen(dd.ctx) ? ", Xen" : "");
	printf("Arch: %s\n", kdump_arch_name(dd.ctx));
	printf("Version: %s\n", dd.ver);
	if (dd.flags & DIF_VERBOSE)
		print_verbose(&dd);

	/* Intentionally ignore errors on close */
	kdump_free(dd.ctx);
	close(dd.fd);

	return 0;
}
