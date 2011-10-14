/* 
 * elfdump.c 
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
#include <unistd.h>
#include <errno.h>

#include <elf.h>

#include "kdumpid.h"

struct xen_p2m {
	uint64_t pfn;
	uint64_t gmfn; 
};

struct load_segment {
	off_t file_offset;
	uint64_t phys_start;
	uint64_t phys_end;
};

struct section {
	off_t file_offset;
	uint64_t size;
	int name_index;
};

struct elfdump_priv {
	int num_load_segments;
	struct load_segment *load_segments;
	int num_note_segments;
	struct load_segment *note_segments;

	int num_sections;
	struct section *sections;

	size_t strtab_size;
	char *strtab;

	off_t xen_pages_offset;
	void *xen_map;
	unsigned long xen_map_size;
	enum {
		xen_map_pfn,
		xen_map_p2m,
	} xen_map_type;
};

static enum arch
mach2arch(unsigned mach)
{
	switch(mach) {
	case EM_ARM:	return ARCH_ARM;
	case EM_ALPHA:
	case EM_FAKE_ALPHA:
			return ARCH_ALPHA;
	case EM_IA_64:	return ARCH_IA64;
	case EM_PPC:	return ARCH_PPC;
	case EM_PPC64:	return ARCH_PPC64;
	case EM_S390:	return ARCH_S390;
	case EM_386:	return ARCH_X86;
	case EM_X86_64:	return ARCH_X86_64;
	default:	return ARCH_UNKNOWN;
	}
}

static void
cleanup(struct elfdump_priv *edp)
{
	if (edp->load_segments)
		free(edp->load_segments);
	if (edp->sections)
		free(edp->sections);
	if (edp->strtab)
		free(edp->strtab);
}

static void
set_page_size(struct dump_desc *dd)
{
	static const int arch_page_shifts[] = {
		[ARCH_ALPHA]= 13,
		[ARCH_ARM] = 12,
		[ARCH_IA64] = 0,
		[ARCH_PPC] = 0,
		[ARCH_PPC64] = 0,
		[ARCH_S390] = 12,
		[ARCH_S390X] = 12,
		[ARCH_X86] = 12,
		[ARCH_X86_64] = 12,
	};
	int shift = arch_page_shifts[dd->arch];

	dd->page_size = 1 << shift;
	if (!shift)
		fprintf(stderr, "Arch size unknown. Guessing %lu\n",
			(unsigned long)dd->page_size);
}

static int
elf_read_page(struct dump_desc *dd, unsigned long pfn)
{
	struct elfdump_priv *edp = dd->priv;
	uint64_t addr = pfn * dd->page_size;
	off_t pos;

	if (edp->num_load_segments == 1) {
		pos = (off_t)addr + (off_t)edp->load_segments[0].file_offset;
	} else {
		struct load_segment *pls;
		int i;
		for (i = 0; i < edp->num_load_segments; i++) {
			pls = &edp->load_segments[i];
			if ((addr >= pls->phys_start) &&
			    (addr < pls->phys_end)) {
				pos = (off_t)(addr - pls->phys_start) +
					pls->file_offset;
				break;
			}
		}
		if (i >= edp->num_load_segments) 
	                return -1;
	}

	/* read page data */
	if (pread(dd->fd, dd->page, dd->page_size, pos) != dd->page_size)
		return -1;

	return 0;
}

static unsigned long
pfn_to_mfn(struct elfdump_priv *edp, unsigned long pfn)
{
	unsigned long i;

	if (edp->xen_map_type == xen_map_pfn) {
		uint64_t *p = edp->xen_map;
		for (i = 0; i < edp->xen_map_size; ++i, ++p)
			if (*p == pfn)
				return i;
	} else if (edp->xen_map_type == xen_map_p2m) {
		struct xen_p2m *p = edp->xen_map;
		for (i = 0; i < edp->xen_map_size; ++i, ++p)
			if (p->pfn == pfn)
				return i;
	}

	return ~0UL;
}

static int
elf_read_xen(struct dump_desc *dd, unsigned long pfn)
{
	struct elfdump_priv *edp = dd->priv;
        unsigned long mfn;
	off_t offset;

	if ((mfn = pfn_to_mfn(edp, pfn)) == ~0UL)
		return -1;

	offset = edp->xen_pages_offset + (off_t)mfn * dd->page_size;
	if (pread(dd->fd, dd->page, dd->page_size, offset) != dd->page_size)
		return -1;

	return 0;
}

static int
init_segments(struct elfdump_priv *edp, unsigned phnum)
{
	if (!phnum)
		return 0;

	edp->load_segments = malloc(2 * phnum * sizeof(struct load_segment));
	if (!edp->load_segments)
		return -1;
	edp->num_load_segments = 0;

	edp->note_segments = edp->load_segments + phnum;
	edp->num_note_segments = 0;
	return 0;
}

static int
init_sections(struct elfdump_priv *edp, unsigned snum)
{
	if (!snum)
		return 0;

	edp->sections = malloc(snum * sizeof(struct section));
	if (!edp->sections)
		return -1;
	edp->num_sections = 0;
	return 0;
}

static void
store_phdr(struct elfdump_priv *edp, unsigned type,
	   off_t offset, uint64_t addr, uint64_t size)
{
	struct load_segment *pls;

	if (type == PT_LOAD) {
		pls = edp->load_segments + edp->num_load_segments;
		++edp->num_load_segments;
	} else if (type == PT_NOTE) {
		pls = edp->note_segments + edp->num_note_segments;
		++edp->num_note_segments;
	} else
		return;

	pls->file_offset = offset;
	pls->phys_start = addr;
	pls->phys_end = addr + size;
}

static void
store_sect(struct elfdump_priv *edp, off_t offset,
	   uint64_t size, unsigned name_index)
{
	struct section *ps;

	ps = edp->sections + edp->num_sections;
	ps->file_offset = offset;
	ps->size = size;
	ps->name_index = name_index;
	++edp->num_sections;
}

static void *
read_elf_sect(struct dump_desc *dd, struct section *sect)
{
	void *buf;

	buf = malloc(sect->size);
	if (!buf)
		return NULL;

	if (pread(dd->fd, buf, sect->size, sect->file_offset) == sect->size)
		return buf;

	free(buf);
	return NULL;
}

static int
init_strtab(struct dump_desc *dd, unsigned strtabidx)
{
	struct elfdump_priv *edp = dd->priv;
	struct section *ps;

	if (!strtabidx || strtabidx >= edp->num_sections)
		return 0;	/* no string table */

	ps = edp->sections + strtabidx;
	edp->strtab_size = ps->size;
	edp->strtab = read_elf_sect(dd, ps);
	if (!edp->strtab)
		return -1;

	return 0;
}

static const char *
strtab_entry(struct elfdump_priv *edp, unsigned index)
{
	return index < edp->strtab_size
		? edp->strtab + index
		: NULL;
}

static int
init_elf32(struct dump_desc *dd, Elf32_Ehdr *ehdr)
{
	struct elfdump_priv *edp = dd->priv;
	Elf32_Phdr *prog;
	Elf32_Shdr *sect;
	int i;

	dd->arch = mach2arch(dump16toh(dd, ehdr->e_machine));
	set_page_size(dd);

	if (init_segments(edp, dump16toh(dd, ehdr->e_phnum)))
		goto fail;

	if (init_sections(edp, dump16toh(dd, ehdr->e_shnum)))
		goto fail;

	i = 0;
	prog = (Elf32_Phdr*)((char*)ehdr + dump32toh(dd, ehdr->e_phoff));
	while (i < dump16toh(dd, ehdr->e_phnum)) {
		store_phdr(edp,
			   dump32toh(dd, prog->p_type),
			   dump32toh(dd, prog->p_offset),
			   dump32toh(dd, prog->p_paddr),
			   dump32toh(dd, prog->p_filesz));
		++prog;
		++i;
	}

	i = 0;
	sect = (Elf32_Shdr*)((char*)ehdr + dump32toh(dd, ehdr->e_shoff));
	while (i < dump16toh(dd, ehdr->e_shnum)) {
		store_sect(edp,
			   dump32toh(dd, sect->sh_offset),
			   dump32toh(dd, sect->sh_size),
			   dump32toh(dd, sect->sh_name));
		++sect;
		++i;
	}

	if (init_strtab(dd, dump16toh(dd, ehdr->e_shstrndx)))
		goto fail;

	return 0;

 fail:
	cleanup(edp);
	return -1;
}

static int
init_elf64(struct dump_desc *dd, Elf64_Ehdr *ehdr)
{
	struct elfdump_priv *edp = dd->priv;
	Elf64_Phdr *prog;
	Elf64_Shdr *sect;
	int i;

	dd->arch = mach2arch(dump16toh(dd, ehdr->e_machine));
	set_page_size(dd);

	if (init_segments(edp, dump16toh(dd, ehdr->e_phnum)))
		goto fail;

	if (init_sections(edp, dump16toh(dd, ehdr->e_shnum)))
		goto fail;

	i = 0;
	prog = (Elf64_Phdr*)((char*)ehdr + dump64toh(dd, ehdr->e_phoff));
	while (i < dump16toh(dd, ehdr->e_phnum)) {
		store_phdr(edp,
			   dump32toh(dd, prog->p_type),
			   dump64toh(dd, prog->p_offset),
			   dump64toh(dd, prog->p_paddr),
			   dump64toh(dd, prog->p_filesz));
		++prog;
		++i;
	}

	i = 0;
	sect = (Elf64_Shdr*)((char*)ehdr + dump64toh(dd, ehdr->e_shoff));
	while (i < dump16toh(dd, ehdr->e_shnum)) {
		store_sect(edp,
			   dump64toh(dd, sect->sh_offset),
			   dump64toh(dd, sect->sh_size),
			   dump32toh(dd, sect->sh_name));
		++sect;
		++i;
	}

	if (init_strtab(dd, dump16toh(dd, ehdr->e_shstrndx)))
		goto fail;

	return 0;

 fail:
	cleanup(edp);
	return -1;
}

#if 0
	if (STREQ(name, ".note.Xen"))
/*
 *  Dump the array of elfnote structures, storing relevant info
 *  when requested during initialization.  This function is 
 *  common to both 32-bit and 64-bit ELF files.
 */
static void 
xc_core_dump_elfnote(off_t sh_offset, size_t sh_size, int store)
{
	int i, lf, index;
	struct elfnote *elfnote;
	ulonglong *data;
	struct xen_dumpcore_elfnote_header_desc *elfnote_header;
	struct xen_dumpcore_elfnote_format_version_desc *format_version;

	elfnote_header = NULL;
	format_version = NULL;

	for (index = 0; index < sh_size; ) {
		elfnote = (struct elfnote *)&notes_buffer[index];
		switch (elfnote->type) 
		{
		case XEN_ELFNOTE_DUMPCORE_NONE:           
			break;
		case XEN_ELFNOTE_DUMPCORE_HEADER:
			elfnote_header = (struct xen_dumpcore_elfnote_header_desc *)
				(elfnote+1);
			break;
		case XEN_ELFNOTE_DUMPCORE_XEN_VERSION:   
			break;
		case XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION:
			format_version = (struct xen_dumpcore_elfnote_format_version_desc *)
				(elfnote+1);
			break;
		default:
			break;
		}

		data = (ulonglong *)(elfnote+1);
		for (i = lf = 0; i < elfnote->descsz/sizeof(ulonglong); i++) {
			if (((i%2)==0)) {
				lf++;
			} else
				lf = 0;
                }
		index += sizeof(struct elfnote) + elfnote->descsz;
	}

	if (elfnote_header) {
		xd->xc_core.header.xch_magic = elfnote_header->xch_magic;
		xd->xc_core.header.xch_nr_vcpus = elfnote_header->xch_nr_vcpus;
		xd->xc_core.header.xch_nr_pages = elfnote_header->xch_nr_pages;
		xd->page_size = elfnote_header->xch_page_size;
	}

	if (format_version) {
		switch (format_version->version)
		{
		case FORMAT_VERSION_0000000000000001:
			break;
		default:
			error(WARNING, 
			    "unsupported xen dump-core format version: %016llx\n",
				format_version->version);
		}
		xd->xc_core.format_version = format_version->version;
	}

}
#endif

static int
handle_common(struct dump_desc *dd)
{
	struct elfdump_priv *edp = dd->priv;
	int i;

	if (!edp->num_load_segments && !edp->num_sections)
		return -1;

	/* get max PFN */
	for (i = 0; i < edp->num_load_segments; ++i) {
		unsigned long pfn =
			edp->load_segments[i].phys_end / dd->page_size;
		if (pfn > dd->max_pfn)
			dd->max_pfn = pfn;
	}

	for (i = 0; i < edp->num_sections; ++i) {
		struct section *sect = edp->sections + i;
		const char *name = strtab_entry(edp, sect->name_index);
		if (!strcmp(name, ".xen_pages"))
			edp->xen_pages_offset = sect->file_offset;
		else if (!strcmp(name, ".xen_p2m")) {
			edp->xen_map = read_elf_sect(dd, sect);
			if (!edp->xen_map)
				goto fail;
			edp->xen_map_type = xen_map_p2m;
			edp->xen_map_size = sect->size /sizeof(struct xen_p2m);
		} else if (!strcmp(name, ".xen_pfn")) {
			edp->xen_map = read_elf_sect(dd, sect);
			if (!edp->xen_map)
				goto fail;
			edp->xen_map_type = xen_map_pfn;
			edp->xen_map_size = sect->size / sizeof(uint64_t);
		}
	}
	if (edp->xen_pages_offset) {
		if (!edp->xen_map) {
			fputs("Xen: no way to map machine pages\n", stderr);
			goto fail;
		}
		dd->flags |= DIF_XEN;
		dd->read_page = elf_read_xen;
	}

	return explore_raw_data(dd);

 fail:
	cleanup(edp);
	return -1;
}

int
handle_elfdump(struct dump_desc *dd)
{
	unsigned char *eheader = dd->buffer;
	Elf32_Ehdr *elf32 = dd->buffer;
	Elf64_Ehdr *elf64 = dd->buffer;
	struct elfdump_priv edp;

	dd->read_page = elf_read_page;
	dd->priv = &edp;
	memset(&edp, 0, sizeof edp);

	switch (eheader[EI_DATA]) {
	case ELFDATA2LSB: dd->endian = __LITTLE_ENDIAN; break;
	case ELFDATA2MSB: dd->endian = __BIG_ENDIAN; break;
	default:
		fprintf(stderr, "ELF header unknown endianity: 0x%x\n",
			eheader[EI_DATA]);
		return -1;
	}

        if ((elf32->e_ident[EI_CLASS] == ELFCLASS32) &&
	    (dump16toh(dd, elf32->e_type) == ET_CORE) &&
	    (dump32toh(dd, elf32->e_version) == EV_CURRENT) &&
	    !init_elf32(dd, elf32)) {
		strcpy(dd->format, "ELF dump, 32-bit");
		return handle_common(dd);
	} else if ((elf64->e_ident[EI_CLASS] == ELFCLASS64) &&
		   (dump16toh(dd, elf64->e_type) == ET_CORE) &&
		   (dump32toh(dd, elf64->e_version) == EV_CURRENT) &&
		   !init_elf64(dd, elf64)) {
		strcpy(dd->format, "ELF dump, 64-bit");
		return handle_common(dd);
	}

	fputs("Unrecognized ELF dumpfile format\n", stderr);
	return -1;
}
