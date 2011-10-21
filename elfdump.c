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

/* System information exported through crash notes. */
#define XEN_ELFNOTE_CRASH_INFO 0x1000001

/* .Xen.note types */
#define XEN_ELFNOTE_DUMPCORE_NONE            0x2000000
#define XEN_ELFNOTE_DUMPCORE_HEADER          0x2000001
#define XEN_ELFNOTE_DUMPCORE_XEN_VERSION     0x2000002
#define XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION  0x2000003

struct xen_p2m {
	uint64_t pfn;
	uint64_t gmfn; 
};

struct xen_elfnote_header {
	uint64_t xch_magic;
	uint64_t xch_nr_vcpus;
	uint64_t xch_nr_pages;
	uint64_t xch_page_size;
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
	unsigned long xen_p2m_mfn;
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

	if (!dd->page_size) {
		int shift = arch_page_shifts[dd->arch];

		dd->page_size = 1 << shift;
		if (!shift)
			fprintf(stderr, "Arch size unknown. Guessing %lu\n",
				(unsigned long)dd->page_size);
	}
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

static int
elf_read_xen_dom0(struct dump_desc *dd, unsigned long pfn)
{
	struct elfdump_priv *edp = dd->priv;
	unsigned fpp = dd->page_size / dd->ptr_size;
	uint64_t mfn_idx, frame_idx;

	mfn_idx = pfn / fpp;
	frame_idx = pfn % fpp;
	if (mfn_idx >= edp->xen_map_size)
		return -1;

	pfn = (dd->ptr_size == 8)
		? ((uint64_t*)edp->xen_map)[mfn_idx]
		: ((uint32_t*)edp->xen_map)[mfn_idx];
	if (elf_read_page(dd, pfn))
		return -1;

	pfn = (dd->ptr_size == 8)
		? ((uint64_t*)dd->page)[frame_idx]
		: ((uint32_t*)dd->page)[frame_idx];
	return elf_read_page(dd, pfn);
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
elf_read_xen_domU(struct dump_desc *dd, unsigned long pfn)
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
read_elf_seg(struct dump_desc *dd, struct load_segment *seg)
{
	size_t size = seg->phys_end - seg->phys_start;
	void *buf = malloc(size);
	if (!buf)
		return NULL;

	if (pread(dd->fd, buf, size, seg->file_offset) == size)
		return buf;

	free(buf);
	return NULL;
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

static void
process_xen_note(struct dump_desc *dd, uint32_t type,
		 void *desc, size_t descsz)
{
	struct elfdump_priv *edp = dd->priv;
	unsigned words = descsz / dd->ptr_size;

	if (type == XEN_ELFNOTE_CRASH_INFO) {
		edp->xen_p2m_mfn = (dd->ptr_size == 8)
			? dump64toh(dd, ((uint64_t*)desc)[words-1])
			: dump32toh(dd, ((uint32_t*)desc)[words-1]);
	}

	dd->flags |= DIF_XEN;
}

static void
process_xc_xen_note(struct dump_desc *dd, uint32_t type,
		    void *desc, size_t descsz)
{
	if (type == XEN_ELFNOTE_DUMPCORE_HEADER) {
		struct xen_elfnote_header *header = desc;
		dd->page_size = dump64toh(dd, header->xch_page_size);
	} else if (type == XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION) {
		uint64_t version = dump64toh(dd, *(uint64_t*)desc);

		if (version != 1)
			fprintf(stderr, "WARNING: unsupported xen dump-core"
				"format version: %016llx\n",
				(unsigned long long)version);
	}
}

static void
process_vmcoreinfo(struct dump_desc *dd, void *desc, size_t descsz)
{
	char *p = desc;

	while (descsz) {
		char *eol, *eq;

		if (! (eol = memchr(p, '\n', descsz)) )
			eol = p + descsz;
		descsz -= eol - p;

		if ( (eq = memchr(p, '=', eol - p)) ) {
			size_t namesz = eq - p;

			++eq;
			if (namesz == sizeof("PAGESIZE") - 1 &&
			    !strncmp(p, "PAGESIZE", namesz))
				sscanf(eq, "%zd", &dd->page_size);
			else if (namesz == sizeof("OSRELEASE") - 1 &&
				 !strncmp(p, "OSRELEASE", namesz)) {
				size_t valsz = eol - eq;
				if (valsz > 65)
					valsz = 65;
				memcpy(&dd->ver, eq, valsz);
				dd->ver[65] = 0;
			}
		}

		p = eol;
		while (descsz && *p == '\n')
			++p, --descsz;
	}
}

static int
note_equal(const char *name, const char *notename, size_t notenamesz)
{
	size_t namelen = strlen(name);
	if (notenamesz >= namelen && notenamesz <= namelen + 1)
		return !memcmp(name, notename, notenamesz);
	return 0;
}

static void
process_notes(struct dump_desc *dd, Elf32_Nhdr *hdr, size_t size)
{
	while (size >= sizeof(Elf32_Nhdr)) {
		char *name, *desc;
		Elf32_Word namesz = dump32toh(dd, hdr->n_namesz);
		Elf32_Word descsz = dump32toh(dd, hdr->n_descsz);
		Elf32_Word type = dump32toh(dd, hdr->n_type);
		size_t descoff = sizeof(Elf32_Nhdr) + ((namesz + 3) & ~3);

		if (size < descoff + ((descsz + 3) & ~3))
			break;
		size -= descoff + ((descsz + 3) & ~3);

		name = (char*) (hdr + 1);
		desc = (char*)hdr + descoff;
		hdr = (Elf32_Nhdr*) (desc + ((descsz + 3) & ~3));

		if (note_equal("Xen", name, namesz))
			process_xen_note(dd, type, desc, descsz);
		else if (note_equal(".note.Xen", name, namesz))
			process_xc_xen_note(dd, type, desc, descsz);
		else if (note_equal("VMCOREINFO", name, namesz))
			process_vmcoreinfo(dd, desc, descsz);
	}

	if (size)
		fprintf(stderr, "Warning: %zd junk bytes after notes\n", size);
}

static int
initialize_xen_map64(struct dump_desc *dd, void *dir)
{
	struct elfdump_priv *edp = dd->priv;
	unsigned fpp = dd->page_size / dd->ptr_size;
	uint64_t *dirp, *p, *map;
	uint64_t pfn;
	unsigned mfns;

	mfns = 0;
	for (dirp = dir, pfn = 0; *dirp && pfn < dd->max_pfn;
	     ++dirp, pfn += fpp * fpp) {
		if (read_page(dd, *dirp))
			return -1;

		for (p = dd->page; (void*)p < dd->page + dd->page_size; ++p)
			if (*p)
				++mfns;
	}

	if (! (map = malloc(mfns * sizeof(uint64_t))) ) {
		perror("Cannot malloc Xen map");
		return -1;
	}
	edp->xen_map = map;
	edp->xen_map_size = mfns;

	for (dirp = dir; mfns; ++dirp) {
		if (read_page(dd, *dirp))
			return -1;
		for (p = dd->page; (void*)p < dd->page + dd->page_size; ++p)
			if (*p) {
				*map++ = dump64toh(dd, *p);
				--mfns;
			}
	}

	return 0;
}

static int
initialize_xen_map32(struct dump_desc *dd, void *dir)
{
	struct elfdump_priv *edp = dd->priv;
	unsigned fpp = dd->page_size / dd->ptr_size;
	uint32_t *dirp, *p, *map;
	uint32_t pfn;
	unsigned mfns;

	mfns = 0;
	for (dirp = dir, pfn = 0; *dirp && pfn < dd->max_pfn;
	     ++dirp, pfn += fpp * fpp) {
		if (read_page(dd, *dirp))
			return -1;

		for (p = dd->page; (void*)p < dd->page + dd->page_size; ++p)
			if (*p)
				++mfns;
	}

	if (! (map = malloc(mfns * sizeof(uint32_t))) ) {
		perror("Cannot malloc Xen map");
		return -1;
	}
	edp->xen_map = map;
	edp->xen_map_size = mfns;

	for (dirp = dir; mfns; ++dirp) {
		if (read_page(dd, *dirp))
			return -1;
		for (p = dd->page; (void*)p < dd->page + dd->page_size; ++p)
			if (*p) {
				*map++ = dump32toh(dd, *p);
				--mfns;
			}
	}

	return 0;
}

static int
initialize_xen_map(struct dump_desc *dd)
{
	struct elfdump_priv *edp = dd->priv;
	void *dir;
	int ret = -1;

	if ( (dir = malloc(dd->page_size)) == NULL) {
		perror("Cannot allocate Xen p2m list");
		goto done;
	}
	dd->page = dir;

	if (read_page(dd, edp->xen_p2m_mfn))
		goto free_dir;

	if ( (dd->page = malloc(dd->page_size)) == NULL) {
		perror("Cannot allocate Xen frame page");
		goto free_dir;
	}

	ret = (dd->ptr_size == 8)
		? initialize_xen_map64(dd, dir)
		: initialize_xen_map32(dd, dir);

	if (!ret)
		dd->read_page = elf_read_xen_dom0;

	free(dd->page);
 free_dir:
	free(dir);
 done:
	return ret;
}

static int
handle_common(struct dump_desc *dd)
{
	struct elfdump_priv *edp = dd->priv;
	int i;

	if (!edp->num_load_segments && !edp->num_sections)
		return -1;

	dd->ptr_size = arch_ptr_size(dd->arch);

	/* read notes */
	for (i = 0; i < edp->num_note_segments; ++i) {
		struct load_segment *seg = edp->note_segments + i;
		Elf32_Nhdr *hdr = read_elf_seg(dd, seg);
		if (!hdr)
			goto fail;
		process_notes(dd, hdr, seg->phys_end - seg->phys_start);
		free(hdr);
	}

	if (!need_explore(dd))
		return 0;

	set_page_size(dd);

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

	if (edp->xen_p2m_mfn && initialize_xen_map(dd))
		goto fail;

	if (edp->xen_pages_offset) {
		if (!edp->xen_map) {
			fputs("Xen: no way to map machine pages\n", stderr);
			goto fail;
		}
		dd->flags |= DIF_XEN;
		dd->read_page = elf_read_xen_domU;
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
