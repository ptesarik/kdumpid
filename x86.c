#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <dis-asm.h>

#include "kdumpid.h"

#define MAX_INSN_LEN	100

struct disas_state {
	uint32_t ecx_value;
	int si_stored, si_modified;
	int depth;
};

struct disas_priv {
	char *iptr;
	struct disas_state initstate;

	char insn[MAX_INSN_LEN];
	unsigned char *pagemap;
};

static const unsigned char xen_cpuid[] =
	{ 0x0f, 0x0b, 0x78, 0x65, 0x6e, 0x0f, 0xa2 };

#define MSR_GS_BASE	0xc0000101

static const char sep[] = ", \t\r\n";
#define wsep	(sep+1)

static int
disas_fn(void *data, const char *fmt, ...)
{
	struct disas_priv *priv = data;
	va_list va;
	size_t remain;
	int len;

	va_start(va, fmt);

	remain = priv->insn + sizeof(priv->insn) - priv->iptr;
	len = vsnprintf(priv->iptr, remain, fmt, va);
	if (len > 0)
		priv->iptr += len;

	va_end(va);

	return 0;
}

static void error_func(int status, bfd_vma memaddr,
		       struct disassemble_info *dinfo)
{
	/* intentionally empty */
}

static size_t
skip_zeroes(unsigned char *buf, size_t len)
{
	size_t num = 0;
	while (len-- && !*buf++)
		++num;
	return (num > 2) ? num : 0;
}

static int
check_xen_early_idt_msg(struct dump_desc *dd)
{
	static const unsigned char msg[] =
		"PANIC: early exception rip %lx error %lx cr2 %lx\n";
	void *p = dd->page;

	while (p < dd->page + 0x100)
		if (!memcmp(p, msg, sizeof msg - 1))
			return 1;
	return 0;
}

static void
set_pagemap(unsigned char *pagemap, unsigned pc, int count)
{
	while (count > 0) {
		pagemap[pc >> 3] |= 1 << (pc & 7);
		++pc, --count;
	}
}

static int
is_lgdt(const char *insn)
{
	return insn && (!strcmp(insn, "lgdt") || !strcmp(insn, "lgdtl"));
}

static int
is_reg(const char *loc, const char *reg)
{
	if (!loc || *loc++ != '%')
		return 0;
	if (*loc == 'r' || *loc == 'e')
		++loc;
	return !strcmp(loc, reg);
}

static int
disas_at(struct dump_desc *dd, struct disassemble_info *info, unsigned pc)
{
	struct disas_priv *priv = info->stream;
	struct disas_state state = priv->initstate;
	char *toksave;
	char *insn, *arg1, *arg2;
	unsigned long long a;
	int count;

	do {
		count = skip_zeroes(dd->page + pc, dd->page_size - pc);
		set_pagemap(priv->pagemap, pc, count);
		pc += count;

		if (dd->page_size - pc == 0)
			break;

		if (dd->page_size - pc >= sizeof(xen_cpuid) &&
		    !memcmp(dd->page + pc, xen_cpuid, sizeof xen_cpuid))
			return 1;

		if ( (priv->pagemap[pc >> 3] & (1 << (pc & 7))) )
			break;

		priv->iptr = priv->insn;
		count = print_insn_i386(info->buffer_vma + pc, info);
		set_pagemap(priv->pagemap, pc, count);
		if (count < 0)
			break;
		pc += count;

		insn = strtok_r(priv->insn, wsep, &toksave);
		arg1 = strtok_r(NULL, sep, &toksave);
		arg2 = strtok_r(NULL, sep, &toksave);

		/* a jump instruction? */
		if ( (*insn == 'j' ||
		      !strncmp(insn, "call", 4)) &&
		     sscanf(arg1, "0x%llx", &a) == 1) {
			int cont = strncmp(insn, "jmp", 3);

			a -= info->buffer_vma;
			if (a < info->buffer_vma + dd->page_size) {
				priv->initstate = state;
				++priv->initstate.depth;
				if (disas_at(dd, info, a))
					return 1;
				--priv->initstate.depth;
			}

			if (cont)
				continue;

			if (state.depth == 1 &&
			    dd->flags & DIF_XEN && state.si_stored)
				return check_xen_early_idt_msg(dd);

			break;
		}
		if (!strncmp(insn, "ret", 3))
			break;

		if (!strcmp(insn, "(bad)"))
			return -1;

		if (is_lgdt(insn))
			return 1;

		if (!strcmp(insn, "wrmsr") && state.ecx_value == MSR_GS_BASE)
			return 1;

		if (!strncmp(insn, "mov", 3)) {
			if (is_reg(arg2, "cx") &&
			    sscanf(arg1, "$0x%llx", &a) == 1)
				state.ecx_value = a;
			if (is_reg(arg1, "si")) {
				state.si_stored = 1;
				if (dd->flags & DIF_XEN &&
				    !state.si_modified &&
				    sscanf(arg2, "0x%llx", &a) == 1)
					dd->xen_start_info = a;
			}
		}

		if (is_reg(arg2, "si"))
			state.si_modified = 1;
	} while (count > 0);

	return 0;
}

/* Decode the first page at addr and check whether it looks like
 * x86 kernel code start.
 */
int
looks_like_kcode_x86(struct dump_desc *dd, uint64_t addr)
{
	struct disassemble_info info;
	struct disas_priv priv;

	if (read_page(dd, addr / dd->page_size))
		return -1;

	memset(&priv, 0, sizeof priv);
	if (! (priv.pagemap = calloc(1, dd->page_size / 8)) )
		return -1;

	init_disassemble_info(&info, &priv, disas_fn);
	info.memory_error_func = error_func;
	info.buffer        = dd->page;
	info.buffer_vma    = addr;
	info.buffer_length = dd->page_size;
	info.arch          = bfd_arch_i386;

	/* Try i386 code first */
	info.mach          = bfd_mach_i386_i386;
	disassemble_init_for_target(&info);
	if (dd->arch != ARCH_X86_64 && disas_at(dd, &info, 0)) {
		free(priv.pagemap);
		return 1;
	}

	/* Try x86_64 if that failed */
	info.mach          = bfd_mach_x86_64;
	disassemble_init_for_target(&info);
	if (dd->arch != ARCH_X86 && disas_at(dd, &info, 0)) {
		free(priv.pagemap);
		return 1;
	}

	free(priv.pagemap);
	return 0;
}
