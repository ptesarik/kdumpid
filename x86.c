#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <dis-asm.h>

#include "kdumpid.h"

#define MAX_INSN_LEN	100

struct disas_priv {
	char *iptr;
	char insn[MAX_INSN_LEN];
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
looks_like_i386(struct dump_desc *dd, uint64_t addr)
{
	struct disassemble_info info;
	struct disas_priv priv;
	char *toksave;
	char *insn, *src, *dst;
	unsigned pc;
	int count;
	int esi_modified;

	init_disassemble_info(&info, &priv, disas_fn);
	info.arch          = bfd_arch_i386;
	info.mach          = bfd_mach_i386_i386;
	info.buffer        = dd->page;
	info.buffer_vma    = addr;
	info.buffer_length = dd->page_size;
	info.memory_error_func = error_func;
	disassemble_init_for_target(&info);

	pc = 0;
	do
	{
		pc += skip_zeroes(dd->page + pc, dd->page_size - pc);
		priv.iptr = priv.insn;
		count = print_insn_i386(addr + pc, &info);

		insn = strtok_r(priv.insn, wsep, &toksave);
		src = strtok_r(NULL, sep, &toksave);
		dst = strtok_r(NULL, sep, &toksave);

		if (is_lgdt(insn))
			return 1;

		if (dd->page_size - pc >= sizeof(xen_cpuid) &&
		    !memcmp(dd->page + pc, xen_cpuid, sizeof xen_cpuid))
			return 1;

		if (dd->flags & DIF_XEN && !esi_modified &&
		    !strncmp(insn, "mov", 3) && is_reg(src, "si")) {
			unsigned long long a;
			if (sscanf(dst, "0x%llx", &a) == 1)
				dd->xen_start_info = a;
		}

		if (is_reg(dst, "si"))
			esi_modified = 1;

		pc += count;
	} while (count > 0);

	return 0;
}

static int
looks_like_x86_64(struct dump_desc *dd, uint64_t addr)
{
	struct disassemble_info info;
	struct disas_priv priv;
	char *toksave;
	char *insn, *src, *dst;
	unsigned pc;
	int count;
	int rsi_modified;
	uint32_t ecx_value;

	/* If unsuccessful, retry for x86_64 */
	init_disassemble_info(&info, &priv, disas_fn);
	info.arch          = bfd_arch_i386;
	info.mach          = bfd_mach_x86_64;
	info.buffer        = dd->page;
	info.buffer_vma    = addr;
	info.buffer_length = dd->page_size;
	info.memory_error_func = error_func;
	disassemble_init_for_target(&info);

	rsi_modified = 0;
	pc = 0;
	ecx_value = 0;
	do
	{
		pc += skip_zeroes(dd->page + pc, dd->page_size - pc);
		priv.iptr = priv.insn;
		count = print_insn_i386(addr + pc, &info);

		insn = strtok_r(priv.insn, wsep, &toksave);
		src = strtok_r(NULL, sep, &toksave);
		dst = strtok_r(NULL, sep, &toksave);

		if (is_lgdt(insn))
			return 1;

		if (dd->page_size - pc >= sizeof(xen_cpuid) &&
		    !memcmp(dd->page + pc, xen_cpuid, sizeof xen_cpuid))
			return 1;

		if (!strcmp(insn, "wrmsr") && ecx_value == MSR_GS_BASE)
			return 1;

		if (dd->flags & DIF_XEN && !rsi_modified &&
		    !strncmp(insn, "mov", 3) && is_reg(src, "si")) {
			unsigned long long a;
			if (sscanf(dst, "0x%llx", &a) == 1)
				dd->xen_start_info = a;
		}

		if (!strcmp(insn, "mov") && is_reg(dst, "cx")) {
			unsigned long long a;
			if (sscanf(src, "$0x%llx", &a) == 1)
				ecx_value = a;
		}

		if (is_reg(dst, "si"))
			rsi_modified = 1;

		pc += count;
	} while (count > 0);

	return 0;
}

/* Decode the first page at addr and check whether it contains
 * an "lgdt" instruction.
 */
int
looks_like_kcode_x86(struct dump_desc *dd, uint64_t addr)
{
	int res;

	if (read_page(dd, addr / dd->page_size))
		return -1;

	if (dd->arch != ARCH_X86_64 && (res = looks_like_i386(dd, addr)) )
		return res;

	if (dd->arch != ARCH_X86 && (res = looks_like_x86_64(dd, addr)) )
		return res;

	return 0;
}
