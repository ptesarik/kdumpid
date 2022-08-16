#! /bin/sh
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
cd "$tmpdir"

cat > dis_asm.c <<EOF
#include <dis-asm.h>
void fn(struct disassemble_info *info, void *stream,
        fprintf_ftype fprintf_func, fprintf_styled_ftype fprintf_styled_func)
{
  init_disassemble_info(info, stream, fprintf_func, fprintf_styled_func);
}
EOF
if make dis_asm.o &> /dev/null
then
    echo "-DDIS_ASM_STYLED_PRINTF"
fi
