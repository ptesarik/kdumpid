#!/bin/sh

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
cd "$tmpdir"

cat > disas.c <<EOF
void disassembler();
void (*fn)() = disassembler;
EOF

rebuild()
{
    gcc -shared -o disas.o disas.c $LIBS
}

LIBS="-lopcodes"
rebuild
if nm -u disas.o | grep -q '^ *U bfd_' ; then
    LIBS="$LIBS -lbfd"
    rebuild
fi
if nm -u disas.o | grep -q '^ *U sframe_' ; then
    LIBS="$LIBS -lsframe"
    rebuild
fi
if nm -u disas.o | grep -q '^ *U \(htab_create\|splay_tree_new\)$' ; then
    LIBS="$LIBS -liberty"
    rebuild
fi
if nm -u disas.o | grep -q '^ *U inflate$' ; then
    LIBS="$LIBS -lz"
fi
if nm -u disas.o | grep -q '^ *U ZSTD_' ; then
    LIBS="$LIBS -lzstd"
fi
if nm -u disas.o | grep -q '^ *U dlopen' ; then
    LIBS="$LIBS -ldl"
fi

echo $LIBS
