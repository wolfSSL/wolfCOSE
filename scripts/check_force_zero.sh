#!/bin/sh
#
# Prove wolfCose_ForceZero survives dead-store elimination. A caller in the
# same translation unit as wolfcose_util.c wipes a local buffer that is dead
# afterwards; at -O3 the zeroing stores must still be in its assembly. A
# plain XMEMSET control in the same file must lose them, which shows the
# optimizer could drop the wipe and the store patterns below are not noise.
# Runs with and without WOLFSSL_NO_ASM, which selects the barrier body.

set -eu

CC=${CC:-cc}
CFLAGS=${CFLAGS:-}

# Keep only include paths and defines from CFLAGS: the optimization level is
# fixed here, and sanitizer or coverage flags would rewrite the stores.
flags=""
take_next=0
for flag in $CFLAGS; do
    if [ "$take_next" -eq 1 ]; then
        flags="$flags $flag"
        take_next=0
        continue
    fi
    case "$flag" in
        -isystem|-I|-D) flags="$flags $flag"; take_next=1 ;;
        -I*|-D*|-isystem*) flags="$flags $flag" ;;
    esac
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat >"$work/probe.c" <<'EOF'
#include "wolfcose_util.c"

void wcProbeFill(unsigned char* buf);
void wcProbeWipe(void);
void wcProbeControl(void);

void wcProbeWipe(void)
{
    unsigned char buf[256];
    wcProbeFill(buf);
    wolfCose_ForceZero(buf, sizeof(buf));
}

void wcProbeControl(void)
{
    unsigned char buf[256];
    wcProbeFill(buf);
    (void)XMEMSET(buf, 0, sizeof(buf));
}
EOF

# Zero sources for x86-64 and AArch64 with GCC and Clang: a memset or bzero
# call, rep stos, an x86 vector zero idiom or $0 immediate store, an AArch64
# zero-register store, or an AArch64 vector zero.
word='(^|[^[:alnum:]_])'
zero_store="memset|bzero|stos|${word}v?(pxor|xorps)[[:space:]]"
zero_store="$zero_store|${word}mov[a-z]*[[:space:]]+[\$]0,"
zero_store="$zero_store|${word}st[a-z]*[[:space:]]+[xw]zr,"
zero_store="$zero_store|movi[^,]*,[[:space:]]*#?0+([[:space:]]|$)"
inline_call='(call|jmp|bl|b)[[:space:]]+_?wolfCose_ForceZero([@[:space:]]|$)'

body() {
    awk -v fn="$1" '
        $0 ~ "^_?" fn ":" { on = 1; next }
        on && /^[[:space:]]*\.(cfi_endproc|size)/ { exit }
        on { print }
    ' "$2"
}

for asm_mode in "" "-DWOLFSSL_NO_ASM"; do
    label=${asm_mode:-default}
    # shellcheck disable=SC2086
    $CC -std=c99 -O3 -DHAVE_ANONYMOUS_INLINE_AGGREGATES=1 -I./include -Isrc \
        $flags $asm_mode -S -o "$work/probe.s" "$work/probe.c"

    body wcProbeWipe "$work/probe.s" >"$work/wipe.s"
    body wcProbeControl "$work/probe.s" >"$work/control.s"

    if [ ! -s "$work/wipe.s" ] || [ ! -s "$work/control.s" ]; then
        echo "FAIL ($label): probe functions not found in assembly"
        exit 1
    fi
    if grep -Eq "$inline_call" "$work/wipe.s"; then
        echo "FAIL ($label): wolfCose_ForceZero not inlined, check is moot"
        exit 1
    fi
    if grep -Eq "$zero_store" "$work/control.s"; then
        echo "FAIL ($label): plain memset kept, check cannot tell"
        exit 1
    fi
    if ! grep -Eq "$zero_store" "$work/wipe.s"; then
        echo "FAIL ($label): wolfCose_ForceZero stores optimized out"
        cat "$work/wipe.s"
        exit 1
    fi
    echo "PASS ($label): wolfCose_ForceZero stores kept at -O3"
done
