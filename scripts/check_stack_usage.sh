#!/bin/sh
# Fail if any wolfCOSE stack frame exceeds the byte budget (default 6144).
# Frames are bounded constants; absence of VLAs/alloca is enforced separately
# by -Werror=vla in the Makefile. Requires a prior build with -fstack-usage.
set -e

BUDGET="${1:-6144}"
SU="src/wolfcose.su src/wolfcose_cbor.su src/wolfcose_eat_psa.su"

for f in $SU; do
    if [ ! -f "$f" ]; then
        echo "missing $f — build with -fstack-usage first" >&2
        exit 2
    fi
done

# Flag unbounded frames (qualifier exactly "dynamic", not "dynamic,bounded" or
# "static") regardless of the printed size, plus any frame over budget.
over=$(awk -F'\t' -v b="$BUDGET" '
    $3 == "dynamic" { print "  " $1 "  UNBOUNDED (dynamic)"; next }
    $2 + 0 > b      { print "  " $1 "  " $2 " bytes" }
' $SU)

if [ -n "$over" ]; then
    echo "FAIL: stack frames over ${BUDGET} bytes:"
    echo "$over"
    exit 1
fi

echo "PASS: all wolfCOSE stack frames within ${BUDGET} bytes"
echo "Largest frames:"
sort -t "	" -k2 -n -r $SU | head -5 | awk -F'\t' '{ print "  " $1 "  " $2 " bytes" }'
