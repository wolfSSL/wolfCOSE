#!/bin/sh

set -eu

if ! command -v lcov >/dev/null 2>&1; then
    echo "lcov is required for release coverage" >&2
    exit 1
fi

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/wolfcose-release-coverage.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM
cd "$ROOT"

capture()
{
    name=$1
    lcov --capture --directory . --output-file "$TMP_DIR/$name.info" \
        --ignore-errors mismatch >/dev/null
    lcov --remove "$TMP_DIR/$name.info" '/usr/*' '*/tests/*' \
        '*/examples/*' --output-file "$TMP_DIR/$name.filtered.info" \
        --ignore-errors unused >/dev/null
}

make coverage-force-failure
capture default

make eat-psa-coverage-force-failure
capture eat-psa

make hpke-coverage-force-failure
capture hpke

lcov --add-tracefile "$TMP_DIR/default.filtered.info" \
    --add-tracefile "$TMP_DIR/eat-psa.filtered.info" \
    --add-tracefile "$TMP_DIR/hpke.filtered.info" \
    --output-file "$TMP_DIR/release.info" >/dev/null

awk '
    /^SF:/ {
        file = substr($0, 4)
        active = (file ~ /\/src\/[^/]+\.c$/)
        if (active) seen[file] = 1
        next
    }
    active && /^DA:/ {
        split(substr($0, 4), fields, ",")
        if (fields[2] == 0) uncovered[file]++
    }
    END {
        failed = 0
        count = 0
        for (file in seen) {
            count++
            missed = uncovered[file] + 0
            printf "%s: %d uncovered line(s)\n", file, missed
            if (missed != 0) failed = 1
        }
        if (count == 0) {
            print "no wolfCOSE source coverage found" > "/dev/stderr"
            failed = 1
        }
        exit failed
    }
' "$TMP_DIR/release.info"

cp "$TMP_DIR/release.info" release-coverage.info
echo "PASS: merged release coverage is 100% per source file"
