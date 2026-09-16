#!/bin/sh

set -eu

usage()
{
    echo "usage: $0 --version X.Y.Z [--ref REF] [--output DIR]" >&2
    exit 2
}

VERSION=
REF=HEAD
OUTPUT=dist

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || usage
            VERSION=$2
            shift 2
            ;;
        --ref)
            [ "$#" -ge 2 ] || usage
            REF=$2
            shift 2
            ;;
        --output)
            [ "$#" -ge 2 ] || usage
            OUTPUT=$2
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

[ -n "$VERSION" ] || usage

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
cd "$REPO_DIR"

"$SCRIPT_DIR/validate.sh" --version "$VERSION" --ref "$REF"

COMMIT=$(git rev-parse "$REF^{commit}")
COMMIT_TIME=$(git show -s --format=%ct "$COMMIT")
PREFIX=wolfcose-$VERSION
OUTPUT_ABS=$(mkdir -p "$OUTPUT" && CDPATH='' cd -- "$OUTPUT" && pwd)
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/wolfcose-release-package.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

TAR_FILE=$OUTPUT_ABS/$PREFIX.tar.gz
ZIP_FILE=$OUTPUT_ABS/$PREFIX.zip
SUM_FILE=$OUTPUT_ABS/$PREFIX.sha256
MANIFEST=$OUTPUT_ABS/release-manifest.json
SUMMARY=$OUTPUT_ABS/release-test-summary.md

rm -f "$TAR_FILE" "$ZIP_FILE" "$SUM_FILE" "$MANIFEST" "$SUMMARY"

git archive --format=tar --prefix="$PREFIX/" "$COMMIT" > "$TMP_DIR/source.tar"
gzip -n -9 < "$TMP_DIR/source.tar" > "$TAR_FILE"
tar -xf "$TMP_DIR/source.tar" -C "$TMP_DIR"

find "$TMP_DIR/$PREFIX" -exec touch -h -d "@$COMMIT_TIME" {} + 2>/dev/null || \
    find "$TMP_DIR/$PREFIX" -exec touch -h -t "$(date -u -r "$COMMIT_TIME" '+%Y%m%d%H%M.%S')" {} +

(
    cd "$TMP_DIR"
    find "$PREFIX" -print | LC_ALL=C sort | zip -X -q "$ZIP_FILE" -@
)

if command -v sha256sum >/dev/null 2>&1; then
    (
        cd "$OUTPUT_ABS"
        sha256sum "$(basename "$TAR_FILE")" "$(basename "$ZIP_FILE")" > "$SUM_FILE"
    )
else
    (
        cd "$OUTPUT_ABS"
        shasum -a 256 "$(basename "$TAR_FILE")" "$(basename "$ZIP_FILE")" > "$SUM_FILE"
    )
fi

TAR_SHA=$(awk -v f="$(basename "$TAR_FILE")" '$2 == f {print $1}' "$SUM_FILE")
ZIP_SHA=$(awk -v f="$(basename "$ZIP_FILE")" '$2 == f {print $1}' "$SUM_FILE")

cat > "$MANIFEST" <<EOF
{
  "product": "wolfCOSE",
  "version": "$VERSION",
  "commit": "$COMMIT",
  "source_date_epoch": $COMMIT_TIME,
  "artifacts": {
    "$(basename "$TAR_FILE")": "$TAR_SHA",
    "$(basename "$ZIP_FILE")": "$ZIP_SHA"
  }
}
EOF

cat > "$SUMMARY" <<EOF
# wolfCOSE $VERSION Release Candidate

- Commit: \`$COMMIT\`
- Source date epoch: \`$COMMIT_TIME\`
- Tarball SHA-256: \`$TAR_SHA\`
- Zip SHA-256: \`$ZIP_SHA\`
- Checksum file: \`$(basename "$SUM_FILE")\`
EOF

mkdir "$TMP_DIR/from-tar" "$TMP_DIR/from-zip"
tar -xzf "$TAR_FILE" -C "$TMP_DIR/from-tar"
unzip -q "$ZIP_FILE" -d "$TMP_DIR/from-zip"

(
    cd "$TMP_DIR/from-tar"
    find "$PREFIX" -type f -print | LC_ALL=C sort | while IFS= read -r file; do
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$file"
        else
            shasum -a 256 "$file"
        fi
    done
) > "$TMP_DIR/tar-files"
(
    cd "$TMP_DIR/from-zip"
    find "$PREFIX" -type f -print | LC_ALL=C sort | while IFS= read -r file; do
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$file"
        else
            shasum -a 256 "$file"
        fi
    done
) > "$TMP_DIR/zip-files"
diff -u "$TMP_DIR/tar-files" "$TMP_DIR/zip-files"

if [ "${RELEASE_SMOKE_TEST:-1}" -eq 1 ]; then
    for tree in "$TMP_DIR/from-tar/$PREFIX" "$TMP_DIR/from-zip/$PREFIX"; do
        make -C "$tree" clean
        make -C "$tree"
        make -C "$tree" test
        make -C "$tree" tool-test
        make -C "$tree" demos
    done
    printf '\n- Archive smoke tests: passed\n' >> "$SUMMARY"
else
    printf '\n- Archive smoke tests: skipped by RELEASE_SMOKE_TEST=0\n' >> "$SUMMARY"
fi

echo "PASS: release artifacts written to $OUTPUT_ABS"
