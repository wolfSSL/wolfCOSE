#!/bin/sh

set -eu

usage()
{
    echo "usage: $0 --version X.Y.Z [--ref REF]" >&2
    exit 2
}

VERSION=
REF=HEAD

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
        *)
            usage
            ;;
    esac
done

[ -n "$VERSION" ] || usage

if ! printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "invalid release version: $VERSION" >&2
    exit 1
fi

if ! git cat-file -e "$REF^{commit}" 2>/dev/null; then
    echo "release ref is not a commit: $REF" >&2
    exit 1
fi

if git rev-parse -q --verify "refs/tags/v$VERSION" >/dev/null; then
    TAG_COMMIT=$(git rev-list -n 1 "v$VERSION")
    REF_COMMIT=$(git rev-parse "$REF^{commit}")
    if [ "$TAG_COMMIT" != "$REF_COMMIT" ]; then
        echo "v$VERSION already points at $TAG_COMMIT, not $REF_COMMIT" >&2
        exit 1
    fi
fi

TRACKED_BUILD_OUTPUT=$(git ls-tree -r --name-only "$REF" | \
    grep -E '\.(o|a|so|su|gcda|gcno)$' || true)
if [ -n "$TRACKED_BUILD_OUTPUT" ]; then
    echo "release ref contains tracked build output:" >&2
    printf '%s\n' "$TRACKED_BUILD_OUTPUT" >&2
    exit 1
fi

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/wolfcose-release-validate.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM
git archive "$REF" | tar -x -C "$TMP_DIR"

VERSION_HEADER=$TMP_DIR/include/wolfcose/version.h
CHANGELOG=$TMP_DIR/ChangeLog.md
RELEASE_NOTES=$TMP_DIR/docs/Release-Notes.md
README=$TMP_DIR/README.md
CURRENT_CHANGELOG=$TMP_DIR/current-release-changelog.md

for file in "$VERSION_HEADER" "$CHANGELOG" "$RELEASE_NOTES" "$README"; do
    if [ ! -f "$file" ]; then
        echo "release metadata file missing: $file" >&2
        exit 1
    fi
done

awk '
    NR > 1 && /^# wolfCOSE Release / { exit }
    { print }
' "$CHANGELOG" > "$CURRENT_CHANGELOG"

HEADER_VERSION=$(awk '/LIBWOLFCOSE_VERSION_STRING/ {gsub(/\"/, "", $3); print $3; exit}' "$VERSION_HEADER")
HEADER_HEX=$(awk '/LIBWOLFCOSE_VERSION_HEX/ {print $3; exit}' "$VERSION_HEADER")

MAJOR=${VERSION%%.*}
VERSION_REMAINDER=${VERSION#*.}
MINOR=${VERSION_REMAINDER%%.*}
PATCH=${VERSION_REMAINDER#*.}
EXPECTED_HEX=$(printf '0x%08X' "$(( (MAJOR << 24) | (MINOR << 12) | PATCH ))")

if [ "$HEADER_VERSION" != "$VERSION" ]; then
    echo "version header says $HEADER_VERSION, expected $VERSION" >&2
    exit 1
fi

if [ "$HEADER_HEX" != "$EXPECTED_HEX" ]; then
    echo "version hex says $HEADER_HEX, expected $EXPECTED_HEX" >&2
    exit 1
fi

CHANGELOG_HEAD=$(sed -n '1p' "$CHANGELOG")
NOTES_HEAD=$(sed -n '3p' "$RELEASE_NOTES")

printf '%s\n' "$CHANGELOG_HEAD" | grep -Eq \
    "^# wolfCOSE Release $VERSION \([A-Z][a-z]+ [0-9]{1,2}, [0-9]{4}\)$" || {
    echo "invalid top ChangeLog heading: $CHANGELOG_HEAD" >&2
    exit 1
}

printf '%s\n' "$NOTES_HEAD" | grep -Eq \
    "^## wolfCOSE $VERSION \([A-Z][a-z]+ [0-9]{1,2}, [0-9]{4}\)$" || {
    echo "invalid top release-notes heading: $NOTES_HEAD" >&2
    exit 1
}

section_line()
{
    awk -v heading="$1" '$0 == heading {print NR; exit}' \
        "$CURRENT_CHANGELOG"
}

VULN_LINE=$(section_line '## Vulnerabilities')
FEATURE_LINE=$(section_line '## New Feature Additions')
FIX_LINE=$(section_line '## Fixes')
IMPROVE_LINE=$(section_line '## Improvements/Optimizations')

if [ -z "$VULN_LINE" ] || [ -z "$FEATURE_LINE" ] || [ -z "$FIX_LINE" ] || \
   [ -z "$IMPROVE_LINE" ] || [ "$VULN_LINE" -ge "$FEATURE_LINE" ] || \
   [ "$FEATURE_LINE" -ge "$FIX_LINE" ] || [ "$FIX_LINE" -ge "$IMPROVE_LINE" ]; then
    echo "ChangeLog release sections are missing or out of order" >&2
    exit 1
fi

grep -Fq "current release is **$VERSION**" "$README" || {
    echo "README current release does not match $VERSION" >&2
    exit 1
}

if [ "$VERSION" = "2.0.0" ]; then
    grep -Fq 'No CVEs were assigned for this release.' \
        "$CURRENT_CHANGELOG" || {
        echo "2.0.0 ChangeLog must record that no CVEs were assigned" >&2
        exit 1
    }
    for rfc in 'RFC 9864' 'RFC 9783' 'RFC 9338' 'RFC 8778'; do
        grep -Fq "$rfc" "$CURRENT_CHANGELOG" || {
            echo "2.0.0 ChangeLog is missing $rfc" >&2
            exit 1
        }
    done
fi

if git rev-parse "$REF^" >/dev/null 2>&1; then
    git diff --check "$REF^" "$REF"
fi

echo "PASS: wolfCOSE $VERSION metadata at $(git rev-parse "$REF^{commit}")"
