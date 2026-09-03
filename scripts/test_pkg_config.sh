#!/bin/sh
# Verify wolfSSL pkg-config discovery without requiring wolfSSL installation.

if [ "${1-}" = "--fake-cc" ]; then
    shift
    if [ -z "${FAKE_CC_LOG-}" ]; then
        exit 1
    fi
    printf '%s\n' "$*" >> "$FAKE_CC_LOG"
    output=
    while [ "$#" -gt 0 ]; do
        if [ "$1" = "-o" ]; then
            shift
            if [ "$#" -eq 0 ]; then
                exit 1
            fi
            output=$1
            break
        fi
        shift
    done
    if [ -z "$output" ]; then
        exit 1
    fi
    : > "$output"
    exit 0
fi

if [ "${1-}" = "--fake-ar" ]; then
    shift
    if [ "$#" -lt 2 ]; then
        exit 1
    fi
    shift
    : > "$1"
    exit 0
fi

if [ "${1-}" = "--fixture" ]; then
    case "${2-}" in
        --exists)
            case "${3-}" in
                wolfssl|wolfssl-custom)
                    exit 0
                    ;;
                *)
                    exit 1
                    ;;
            esac
            ;;
        --cflags)
            case "${3-}" in
                wolfssl)
                    printf '%s\n' '-I/fake/wolfssl/include -DFAKE_WOLFSSL_PACKAGE=1'
                    ;;
                wolfssl-custom)
                    printf '%s\n' '-I/fake/custom-wolfssl/include'
                    ;;
                *)
                    exit 1
                    ;;
            esac
            ;;
        --libs)
            case "${3-}" in
                wolfssl)
                    printf '%s\n' '-L/fake/wolfssl/lib -lfakewolfssl'
                    ;;
                wolfssl-custom)
                    printf '%s\n' '-L/fake/custom-wolfssl/lib -lfakecustomwolfssl'
                    ;;
                *)
                    exit 1
                    ;;
            esac
            ;;
        *)
            exit 1
            ;;
    esac
    exit 0
fi

set -eu

ROOT_DIR=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
MAKE_BIN=${MAKE:-make}
SCRIPT_PATH="$ROOT_DIR/scripts/test_pkg_config.sh"

contains() {
    case "$1" in
        *"$2"*) ;;
        *)
            printf 'FAIL: expected build flags to contain %s\n' "$2" >&2
            exit 1
            ;;
    esac
}

excludes() {
    case "$1" in
        *"$2"*)
            printf 'FAIL: expected build flags to exclude %s\n' "$2" >&2
            exit 1
            ;;
        *) ;;
    esac
}

run_make() {
    target=$1
    shift
    env -i PATH="${PATH:-/usr/bin:/bin}" TMPDIR="${TMPDIR:-/tmp}" \
        "$MAKE_BIN" -C "$ROOT_DIR" -B -n "$@" "$target"
}

run_make_with_cflags() {
    target=$1
    cflags=$2
    shift 2
    env -i PATH="${PATH:-/usr/bin:/bin}" TMPDIR="${TMPDIR:-/tmp}" \
        CFLAGS="$cflags" "$MAKE_BIN" -C "$ROOT_DIR" -B -n "$@" "$target"
}

run_config_make() {
    env -i PATH="${PATH:-/usr/bin:/bin}" TMPDIR="${TMPDIR:-/tmp}" \
        FAKE_CC_LOG="$FAKE_CC_LOG" "$MAKE_BIN" -s -C "$config_fixture" "$@"
}

check_config_rebuild() (
    config_fixture=$(mktemp -d "${TMPDIR:-/tmp}/wolfcose-config.XXXXXX")
    trap 'rm -rf "$config_fixture"' 0 1 2 3 15
    mkdir -p "$config_fixture/src" "$config_fixture/include/wolfcose"
    cp "$ROOT_DIR/Makefile" "$config_fixture/Makefile"
    cp "$ROOT_DIR/src/wolfcose_cbor.c" "$ROOT_DIR/src/wolfcose.c" \
        "$ROOT_DIR/src/wolfcose_eat_psa.c" \
        "$ROOT_DIR/src/wolfcose_internal.h" "$config_fixture/src/"
    cp "$ROOT_DIR/include/wolfcose/wolfcose.h" \
        "$ROOT_DIR/include/wolfcose/eat_psa.h" \
        "$config_fixture/include/wolfcose/"

    FAKE_CC_LOG="$config_fixture/compiler.log"
    run_config_make \
        "CC=sh $SCRIPT_PATH --fake-cc" \
        "AR=sh $SCRIPT_PATH --fake-ar" \
        'PKG_CONFIG=false' \
        'WOLFSSL_CFLAGS=-I/fake/first/include' \
        'WOLFSSL_LIBS=-L/fake/first/lib -lfakefirst' \
        libwolfcose.a
    run_config_make \
        "CC=sh $SCRIPT_PATH --fake-cc" \
        "AR=sh $SCRIPT_PATH --fake-ar" \
        'PKG_CONFIG=false' \
        'WOLFSSL_CFLAGS=-I/fake/second/include' \
        'WOLFSSL_LIBS=-L/fake/second/lib -lfakesecond' \
        libwolfcose.a
    run_config_make \
        "CC=sh $SCRIPT_PATH --fake-cc" \
        "AR=sh $SCRIPT_PATH --fake-ar" \
        'PKG_CONFIG=false' \
        'WOLFSSL_CFLAGS=-I/fake/second/include' \
        'WOLFSSL_LIBS=-L/fake/second/lib -lfakesecond' \
        libwolfcose.a

    # Some supported file systems expose only one-second timestamp precision.
    sleep 1
    touch "$config_fixture/include/wolfcose/eat_psa.h"
    run_config_make \
        "CC=sh $SCRIPT_PATH --fake-cc" \
        "AR=sh $SCRIPT_PATH --fake-ar" \
        'PKG_CONFIG=false' \
        'WOLFSSL_CFLAGS=-I/fake/second/include' \
        'WOLFSSL_LIBS=-L/fake/second/lib -lfakesecond' \
        libwolfcose.a

    compiler_args=$(cat "$FAKE_CC_LOG")
    contains "$compiler_args" '-I/fake/second/include'
    compiler_count=$(wc -l < "$FAKE_CC_LOG" | tr -d ' ')
    if [ "$compiler_count" -ne 7 ]; then
        printf 'FAIL: expected 7 config/header compiles, got %s\n' \
            "$compiler_count" >&2
        exit 1
    fi
    last_compile=$(tail -n 1 "$FAKE_CC_LOG")
    contains "$last_compile" 'src/wolfcose_eat_psa.c'
)

pkg_config_output=$(run_make tool \
    "PKG_CONFIG=sh $SCRIPT_PATH --fixture")
contains "$pkg_config_output" '-I/fake/wolfssl/include'
contains "$pkg_config_output" '-L/fake/wolfssl/lib -lfakewolfssl'
excludes "$pkg_config_output" '/usr/local/include'
excludes "$pkg_config_output" '/usr/local/lib'

shared_pkg_config_output=$(run_make shared \
    "PKG_CONFIG=sh $SCRIPT_PATH --fixture")
contains "$shared_pkg_config_output" '-L/fake/wolfssl/lib -lfakewolfssl'
excludes "$shared_pkg_config_output" '/usr/local/lib'

c99_output=$(run_make c99-check "PKG_CONFIG=sh $SCRIPT_PATH --fixture")
contains "$c99_output" '-isystem /fake/wolfssl/include'
contains "$c99_output" '-DFAKE_WOLFSSL_PACKAGE=1'
excludes "$c99_output" '-I/fake/wolfssl/include'
excludes "$c99_output" '/usr/local/include'

fallback_output=$(run_make tool 'PKG_CONFIG=false')
contains "$fallback_output" '-isystem /usr/local/include'
contains "$fallback_output" '-L/usr/local/lib -lwolfssl'

prefix_output=$(run_make tool 'PKG_CONFIG=false' \
    'WOLFSSL_PREFIX=/custom/prefix')
contains "$prefix_output" '-isystem /custom/prefix/include'
contains "$prefix_output" '-L/custom/prefix/lib -lwolfssl'

custom_package_output=$(run_make tool \
    "PKG_CONFIG=sh $SCRIPT_PATH --fixture" \
    'WOLFSSL_PACKAGE=wolfssl-custom')
contains "$custom_package_output" '-I/fake/custom-wolfssl/include'
contains "$custom_package_output" '-L/fake/custom-wolfssl/lib -lfakecustomwolfssl'
excludes "$custom_package_output" '/fake/wolfssl'

override_output=$(run_make tool \
    "PKG_CONFIG=sh $SCRIPT_PATH --fixture" \
    'WOLFSSL_CFLAGS=-I/custom/include' \
    'WOLFSSL_LIBS=-L/custom/lib -lcustomwolfssl')
contains "$override_output" '-I/custom/include'
contains "$override_output" '-L/custom/lib -lcustomwolfssl'
excludes "$override_output" '/fake/wolfssl'

cross_override_output=$(run_make tool 'PKG_CONFIG=false' \
    'WOLFSSL_CFLAGS=-I/cross/include' \
    'WOLFSSL_LIBS=-L/cross/lib -lcrosswolfssl')
contains "$cross_override_output" '-I/cross/include'
contains "$cross_override_output" '-L/cross/lib -lcrosswolfssl'
excludes "$cross_override_output" '-isystem /usr/local/include'
excludes "$cross_override_output" '-L/usr/local/lib'

c99_override_output=$(run_make c99-check \
    'PKG_CONFIG=false' 'WOLFSSL_INC=/custom/include')
contains "$c99_override_output" '-isystem /custom/include'

c99_system_override_output=$(run_make c99-check \
    'PKG_CONFIG=false' 'WOLFSSL_CFLAGS=-isystem /custom/include')
contains "$c99_system_override_output" '-isystem /custom/include'
excludes "$c99_system_override_output" '-isystem system'

inherited_cflags_output=$(run_make_with_cflags tool '-O2' 'PKG_CONFIG=false')
contains "$inherited_cflags_output" '-std=c99'
contains "$inherited_cflags_output" '-Wconversion'

check_config_rebuild

printf 'PASS: pkg-config build discovery\n'
