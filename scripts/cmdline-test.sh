#!/usr/bin/env bash
# Exercise every wolfcose_tool command-line subcommand across algorithms.
#
# Drives the actual built binary (not the unit-test harness) so the command
# line paths — argument parsing, key file round-trips, and the
# keygen/sign/verify/enc/dec/mac/macverify/info dispatch — are covered end
# to end. Algorithm names match the tool's own parser (see `wolfcose_tool`
# usage). An algorithm whose keygen fails is treated as "not built in this
# configuration" and skipped, so this script is safe on minimal builds.
#
# Usage: scripts/cmdline-test.sh [path-to-wolfcose_tool]
set -u

TOOL="${1:-./tools/wolfcose_tool}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ ! -x "$TOOL" ]; then
    echo "cmdline-test: tool not found or not executable: $TOOL" >&2
    exit 2
fi

PASS=0
FAIL=0
SKIP=0
IN="$WORK/payload.bin"
printf 'wolfCOSE cmdline test payload \x01\x02\x03\xde\xad\xbe\xef' > "$IN"

ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
skip() { SKIP=$((SKIP+1)); printf '  SKIP  %s (%s)\n' "$1" "${2:-not built}"; }

# When an algorithm is expected to be built, a keygen failure is a FAIL, not a
# silent skip. ML-DSA is only expected when the wolfSSL leg enabled PQC.
EXPECT_PQC="${EXPECT_PQC:-false}"
# keygen $alg $out $optional(0|1): on failure, skip if optional else FAIL.
keygen_or() {
    if "$TOOL" keygen -a "$1" -o "$2" >/dev/null 2>&1; then return 0; fi
    if [ "$3" = "1" ]; then skip "$1"; else bad "$1 keygen"; fi
    return 1
}

# Names exactly as wolfcose_tool's parser accepts them.
SIGN_ALGS="ES256 EdDSA Ed448 ML-DSA-44 ML-DSA-65 ML-DSA-87"
ENC_ALGS="A128GCM A192GCM A256GCM ChaCha20 AES-CCM"
MAC_ALGS="HMAC256 HMAC384 HMAC512"

echo "== Signing: keygen -> sign -> verify -> self-test =="
for A in $SIGN_ALGS; do
    K="$WORK/sig.key"; C="$WORK/sig.cose"
    case "$A" in
        ML-DSA-*) [ "$EXPECT_PQC" = "true" ] && OPT=0 || OPT=1 ;;
        *)        OPT=0 ;;
    esac
    if ! keygen_or "$A" "$K" "$OPT"; then continue; fi
    if ! "$TOOL" sign -k "$K" -a "$A" -i "$IN" -o "$C" >/dev/null 2>&1; then
        bad "$A sign"; continue
    fi
    if "$TOOL" verify -k "$K" -i "$C" >/dev/null 2>&1; then
        ok "$A sign/verify"
    else
        bad "$A verify"
    fi
    if "$TOOL" test -a "$A" >/dev/null 2>&1; then
        ok "$A self-test"
    else
        bad "$A self-test"
    fi
done

echo "== Countersignatures: sign -> countersign -> verify both layers =="
PK="$WORK/primary.key"; CK="$WORK/counter.key"
BASE="$WORK/primary.cose"; COUNTER="$WORK/counter.cose"
COUNTER2="$WORK/counter2.cose"; AAD="$WORK/counter.aad"
printf 'release approval policy' > "$AAD"
if "$TOOL" keygen -a ES256 -o "$PK" >/dev/null 2>&1 && \
   "$TOOL" keygen -a ES256 -o "$CK" >/dev/null 2>&1 && \
   "$TOOL" sign -k "$PK" -a ES256 -i "$IN" -o "$BASE" \
       >/dev/null 2>&1; then
    if "$TOOL" countersign -k "$CK" -a ES256 -i "$BASE" \
        -o "$COUNTER" --aad "$AAD" >/dev/null 2>&1 && \
       "$TOOL" counterverify -k "$CK" -i "$COUNTER" --aad "$AAD" \
        >/dev/null 2>&1 && \
       "$TOOL" verify -k "$PK" -i "$COUNTER" >/dev/null 2>&1; then
        ok "ES256 countersign and verify both layers"
    else
        bad "ES256 countersign round-trip"
    fi
    if "$TOOL" countersign -k "$CK" -a ES256 -i "$COUNTER" \
        -o "$COUNTER2" --aad "$AAD" >/dev/null 2>&1 && \
       "$TOOL" counterverify -k "$CK" -i "$COUNTER2" --index 1 \
        --aad "$AAD" >/dev/null 2>&1; then
        ok "ES256 second countersignature index"
    else
        bad "ES256 second countersignature index"
    fi
    if "$TOOL" counterverify -k "$CK" -i "$COUNTER" \
        >/dev/null 2>&1; then
        bad "countersignature wrong AAD rejected"
    else
        ok "countersignature wrong AAD rejected"
    fi
else
    skip "countersignature (ES256)"
fi

# Public-only RSA builds can't sign a decoded key, so skip; the self-test
# still covers RSA signing.
echo "== RSA-PSS: keygen -> sign -> verify -> self-test =="
for A in PS256 PS384 PS512; do
    K="$WORK/rsa.key"; C="$WORK/rsa.cose"
    if ! keygen_or "$A" "$K" 0; then continue; fi
    if "$TOOL" sign -k "$K" -a "$A" -i "$IN" -o "$C" >/dev/null 2>&1; then
        if "$TOOL" verify -k "$K" -i "$C" >/dev/null 2>&1; then
            ok "$A sign/verify"
        else
            bad "$A verify"
        fi
    elif [ "$(wc -c < "$K")" -lt 500 ]; then
        # Public-only key (n,e only) is ~271B; a full private key is ~924B.
        skip "$A sign/verify" "public-only RSA COSE_Key build"
    else
        bad "$A sign"
    fi
    if "$TOOL" test -a "$A" >/dev/null 2>&1; then
        ok "$A self-test"
    else
        bad "$A self-test"
    fi
done

echo "== Tamper detection: corrupted COSE_Sign1 must NOT verify =="
TK="$WORK/tamper.key"; TC="$WORK/tamper.cose"
if "$TOOL" keygen -a ES256 -o "$TK" >/dev/null 2>&1 && \
   "$TOOL" sign -k "$TK" -a ES256 -i "$IN" -o "$TC" >/dev/null 2>&1; then
    SZ=$(wc -c < "$TC")
    # Invert the last byte rather than setting it to a fixed value: an ECDSA
    # signature ends in 0xff about once in 256 runs, and overwriting it with
    # 0xff then left the message intact and the check failing.
    LAST=$(dd if="$TC" bs=1 skip=$((SZ-1)) count=1 2>/dev/null | od -An -tu1 | tr -d '[:space:]')
    printf "\\$(printf '%03o' $((LAST ^ 255)))" |
        dd of="$TC" bs=1 seek=$((SZ-1)) count=1 conv=notrunc >/dev/null 2>&1
    if "$TOOL" verify -k "$TK" -i "$TC" >/dev/null 2>&1; then
        bad "tampered signature rejected"
    else
        ok "tampered signature rejected"
    fi
else
    skip "tamper (ES256)"
fi

echo "== Encryption: keygen -> enc -> dec =="
for A in $ENC_ALGS; do
    K="$WORK/enc.key"; C="$WORK/enc.cose"; O="$WORK/enc.out"
    if ! keygen_or "$A" "$K" 0; then continue; fi
    if ! "$TOOL" enc -k "$K" -a "$A" -i "$IN" -o "$C" >/dev/null 2>&1; then
        bad "$A enc"; continue
    fi
    if "$TOOL" dec -k "$K" -i "$C" -o "$O" >/dev/null 2>&1 && cmp -s "$IN" "$O"; then
        ok "$A enc/dec"
    else
        bad "$A dec"
    fi
done

echo "== MAC: keygen -> mac -> macverify =="
for A in $MAC_ALGS; do
    K="$WORK/mac.key"; C="$WORK/mac.cose"
    if ! keygen_or "$A" "$K" 0; then continue; fi
    if ! "$TOOL" mac -k "$K" -a "$A" -i "$IN" -o "$C" >/dev/null 2>&1; then
        bad "$A mac"; continue
    fi
    if "$TOOL" macverify -k "$K" -i "$C" >/dev/null 2>&1; then
        ok "$A mac/macverify"
    else
        bad "$A macverify"
    fi
done

echo "== info on a signed message =="
IK="$WORK/info.key"; IC="$WORK/info.cose"
if "$TOOL" keygen -a ES256 -o "$IK" >/dev/null 2>&1 && \
   "$TOOL" sign -k "$IK" -a ES256 -i "$IN" -o "$IC" >/dev/null 2>&1; then
    if "$TOOL" info -i "$IC" >/dev/null 2>&1; then
        ok "info"
    else
        bad "info"
    fi
else
    skip "info (ES256)"
fi

echo "== Usage errors must exit non-zero =="
if "$TOOL" >/dev/null 2>&1; then bad "no-args exits non-zero"; else ok "no-args exits non-zero"; fi
if "$TOOL" boguscmd >/dev/null 2>&1; then bad "bad command exits non-zero"; else ok "bad command exits non-zero"; fi

echo
echo "== Command-line test summary: $PASS passed, $FAIL failed, $SKIP skipped =="
[ "$FAIL" -eq 0 ]
