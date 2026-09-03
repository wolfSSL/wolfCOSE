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
# HPKE is experimental and disabled by default. The dedicated CI lane sets
# this so a missing opt-in path cannot be silently skipped.
EXPECT_HPKE="${EXPECT_HPKE:-false}"
# The default matches WOLFCOSE_TOOL_MAX_MSG. Set this when validating a tool
# compiled with a non-default message limit.
HPKE_TOOL_MAX_MSG="${HPKE_TOOL_MAX_MSG:-8192}"
# keygen $alg $out $optional(0|1): on failure, skip if optional else FAIL.
keygen_or() {
    if "$TOOL" keygen -a "$1" -o "$2" >/dev/null 2>&1; then return 0; fi
    if [ "$3" = "1" ]; then skip "$1"; else bad "$1 keygen"; fi
    return 1
}

# HPKE keygen also writes the public recipient key used for encryption.
hpke_keygen_or() {
    if "$TOOL" keygen -a "$1" -o "$2" -p "$3" >/dev/null 2>&1; then return 0; fi
    if [ "$EXPECT_HPKE" = "true" ]; then bad "$1 keygen"; else skip "$1"; fi
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

echo "== Experimental COSE-HPKE: keygen -> encrypt -> decrypt -> self-test =="
H0_PRIV="$WORK/hpke0.private"; H0_PUB="$WORK/hpke0.public"
H0_COSE="$WORK/hpke0.cose"; H0_OUT="$WORK/hpke0.out"
if hpke_keygen_or "HPKE-0" "$H0_PRIV" "$H0_PUB"; then
    H0_SAME="$WORK/hpke0.same"
    if "$TOOL" keygen -a "HPKE-0" -o "$H0_SAME" -p "$H0_SAME" \
            >/dev/null 2>&1; then
        bad "HPKE-0 keygen rejects identical private/public paths"
    else
        ok "HPKE-0 keygen rejects identical private/public paths"
    fi
    H0_ALIAS="$WORK/hpke0.alias"
    if "$TOOL" keygen -a "HPKE-0" -o "$H0_ALIAS" -p "$WORK/./hpke0.alias" \
            >/dev/null 2>&1; then
        bad "HPKE-0 keygen rejects normalized private/public paths"
    else
        ok "HPKE-0 keygen rejects normalized private/public paths"
    fi
    H0_CASE_LOWER="$WORK/hpke0.case"
    H0_CASE_UPPER="$WORK/HPKE0.CASE"
    if touch "$H0_CASE_LOWER"; then
        if [ -e "$H0_CASE_UPPER" ]; then
            rm -f "$H0_CASE_LOWER"
            if "$TOOL" keygen -a "HPKE-0" -o "$H0_CASE_LOWER" \
                    -p "$H0_CASE_UPPER" >/dev/null 2>&1 || \
               [ -e "$H0_CASE_LOWER" ]; then
                bad "HPKE-0 keygen rejects case-alias private/public paths"
            else
                ok "HPKE-0 keygen rejects case-alias private/public paths"
            fi
        else
            rm -f "$H0_CASE_LOWER"
            skip "HPKE-0 keygen case-alias paths" "case-sensitive filesystem"
        fi
    else
        bad "HPKE-0 keygen case-alias test setup"
    fi
    H0_SYMLINK_TARGET="$WORK/hpke0.symlink-target"
    H0_SYMLINK="$WORK/hpke0.symlink"
    if ln -s "$H0_SYMLINK_TARGET" "$H0_SYMLINK" && \
       "$TOOL" keygen -a "HPKE-0" -o "$H0_SYMLINK_TARGET" -p "$H0_SYMLINK" \
            >/dev/null 2>&1; then
        bad "HPKE-0 keygen rejects symlink private/public paths"
    elif [ -e "$H0_SYMLINK_TARGET" ]; then
        bad "HPKE-0 keygen leaves symlink target untouched"
    else
        ok "HPKE-0 keygen rejects symlink private/public paths"
    fi
    H0_EXISTING_PRIV="$WORK/hpke0-existing.private"
    H0_EXISTING_COPY="$WORK/hpke0-existing.copy"
    H0_NEW_PUB="$WORK/hpke0-new.public"
    if printf 'existing HPKE private key\n' > "$H0_EXISTING_PRIV" && \
       cp "$H0_EXISTING_PRIV" "$H0_EXISTING_COPY"; then
        if "$TOOL" keygen -a "HPKE-0" -o "$H0_EXISTING_PRIV" \
                -p "$H0_NEW_PUB" >/dev/null 2>&1; then
            bad "HPKE-0 keygen rejects existing output paths"
        elif cmp -s "$H0_EXISTING_PRIV" "$H0_EXISTING_COPY" && \
             [ ! -e "$H0_NEW_PUB" ]; then
            ok "HPKE-0 keygen preserves existing output paths"
        else
            bad "HPKE-0 keygen preserves existing output paths"
        fi
    else
        bad "HPKE-0 existing output test setup"
    fi
    H0_FAILED_PRIV="$WORK/hpke0-failed.private"
    H0_BLOCKED_PUB="$WORK/hpke0-public-directory"
    if mkdir "$H0_BLOCKED_PUB"; then
        if "$TOOL" keygen -a "HPKE-0" -o "$H0_FAILED_PRIV" \
                -p "$H0_BLOCKED_PUB" >/dev/null 2>&1; then
            bad "HPKE-0 keygen rejects unusable public output"
        elif [ -e "$H0_FAILED_PRIV" ]; then
            bad "HPKE-0 keygen leaves no partial private output"
        else
            ok "HPKE-0 keygen leaves no partial private output"
        fi
    else
        bad "HPKE-0 unusable public output test setup"
    fi
    if "$TOOL" hpke0-enc -k "$H0_PUB" -i "$IN" -o "$H0_COSE" >/dev/null 2>&1 && \
       "$TOOL" hpke0-dec -k "$H0_PRIV" -i "$H0_COSE" -o "$H0_OUT" >/dev/null 2>&1 && \
       cmp -s "$IN" "$H0_OUT"; then
        ok "HPKE-0 enc/dec"
    else
        bad "HPKE-0 enc/dec"
    fi
    if "$TOOL" test -a "HPKE-0" >/dev/null 2>&1; then
        ok "HPKE-0 self-test"
    else
        bad "HPKE-0 self-test"
    fi
    H0_MAX_IN="$WORK/hpke0-max.bin"; H0_MAX_COSE="$WORK/hpke0-max.cose"
    H0_MAX_OUT="$WORK/hpke0-max.out"
    if dd if=/dev/zero of="$H0_MAX_IN" bs="$HPKE_TOOL_MAX_MSG" count=1 \
            >/dev/null 2>&1 && \
       "$TOOL" hpke0-enc -k "$H0_PUB" -i "$H0_MAX_IN" -o "$H0_MAX_COSE" \
            >/dev/null 2>&1 && \
       "$TOOL" hpke0-dec -k "$H0_PRIV" -i "$H0_MAX_COSE" -o "$H0_MAX_OUT" \
            >/dev/null 2>&1 && \
       "$TOOL" info -i "$H0_MAX_COSE" >/dev/null 2>&1 && \
       cmp -s "$H0_MAX_IN" "$H0_MAX_OUT"; then
        ok "HPKE-0 maximum message enc/dec"
    else
        bad "HPKE-0 maximum message enc/dec"
    fi
    H0_OVERSIZE_IN="$WORK/hpke0-oversize.bin"
    H0_OVERSIZE_COSE="$WORK/hpke0-oversize.cose"
    if dd if=/dev/zero of="$H0_OVERSIZE_IN" bs="$HPKE_TOOL_MAX_MSG" count=1 \
            >/dev/null 2>&1 && printf '\0' >> "$H0_OVERSIZE_IN"; then
        if "$TOOL" hpke0-enc -k "$H0_PUB" -i "$H0_OVERSIZE_IN" \
                -o "$H0_OVERSIZE_COSE" >/dev/null 2>&1; then
            bad "HPKE-0 rejects oversized plaintext"
        else
            ok "HPKE-0 rejects oversized plaintext"
        fi
    else
        bad "HPKE-0 oversized plaintext test setup"
    fi
else
    skip "HPKE-0 command and self-test"
fi

HKE0_PRIV="$WORK/hpke-ke-0.private"; HKE0_PUB="$WORK/hpke-ke-0.public"
HKE1_PRIV="$WORK/hpke-ke-1.private"; HKE1_PUB="$WORK/hpke-ke-1.public"
HKE_COSE="$WORK/hpke-ke.cose"; HKE0_OUT="$WORK/hpke-ke-0.out"
HKE1_OUT="$WORK/hpke-ke-1.out"
if hpke_keygen_or "HPKE-0-KE" "$HKE0_PRIV" "$HKE0_PUB" && \
   hpke_keygen_or "HPKE-0-KE" "$HKE1_PRIV" "$HKE1_PUB"; then
    if "$TOOL" hpke-ke-enc -a A128GCM -k "$HKE0_PUB" -k "$HKE1_PUB" \
           -i "$IN" -o "$HKE_COSE" >/dev/null 2>&1 && \
       "$TOOL" hpke-ke-dec -k "$HKE0_PRIV" -r 0 -i "$HKE_COSE" \
           -o "$HKE0_OUT" >/dev/null 2>&1 && \
       "$TOOL" hpke-ke-dec -k "$HKE1_PRIV" -r 1 -i "$HKE_COSE" \
           -o "$HKE1_OUT" >/dev/null 2>&1 && \
       cmp -s "$IN" "$HKE0_OUT" && cmp -s "$IN" "$HKE1_OUT"; then
        ok "HPKE-0-KE multi-recipient enc/dec"
    else
        bad "HPKE-0-KE multi-recipient enc/dec"
    fi
    if "$TOOL" test -a "HPKE-0-KE" >/dev/null 2>&1; then
        ok "HPKE-0-KE self-test"
    else
        bad "HPKE-0-KE self-test"
    fi
    HKE_MAX_IN="$WORK/hpke-ke-max.bin"; HKE_MAX_COSE="$WORK/hpke-ke-max.cose"
    HKE_MAX_OUT="$WORK/hpke-ke-max.out"
    if dd if=/dev/zero of="$HKE_MAX_IN" bs="$HPKE_TOOL_MAX_MSG" count=1 \
            >/dev/null 2>&1 && \
       "$TOOL" hpke-ke-enc -a A128GCM -k "$HKE0_PUB" -k "$HKE1_PUB" \
            -i "$HKE_MAX_IN" -o "$HKE_MAX_COSE" >/dev/null 2>&1 && \
       "$TOOL" hpke-ke-dec -k "$HKE0_PRIV" -r 0 -i "$HKE_MAX_COSE" \
            -o "$HKE_MAX_OUT" >/dev/null 2>&1 && \
       cmp -s "$HKE_MAX_IN" "$HKE_MAX_OUT"; then
        ok "HPKE-0-KE maximum message enc/dec"
    else
        bad "HPKE-0-KE maximum message enc/dec"
    fi
    HKE_OVERSIZE_IN="$WORK/hpke-ke-oversize.bin"
    HKE_OVERSIZE_COSE="$WORK/hpke-ke-oversize.cose"
    if dd if=/dev/zero of="$HKE_OVERSIZE_IN" bs="$HPKE_TOOL_MAX_MSG" count=1 \
            >/dev/null 2>&1 && printf '\0' >> "$HKE_OVERSIZE_IN"; then
        if "$TOOL" hpke-ke-enc -a A128GCM -k "$HKE0_PUB" -k "$HKE1_PUB" \
                -i "$HKE_OVERSIZE_IN" -o "$HKE_OVERSIZE_COSE" \
                >/dev/null 2>&1; then
            bad "HPKE-0-KE rejects oversized plaintext"
        else
            ok "HPKE-0-KE rejects oversized plaintext"
        fi
    else
        bad "HPKE-0-KE oversized plaintext test setup"
    fi
else
    skip "HPKE-0-KE command and self-test"
fi

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
