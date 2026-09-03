/* wolfcose_eat_psa.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfCOSE.
 *
 * wolfCOSE is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfCOSE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfcose/eat_psa.h>

#ifdef WOLFCOSE_EAT_PSA

#include "wolfcose_internal.h"

/* RFC 9783 current claim labels. Recognize both standardized namespaces even
 * in a selective build so that a disabled or mixed profile is rejected rather
 * than silently treated as an unknown extension. */
#define WOLFCOSE_EAT_PSA_LABEL_NONCE          10
#define WOLFCOSE_EAT_PSA_LABEL_UEID           256
#define WOLFCOSE_EAT_PSA_LABEL_PROFILE        265
#define WOLFCOSE_EAT_PSA_LABEL_BOOT_SEED      268
#define WOLFCOSE_EAT_PSA_LABEL_CLIENT_ID      2394
#define WOLFCOSE_EAT_PSA_LABEL_LIFECYCLE      2395
#define WOLFCOSE_EAT_PSA_LABEL_IMPLEMENTATION 2396
#define WOLFCOSE_EAT_PSA_LABEL_CERT_REF       2398
#define WOLFCOSE_EAT_PSA_LABEL_COMPONENTS     2399
#define WOLFCOSE_EAT_PSA_LABEL_VSI            2400

/* RFC 9783 Section 4.6 legacy claim labels. */
#define WOLFCOSE_EAT_PSA_OLD_LABEL_PROFILE        (-75000)
#define WOLFCOSE_EAT_PSA_OLD_LABEL_CLIENT_ID      (-75001)
#define WOLFCOSE_EAT_PSA_OLD_LABEL_LIFECYCLE      (-75002)
#define WOLFCOSE_EAT_PSA_OLD_LABEL_IMPLEMENTATION (-75003)
#define WOLFCOSE_EAT_PSA_OLD_LABEL_BOOT_SEED      (-75004)
#define WOLFCOSE_EAT_PSA_OLD_LABEL_CERT_REF       (-75005)
#define WOLFCOSE_EAT_PSA_OLD_LABEL_COMPONENTS     (-75006)
#define WOLFCOSE_EAT_PSA_OLD_LABEL_NO_MEASUREMENTS (-75007)
#define WOLFCOSE_EAT_PSA_OLD_LABEL_NONCE          (-75008)
#define WOLFCOSE_EAT_PSA_OLD_LABEL_UEID           (-75009)
#define WOLFCOSE_EAT_PSA_OLD_LABEL_VSI            (-75010)

#define WOLFCOSE_EAT_PSA_COMPONENT_TYPE  1
#define WOLFCOSE_EAT_PSA_COMPONENT_VALUE 2
#define WOLFCOSE_EAT_PSA_COMPONENT_VER   4
#define WOLFCOSE_EAT_PSA_COMPONENT_SIGNER 5
#define WOLFCOSE_EAT_PSA_COMPONENT_DESC  6

#define WOLFCOSE_EAT_PSA_HAVE_NONCE          0x0001u
#define WOLFCOSE_EAT_PSA_HAVE_UEID           0x0002u
#define WOLFCOSE_EAT_PSA_HAVE_PROFILE        0x0004u
#define WOLFCOSE_EAT_PSA_HAVE_CLIENT_ID      0x0008u
#define WOLFCOSE_EAT_PSA_HAVE_LIFECYCLE      0x0010u
#define WOLFCOSE_EAT_PSA_HAVE_IMPLEMENTATION 0x0020u
#define WOLFCOSE_EAT_PSA_HAVE_COMPONENTS     0x0040u
#define WOLFCOSE_EAT_PSA_HAVE_BOOT_SEED      0x0080u
#define WOLFCOSE_EAT_PSA_HAVE_CERT_REF       0x0100u
#define WOLFCOSE_EAT_PSA_HAVE_VSI            0x0200u
#define WOLFCOSE_EAT_PSA_HAVE_NO_MEASUREMENTS 0x0400u

#define WOLFCOSE_EAT_PSA_CURRENT_REQUIRED \
    (WOLFCOSE_EAT_PSA_HAVE_NONCE | WOLFCOSE_EAT_PSA_HAVE_UEID | \
     WOLFCOSE_EAT_PSA_HAVE_PROFILE | WOLFCOSE_EAT_PSA_HAVE_CLIENT_ID | \
     WOLFCOSE_EAT_PSA_HAVE_LIFECYCLE | \
     WOLFCOSE_EAT_PSA_HAVE_IMPLEMENTATION | \
     WOLFCOSE_EAT_PSA_HAVE_COMPONENTS)

#define WOLFCOSE_EAT_PSA_OLD_REQUIRED \
    (WOLFCOSE_EAT_PSA_HAVE_NONCE | WOLFCOSE_EAT_PSA_HAVE_UEID | \
     WOLFCOSE_EAT_PSA_HAVE_CLIENT_ID | WOLFCOSE_EAT_PSA_HAVE_LIFECYCLE | \
     WOLFCOSE_EAT_PSA_HAVE_IMPLEMENTATION | WOLFCOSE_EAT_PSA_HAVE_BOOT_SEED)

#if defined(WOLFCOSE_EAT_PSA_CURRENT) && \
    (defined(WOLFCOSE_EAT_PSA_TFM_FULL) || defined(WOLFCOSE_EAT_PSA_ISSUE))
static const uint8_t kEatPsaTfmProfile[] = WOLFCOSE_EAT_PSA_PROFILE_TFM;
#endif
/* RFC 9783 Section 5.1 allows CBOR variation serialization. Keep that
 * tolerance scoped to authenticated PSA/EAT parsing; the public CBOR API
 * remains strict and carries no profile-specific decode state. */
#define WOLFCOSE_EAT_PSA_DECODE_FLAGS \
    WOLFCOSE_COSE_DECODE_ALLOW_NONPREFERRED
#define WOLFCOSE_EAT_PSA_DECODE_UINT(ctx, value) \
    wolfCose_CBOR_DecodeUint_ex((ctx), (value), WOLFCOSE_EAT_PSA_DECODE_FLAGS)
#define WOLFCOSE_EAT_PSA_DECODE_INT(ctx, value) \
    wolfCose_CBOR_DecodeInt_ex((ctx), (value), WOLFCOSE_EAT_PSA_DECODE_FLAGS)
#define WOLFCOSE_EAT_PSA_DECODE_BSTR(ctx, data, len) \
    wolfCose_CBOR_DecodeBstr_ex((ctx), (data), (len), \
        WOLFCOSE_EAT_PSA_DECODE_FLAGS)
#define WOLFCOSE_EAT_PSA_DECODE_TSTR(ctx, data, len) \
    wolfCose_CBOR_DecodeTstr_ex((ctx), (data), (len), \
        WOLFCOSE_EAT_PSA_DECODE_FLAGS)
#define WOLFCOSE_EAT_PSA_DECODE_ARRAY(ctx, count) \
    wolfCose_CBOR_DecodeArrayStart_ex((ctx), (count), \
        WOLFCOSE_EAT_PSA_DECODE_FLAGS)
#define WOLFCOSE_EAT_PSA_DECODE_MAP(ctx, count) \
    wolfCose_CBOR_DecodeMapStart_ex((ctx), (count), \
        WOLFCOSE_EAT_PSA_DECODE_FLAGS)
#define WOLFCOSE_EAT_PSA_DECODE_TAG(ctx, tag) \
    wolfCose_CBOR_DecodeTag_ex((ctx), (tag), WOLFCOSE_EAT_PSA_DECODE_FLAGS)
#define WOLFCOSE_EAT_PSA_DECODE_LABEL(ctx, label) \
    wolfCose_CBOR_DecodeLabel_ex((ctx), (label), \
        WOLFCOSE_EAT_PSA_DECODE_FLAGS)
#define WOLFCOSE_EAT_PSA_SKIP(ctx) \
    wolfCose_CBOR_Skip_ex((ctx), WOLFCOSE_EAT_PSA_DECODE_FLAGS)

#if defined(WOLFCOSE_EAT_PSA_VERIFY)
static int wolfCose_EatPsaConstantCompare(const uint8_t* a, const uint8_t* b,
    size_t length)
{
    size_t i;
    volatile unsigned int result = 0u;

    for (i = 0u; i < length; i++) {
        result |= (unsigned int)a[i] ^ (unsigned int)b[i];
    }

    return (int)result;
}
#endif

#if defined(WOLFCOSE_EAT_PSA_ISSUE)
static int wolfCose_EatPsaBuffersOverlap(const uint8_t* a, size_t aSz,
    const uint8_t* b, size_t bSz)
{
    int overlap = 0;

    if ((a != NULL) && (b != NULL) && (aSz != 0u) && (bSz != 0u)) {
        /* uintptr_t is used intentionally: relational comparison of pointers
         * to unrelated caller-owned objects is not defined by ISO C. */
        uintptr_t aStart = (uintptr_t)a;
        uintptr_t bStart = (uintptr_t)b;

        if ((aStart <= bStart) &&
            ((bStart - aStart) < (uintptr_t)aSz)) {
            overlap = 1;
        }
        else if ((aStart > bStart) &&
                 ((aStart - bStart) < (uintptr_t)bSz)) {
            overlap = 1;
        }
        else {
            /* The nonempty buffer ranges are disjoint. */
        }
    }

    return overlap;
}

static int wolfCose_EatPsaSpanOverlapsBuffer(
    const WOLFCOSE_EAT_PSA_SPAN* span, const uint8_t* buffer,
    size_t bufferSz)
{
    return ((span != NULL) &&
            (wolfCose_EatPsaBuffersOverlap(span->data, span->len,
                buffer, bufferSz) != 0)) ? 1 : 0;
}

static int wolfCose_EatPsaComponentOverlapsBuffer(
    const WOLFCOSE_EAT_PSA_COMPONENT* component, const uint8_t* buffer,
    size_t bufferSz)
{
    int overlap = 0;

    if ((component != NULL) && (
            (wolfCose_EatPsaBuffersOverlap(
                 (const uint8_t*)component, sizeof(*component),
                 buffer, bufferSz) != 0) ||
            (wolfCose_EatPsaSpanOverlapsBuffer(&component->measurementType,
                 buffer, bufferSz) != 0) ||
            (wolfCose_EatPsaSpanOverlapsBuffer(&component->measurementValue,
                 buffer, bufferSz) != 0) ||
            (wolfCose_EatPsaSpanOverlapsBuffer(&component->version,
                 buffer, bufferSz) != 0) ||
            (wolfCose_EatPsaSpanOverlapsBuffer(&component->signerId,
                 buffer, bufferSz) != 0) ||
            (wolfCose_EatPsaSpanOverlapsBuffer(&component->measurementDesc,
                 buffer, bufferSz) != 0))) {
        overlap = 1;
    }

    return overlap;
}

/* Call only after claim validation has bounded componentCount and checked all
 * required pointers. Encoding is deliberately not an in-place operation:
 * later map keys and string headers must never overwrite data still to read. */
static int wolfCose_EatPsaClaimsOverlapBuffer(
    const WOLFCOSE_EAT_PSA_CLAIMS* claims, const uint8_t* buffer,
    size_t bufferSz)
{
    int overlap = 0;

    if (claims != NULL) {
        size_t i;

        if (
            (wolfCose_EatPsaBuffersOverlap(
                 (const uint8_t*)claims, sizeof(*claims),
                 buffer, bufferSz) != 0) ||
            (wolfCose_EatPsaSpanOverlapsBuffer(&claims->nonce,
                 buffer, bufferSz) != 0) ||
            (wolfCose_EatPsaSpanOverlapsBuffer(&claims->ueid,
                 buffer, bufferSz) != 0) ||
            (wolfCose_EatPsaSpanOverlapsBuffer(&claims->implementationId,
                 buffer, bufferSz) != 0) ||
            (wolfCose_EatPsaSpanOverlapsBuffer(&claims->bootSeed,
                 buffer, bufferSz) != 0) ||
            (wolfCose_EatPsaSpanOverlapsBuffer(
                 &claims->certificationReference, buffer, bufferSz) != 0) ||
            (wolfCose_EatPsaSpanOverlapsBuffer(
                 &claims->verificationServiceIndicator, buffer,
                 bufferSz) != 0)) {
            overlap = 1;
        }
        for (i = 0u; (overlap == 0) && (i < claims->componentCount); i++) {
            overlap = wolfCose_EatPsaComponentOverlapsBuffer(
                &claims->components[i], buffer, bufferSz);
        }
    }

    return overlap;
}

#if defined(WOLFCOSE_EAT_PSA_SIGN1_ISSUE) || \
    defined(WOLFCOSE_EAT_PSA_MAC0_ISSUE)
static int wolfCose_EatPsaIssueBuffersOverlap(
    const uint8_t* claimsBuf, size_t claimsBufSz,
    const uint8_t* scratch, size_t scratchSz,
    const uint8_t* out, size_t outSz)
{
    return ((wolfCose_EatPsaBuffersOverlap(claimsBuf, claimsBufSz,
                 scratch, scratchSz) != 0) ||
            (wolfCose_EatPsaBuffersOverlap(claimsBuf, claimsBufSz,
                 out, outSz) != 0) ||
            (wolfCose_EatPsaBuffersOverlap(scratch, scratchSz,
                 out, outSz) != 0)) ? 1 : 0;
}
#endif
#endif /* WOLFCOSE_EAT_PSA_ISSUE */

static int wolfCose_EatPsaIsHash(const WOLFCOSE_EAT_PSA_SPAN* span)
{
    int ret = 0;

    if ((span != NULL) && (span->data != NULL) &&
        ((span->len == 32u) || (span->len == 48u) || (span->len == 64u))) {
        ret = 1;
    }

    return ret;
}

#if defined(WOLFCOSE_EAT_PSA_ISSUE) && defined(WOLFCOSE_CBOR_ENCODE)
static int wolfCose_EatPsaIsOptionalSpan(const WOLFCOSE_EAT_PSA_SPAN* span)
{
    int ret = 0;

    if ((span != NULL) &&
        (((span->data == NULL) && (span->len == 0u)) ||
         (span->data != NULL))) {
        ret = 1;
    }

    return ret;
}
#endif /* WOLFCOSE_EAT_PSA_ISSUE && WOLFCOSE_CBOR_ENCODE */

static int wolfCose_EatPsaLifecycleValid(uint16_t lifecycle)
{
    uint16_t major = (uint16_t)(lifecycle & 0xFF00u);

    return ((major == 0x0000u) || (major == 0x1000u) ||
            (major == 0x2000u) || (major == 0x3000u) ||
            (major == 0x4000u) || (major == 0x5000u) ||
            (major == 0x6000u)) ? 1 : 0;
}

static int wolfCose_EatPsaCertRefValid(const WOLFCOSE_EAT_PSA_SPAN* span,
    size_t digits, int hasVersion)
{
    int ret = 1;

    if ((span == NULL) || (span->data == NULL) ||
        (span->len != (digits + ((hasVersion != 0) ? 1u : 0u)))) {
        ret = 0;
    }
    else {
        size_t i;

        for (i = 0u; i < span->len; i++) {
            if ((hasVersion != 0) && (i == 13u)) {
                if (span->data[i] != (uint8_t)'-') {
                    ret = 0;
                }
            }
            else if ((span->data[i] < (uint8_t)'0') ||
                     (span->data[i] > (uint8_t)'9')) {
                ret = 0;
            }
            else {
                /* The character is a valid decimal digit. */
            }
        }
    }

    return ret;
}

#if defined(WOLFCOSE_EAT_PSA_SIGN1) || \
    defined(WOLFCOSE_EAT_PSA_SIGN1_ISSUE)
static int wolfCose_EatPsaSignAlg(int32_t alg)
{
    int ret = 0;

    switch (alg) {
#if defined(WOLFCOSE_HAVE_ES256)
        case WOLFCOSE_ALG_ES256:
            ret = 1;
            break;
#endif
#if defined(WOLFCOSE_HAVE_ES384)
        case WOLFCOSE_ALG_ES384:
            ret = 1;
            break;
#endif
#if defined(WOLFCOSE_HAVE_ES512)
        case WOLFCOSE_ALG_ES512:
            ret = 1;
            break;
#endif
        default:
            break;
    }

    return ret;
}
#endif /* WOLFCOSE_EAT_PSA_SIGN1 || WOLFCOSE_EAT_PSA_SIGN1_ISSUE */

#if defined(WOLFCOSE_EAT_PSA_MAC0) || \
    defined(WOLFCOSE_EAT_PSA_MAC0_ISSUE)
static int wolfCose_EatPsaMacAlg(int32_t alg)
{
    int ret = 0;

    switch (alg) {
#if defined(WOLFCOSE_HAVE_HMAC256)
        case WOLFCOSE_ALG_HMAC_256_256:
            ret = 1;
            break;
#endif
#if defined(WOLFCOSE_HAVE_HMAC384)
        case WOLFCOSE_ALG_HMAC_384_384:
            ret = 1;
            break;
#endif
#if defined(WOLFCOSE_HAVE_HMAC512)
        case WOLFCOSE_ALG_HMAC_512_512:
            ret = 1;
            break;
#endif
        default:
            break;
    }

    return ret;
}
#endif /* WOLFCOSE_EAT_PSA_MAC0 || WOLFCOSE_EAT_PSA_MAC0_ISSUE */

#if defined(WOLFCOSE_EAT_PSA_ISSUE) && defined(WOLFCOSE_CBOR_ENCODE)
static int wolfCose_EatPsaValidateComponent(
    const WOLFCOSE_EAT_PSA_COMPONENT* component)
{
    int ret = WOLFCOSE_SUCCESS;

    if ((component == NULL) ||
        (wolfCose_EatPsaIsHash(&component->measurementValue) == 0) ||
        (wolfCose_EatPsaIsHash(&component->signerId) == 0) ||
        (wolfCose_EatPsaIsOptionalSpan(&component->measurementType) == 0) ||
        (wolfCose_EatPsaIsOptionalSpan(&component->version) == 0) ||
        (wolfCose_EatPsaIsOptionalSpan(&component->measurementDesc) == 0)) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }

    return ret;
}

static int wolfCose_EatPsaValidateClaims(
    const WOLFCOSE_EAT_PSA_CLAIMS* claims)
{
    int ret = WOLFCOSE_SUCCESS;
    size_t i;

    if ((claims == NULL) || (claims->nonce.data == NULL) ||
        ((claims->nonce.len != 32u) && (claims->nonce.len != 48u) &&
         (claims->nonce.len != 64u)) ||
        (claims->ueid.data == NULL) || (claims->ueid.len != 33u) ||
        (claims->ueid.data[0] != 0x01u) ||
        (claims->implementationId.data == NULL) ||
        (claims->implementationId.len != 32u) || (claims->clientId == 0) ||
        (wolfCose_EatPsaLifecycleValid(claims->lifecycle) == 0) ||
        (claims->components == NULL) || (claims->componentCount == 0u) ||
        (claims->componentCount > WOLFCOSE_EAT_PSA_MAX_COMPONENTS)) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((wolfCose_EatPsaIsOptionalSpan(&claims->bootSeed) == 0) ||
         ((claims->bootSeed.data != NULL) &&
          ((claims->bootSeed.len < 8u) || (claims->bootSeed.len > 32u))) ||
         (wolfCose_EatPsaIsOptionalSpan(&claims->certificationReference) == 0) ||
         ((claims->certificationReference.data != NULL) &&
          (wolfCose_EatPsaCertRefValid(&claims->certificationReference,
              18u, 1) == 0)) ||
         (wolfCose_EatPsaIsOptionalSpan(
             &claims->verificationServiceIndicator) == 0))) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }
    for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < claims->componentCount);
         i++) {
        ret = wolfCose_EatPsaValidateComponent(&claims->components[i]);
    }

    return ret;
}

static int wolfCose_EatPsaEncodeComponent(WOLFCOSE_CBOR_CTX* ctx,
    const WOLFCOSE_EAT_PSA_COMPONENT* component)
{
    int ret = WOLFCOSE_SUCCESS;
    size_t count = 2u;

    if ((component->measurementType.data != NULL) ||
        (component->version.data != NULL) ||
        (component->measurementDesc.data != NULL)) {
        count += (component->measurementType.data != NULL) ? 1u : 0u;
        count += (component->version.data != NULL) ? 1u : 0u;
        count += (component->measurementDesc.data != NULL) ? 1u : 0u;
    }

    ret = wc_CBOR_EncodeMapStart(ctx, count);
    if ((ret == WOLFCOSE_SUCCESS) && (component->measurementType.data != NULL)) {
        ret = wc_CBOR_EncodeUint(ctx, WOLFCOSE_EAT_PSA_COMPONENT_TYPE);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeTstr(ctx, component->measurementType.data,
                                     component->measurementType.len);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(ctx, WOLFCOSE_EAT_PSA_COMPONENT_VALUE);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(ctx, component->measurementValue.data,
                                 component->measurementValue.len);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (component->version.data != NULL)) {
        ret = wc_CBOR_EncodeUint(ctx, WOLFCOSE_EAT_PSA_COMPONENT_VER);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeTstr(ctx, component->version.data,
                                     component->version.len);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(ctx, WOLFCOSE_EAT_PSA_COMPONENT_SIGNER);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(ctx, component->signerId.data,
                                 component->signerId.len);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (component->measurementDesc.data != NULL)) {
        ret = wc_CBOR_EncodeUint(ctx, WOLFCOSE_EAT_PSA_COMPONENT_DESC);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeTstr(ctx, component->measurementDesc.data,
                                     component->measurementDesc.len);
        }
    }

    return ret;
}
#endif /* WOLFCOSE_EAT_PSA_ISSUE && WOLFCOSE_CBOR_ENCODE */

#if defined(WOLFCOSE_EAT_PSA_ISSUE)
int wc_CoseEatPsaToken_EncodeClaims(const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    uint8_t* out, size_t outSz, size_t* outLen)
{
#if defined(WOLFCOSE_CBOR_ENCODE)
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    size_t count = 7u;
    size_t i;

    if (outLen != NULL) {
        *outLen = 0u;
    }
    if ((out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wolfCose_EatPsaValidateClaims(claims);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (wolfCose_EatPsaClaimsOverlapBuffer(claims, out, outSz) != 0)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        count += (claims->bootSeed.data != NULL) ? 1u : 0u;
        count += (claims->certificationReference.data != NULL) ? 1u : 0u;
        count += (claims->verificationServiceIndicator.data != NULL) ? 1u : 0u;
        ret = wc_CBOR_EncoderInit(&ctx, out, outSz);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&ctx, count);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, WOLFCOSE_EAT_PSA_LABEL_NONCE);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, claims->nonce.data, claims->nonce.len);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, WOLFCOSE_EAT_PSA_LABEL_UEID);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, claims->ueid.data, claims->ueid.len);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, WOLFCOSE_EAT_PSA_LABEL_PROFILE);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeTstr(&ctx, kEatPsaTfmProfile,
                                 sizeof(kEatPsaTfmProfile) - 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (claims->bootSeed.data != NULL)) {
        ret = wc_CBOR_EncodeUint(&ctx, WOLFCOSE_EAT_PSA_LABEL_BOOT_SEED);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, claims->bootSeed.data,
                                     claims->bootSeed.len);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, WOLFCOSE_EAT_PSA_LABEL_CLIENT_ID);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, (int64_t)claims->clientId);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, WOLFCOSE_EAT_PSA_LABEL_LIFECYCLE);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)claims->lifecycle);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, WOLFCOSE_EAT_PSA_LABEL_IMPLEMENTATION);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, claims->implementationId.data,
                                 claims->implementationId.len);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (claims->certificationReference.data != NULL)) {
        ret = wc_CBOR_EncodeUint(&ctx, WOLFCOSE_EAT_PSA_LABEL_CERT_REF);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeTstr(&ctx, claims->certificationReference.data,
                                     claims->certificationReference.len);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, WOLFCOSE_EAT_PSA_LABEL_COMPONENTS);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, claims->componentCount);
    }
    for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < claims->componentCount);
         i++) {
        ret = wolfCose_EatPsaEncodeComponent(&ctx, &claims->components[i]);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (claims->verificationServiceIndicator.data != NULL)) {
        ret = wc_CBOR_EncodeUint(&ctx, WOLFCOSE_EAT_PSA_LABEL_VSI);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeTstr(&ctx,
                claims->verificationServiceIndicator.data,
                claims->verificationServiceIndicator.len);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = ctx.idx;
    }

    return ret;
#else
    (void)claims;
    (void)out;
    (void)outSz;
    (void)outLen;
    return WOLFCOSE_E_UNSUPPORTED;
#endif
}
#endif /* WOLFCOSE_EAT_PSA_ISSUE */

#if defined(WOLFCOSE_EAT_PSA_VERIFY)

static int wolfCose_EatPsaLabelsEqual(const WOLFCOSE_CBOR_LABEL* first,
    const WOLFCOSE_CBOR_LABEL* second)
{
    int ret = 0;

    if ((first != NULL) && (second != NULL) &&
        (first->isText == second->isText)) {
        if (first->isText != 0u) {
            ret = wc_CBOR_LabelIsText(first, second->text, second->textLen);
        }
        else if (first->val == second->val) {
            ret = 1;
        }
        else {
            /* Labels differ. */
        }
    }

    return ret;
}

/* RFC 9783 Section 5.1.1 requires valid CBOR. The profile maps accept
 * unknown extension labels, so a fixed seen-bit mask alone cannot reject a
 * duplicate unknown key. Re-scan only the earlier pairs in this bounded input
 * map. The caller-configurable profile claim limits bound this work without
 * requiring allocation or restricting the labels assigned to extensions. */
static int wolfCose_EatPsaMapHasPriorLabel(const uint8_t* map, size_t mapSz,
    size_t before, const WOLFCOSE_CBOR_LABEL* label, int* duplicate)
{
    int ret;
    WOLFCOSE_CBOR_CTX scan;
    size_t count = 0u;
    size_t i;

    if ((map == NULL) || (label == NULL) || (duplicate == NULL) ||
        (before > mapSz)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        *duplicate = 0;
        ret = wc_CBOR_DecoderInit(&scan, map, mapSz);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_EAT_PSA_DECODE_MAP(&scan, &count);
    }
    for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < count) &&
         (scan.idx < before); i++) {
        WOLFCOSE_CBOR_LABEL prior;

        ret = WOLFCOSE_EAT_PSA_DECODE_LABEL(&scan, &prior);
        if ((ret == WOLFCOSE_SUCCESS) &&
            (wolfCose_EatPsaLabelsEqual(&prior, label) != 0)) {
            *duplicate = 1;
            break;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = WOLFCOSE_EAT_PSA_SKIP(&scan);
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) && (*duplicate == 0) &&
        (scan.idx != before)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }

    return ret;
}

static int wolfCose_EatPsaDecodeComponent(WOLFCOSE_CBOR_CTX* ctx,
    WOLFCOSE_EAT_PSA_COMPONENT* component)
{
    int ret;
    size_t count = 0u;
    size_t i;
    size_t mapStart = 0u;
    uint32_t seen = 0u;

    if ((ctx == NULL) || (component == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        (void)XMEMSET(component, 0, sizeof(*component));
        mapStart = ctx->idx;
        ret = WOLFCOSE_EAT_PSA_DECODE_MAP(ctx, &count);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (count > WOLFCOSE_EAT_PSA_MAX_COMPONENT_CLAIMS)) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }
    for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < count); i++) {
        WOLFCOSE_CBOR_LABEL label;
        size_t labelStart = ctx->idx - mapStart;
        int duplicate = 0;

        ret = WOLFCOSE_EAT_PSA_DECODE_LABEL(ctx, &label);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_EatPsaMapHasPriorLabel(&ctx->cbuf[mapStart],
                ctx->bufSz - mapStart, labelStart, &label, &duplicate);
        }
        if ((ret == WOLFCOSE_SUCCESS) && (duplicate != 0)) {
            ret = WOLFCOSE_E_EAT_PSA_CLAIM;
        }
        if ((ret == WOLFCOSE_SUCCESS) && (label.isText != 0u)) {
            ret = WOLFCOSE_EAT_PSA_SKIP(ctx);
        }
        else if ((ret == WOLFCOSE_SUCCESS) &&
            (label.val == WOLFCOSE_EAT_PSA_COMPONENT_TYPE)) {
            if ((seen & 0x01u) != 0u) {
                ret = WOLFCOSE_E_EAT_PSA_CLAIM;
            }
            else {
                seen |= 0x01u;
                ret = WOLFCOSE_EAT_PSA_DECODE_TSTR(ctx, &component->measurementType.data,
                                         &component->measurementType.len);
            }
        }
        else if ((ret == WOLFCOSE_SUCCESS) &&
            (label.val == WOLFCOSE_EAT_PSA_COMPONENT_VALUE)) {
            if ((seen & 0x02u) != 0u) {
                ret = WOLFCOSE_E_EAT_PSA_CLAIM;
            }
            else {
                seen |= 0x02u;
                ret = WOLFCOSE_EAT_PSA_DECODE_BSTR(ctx, &component->measurementValue.data,
                                         &component->measurementValue.len);
            }
        }
        else if ((ret == WOLFCOSE_SUCCESS) &&
            (label.val == WOLFCOSE_EAT_PSA_COMPONENT_VER)) {
            if ((seen & 0x04u) != 0u) {
                ret = WOLFCOSE_E_EAT_PSA_CLAIM;
            }
            else {
                seen |= 0x04u;
                ret = WOLFCOSE_EAT_PSA_DECODE_TSTR(ctx, &component->version.data,
                                         &component->version.len);
            }
        }
        else if ((ret == WOLFCOSE_SUCCESS) &&
            (label.val == WOLFCOSE_EAT_PSA_COMPONENT_SIGNER)) {
            if ((seen & 0x08u) != 0u) {
                ret = WOLFCOSE_E_EAT_PSA_CLAIM;
            }
            else {
                seen |= 0x08u;
                ret = WOLFCOSE_EAT_PSA_DECODE_BSTR(ctx, &component->signerId.data,
                                         &component->signerId.len);
            }
        }
        else if ((ret == WOLFCOSE_SUCCESS) &&
            (label.val == WOLFCOSE_EAT_PSA_COMPONENT_DESC)) {
            if ((seen & 0x10u) != 0u) {
                ret = WOLFCOSE_E_EAT_PSA_CLAIM;
            }
            else {
                seen |= 0x10u;
                ret = WOLFCOSE_EAT_PSA_DECODE_TSTR(ctx, &component->measurementDesc.data,
                                         &component->measurementDesc.len);
            }
        }
        else if (ret == WOLFCOSE_SUCCESS) {
            ret = WOLFCOSE_EAT_PSA_SKIP(ctx);
        }
        else {
            /* Preserve the error produced while decoding the component. */
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((wolfCose_EatPsaIsHash(&component->measurementValue) == 0) ||
         (wolfCose_EatPsaIsHash(&component->signerId) == 0))) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }

    return ret;
}

static int wolfCose_EatPsaDecodeComponents(WOLFCOSE_CBOR_CTX* ctx,
    WOLFCOSE_EAT_PSA_TOKEN* token)
{
    int ret;
    size_t i;
    size_t count = 0u;
    size_t startIdx = 0u;
    const uint8_t* start;
    WOLFCOSE_EAT_PSA_COMPONENT component;

    if ((ctx == NULL) || (token == NULL) || (ctx->idx >= ctx->bufSz)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        startIdx = ctx->idx;
        start = &ctx->cbuf[startIdx];
        ret = WOLFCOSE_EAT_PSA_DECODE_ARRAY(ctx, &count);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((count == 0u) || (count > WOLFCOSE_EAT_PSA_MAX_COMPONENTS))) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }
    for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < count); i++) {
        ret = wolfCose_EatPsaDecodeComponent(ctx, &component);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        token->components.data = start;
        token->components.len = ctx->idx - startIdx;
        token->componentCount = count;
    }

    return ret;
}

static int wolfCose_EatPsaSetProfile(WOLFCOSE_EAT_PSA_TOKEN* token,
    const uint8_t* text, size_t textLen, WOLFCOSE_EAT_PSA_PROFILE profile)
{
    int ret = WOLFCOSE_SUCCESS;
    const uint8_t* expected = NULL;
    size_t expectedLen = 0u;

    if (profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT) {
#if defined(WOLFCOSE_EAT_PSA_CURRENT) && defined(WOLFCOSE_EAT_PSA_TFM_FULL)
        expected = kEatPsaTfmProfile;
        expectedLen = sizeof(kEatPsaTfmProfile) - 1u;
#else
        /* RFC 9783 Section 5.2 requires a #tfm receiver to accept both
         * envelopes and every mandatory ESxxx/HMACxxx algorithm. A selective
         * build must use a separately named profile, which this standard
         * profile API deliberately does not mint or accept. */
        ret = WOLFCOSE_E_EAT_PSA_PROFILE;
#endif
    }
    else if (profile == WOLFCOSE_EAT_PSA_PROFILE_OLD) {
#if defined(WOLFCOSE_EAT_PSA_LEGACY)
        static const uint8_t legacyProfile[] =
            WOLFCOSE_EAT_PSA_PROFILE_LEGACY;

        expected = legacyProfile;
        expectedLen = sizeof(legacyProfile) - 1u;
#else
        ret = WOLFCOSE_E_EAT_PSA_PROFILE;
#endif
    }
    else {
        ret = WOLFCOSE_E_EAT_PSA_PROFILE;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        if ((textLen != expectedLen) ||
            (wolfCose_EatPsaConstantCompare(text, expected, textLen) != 0)) {
            ret = WOLFCOSE_E_EAT_PSA_PROFILE;
        }
        else {
            token->profile = profile;
        }
    }

    return ret;
}

/* Map both standardized claim namespaces. Unknown EAT claims remain skippable,
 * but a recognized label from a disabled profile is a profile error. */
static void wolfCose_EatPsaClaimType(int64_t label, uint32_t* bit,
    int* type, uint8_t* legacy)
{
    *bit = 0u;
    *type = 0;
    *legacy = 0u;

    switch (label) {
        case WOLFCOSE_EAT_PSA_LABEL_NONCE:
            *bit = WOLFCOSE_EAT_PSA_HAVE_NONCE;
            *type = 1;
            break;
        case WOLFCOSE_EAT_PSA_LABEL_UEID:
            *bit = WOLFCOSE_EAT_PSA_HAVE_UEID;
            *type = 2;
            break;
        case WOLFCOSE_EAT_PSA_LABEL_PROFILE:
            *bit = WOLFCOSE_EAT_PSA_HAVE_PROFILE;
            *type = 3;
            break;
        case WOLFCOSE_EAT_PSA_LABEL_BOOT_SEED:
            *bit = WOLFCOSE_EAT_PSA_HAVE_BOOT_SEED;
            *type = 4;
            break;
        case WOLFCOSE_EAT_PSA_LABEL_CLIENT_ID:
            *bit = WOLFCOSE_EAT_PSA_HAVE_CLIENT_ID;
            *type = 5;
            break;
        case WOLFCOSE_EAT_PSA_LABEL_LIFECYCLE:
            *bit = WOLFCOSE_EAT_PSA_HAVE_LIFECYCLE;
            *type = 6;
            break;
        case WOLFCOSE_EAT_PSA_LABEL_IMPLEMENTATION:
            *bit = WOLFCOSE_EAT_PSA_HAVE_IMPLEMENTATION;
            *type = 7;
            break;
        case WOLFCOSE_EAT_PSA_LABEL_CERT_REF:
            *bit = WOLFCOSE_EAT_PSA_HAVE_CERT_REF;
            *type = 8;
            break;
        case WOLFCOSE_EAT_PSA_LABEL_COMPONENTS:
            *bit = WOLFCOSE_EAT_PSA_HAVE_COMPONENTS;
            *type = 9;
            break;
        case WOLFCOSE_EAT_PSA_LABEL_VSI:
            *bit = WOLFCOSE_EAT_PSA_HAVE_VSI;
            *type = 11;
            break;
        case WOLFCOSE_EAT_PSA_OLD_LABEL_NONCE:
            *bit = WOLFCOSE_EAT_PSA_HAVE_NONCE;
            *type = 1;
            *legacy = 1u;
            break;
        case WOLFCOSE_EAT_PSA_OLD_LABEL_UEID:
            *bit = WOLFCOSE_EAT_PSA_HAVE_UEID;
            *type = 2;
            *legacy = 1u;
            break;
        case WOLFCOSE_EAT_PSA_OLD_LABEL_PROFILE:
            *bit = WOLFCOSE_EAT_PSA_HAVE_PROFILE;
            *type = 3;
            *legacy = 1u;
            break;
        case WOLFCOSE_EAT_PSA_OLD_LABEL_BOOT_SEED:
            *bit = WOLFCOSE_EAT_PSA_HAVE_BOOT_SEED;
            *type = 4;
            *legacy = 1u;
            break;
        case WOLFCOSE_EAT_PSA_OLD_LABEL_CLIENT_ID:
            *bit = WOLFCOSE_EAT_PSA_HAVE_CLIENT_ID;
            *type = 5;
            *legacy = 1u;
            break;
        case WOLFCOSE_EAT_PSA_OLD_LABEL_LIFECYCLE:
            *bit = WOLFCOSE_EAT_PSA_HAVE_LIFECYCLE;
            *type = 6;
            *legacy = 1u;
            break;
        case WOLFCOSE_EAT_PSA_OLD_LABEL_IMPLEMENTATION:
            *bit = WOLFCOSE_EAT_PSA_HAVE_IMPLEMENTATION;
            *type = 7;
            *legacy = 1u;
            break;
        case WOLFCOSE_EAT_PSA_OLD_LABEL_CERT_REF:
            *bit = WOLFCOSE_EAT_PSA_HAVE_CERT_REF;
            *type = 8;
            *legacy = 1u;
            break;
        case WOLFCOSE_EAT_PSA_OLD_LABEL_COMPONENTS:
            *bit = WOLFCOSE_EAT_PSA_HAVE_COMPONENTS;
            *type = 9;
            *legacy = 1u;
            break;
        case WOLFCOSE_EAT_PSA_OLD_LABEL_NO_MEASUREMENTS:
            *bit = WOLFCOSE_EAT_PSA_HAVE_NO_MEASUREMENTS;
            *type = 10;
            *legacy = 1u;
            break;
        case WOLFCOSE_EAT_PSA_OLD_LABEL_VSI:
            *bit = WOLFCOSE_EAT_PSA_HAVE_VSI;
            *type = 11;
            *legacy = 1u;
            break;
        default:
            break;
    }
}

static int wolfCose_EatPsaDecodeClaims(const uint8_t* payload,
    size_t payloadLen, WOLFCOSE_EAT_PSA_TOKEN* token)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    size_t count = 0u;
    size_t i;
    size_t mapStart = 0u;
    uint32_t seen = 0u;
    uint8_t currentLabels = 0u;
    uint8_t oldLabels = 0u;

    if ((payload == NULL) || (token == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        (void)XMEMSET(token, 0, sizeof(*token));
        ret = wc_CBOR_DecoderInit(&ctx, payload, payloadLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        mapStart = ctx.idx;
        ret = WOLFCOSE_EAT_PSA_DECODE_MAP(&ctx, &count);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (count > WOLFCOSE_EAT_PSA_MAX_CLAIMS)) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }
    for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < count); i++) {
        WOLFCOSE_CBOR_LABEL label;
        size_t labelStart = ctx.idx - mapStart;
        uint32_t bit = 0u;
        int type = 0;
        int duplicate = 0;
        int enabled = 0;
        uint8_t legacy = 0u;

        ret = WOLFCOSE_EAT_PSA_DECODE_LABEL(&ctx, &label);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_EatPsaMapHasPriorLabel(&ctx.cbuf[mapStart],
                ctx.bufSz - mapStart, labelStart, &label, &duplicate);
        }
        if ((ret == WOLFCOSE_SUCCESS) && (duplicate != 0)) {
            ret = WOLFCOSE_E_EAT_PSA_CLAIM;
        }
        if ((ret == WOLFCOSE_SUCCESS) && (label.isText != 0u)) {
            ret = WOLFCOSE_EAT_PSA_SKIP(&ctx);
        }
        else if (ret == WOLFCOSE_SUCCESS) {
            wolfCose_EatPsaClaimType(label.val, &bit, &type, &legacy);
            if (type == 0) {
                ret = WOLFCOSE_EAT_PSA_SKIP(&ctx);
            }
            else {
#if defined(WOLFCOSE_EAT_PSA_CURRENT)
                if (legacy == 0u) {
                    enabled = 1;
                }
#endif
#if defined(WOLFCOSE_EAT_PSA_LEGACY)
                if (legacy != 0u) {
                    enabled = 1;
                }
#endif
                if (enabled == 0) {
                    ret = WOLFCOSE_E_EAT_PSA_PROFILE;
                }
                else if (((legacy != 0u) && (currentLabels != 0u)) ||
                         ((legacy == 0u) && (oldLabels != 0u))) {
                    ret = WOLFCOSE_E_EAT_PSA_PROFILE;
                }
                else if ((seen & bit) != 0u) {
                    ret = WOLFCOSE_E_EAT_PSA_CLAIM;
                }
                else {
                    seen |= bit;
                    if (legacy != 0u) {
                        oldLabels = 1u;
                    }
                    else {
                        currentLabels = 1u;
                    }

                    if (type == 1) {
                        ret = WOLFCOSE_EAT_PSA_DECODE_BSTR(&ctx,
                            &token->nonce.data, &token->nonce.len);
                    }
                    else if (type == 2) {
                        ret = WOLFCOSE_EAT_PSA_DECODE_BSTR(&ctx,
                            &token->ueid.data, &token->ueid.len);
                    }
                    else if (type == 3) {
                        const uint8_t* profile;
                        size_t profileLen;
                        ret = WOLFCOSE_EAT_PSA_DECODE_TSTR(&ctx, &profile,
                            &profileLen);
                        if (ret == WOLFCOSE_SUCCESS) {
                            ret = wolfCose_EatPsaSetProfile(token, profile,
                                profileLen, (legacy != 0u) ?
                                WOLFCOSE_EAT_PSA_PROFILE_OLD :
                                WOLFCOSE_EAT_PSA_PROFILE_CURRENT);
                        }
                    }
                    else if (type == 4) {
                        ret = WOLFCOSE_EAT_PSA_DECODE_BSTR(&ctx,
                            &token->bootSeed.data, &token->bootSeed.len);
                    }
                    else if (type == 5) {
                        int64_t clientId;
                        ret = WOLFCOSE_EAT_PSA_DECODE_INT(&ctx, &clientId);
                        if ((ret == WOLFCOSE_SUCCESS) &&
                            ((clientId < (-2147483647LL - 1LL)) ||
                             (clientId > 2147483647LL) || (clientId == 0))) {
                            ret = WOLFCOSE_E_EAT_PSA_CLAIM;
                        }
                        if (ret == WOLFCOSE_SUCCESS) {
                            token->clientId = (int32_t)clientId;
                        }
                    }
                    else if (type == 6) {
                        uint64_t lifecycle;
                        ret = WOLFCOSE_EAT_PSA_DECODE_UINT(&ctx, &lifecycle);
                        if ((ret == WOLFCOSE_SUCCESS) &&
                            ((lifecycle > 0xFFFFu) ||
                             (wolfCose_EatPsaLifecycleValid(
                                  (uint16_t)lifecycle) == 0))) {
                            ret = WOLFCOSE_E_EAT_PSA_CLAIM;
                        }
                        if (ret == WOLFCOSE_SUCCESS) {
                            token->lifecycle = (uint16_t)lifecycle;
                        }
                    }
                    else if (type == 7) {
                        ret = WOLFCOSE_EAT_PSA_DECODE_BSTR(&ctx,
                            &token->implementationId.data,
                            &token->implementationId.len);
                    }
                    else if (type == 8) {
                        ret = WOLFCOSE_EAT_PSA_DECODE_TSTR(&ctx,
                            &token->certificationReference.data,
                            &token->certificationReference.len);
                    }
                    else if (type == 9) {
                        ret = wolfCose_EatPsaDecodeComponents(&ctx, token);
                    }
#if defined(WOLFCOSE_EAT_PSA_LEGACY)
                    else if (type == 10) {
                        uint64_t noMeasurements;

                        ret = WOLFCOSE_EAT_PSA_DECODE_UINT(&ctx,
                            &noMeasurements);
                        if ((ret == WOLFCOSE_SUCCESS) &&
                            (noMeasurements != 1u)) {
                            ret = WOLFCOSE_E_EAT_PSA_CLAIM;
                        }
                        if (ret == WOLFCOSE_SUCCESS) {
                            token->noSoftwareMeasurements = 1u;
                        }
                    }
#endif
                    else {
                        ret = WOLFCOSE_EAT_PSA_DECODE_TSTR(&ctx,
                            &token->verificationServiceIndicator.data,
                            &token->verificationServiceIndicator.len);
                    }
                }
            }
        }
        else {
            /* Preserve the error produced while decoding the map label. */
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != ctx.bufSz)) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((currentLabels != 0u) == (oldLabels != 0u))) {
        ret = WOLFCOSE_E_EAT_PSA_PROFILE;
    }
#if defined(WOLFCOSE_EAT_PSA_CURRENT)
    if ((ret == WOLFCOSE_SUCCESS) && (currentLabels != 0u)) {
        if ((seen & WOLFCOSE_EAT_PSA_CURRENT_REQUIRED) !=
            WOLFCOSE_EAT_PSA_CURRENT_REQUIRED) {
            ret = WOLFCOSE_E_EAT_PSA_CLAIM;
        }
        else if (token->profile != WOLFCOSE_EAT_PSA_PROFILE_CURRENT) {
            ret = WOLFCOSE_E_EAT_PSA_PROFILE;
        }
        else {
            /* All required current-profile claims were decoded. */
        }
    }
#endif
#if defined(WOLFCOSE_EAT_PSA_LEGACY)
    if ((ret == WOLFCOSE_SUCCESS) && (oldLabels != 0u)) {
        if ((seen & WOLFCOSE_EAT_PSA_OLD_REQUIRED) !=
            WOLFCOSE_EAT_PSA_OLD_REQUIRED) {
            ret = WOLFCOSE_E_EAT_PSA_CLAIM;
        }
        else if (((seen & WOLFCOSE_EAT_PSA_HAVE_COMPONENTS) != 0u) ==
                 ((seen & WOLFCOSE_EAT_PSA_HAVE_NO_MEASUREMENTS) != 0u)) {
            ret = WOLFCOSE_E_EAT_PSA_CLAIM;
        }
        else if (token->profile == WOLFCOSE_EAT_PSA_PROFILE_NONE) {
            token->profile = WOLFCOSE_EAT_PSA_PROFILE_OLD;
        }
        else if (token->profile != WOLFCOSE_EAT_PSA_PROFILE_OLD) {
            ret = WOLFCOSE_E_EAT_PSA_PROFILE;
        }
        else {
            /* All required legacy-profile claims were decoded. */
        }
    }
#endif
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((token->nonce.len != 32u) && (token->nonce.len != 48u) &&
         (token->nonce.len != 64u))) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((token->ueid.len != 33u) || (token->ueid.data[0] != 0x01u) ||
         (token->implementationId.len != 32u))) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }
#if defined(WOLFCOSE_EAT_PSA_CURRENT)
    if ((ret == WOLFCOSE_SUCCESS) &&
        (token->profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT) &&
        (token->bootSeed.data != NULL) &&
        ((token->bootSeed.len < 8u) || (token->bootSeed.len > 32u))) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }
#endif
#if defined(WOLFCOSE_EAT_PSA_LEGACY)
    if ((ret == WOLFCOSE_SUCCESS) &&
        (token->profile == WOLFCOSE_EAT_PSA_PROFILE_OLD) &&
        (token->bootSeed.len != 32u)) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }
#endif
#if defined(WOLFCOSE_EAT_PSA_CURRENT)
    if ((ret == WOLFCOSE_SUCCESS) &&
        (token->certificationReference.data != NULL) &&
        (token->profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT) &&
        (wolfCose_EatPsaCertRefValid(&token->certificationReference,
            18u, 1) == 0)) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }
#endif
#if defined(WOLFCOSE_EAT_PSA_LEGACY)
    if ((ret == WOLFCOSE_SUCCESS) &&
        (token->certificationReference.data != NULL) &&
        (token->profile == WOLFCOSE_EAT_PSA_PROFILE_OLD) &&
        (wolfCose_EatPsaCertRefValid(&token->certificationReference,
            13u, 0) == 0)) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }
#endif
    if ((ret != WOLFCOSE_SUCCESS) && (token != NULL)) {
        (void)XMEMSET(token, 0, sizeof(*token));
    }

    return ret;
}

static int wolfCose_EatPsaGetEnvelope(const uint8_t* in, size_t inSz,
    uint64_t* tag, const uint8_t** payload, size_t* payloadLen, int32_t* alg)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    WOLFCOSE_HDR hdr = { 0 };
    WOLFCOSE_HDR_STATE hdrState;
    size_t arrayCount = 0u;
    const uint8_t* protectedData;
    size_t protectedLen;
    const uint8_t* ignored;
    size_t ignoredLen;

    if ((in == NULL) || (tag == NULL) || (payload == NULL) ||
        (payloadLen == NULL) || (alg == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wc_CBOR_DecoderInit(&ctx, in, inSz);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_EAT_PSA_DECODE_TAG(&ctx, tag);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (*tag != WOLFCOSE_TAG_SIGN1) &&
        (*tag != WOLFCOSE_TAG_MAC0)) {
        ret = WOLFCOSE_E_COSE_BAD_TAG;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_EAT_PSA_DECODE_ARRAY(&ctx, &arrayCount);
        if ((ret == WOLFCOSE_SUCCESS) && (arrayCount != 4u)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_EAT_PSA_DECODE_BSTR(&ctx, &protectedData, &protectedLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        (void)XMEMSET(&hdr, 0, sizeof(hdr));
        ret = wolfCose_DecodeProtectedHdr_ex(protectedData, protectedLen,
            &hdr, &hdrState, WOLFCOSE_COSE_DECODE_ALLOW_NONPREFERRED);
    }
    /* COSE requires alg to be authenticated where the construction permits
     * it. PSA uses no external AAD, so the only valid location is protected. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((hdrState.labelBits & 0x00000001u) == 0u)) {
        ret = WOLFCOSE_E_COSE_BAD_HDR;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeUnprotectedHdr_ex(&ctx, &hdr, &hdrState,
            WOLFCOSE_EAT_PSA_DECODE_FLAGS);
    }
    /* This API deliberately uses caller-supplied raw verification keys. Do
     * not accept an x5chain parameter that would look validated but is not. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((hdr.flags & WOLFCOSE_HDR_FLAG_X5CHAIN) != 0u)) {
        ret = WOLFCOSE_E_UNSUPPORTED;
    }
    if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx < ctx.bufSz) &&
        (ctx.cbuf[ctx.idx] == WOLFCOSE_CBOR_NULL)) {
        ret = WOLFCOSE_E_DETACHED_PAYLOAD;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_EAT_PSA_DECODE_BSTR(&ctx, payload, payloadLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_EAT_PSA_DECODE_BSTR(&ctx, &ignored, &ignoredLen);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != ctx.bufSz)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        *alg = hdr.alg;
    }

    return ret;
}

static int wolfCose_EatPsaCheckNonce(const WOLFCOSE_EAT_PSA_TOKEN* token,
    const uint8_t* expectedNonce, size_t expectedNonceLen)
{
    int ret = WOLFCOSE_SUCCESS;

    if ((token == NULL) || (expectedNonce == NULL) ||
        ((expectedNonceLen != 32u) && (expectedNonceLen != 48u) &&
         (expectedNonceLen != 64u))) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((token->nonce.len != expectedNonceLen) ||
        (wolfCose_EatPsaConstantCompare(token->nonce.data, expectedNonce,
             expectedNonceLen) != 0)) {
        ret = WOLFCOSE_E_EAT_PSA_NONCE;
    }
    else {
        /* The authenticated nonce matches the caller's challenge. */
    }

    return ret;
}

static int wolfCose_EatPsaCheckEnvelopeAlg(uint64_t tag, int32_t alg)
{
    int ret = WOLFCOSE_SUCCESS;

    if (tag == WOLFCOSE_TAG_SIGN1) {
#if defined(WOLFCOSE_EAT_PSA_SIGN1)
        if (wolfCose_EatPsaSignAlg(alg) == 0) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
#else
        ret = WOLFCOSE_E_UNSUPPORTED;
#endif
    }
    else if (tag == WOLFCOSE_TAG_MAC0) {
#if defined(WOLFCOSE_EAT_PSA_MAC0)
        if (wolfCose_EatPsaMacAlg(alg) == 0) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
#else
        ret = WOLFCOSE_E_UNSUPPORTED;
#endif
    }
    else {
        ret = WOLFCOSE_E_COSE_BAD_TAG;
    }

    return ret;
}

int wc_CoseEatPsaToken_Verify(const WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* expectedNonce, size_t expectedNonceLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_EAT_PSA_TOKEN* token)
{
    int ret;
    uint64_t tag = 0u;
    const uint8_t* payload = NULL;
    size_t payloadLen = 0u;
    int32_t alg = WOLFCOSE_ALG_UNSET;
    WOLFCOSE_HDR hdr = { 0 };

    if ((key == NULL) || (in == NULL) || (expectedNonce == NULL) ||
        (scratch == NULL) || (token == NULL) ||
        ((expectedNonceLen != 32u) && (expectedNonceLen != 48u) &&
         (expectedNonceLen != 64u))) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        (void)XMEMSET(token, 0, sizeof(*token));
        ret = wolfCose_EatPsaGetEnvelope(in, inSz, &tag, &payload,
            &payloadLen, &alg);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EatPsaCheckEnvelopeAlg(tag, alg);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (tag == WOLFCOSE_TAG_SIGN1)) {
#if defined(WOLFCOSE_EAT_PSA_SIGN1)
        ret = wolfCose_Sign1_Verify_ex(key, in, inSz, NULL, 0u, NULL, 0u,
            scratch, scratchSz, &hdr, &payload, &payloadLen,
            WOLFCOSE_COSE_DECODE_ALLOW_NONPREFERRED);
#else
        ret = WOLFCOSE_E_UNSUPPORTED;
#endif
    }
    if ((ret == WOLFCOSE_SUCCESS) && (tag == WOLFCOSE_TAG_MAC0)) {
#if defined(WOLFCOSE_EAT_PSA_MAC0)
        ret = wolfCose_Mac0_Verify_ex(key, in, inSz, NULL, 0u, NULL, 0u,
            scratch, scratchSz, &hdr, &payload, &payloadLen,
            WOLFCOSE_COSE_DECODE_ALLOW_NONPREFERRED);
#else
        ret = WOLFCOSE_E_UNSUPPORTED;
#endif
    }
    if ((ret == WOLFCOSE_SUCCESS) && ((hdr.flags & WOLFCOSE_HDR_FLAG_DETACHED) != 0u)) {
        ret = WOLFCOSE_E_DETACHED_PAYLOAD;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EatPsaDecodeClaims(payload, payloadLen, token);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        token->protection = (tag == WOLFCOSE_TAG_SIGN1) ?
            WOLFCOSE_EAT_PSA_PROTECTION_SIGN1 :
            WOLFCOSE_EAT_PSA_PROTECTION_MAC0;
        ret = wolfCose_EatPsaCheckNonce(token, expectedNonce, expectedNonceLen);
    }
    if ((ret != WOLFCOSE_SUCCESS) && (token != NULL)) {
        (void)XMEMSET(token, 0, sizeof(*token));
    }

    return ret;
}

#if defined(WOLFCOSE_EAT_PSA_UEID_RESOLVER)
int wc_CoseEatPsaToken_VerifyByUeid(WOLFCOSE_EAT_PSA_KEY_RESOLVER resolver,
    void* resolverCtx, const uint8_t* in, size_t inSz,
    const uint8_t* expectedNonce, size_t expectedNonceLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_EAT_PSA_TOKEN* token)
{
    int ret;
    uint64_t tag = 0u;
    const uint8_t* payload = NULL;
    size_t payloadLen = 0u;
    int32_t alg = WOLFCOSE_ALG_UNSET;
    WOLFCOSE_EAT_PSA_TOKEN untrusted;
    WOLFCOSE_KEY key;

    (void)XMEMSET(&key, 0, sizeof(key));

    if ((resolver == NULL) || (in == NULL) || (expectedNonce == NULL) ||
        (scratch == NULL) || (token == NULL) ||
        ((expectedNonceLen != 32u) && (expectedNonceLen != 48u) &&
         (expectedNonceLen != 64u))) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        (void)XMEMSET(token, 0, sizeof(*token));
        ret = wolfCose_EatPsaGetEnvelope(in, inSz, &tag, &payload, &payloadLen,
            &alg);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EatPsaCheckEnvelopeAlg(tag, alg);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EatPsaDecodeClaims(payload, payloadLen, &untrusted);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseKey_Init(&key);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = resolver(resolverCtx, untrusted.profile, untrusted.ueid.data,
            untrusted.ueid.len, alg, &key);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseEatPsaToken_Verify(&key, in, inSz, expectedNonce,
            expectedNonceLen, scratch, scratchSz, token);
    }
    if ((ret != WOLFCOSE_SUCCESS) && (token != NULL)) {
        (void)XMEMSET(token, 0, sizeof(*token));
    }
    wc_CoseKey_Free(&key);

    return ret;
}
#endif /* WOLFCOSE_EAT_PSA_UEID_RESOLVER */

#if defined(WOLFCOSE_EAT_PSA_COMPONENT_ITERATOR)
int wc_CoseEatPsaToken_ForEachComponent(const WOLFCOSE_EAT_PSA_TOKEN* token,
    WOLFCOSE_EAT_PSA_COMPONENT_CB cb, void* cbCtx)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    size_t count = 0u;
    size_t i;
    WOLFCOSE_EAT_PSA_COMPONENT component;

    if ((token == NULL) || (cb == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (token->noSoftwareMeasurements != 0u) {
        ret = WOLFCOSE_SUCCESS;
    }
    else if (token->components.data == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wc_CBOR_DecoderInit(&ctx, token->components.data,
            token->components.len);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (token->noSoftwareMeasurements == 0u)) {
        ret = WOLFCOSE_EAT_PSA_DECODE_ARRAY(&ctx, &count);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (token->noSoftwareMeasurements == 0u) &&
        (count != token->componentCount)) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }
    for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < count); i++) {
        ret = wolfCose_EatPsaDecodeComponent(&ctx, &component);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = cb(cbCtx, &component);
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (token->noSoftwareMeasurements == 0u) && (ctx.idx != ctx.bufSz)) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }

    return ret;
}
#endif /* WOLFCOSE_EAT_PSA_COMPONENT_ITERATOR */

#endif /* WOLFCOSE_EAT_PSA_VERIFY */

#if defined(WOLFCOSE_EAT_PSA_SIGN1_ISSUE)
int wc_CoseEatPsaToken_CreateSign1(WOLFCOSE_KEY* key, int32_t alg,
    const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    uint8_t* claimsBuf, size_t claimsBufSz,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng)
{
    int ret;
    size_t claimsLen = 0u;

    if (outLen != NULL) {
        *outLen = 0u;
    }
    if ((key == NULL) || (claimsBuf == NULL) || (scratch == NULL) ||
        (out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (wolfCose_EatPsaIssueBuffersOverlap(claimsBuf, claimsBufSz,
                 scratch, scratchSz, out, outSz) != 0) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (wolfCose_EatPsaSignAlg(alg) == 0) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        ret = wc_CoseEatPsaToken_EncodeClaims(claims, claimsBuf, claimsBufSz,
            &claimsLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseSign1_Sign_ex(key, alg, NULL, 0u, claimsBuf, claimsLen,
            NULL, 0u, NULL, 0u, scratch, scratchSz, out, outSz, outLen, rng,
            0u);
    }
    if ((ret != WOLFCOSE_SUCCESS) && (out != NULL)) {
        (void)wolfCose_ForceZero(out, outSz);
    }

    return ret;
}
#endif /* WOLFCOSE_EAT_PSA_SIGN1_ISSUE */

#if defined(WOLFCOSE_EAT_PSA_MAC0_ISSUE)
int wc_CoseEatPsaToken_CreateMac0(const WOLFCOSE_KEY* key, int32_t alg,
    const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    uint8_t* claimsBuf, size_t claimsBufSz,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen)
{
    int ret;
    size_t claimsLen = 0u;

    if (outLen != NULL) {
        *outLen = 0u;
    }
    if ((key == NULL) || (claimsBuf == NULL) || (scratch == NULL) ||
        (out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (wolfCose_EatPsaIssueBuffersOverlap(claimsBuf, claimsBufSz,
                 scratch, scratchSz, out, outSz) != 0) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (wolfCose_EatPsaMacAlg(alg) == 0) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        ret = wc_CoseEatPsaToken_EncodeClaims(claims, claimsBuf, claimsBufSz,
            &claimsLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseMac0_Create(key, alg, NULL, 0u, claimsBuf, claimsLen,
            NULL, 0u, NULL, 0u, scratch, scratchSz, out, outSz, outLen);
    }
    if ((ret != WOLFCOSE_SUCCESS) && (out != NULL)) {
        (void)wolfCose_ForceZero(out, outSz);
    }

    return ret;
}
#endif /* WOLFCOSE_EAT_PSA_MAC0_ISSUE */

#endif /* WOLFCOSE_EAT_PSA */
