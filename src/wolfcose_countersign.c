/* wolfcose_countersign.c
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

/**
 * COSE countersignatures. RFC 9338 Section 3 and Section 4.
 * Full countersignatures and abbreviated (Countersignature0) over a COSE
 * message body. All crypto via wolfCrypt wc_* APIs. Zero allocation.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfcose_internal.h"
/* wolfcose.h (via internal.h) includes ecc.h, ed25519.h, ed448.h,
 * wc_mldsa.h (ML-DSA), rsa.h, random.h.  Only list headers not pulled in. */
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>  /* XMEMCPY */
#if defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM) || \
    defined(WOLFCOSE_HAVE_AESMAC) || defined(WOLFCOSE_KEY_WRAP)
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#ifdef WOLFCOSE_HAVE_HMAC
    #include <wolfssl/wolfcrypt/hmac.h>
#endif
#if defined(WOLFCOSE_HAVE_CHACHA20)
    #include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#endif
#include <string.h>
#include <limits.h>

#if defined(WOLFCOSE_COUNTERSIGN)

typedef struct WOLFCOSE_COUNTER_TARGET {
    uint64_t tag;
    const uint8_t* bodyProtected;
    size_t bodyProtectedLen;
    const uint8_t* payload;
    size_t payloadLen;
    const uint8_t* other;
    size_t otherLen;
    size_t otherCount;
    size_t mapStart;
    size_t mapContentStart;
    size_t mapEnd;
    size_t mapCount;
    size_t fullValueStart;
    size_t fullValueEnd;
    size_t abbreviatedValueStart;
    size_t abbreviatedValueEnd;
    size_t legacyFullValueStart;
    size_t legacyFullValueEnd;
    size_t legacyAbbreviatedValueStart;
    size_t legacyAbbreviatedValueEnd;
    uint8_t hasFull;
    uint8_t hasAbbreviated;
    uint8_t hasLegacyFull;
    uint8_t hasLegacyAbbreviated;
} WOLFCOSE_COUNTER_TARGET;

typedef struct WOLFCOSE_COUNTER_LIST_INFO {
    size_t count;
    size_t contentOffset;
    uint8_t isList;
} WOLFCOSE_COUNTER_LIST_INFO;

typedef struct WOLFCOSE_COUNTER_ATTACH_PLAN {
    WOLFCOSE_COUNTER_LIST_INFO listInfo;
    size_t oldValueLen;
    size_t newValueLen;
    size_t counterLen;
    size_t delta;
    size_t finalLen;
    size_t newMapCount;
    size_t newMapHeadLen;
    uint8_t replacesValue;
} WOLFCOSE_COUNTER_ATTACH_PLAN;

static int wolfCose_ParseCounterMap(WOLFCOSE_CBOR_CTX* ctx,
    WOLFCOSE_COUNTER_TARGET* target, WOLFCOSE_HDR_STATE* hdrState)
{
    int ret;
    size_t i;
    size_t count = 0u;
    WOLFCOSE_HDR_STATE mapState;

    wolfCose_HdrStateInit(&mapState);
    target->mapStart = ctx->idx;
    ret = wc_CBOR_DecodeMapStart(ctx, &count);
    if ((ret == WOLFCOSE_SUCCESS) &&
        (count > (size_t)WOLFCOSE_MAX_MAP_ITEMS)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
        count = 0u;
    }
    target->mapCount = count;
    target->mapContentStart = ctx->idx;

    for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < count); i++) {
        WOLFCOSE_CBOR_LABEL label;
        const uint8_t* encodedLabel = NULL;
        const uint8_t* value = NULL;
        size_t valueLen = 0u;
        size_t valueStart;
        uint8_t valueType = 0xFFu;

        if ((ctx->cbuf != NULL) && (ctx->idx < ctx->bufSz)) {
            encodedLabel = &ctx->cbuf[ctx->idx];
        }
        ret = wc_CBOR_DecodeLabel(ctx, &label);
        if ((ret == WOLFCOSE_SUCCESS) &&
            (wc_CBOR_LabelIsInt(&label, WOLFCOSE_HDR_CRIT) != 0)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            if ((wolfCose_HdrStateContainsLabel(&mapState, &label) != 0) ||
                (wolfCose_HdrStateContainsLabel(hdrState, &label) != 0)) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            else {
                ret = wolfCose_HdrStateAddLabel(&mapState, &label,
                    encodedLabel);
            }
        }
        valueStart = ctx->idx;
        valueType = wc_CBOR_PeekType(ctx);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_SkipItem(ctx, &value, &valueLen);
        }
        /* Registered countersignature labels carry a fixed major type; a wrong
         * type is malformed even when this call does not use that variant. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            (wc_CBOR_LabelIsInt(&label,
                WOLFCOSE_HDR_COUNTERSIGNATURE_V2) != 0)) {
            if ((target->hasFull != 0u) ||
                (valueType != WOLFCOSE_CBOR_ARRAY)) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            else {
                target->hasFull = 1u;
                target->fullValueStart = valueStart;
                target->fullValueEnd = ctx->idx;
            }
        }
        else if ((ret == WOLFCOSE_SUCCESS) &&
                 (wc_CBOR_LabelIsInt(&label,
                    WOLFCOSE_HDR_COUNTERSIGNATURE0_V2) != 0)) {
            if ((target->hasAbbreviated != 0u) ||
                (valueType != WOLFCOSE_CBOR_BSTR)) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            else {
                target->hasAbbreviated = 1u;
                target->abbreviatedValueStart = valueStart;
                target->abbreviatedValueEnd = ctx->idx;
            }
        }
        else if ((ret == WOLFCOSE_SUCCESS) &&
                 (wc_CBOR_LabelIsInt(&label,
                    WOLFCOSE_HDR_COUNTERSIGNATURE_LEGACY) != 0)) {
            if ((target->hasLegacyFull != 0u) ||
                (valueType != WOLFCOSE_CBOR_ARRAY)) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            else {
                target->hasLegacyFull = 1u;
                target->legacyFullValueStart = valueStart;
                target->legacyFullValueEnd = ctx->idx;
            }
        }
        else if ((ret == WOLFCOSE_SUCCESS) &&
                 (wc_CBOR_LabelIsInt(&label,
                    WOLFCOSE_HDR_COUNTERSIGNATURE0_LEGACY) != 0)) {
            if ((target->hasLegacyAbbreviated != 0u) ||
                (valueType != WOLFCOSE_CBOR_BSTR)) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            else {
                target->hasLegacyAbbreviated = 1u;
                target->legacyAbbreviatedValueStart = valueStart;
                target->legacyAbbreviatedValueEnd = ctx->idx;
            }
        }
        else {
            /* No action required */
        }
        (void)value;
        (void)valueLen;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        target->mapEnd = ctx->idx;
    }
    return ret;
}

static int wolfCose_ParseCounterTarget(const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    WOLFCOSE_COUNTER_TARGET* target)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    WOLFCOSE_HDR hdr;
    WOLFCOSE_HDR_STATE hdrState;
    size_t arrayCount = 0u;
    size_t expectedCount = 0u;

    (void)XMEMSET(&ctx, 0, sizeof(ctx));
    if ((in == NULL) || (target == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        (void)XMEMSET(target, 0, sizeof(*target));
        (void)XMEMSET(&hdr, 0, sizeof(hdr));
        ret = wc_CBOR_DecoderInit(&ctx, in, inSz);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((ctx.idx >= ctx.bufSz) ||
         (wc_CBOR_PeekType(&ctx) != WOLFCOSE_CBOR_TAG))) {
        ret = WOLFCOSE_E_COSE_BAD_TAG;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeTag(&ctx, &target->tag);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        switch (target->tag) {
            case WOLFCOSE_TAG_ENCRYPT0:
                expectedCount = 3u;
                break;
            case WOLFCOSE_TAG_MAC0:
            case WOLFCOSE_TAG_SIGN1:
            case WOLFCOSE_TAG_SIGN:
            case WOLFCOSE_TAG_ENCRYPT:
                expectedCount = 4u;
                break;
            case WOLFCOSE_TAG_MAC:
                expectedCount = 5u;
                break;
            default:
                ret = WOLFCOSE_E_COSE_BAD_TAG;
                break;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
        if ((ret == WOLFCOSE_SUCCESS) && (arrayCount != expectedCount)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &target->bodyProtected,
                                  &target->bodyProtectedLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeProtectedHdr(target->bodyProtected,
            target->bodyProtectedLen, &hdr, &hdrState);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((wolfCose_HdrStateContains(&hdrState,
            WOLFCOSE_HDR_COUNTERSIGNATURE_V2) != 0) ||
         (wolfCose_HdrStateContains(&hdrState,
            WOLFCOSE_HDR_COUNTERSIGNATURE0_V2) != 0) ||
         (wolfCose_HdrStateContains(&hdrState,
            WOLFCOSE_HDR_COUNTERSIGNATURE_LEGACY) != 0) ||
         (wolfCose_HdrStateContains(&hdrState,
            WOLFCOSE_HDR_COUNTERSIGNATURE0_LEGACY) != 0))) {
        ret = WOLFCOSE_E_COSE_BAD_HDR;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_ParseCounterMap(&ctx, target, &hdrState);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ctx.idx = target->mapStart;
        ret = wolfCose_DecodeUnprotectedHdr(&ctx, &hdr, &hdrState);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != target->mapEnd)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        if ((ctx.idx < ctx.bufSz) &&
            (ctx.cbuf[ctx.idx] == WOLFCOSE_CBOR_NULL)) {
            ctx.idx++;
            if (detachedPayload == NULL) {
                ret = WOLFCOSE_E_DETACHED_PAYLOAD;
            }
            else {
                target->payload = detachedPayload;
                target->payloadLen = detachedLen;
            }
        }
        else {
            ret = wc_CBOR_DecodeBstr(&ctx, &target->payload,
                                      &target->payloadLen);
        }
    }

    if ((ret == WOLFCOSE_SUCCESS) &&
        ((target->tag == WOLFCOSE_TAG_SIGN1) ||
         (target->tag == WOLFCOSE_TAG_MAC0) ||
         (target->tag == WOLFCOSE_TAG_MAC))) {
        ret = wc_CBOR_DecodeBstr(&ctx, &target->other, &target->otherLen);
        if (ret == WOLFCOSE_SUCCESS) {
            target->otherCount = 1u;
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((target->tag == WOLFCOSE_TAG_SIGN) ||
         (target->tag == WOLFCOSE_TAG_ENCRYPT) ||
         (target->tag == WOLFCOSE_TAG_MAC))) {
        size_t childCount = 0u;
        size_t i;

        /* RFC 9338 Section 3.3 counts bstr fields in the selected target,
         * not bstr values nested inside an aggregate child array. COSE_Sign
         * and COSE_Encrypt have no direct bstr after the payload or
         * ciphertext. COSE_Mac's direct tag bstr is captured above. Appendix
         * A.1.1 exercises this COSE_Sign form with other_fields absent. */
        ret = wc_CBOR_DecodeArrayStart(&ctx, &childCount);
        if ((ret == WOLFCOSE_SUCCESS) && (childCount == 0u)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
        for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < childCount); i++) {
            if (target->tag == WOLFCOSE_TAG_SIGN) {
                ret = wolfCose_DecodeSkippedSignature(&ctx);
            }
            else {
                int32_t recipientAlg = WOLFCOSE_ALG_UNSET;

                ret = wolfCose_DecodeSkippedRecipient(&ctx, &recipientAlg);
            }
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != ctx.bufSz)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    return ret;
}

static int wolfCose_ValidateFullCounter(const uint8_t* in, size_t inSz)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    WOLFCOSE_HDR hdr;
    WOLFCOSE_HDR_STATE hdrState;
    const uint8_t* protectedData = NULL;
    const uint8_t* sig = NULL;
    size_t protectedLen = 0u;
    size_t sigLen = 0u;
    size_t count = 0u;

    (void)XMEMSET(&hdr, 0, sizeof(hdr));
    ret = wc_CBOR_DecoderInit(&ctx, in, inSz);
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &count);
        if ((ret == WOLFCOSE_SUCCESS) && (count != 3u)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &protectedData, &protectedLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeProtectedHdr(protectedData, protectedLen,
                                          &hdr, &hdrState);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeUnprotectedHdr(&ctx, &hdr, &hdrState);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &sig, &sigLen);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != ctx.bufSz)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    (void)sig;
    (void)sigLen;
    return ret;
}

static int wolfCose_CounterListInfo(const uint8_t* in, size_t inSz,
                                     WOLFCOSE_COUNTER_LIST_INFO* info)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    size_t count = 0u;
    size_t i;

    if ((in == NULL) || (info == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        (void)XMEMSET(info, 0, sizeof(*info));
        ret = wc_CBOR_DecoderInit(&ctx, in, inSz);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &count);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((count == 0u) || (ctx.idx >= ctx.bufSz))) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_BSTR)) {
        ret = wolfCose_ValidateFullCounter(in, inSz);
        if (ret == WOLFCOSE_SUCCESS) {
            info->count = 1u;
            info->contentOffset = 0u;
            info->isList = 0u;
        }
    }
    else if ((ret == WOLFCOSE_SUCCESS) &&
             (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_ARRAY)) {
        if (count > (size_t)WOLFCOSE_MAX_MAP_ITEMS) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
        info->contentOffset = ctx.idx;
        for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < count); i++) {
            const uint8_t* value = NULL;
            size_t valueLen = 0u;

            ret = wc_CBOR_SkipItem(&ctx, &value, &valueLen);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_ValidateFullCounter(value, valueLen);
            }
        }
        if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != ctx.bufSz)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            info->count = count;
            info->isList = 1u;
        }
    }
    else if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    else {
        /* No action required */
    }
    return ret;
}

#if defined(WOLFCOSE_COUNTERSIGN_VERIFY)
static int wolfCose_SelectFullCounter(const uint8_t* in, size_t inSz,
    size_t counterIndex, const uint8_t** selected, size_t* selectedLen)
{
    int ret;
    WOLFCOSE_COUNTER_LIST_INFO info;

    (void)XMEMSET(&info, 0, sizeof(info));
    if ((selected == NULL) || (selectedLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        *selected = NULL;
        *selectedLen = 0u;
        ret = wolfCose_CounterListInfo(in, inSz, &info);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (counterIndex >= info.count)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    if ((ret == WOLFCOSE_SUCCESS) && (info.isList == 0u)) {
        *selected = in;
        *selectedLen = inSz;
    }
    else if (ret == WOLFCOSE_SUCCESS) {
        WOLFCOSE_CBOR_CTX ctx;
        size_t count = 0u;
        size_t i;

        ret = wc_CBOR_DecoderInit(&ctx, in, inSz);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_DecodeArrayStart(&ctx, &count);
        }
        for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i <= counterIndex); i++) {
            ret = wc_CBOR_SkipItem(&ctx, selected, selectedLen);
        }
        (void)count;
    }
    else {
        /* No action required */
    }
    return ret;
}
#endif /* WOLFCOSE_COUNTERSIGN_VERIFY */

static int wolfCose_BuildCounterStructure(
    const WOLFCOSE_COUNTER_TARGET* target,
    const uint8_t* signProtected, size_t signProtectedLen,
    const uint8_t* extAad, size_t extAadLen, uint8_t abbreviated,
    uint8_t legacy, uint8_t* scratch, size_t scratchSz, size_t* structLen)
{
    static const uint8_t contextCounter[] = "CounterSignature";
    static const uint8_t contextCounter0[] = "CounterSignature0";
    static const uint8_t contextCounterV2[] = "CounterSignatureV2";
    static const uint8_t contextCounter0V2[] = "CounterSignature0V2";
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    const uint8_t* context;
    size_t contextLen;
    size_t arrayCount;

    if ((target == NULL) || (scratch == NULL) || (structLen == NULL) ||
        ((extAad == NULL) && (extAadLen != 0u)) ||
        ((abbreviated == 0u) && (signProtected == NULL))) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        if (legacy != 0u) {
            if (abbreviated != 0u) {
                context = contextCounter0;
                contextLen = sizeof(contextCounter0) - 1u;
                arrayCount = 4u;
            }
            else {
                context = contextCounter;
                contextLen = sizeof(contextCounter) - 1u;
                arrayCount = 5u;
            }
        }
        else if (abbreviated != 0u) {
            if (target->otherCount != 0u) {
                context = contextCounter0V2;
                contextLen = sizeof(contextCounter0V2) - 1u;
                arrayCount = 5u;
            }
            else {
                context = contextCounter0;
                contextLen = sizeof(contextCounter0) - 1u;
                arrayCount = 4u;
            }
        }
        else {
            if (target->otherCount != 0u) {
                context = contextCounterV2;
                contextLen = sizeof(contextCounterV2) - 1u;
                arrayCount = 6u;
            }
            else {
                context = contextCounter;
                contextLen = sizeof(contextCounter) - 1u;
                arrayCount = 5u;
            }
        }
        ret = wc_CBOR_EncoderInit(&ctx, scratch, scratchSz);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, arrayCount);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeTstr(&ctx, context, contextLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, target->bodyProtected,
                                  target->bodyProtectedLen);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (abbreviated == 0u)) {
        ret = wc_CBOR_EncodeBstr(&ctx, signProtected, signProtectedLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, extAad, extAadLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, target->payload, target->payloadLen);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (legacy == 0u) &&
        (target->otherCount != 0u)) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, target->otherCount);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, target->other, target->otherLen);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        *structLen = ctx.idx;
    }
    return ret;
}

#if defined(WOLFCOSE_COUNTERSIGN_SIGN)
static int wolfCose_FullCounterSize(size_t protectedLen, size_t kidLen,
                                     size_t sigLen, size_t* encodedLen)
{
    int ret;
    size_t itemLen = 0u;
    size_t total = 1u;

    ret = wolfCose_CborStringSize(protectedLen, &itemLen);
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_SizeAdd(&total, itemLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_SizeAdd(&total, 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (kidLen != 0u)) {
        ret = wolfCose_SizeAdd(&total, 1u);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_CborStringSize(kidLen, &itemLen);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_SizeAdd(&total, itemLen);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CborStringSize(sigLen, &itemLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_SizeAdd(&total, itemLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        *encodedLen = total;
    }
    return ret;
}

static int wolfCose_EncodeFullCounter(WOLFCOSE_CBOR_CTX* ctx,
    const uint8_t* protectedData, size_t protectedLen,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* sig, size_t sigLen)
{
    int ret;
    size_t mapCount = 0u;

    if (kidLen != 0u) {
        mapCount = 1u;
    }
    ret = wc_CBOR_EncodeArrayStart(ctx, 3u);
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(ctx, protectedData, protectedLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(ctx, mapCount);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (kidLen != 0u)) {
        ret = wc_CBOR_EncodeInt(ctx, WOLFCOSE_HDR_KID);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(ctx, kid, kidLen);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(ctx, sig, sigLen);
    }
    return ret;
}
#endif /* WOLFCOSE_COUNTERSIGN_SIGN */

#if defined(WOLFCOSE_COUNTERSIGN_SIGN)
static int wolfCose_CounterSignTbs(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* tbs, size_t tbsLen,
    uint8_t* sig, size_t sigSz, size_t* sigLen, WC_RNG* rng)
{
    int ret = WOLFCOSE_SUCCESS;
    uint8_t hashBuf[WC_MAX_DIGEST_SIZE];

    if ((key == NULL) || (tbs == NULL) || (sig == NULL) ||
        (sigLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        *sigLen = 0u;
    }
#if defined(WOLFCOSE_EXT_SIGN)
    if ((ret == WOLFCOSE_SUCCESS) && (key->signCb == NULL) && (rng == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#else
    if ((ret == WOLFCOSE_SUCCESS) && (rng == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#endif
#ifdef WOLFCOSE_CHECK_WORD32_LEN
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((wolfCose_LenFitsWord32(tbsLen) == 0) ||
         (wolfCose_LenFitsWord32(sigSz) == 0))) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#endif
    if ((ret == WOLFCOSE_SUCCESS) &&
        (wolfCose_KeyCanSign(key) == 0)) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (key->alg != WOLFCOSE_ALG_UNSET) && (key->alg != alg)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

#if defined(WOLFCOSE_EXT_SIGN)
    if ((ret == WOLFCOSE_SUCCESS) && (key->signCb != NULL)) {
        ret = wolfCose_ExtSign(key, alg, tbs, tbsLen,
                               sig, sigSz, sigLen);
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_ECDSA
    if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_AlgIsEcdsa(alg) != 0)) {
        enum wc_HashType hashType = WC_HASH_TYPE_NONE;
        int digestSz = 0;
        size_t coordSz = 0u;

        if (key->kty != WOLFCOSE_KTY_EC2) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        /* Each ECDSA alg is bound to one curve. */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AlgCheckCrv(alg, key->crv);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_EccKeyCheckCurve(key->crv, key->key.ecc);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AlgToHashType(alg, &hashType);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            digestSz = wc_HashGetDigestSize(hashType);
            if (digestSz <= 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_HASH, -1,
                ret = wc_Hash(hashType, tbs, (word32)tbsLen,
                               hashBuf, (word32)digestSz));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_CrvKeySize(key->crv, &coordSz);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            *sigLen = sigSz;
            ret = wolfCose_EccSignRaw(hashBuf, (size_t)digestSz,
                                       sig, sigLen, coordSz, hashType,
                                       rng, key->key.ecc);
        }
    }
    else
#endif
#if defined(WOLFCOSE_HAVE_EDDSA) || defined(WOLFCOSE_HAVE_ED448)
    if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_AlgIsEddsa(alg) != 0)) {
        word32 outLen = (word32)sigSz;

        if (key->kty != WOLFCOSE_KTY_OKP) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AlgCheckCrv(alg, key->crv);
        }
#ifdef WOLFCOSE_HAVE_EDDSA
        if ((ret == WOLFCOSE_SUCCESS) &&
            (key->crv == WOLFCOSE_CRV_ED25519)) {
            if (key->key.ed25519 == NULL) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else {
                INJECT_FAILURE(WOLF_FAIL_ED25519_SIGN, -1,
                    ret = wc_ed25519_sign_msg(tbs, (word32)tbsLen,
                                               sig, &outLen,
                                               key->key.ed25519));
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }
        }
        else
#endif
#ifdef WOLFCOSE_HAVE_ED448
        if ((ret == WOLFCOSE_SUCCESS) &&
            (key->crv == WOLFCOSE_CRV_ED448)) {
            if (key->key.ed448 == NULL) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else {
                INJECT_FAILURE(WOLF_FAIL_ED448_SIGN, -1,
                    ret = wc_ed448_sign_msg(tbs, (word32)tbsLen,
                                             sig, &outLen,
                                             key->key.ed448, NULL, 0));
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }
        }
        else
#endif
        if (ret == WOLFCOSE_SUCCESS) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
        else {
            /* No action required */
        }
        if (ret == WOLFCOSE_SUCCESS) {
            *sigLen = (size_t)outLen;
        }
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_RSAPSS
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_PS256) || (alg == WOLFCOSE_ALG_PS384) ||
         (alg == WOLFCOSE_ALG_PS512))) {
        enum wc_HashType hashType = WC_HASH_TYPE_NONE;
        int digestSz = 0;
        WOLFCOSE_MGF_ID mgf = 0;

        ret = wolfCose_RsaPssCheckKey(key, NULL);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AlgToHashType(alg, &hashType);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            digestSz = wc_HashGetDigestSize(hashType);
            if (digestSz <= 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_HASH, -1,
                ret = wc_Hash(hashType, tbs, (word32)tbsLen,
                               hashBuf, (word32)digestSz));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_HashToMgf(hashType, &mgf);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_RSA_SSL_SIGN, -1,
                ret = wc_RsaPSS_Sign_ex(hashBuf, (word32)digestSz,
                                          sig, (word32)sigSz,
                                          hashType, mgf, digestSz,
                                          key->key.rsa, rng));
            if (ret <= 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                *sigLen = (size_t)ret;
                ret = WOLFCOSE_SUCCESS;
            }
        }
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_MLDSA
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_ML_DSA_44) ||
         (alg == WOLFCOSE_ALG_ML_DSA_65) ||
         (alg == WOLFCOSE_ALG_ML_DSA_87))) {
        word32 outLen = (word32)sigSz;

        ret = wolfCose_MlDsaCheckKey(key, alg);
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_MLDSA_SIGN, -1,
                ret = wc_MlDsaKey_SignCtx(key->key.mldsa, NULL, 0,
                    sig, &outLen, tbs, (word32)tbsLen, rng));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                *sigLen = (size_t)outLen;
            }
        }
    }
    else
#endif
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        /* No action required */
    }

    (void)wolfCose_ForceZero(hashBuf, sizeof(hashBuf));
    return ret;
}
#endif /* WOLFCOSE_COUNTERSIGN_SIGN */

#if defined(WOLFCOSE_COUNTERSIGN_VERIFY)
static int wolfCose_CounterVerifyTbs(const WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* tbs, size_t tbsLen,
    const uint8_t* sig, size_t sigLen,
    uint8_t* scratch, size_t scratchSz)
{
    int ret = WOLFCOSE_SUCCESS;
    uint8_t hashBuf[WC_MAX_DIGEST_SIZE];

    if ((key == NULL) || (tbs == NULL) || (sig == NULL) ||
        (scratch == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#ifdef WOLFCOSE_CHECK_WORD32_LEN
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((wolfCose_LenFitsWord32(tbsLen) == 0) ||
         (wolfCose_LenFitsWord32(sigLen) == 0) ||
         (wolfCose_LenFitsWord32(scratchSz) == 0))) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#endif
    if ((ret == WOLFCOSE_SUCCESS) &&
        (key->alg != WOLFCOSE_ALG_UNSET) && (key->alg != alg)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

#if defined(WOLFCOSE_HAVE_EDDSA) || defined(WOLFCOSE_HAVE_ED448)
    if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_AlgIsEddsa(alg) != 0)) {
        int verified = 0;

        if (key->kty != WOLFCOSE_KTY_OKP) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AlgCheckCrv(alg, key->crv);
        }
#ifdef WOLFCOSE_HAVE_EDDSA
        if ((ret == WOLFCOSE_SUCCESS) &&
            (key->crv == WOLFCOSE_CRV_ED25519)) {
            if ((key->attachedType != WOLFCOSE_ATT_ED25519) ||
                (key->key.ed25519 == NULL)) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else {
                ed25519_key* ed25519Key = key->key.ed25519;

                INJECT_FAILURE(WOLF_FAIL_ED25519_VERIFY, -1,
                    ret = wc_ed25519_verify_msg(sig, (word32)sigLen,
                        tbs, (word32)tbsLen, &verified, ed25519Key));
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }
        }
        else
#endif
#ifdef WOLFCOSE_HAVE_ED448
        if ((ret == WOLFCOSE_SUCCESS) &&
            (key->crv == WOLFCOSE_CRV_ED448)) {
            if ((key->attachedType != WOLFCOSE_ATT_ED448) ||
                (key->key.ed448 == NULL)) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else {
                ed448_key* ed448Key = key->key.ed448;

                INJECT_FAILURE(WOLF_FAIL_ED448_VERIFY, -1,
                    ret = wc_ed448_verify_msg(sig, (word32)sigLen,
                        tbs, (word32)tbsLen, &verified, ed448Key,
                        NULL, 0));
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }
        }
        else
#endif
        if (ret == WOLFCOSE_SUCCESS) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
        else {
            /* No action required */
        }
        if ((ret == WOLFCOSE_SUCCESS) && (verified != 1)) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
        }
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_ECDSA
    if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_AlgIsEcdsa(alg) != 0)) {
        ecc_key* eccKey = NULL;
        enum wc_HashType hashType = WC_HASH_TYPE_NONE;
        int digestSz = 0;
        int verified = 0;
        size_t coordSz = 0u;

        if (key->kty != WOLFCOSE_KTY_EC2) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        /* Each ECDSA alg is bound to one curve. */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AlgCheckCrv(alg, key->crv);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            eccKey = key->key.ecc;
            ret = wolfCose_EccKeyCheckCurve(key->crv, eccKey);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AlgToHashType(alg, &hashType);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            digestSz = wc_HashGetDigestSize(hashType);
            if (digestSz <= 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_HASH, -1,
                ret = wc_Hash(hashType, tbs, (word32)tbsLen,
                               hashBuf, (word32)digestSz));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_CrvKeySize(key->crv, &coordSz);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_EccVerifyRaw(sig, sigLen, hashBuf,
                (size_t)digestSz, coordSz, eccKey, &verified);
        }
        if ((ret == WOLFCOSE_SUCCESS) && (verified != 1)) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
        }
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_RSAPSS
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_PS256) || (alg == WOLFCOSE_ALG_PS384) ||
         (alg == WOLFCOSE_ALG_PS512))) {
        RsaKey* rsaKey = NULL;
        enum wc_HashType hashType = WC_HASH_TYPE_NONE;
        int digestSz = 0;
        WOLFCOSE_MGF_ID mgf = 0;

        ret = wolfCose_RsaPssCheckKey(key, NULL);
        if (ret == WOLFCOSE_SUCCESS) {
            rsaKey = key->key.rsa;
            ret = wolfCose_AlgToHashType(alg, &hashType);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            digestSz = wc_HashGetDigestSize(hashType);
            if (digestSz <= 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_HASH, -1,
                ret = wc_Hash(hashType, tbs, (word32)tbsLen,
                               hashBuf, (word32)digestSz));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_HashToMgf(hashType, &mgf);
        }
        if ((ret == WOLFCOSE_SUCCESS) && (sigLen > scratchSz)) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            (void)XMEMCPY(scratch, sig, sigLen);
            INJECT_FAILURE(WOLF_FAIL_RSA_SSL_VERIFY, -1,
                ret = wc_RsaPSS_VerifyCheck(scratch, (word32)sigLen,
                    scratch, (word32)scratchSz, hashBuf,
                    (word32)digestSz, hashType, mgf, rsaKey));
            if (ret < 0) {
                ret = WOLFCOSE_E_COSE_SIG_FAIL;
            }
            else {
                ret = WOLFCOSE_SUCCESS;
            }
        }
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_MLDSA
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_ML_DSA_44) ||
         (alg == WOLFCOSE_ALG_ML_DSA_65) ||
         (alg == WOLFCOSE_ALG_ML_DSA_87))) {
        int verified = 0;

        ret = wolfCose_MlDsaCheckKey(key, alg);
        if (ret == WOLFCOSE_SUCCESS) {
            wc_MlDsaKey* mldsaKey = key->key.mldsa;

            INJECT_FAILURE(WOLF_FAIL_MLDSA_VERIFY, -1,
                ret = wc_MlDsaKey_VerifyCtx(mldsaKey,
                    sig, (word32)sigLen, NULL, 0,
                    tbs, (word32)tbsLen, &verified));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if ((ret == WOLFCOSE_SUCCESS) && (verified != 1)) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
        }
    }
    else
#endif
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        /* No action required */
    }

    (void)wolfCose_ForceZero(hashBuf, sizeof(hashBuf));
    return ret;
}
#endif /* WOLFCOSE_COUNTERSIGN_VERIFY */

static int wolfCose_RangesOverlap(const uint8_t* a, size_t aLen,
                                  const uint8_t* b, size_t bLen)
{
    int overlaps = 0;

    if ((aLen != 0u) && (bLen != 0u)) {
        size_t i;

        for (i = 0u; (i < aLen) && (overlaps == 0); i++) {
            if (&a[i] == b) {
                overlaps = 1;
            }
        }
        for (i = 0u; (i < bLen) && (overlaps == 0); i++) {
            if (&b[i] == a) {
                overlaps = 1;
            }
        }
    }
    return overlaps;
}

#if defined(WOLFCOSE_COUNTERSIGN_SIGN)
/* Every check and size that attaching depends on follows from the expected
 * signature length alone, so this runs before any signer: a request that would
 * fail here must not consume one-time-state (HSS/LMS or delegated) key material. */
static int wolfCose_PlanAttachCounter(const WOLFCOSE_COUNTER_TARGET* target,
    const uint8_t* in, size_t inSz, size_t protectedLen, size_t kidLen,
    size_t sigLen, uint8_t abbreviated, size_t outSz,
    WOLFCOSE_COUNTER_ATTACH_PLAN* plan)
{
    int ret = WOLFCOSE_SUCCESS;
    size_t oldMapHeadLen;

    (void)XMEMSET(plan, 0, sizeof(*plan));
    oldMapHeadLen = target->mapContentStart - target->mapStart;
    plan->newMapCount = target->mapCount;
    plan->finalLen = inSz;

    /* Verification prefers the V2 label when both versions are present, so
     * attaching beside a legacy (RFC 8152) countersignature would make that
     * signature unreachable; refuse rather than silently hide it. */
    if (abbreviated != 0u) {
        if ((target->hasAbbreviated != 0u) ||
            (target->hasLegacyAbbreviated != 0u)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
        else {
            ret = wolfCose_CborStringSize(sigLen, &plan->counterLen);
        }
    }
    else {
        if (target->hasLegacyFull != 0u) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
        else {
            ret = wolfCose_FullCounterSize(protectedLen, kidLen, sigLen,
                                            &plan->counterLen);
        }
        if ((ret == WOLFCOSE_SUCCESS) && (target->hasFull != 0u)) {
            plan->oldValueLen = target->fullValueEnd - target->fullValueStart;
            ret = wolfCose_CounterListInfo(
                &in[target->fullValueStart], plan->oldValueLen,
                &plan->listInfo);
            if (ret == WOLFCOSE_SUCCESS) {
                plan->replacesValue = 1u;
                if (plan->listInfo.isList != 0u) {
                    size_t contentLen =
                        plan->oldValueLen - plan->listInfo.contentOffset;

                    if (plan->listInfo.count >=
                        (size_t)WOLFCOSE_MAX_MAP_ITEMS) {
                        ret = WOLFCOSE_E_COSE_BAD_HDR;
                    }
                    else {
                        plan->newValueLen = wolfCose_CborHeadSize(
                            (uint64_t)(plan->listInfo.count + 1u));
                        ret = wolfCose_SizeAdd(&plan->newValueLen,
                                               contentLen);
                    }
                }
                else {
                    plan->newValueLen = wolfCose_CborHeadSize(2u);
                    ret = wolfCose_SizeAdd(&plan->newValueLen,
                                           plan->oldValueLen);
                }
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wolfCose_SizeAdd(&plan->newValueLen,
                                           plan->counterLen);
                }
            }
        }
    }

    if ((ret == WOLFCOSE_SUCCESS) && (plan->replacesValue == 0u)) {
        if (target->mapCount >= (size_t)WOLFCOSE_MAX_MAP_ITEMS) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
        else {
            plan->newMapCount++;
            plan->delta = 1u;
            ret = wolfCose_SizeAdd(&plan->delta, plan->counterLen);
        }
    }
    else if (ret == WOLFCOSE_SUCCESS) {
        plan->delta = plan->newValueLen - plan->oldValueLen;
    }
    else {
        /* No action required */
    }

    plan->newMapHeadLen = wolfCose_CborHeadSize((uint64_t)plan->newMapCount);
    if ((ret == WOLFCOSE_SUCCESS) && (plan->replacesValue == 0u)) {
        ret = wolfCose_SizeAdd(&plan->delta,
                               plan->newMapHeadLen - oldMapHeadLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_SizeAdd(&plan->finalLen, plan->delta);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (plan->finalLen > outSz)) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }
    return ret;
}

static int wolfCose_AttachCounter(const WOLFCOSE_COUNTER_TARGET* target,
    const WOLFCOSE_COUNTER_ATTACH_PLAN* plan,
    const uint8_t* in, size_t inSz,
    const uint8_t* protectedData, size_t protectedLen,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* sig, size_t sigLen, uint8_t abbreviated,
    uint8_t* out, size_t* outLen)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_CBOR_CTX ctx;
    size_t suffixLen = inSz - target->mapEnd;

    if (out != in) {
        (void)XMEMMOVE(out, in, inSz);
    }
    (void)XMEMMOVE(&out[target->mapEnd + plan->delta],
                   &out[target->mapEnd], suffixLen);

    if (plan->replacesValue != 0u) {
        size_t afterValueLen = target->mapEnd - target->fullValueEnd;
        size_t newValueEnd = target->fullValueStart + plan->newValueLen;
        size_t headLen;

        (void)XMEMMOVE(&out[newValueEnd], &out[target->fullValueEnd],
                       afterValueLen);
        if (plan->listInfo.isList != 0u) {
            size_t contentLen =
                plan->oldValueLen - plan->listInfo.contentOffset;
            headLen = wolfCose_CborHeadSize(
                (uint64_t)(plan->listInfo.count + 1u));
            (void)XMEMMOVE(&out[target->fullValueStart + headLen],
                &out[target->fullValueStart + plan->listInfo.contentOffset],
                contentLen);
            ret = wc_CBOR_EncoderInit(&ctx,
                &out[target->fullValueStart], plan->newValueLen);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeArrayStart(&ctx,
                                                plan->listInfo.count + 1u);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ctx.idx = headLen + contentLen;
            }
        }
        else {
            headLen = wolfCose_CborHeadSize(2u);
            (void)XMEMMOVE(&out[target->fullValueStart + headLen],
                           &out[target->fullValueStart], plan->oldValueLen);
            ret = wc_CBOR_EncoderInit(&ctx,
                &out[target->fullValueStart], plan->newValueLen);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeArrayStart(&ctx, 2u);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ctx.idx = headLen + plan->oldValueLen;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_EncodeFullCounter(&ctx, protectedData,
                protectedLen, kid, kidLen, sig, sigLen);
        }
        if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != plan->newValueLen)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }
    else {
        size_t contentLen = target->mapEnd - target->mapContentStart;
        size_t newContentStart = target->mapStart + plan->newMapHeadLen;
        size_t appendOffset = newContentStart + contentLen;
        int64_t label;

        if (abbreviated != 0u) {
            label = WOLFCOSE_HDR_COUNTERSIGNATURE0_V2;
        }
        else {
            label = WOLFCOSE_HDR_COUNTERSIGNATURE_V2;
        }

        (void)XMEMMOVE(&out[newContentStart],
                       &out[target->mapContentStart], contentLen);
        ret = wc_CBOR_EncoderInit(&ctx, &out[target->mapStart],
                                   plan->finalLen - target->mapStart);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeMapStart(&ctx, plan->newMapCount);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ctx.idx = appendOffset - target->mapStart;
            ret = wc_CBOR_EncodeInt(&ctx, label);
        }
        if ((ret == WOLFCOSE_SUCCESS) && (abbreviated != 0u)) {
            ret = wc_CBOR_EncodeBstr(&ctx, sig, sigLen);
        }
        else if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_EncodeFullCounter(&ctx, protectedData,
                protectedLen, kid, kidLen, sig, sigLen);
        }
        else {
            /* No action required */
        }
        if ((ret == WOLFCOSE_SUCCESS) &&
            (ctx.idx != ((target->mapEnd + plan->delta) - target->mapStart))) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }

    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = plan->finalLen;
    }
    return ret;
}

static int wolfCose_AddCounterCommon(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* kid, size_t kidLen, uint8_t abbreviated,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen, WC_RNG* rng)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_COUNTER_TARGET target;
    uint8_t protectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t protectedLen = 0u;
    size_t sigLen = 0u;
    size_t actualSigLen = 0u;
    size_t tbsLen = 0u;
    uint8_t* sig;
    int scratchAliases = 0;
    int lensOk = 1;
    WOLFCOSE_COUNTER_ATTACH_PLAN plan;

    if ((key == NULL) || (in == NULL) || (scratch == NULL) ||
        (out == NULL) || (outLen == NULL) ||
        ((kid == NULL) && (kidLen != 0u)) ||
        ((kid != NULL) && (kidLen == 0u)) ||
        ((detachedPayload == NULL) && (detachedLen != 0u)) ||
        ((extAad == NULL) && (extAadLen != 0u))) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        *outLen = 0u;
    }
    /* Countersignatures have no HSS/LMS one-time-state path; refuse the
     * algorithm before any signer, delegated or local, can be reached. */
    if ((ret == WOLFCOSE_SUCCESS) && (alg == WOLFCOSE_ALG_HSS_LMS)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
#ifdef WOLFCOSE_CHECK_WORD32_LEN
    /* Refuse lengths wolfCrypt cannot take before any per-byte overlap walk
     * or scratch zeroing could be driven by them. */
    if ((wolfCose_LenFitsWord32(inSz) == 0) ||
        (wolfCose_LenFitsWord32(detachedLen) == 0) ||
        (wolfCose_LenFitsWord32(extAadLen) == 0) ||
        (wolfCose_LenFitsWord32(scratchSz) == 0) ||
        (wolfCose_LenFitsWord32(outSz) == 0)) {
        lensOk = 0;
        if (ret == WOLFCOSE_SUCCESS) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
    }
#endif
    if ((lensOk != 0) && (scratch != NULL) &&
        (((in != NULL) &&
          (wolfCose_RangesOverlap(scratch, scratchSz, in, inSz) != 0)) ||
         ((out != NULL) &&
          (wolfCose_RangesOverlap(scratch, scratchSz, out, outSz) != 0)) ||
         ((kid != NULL) &&
          (wolfCose_RangesOverlap(scratch, scratchSz, kid, kidLen) != 0)) ||
         ((detachedPayload != NULL) &&
          (wolfCose_RangesOverlap(scratch, scratchSz,
                                  detachedPayload, detachedLen) != 0)) ||
         ((extAad != NULL) &&
          (wolfCose_RangesOverlap(scratch, scratchSz,
                                  extAad, extAadLen) != 0)))) {
        scratchAliases = 1;
    }
    if ((ret == WOLFCOSE_SUCCESS) && (scratchAliases != 0)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    if ((ret == WOLFCOSE_SUCCESS) && (out != in) &&
        (wolfCose_RangesOverlap(in, inSz, out, outSz) != 0)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    /* kid is read while the countersignature is encoded into out; an in-place
     * attach rewrites out first, so a kid aliasing it would read stale bytes. */
    if ((ret == WOLFCOSE_SUCCESS) && (kid != NULL) &&
        (wolfCose_RangesOverlap(kid, kidLen, out, outSz) != 0)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_ParseCounterTarget(in, inSz, detachedPayload,
                                           detachedLen, &target);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_SignSigLen(key, alg, &sigLen);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (sigLen > scratchSz)) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }
    if ((ret == WOLFCOSE_SUCCESS) && (abbreviated == 0u)) {
        ret = wolfCose_EncodeProtectedHdr(alg, protectedBuf,
            sizeof(protectedBuf), &protectedLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildCounterStructure(&target,
            (abbreviated != 0u) ? NULL : protectedBuf, protectedLen,
            extAad, extAadLen, abbreviated,
            0u, scratch, scratchSz - sigLen, &tbsLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_PlanAttachCounter(&target, in, inSz, protectedLen,
            kidLen, sigLen, abbreviated, outSz, &plan);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        sig = &scratch[tbsLen];
        ret = wolfCose_CounterSignTbs(key, alg, scratch, tbsLen,
            sig, sigLen, &actualSigLen, rng);
    }
    else {
        sig = NULL;
    }
    if ((ret == WOLFCOSE_SUCCESS) && (actualSigLen != sigLen)) {
        ret = WOLFCOSE_E_CRYPTO;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_AttachCounter(&target, &plan, in, inSz,
            protectedBuf, protectedLen, kid, kidLen, sig, sigLen,
            abbreviated, out, outLen);
    }

    (void)wolfCose_ForceZero(protectedBuf, sizeof(protectedBuf));
    if ((scratch != NULL) && (scratchAliases == 0) && (lensOk != 0)) {
        (void)wolfCose_ForceZero(scratch, scratchSz);
    }
    if ((ret != WOLFCOSE_SUCCESS) && (outLen != NULL)) {
        *outLen = 0u;
    }
    return ret;
}

int wc_Cose_AddCounterSignature(
    const WOLFCOSE_COUNTERSIGNATURE* counterSigner,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen, WC_RNG* rng)
{
    int ret;

    if (outLen != NULL) {
        *outLen = 0u;
    }
    if (counterSigner == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        WOLFCOSE_KEY* key = counterSigner->key;

        ret = wolfCose_AddCounterCommon(key,
            counterSigner->algId, counterSigner->kid,
            counterSigner->kidLen, 0u, in, inSz,
            detachedPayload, detachedLen, extAad, extAadLen,
            scratch, scratchSz, out, outSz, outLen, rng);
    }
    return ret;
}

int wc_Cose_AddCounterSignature0(
    const WOLFCOSE_COUNTERSIGNATURE0* counterSigner,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen, WC_RNG* rng)
{
    int ret;

    if (outLen != NULL) {
        *outLen = 0u;
    }
    if (counterSigner == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        WOLFCOSE_KEY* key = counterSigner->key;

        ret = wolfCose_AddCounterCommon(key,
            counterSigner->algId, NULL, 0u, 1u, in, inSz,
            detachedPayload, detachedLen, extAad, extAadLen,
            scratch, scratchSz, out, outSz, outLen, rng);
    }
    return ret;
}
#endif /* WOLFCOSE_COUNTERSIGN_SIGN */

#if defined(WOLFCOSE_COUNTERSIGN_VERIFY)
static int wolfCose_DecodeFullCounter(const uint8_t* in, size_t inSz,
    WOLFCOSE_HDR* hdr, const uint8_t** protectedData,
    size_t* protectedLen, const uint8_t** sig, size_t* sigLen,
    int* algProtected)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    WOLFCOSE_HDR_STATE hdrState;
    size_t count = 0u;

    (void)XMEMSET(hdr, 0, sizeof(*hdr));
    ret = wc_CBOR_DecoderInit(&ctx, in, inSz);
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &count);
        if ((ret == WOLFCOSE_SUCCESS) && (count != 3u)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, protectedData, protectedLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeProtectedHdr(*protectedData, *protectedLen,
                                          hdr, &hdrState);
        if (ret == WOLFCOSE_SUCCESS) {
            *algProtected = wolfCose_HdrStateContains(&hdrState,
                                                       WOLFCOSE_HDR_ALG);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr, &hdrState);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, sig, sigLen);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != ctx.bufSz)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    return ret;
}

int wc_Cose_VerifyCounterSignature(const WOLFCOSE_KEY* key,
    size_t counterIndex, const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz, WOLFCOSE_HDR* counterHdr)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_COUNTER_TARGET target;
    const uint8_t* selected = NULL;
    const uint8_t* protectedData = NULL;
    const uint8_t* sig = NULL;
    size_t selectedLen = 0u;
    size_t protectedLen = 0u;
    size_t sigLen = 0u;
    size_t tbsLen = 0u;
    int algProtected = 0;
    uint8_t legacy = 0u;
    int scratchAliases = 0;
    int lensOk = 1;

#ifdef WOLFCOSE_CHECK_WORD32_LEN
    /* Refuse lengths wolfCrypt cannot take before any per-byte overlap walk
     * or scratch zeroing could be driven by them. */
    if ((wolfCose_LenFitsWord32(inSz) == 0) ||
        (wolfCose_LenFitsWord32(detachedLen) == 0) ||
        (wolfCose_LenFitsWord32(extAadLen) == 0) ||
        (wolfCose_LenFitsWord32(scratchSz) == 0)) {
        lensOk = 0;
    }
#endif
    if ((lensOk != 0) && (scratch != NULL) &&
        (((in != NULL) &&
          (wolfCose_RangesOverlap(scratch, scratchSz, in, inSz) != 0)) ||
         ((detachedPayload != NULL) &&
          (wolfCose_RangesOverlap(scratch, scratchSz,
                                  detachedPayload, detachedLen) != 0)) ||
         ((extAad != NULL) &&
          (wolfCose_RangesOverlap(scratch, scratchSz,
                                  extAad, extAadLen) != 0)) ||
         ((counterHdr != NULL) &&
          (wolfCose_RangesOverlap(scratch, scratchSz,
              (const uint8_t*)counterHdr,
              sizeof(*counterHdr)) != 0)))) {
        scratchAliases = 1;
    }
    if ((key == NULL) || (in == NULL) || (scratch == NULL) ||
        (counterHdr == NULL) ||
        ((detachedPayload == NULL) && (detachedLen != 0u)) ||
        ((extAad == NULL) && (extAadLen != 0u)) ||
        (scratchAliases != 0) || (lensOk == 0)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_ParseCounterTarget(in, inSz, detachedPayload,
                                           detachedLen, &target);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (target.hasFull == 0u) &&
        (target.hasLegacyFull == 0u)) {
        ret = WOLFCOSE_E_COSE_BAD_HDR;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        size_t valueStart = target.fullValueStart;
        size_t valueEnd = target.fullValueEnd;

        if (target.hasFull == 0u) {
            legacy = 1u;
            valueStart = target.legacyFullValueStart;
            valueEnd = target.legacyFullValueEnd;
        }
        ret = wolfCose_SelectFullCounter(&in[valueStart],
            valueEnd - valueStart, counterIndex, &selected, &selectedLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeFullCounter(selected, selectedLen,
            counterHdr, &protectedData, &protectedLen,
            &sig, &sigLen, &algProtected);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (algProtected == 0) &&
        ((key->alg == WOLFCOSE_ALG_UNSET) ||
         (key->alg != counterHdr->alg))) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildCounterStructure(&target, protectedData,
            protectedLen, extAad, extAadLen, 0u,
            legacy, scratch, scratchSz, &tbsLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CounterVerifyTbs(key, counterHdr->alg,
            scratch, tbsLen, sig, sigLen, scratch, scratchSz);
    }

    wolfCose_HdrClearOnFail(ret, counterHdr);
    if ((scratch != NULL) && (scratchAliases == 0) && (lensOk != 0)) {
        (void)wolfCose_ForceZero(scratch, scratchSz);
    }
    return ret;
}

int wc_Cose_VerifyCounterSignature0(
    const WOLFCOSE_COUNTERSIGNATURE0* counterSigner,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_COUNTER_TARGET target;
    WOLFCOSE_CBOR_CTX ctx;
    const uint8_t* sig = NULL;
    size_t sigLen = 0u;
    size_t tbsLen = 0u;
    uint8_t legacy = 0u;
    int scratchAliases = 0;
    int lensOk = 1;

#ifdef WOLFCOSE_CHECK_WORD32_LEN
    /* Refuse lengths wolfCrypt cannot take before any per-byte overlap walk
     * or scratch zeroing could be driven by them. */
    if ((wolfCose_LenFitsWord32(inSz) == 0) ||
        (wolfCose_LenFitsWord32(detachedLen) == 0) ||
        (wolfCose_LenFitsWord32(extAadLen) == 0) ||
        (wolfCose_LenFitsWord32(scratchSz) == 0)) {
        lensOk = 0;
    }
#endif
    if ((lensOk != 0) && (scratch != NULL) &&
        (((in != NULL) &&
          (wolfCose_RangesOverlap(scratch, scratchSz, in, inSz) != 0)) ||
         ((detachedPayload != NULL) &&
          (wolfCose_RangesOverlap(scratch, scratchSz,
                                  detachedPayload, detachedLen) != 0)) ||
         ((extAad != NULL) &&
          (wolfCose_RangesOverlap(scratch, scratchSz,
                                  extAad, extAadLen) != 0)))) {
        scratchAliases = 1;
    }
    if ((counterSigner == NULL) || (counterSigner->key == NULL) ||
        (in == NULL) || (scratch == NULL) ||
        ((detachedPayload == NULL) && (detachedLen != 0u)) ||
        ((extAad == NULL) && (extAadLen != 0u)) ||
        (scratchAliases != 0) || (lensOk == 0)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_ParseCounterTarget(in, inSz, detachedPayload,
                                           detachedLen, &target);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (target.hasAbbreviated == 0u) &&
        (target.hasLegacyAbbreviated == 0u)) {
        ret = WOLFCOSE_E_COSE_BAD_HDR;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        size_t valueStart = target.abbreviatedValueStart;
        size_t valueEnd = target.abbreviatedValueEnd;

        if (target.hasAbbreviated == 0u) {
            legacy = 1u;
            valueStart = target.legacyAbbreviatedValueStart;
            valueEnd = target.legacyAbbreviatedValueEnd;
        }
        ret = wc_CBOR_DecoderInit(&ctx,
            &in[valueStart], valueEnd - valueStart);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &sig, &sigLen);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != ctx.bufSz)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildCounterStructure(&target, NULL, 0u,
            extAad, extAadLen, 1u, legacy,
            scratch, scratchSz, &tbsLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CounterVerifyTbs(counterSigner->key,
            counterSigner->algId, scratch, tbsLen,
            sig, sigLen, scratch, scratchSz);
    }

    if ((scratch != NULL) && (scratchAliases == 0) && (lensOk != 0)) {
        (void)wolfCose_ForceZero(scratch, scratchSz);
    }
    return ret;
}
#endif /* WOLFCOSE_COUNTERSIGN_VERIFY */

#endif /* WOLFCOSE_COUNTERSIGN */
