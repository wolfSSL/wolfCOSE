/* wolfcose_hdr.c
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
 * Protected/unprotected COSE header encode and decode. RFC 9052 Section 3.
 * All crypto via wolfCrypt wc_* APIs. Zero allocation.
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


/* ----- Internal: Protected/Unprotected header encode/decode ----- */

#if defined(WOLFCOSE_CBOR_DECODE)
/* COSE algorithm, key type, and curve identifiers are stored in int32_t
 * fields. Reject decoded CBOR integers that do not fit before narrowing so a
 * non-representable value cannot alias a valid identifier. */
int wolfCose_InInt32Range(int64_t val)
{
    return ((val >= INT32_MIN) && (val <= INT32_MAX)) ? 1 : 0;
}

/* Map a COSE header/key label to a fast-path tracking bit. Labels outside
 * the small known range fall back to the slower extra-label array. */
static uint32_t wolfCose_LabelBit(int64_t label)
{
    uint32_t bit = 0u;
    uint32_t shift;

    if ((label >= 1) && (label <= 16)) {
        shift = (uint32_t)label;
        bit = ((uint32_t)1u) << (shift - 1u);
    }
    else if ((label <= -1) && (label >= -16)) {
        int64_t magnitude = -label;

        shift = (uint32_t)magnitude;
        bit = ((uint32_t)1u) << (shift + 15u);
    }
    else {
        /* No tracked bit. */
    }
    return bit;
}

void wolfCose_HdrStateInit(WOLFCOSE_HDR_STATE* state)
{
    if (state != NULL) {
        state->labelBits = 0u;
        state->extraIntegerCount = 0u;
#if defined(WOLFCOSE_COSE_TEXT_LABELS)
        state->extraTextCount = 0u;
#endif
    }
}

int wolfCose_HdrStateContains(const WOLFCOSE_HDR_STATE* state,
    int64_t label)
{
    int found = 0;

    if (state != NULL) {
        uint32_t bit = wolfCose_LabelBit(label);

        if ((bit != 0u) && ((state->labelBits & bit) != 0u)) {
            found = 1;
        }
        else {
            size_t i;
            for (i = 0u; i < state->extraIntegerCount; i++) {
                if (state->extraIntegerLabels[i] == label) {
                    found = 1;
                    break;
                }
            }
        }
    }

    return found;
}

static int wolfCose_HdrStateAdd(WOLFCOSE_HDR_STATE* state, int64_t label)
{
    int ret = WOLFCOSE_SUCCESS;

    if (state == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        uint32_t bit = wolfCose_LabelBit(label);

        if (bit != 0u) {
            state->labelBits |= bit;
        }
        else if (state->extraIntegerCount >=
                 (size_t)WOLFCOSE_MAX_HEADER_LABELS) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
        else {
            state->extraIntegerLabels[state->extraIntegerCount] = label;
            state->extraIntegerCount++;
        }
    }

    return ret;
}

int wolfCose_HdrStateCheckAndAdd(WOLFCOSE_HDR_STATE* state,
    int64_t label)
{
    int ret = WOLFCOSE_SUCCESS;

    if (wolfCose_HdrStateContains(state, label) != 0) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    else {
        ret = wolfCose_HdrStateAdd(state, label);
    }

    return ret;
}

#if defined(WOLFCOSE_COSE_TEXT_LABELS)
static int wolfCose_TextLabelEquals(const uint8_t* encoded,
    const WOLFCOSE_CBOR_LABEL* label)
{
    uint8_t ai;
    uint64_t textLen = 0u;
    size_t headLen = 0u;
    size_t i;
    int equal = 0;
    int valid = 1;

    ai = (uint8_t)(encoded[0] & 0x1Fu);
    if (ai < 24u) {
        textLen = ai;
        headLen = 1u;
    }
    else if (ai <= 27u) {
        /* additional-info 24/25/26/27 carry 1/2/4/8 big-endian length bytes;
         * the stored head already passed shortest-form decoding. */
        if (ai == 24u) {
            headLen = 2u;
        }
        else if (ai == 25u) {
            headLen = 3u;
        }
        else if (ai == 26u) {
            headLen = 5u;
        }
        else {
            headLen = 9u;
        }
        textLen = 0u;
        for (i = 1u; i < headLen; i++) {
            textLen <<= 8u;
            textLen |= (uint64_t)encoded[i];
        }
    }
    else {
        /* additional-info above 27 has no representable text length. */
        valid = 0;
    }

    if ((valid != 0) && (textLen > (uint64_t)(SIZE_MAX - headLen))) {
        valid = 0;
    }

    /* The core library takes no variable-time compares even on public map
     * labels (.github/semgrep-rules.yml); wc_CBOR_LabelIsText scans the whole
     * label. */
    if ((valid != 0) && (textLen == (uint64_t)label->textLen) &&
        (wc_CBOR_LabelIsText(label, &encoded[headLen],
                             label->textLen) != 0)) {
        equal = 1;
    }

    return equal;
}
#endif

int wolfCose_HdrStateContainsLabel(const WOLFCOSE_HDR_STATE* state,
    const WOLFCOSE_CBOR_LABEL* label)
{
    int found = 0;

    if ((state != NULL) && (label != NULL)) {
        if (label->isText == 0u) {
            found = wolfCose_HdrStateContains(state, label->val);
        }
        else {
#if defined(WOLFCOSE_COSE_TEXT_LABELS)
            size_t i;

            for (i = 0u; i < state->extraTextCount; i++) {
                if (wolfCose_TextLabelEquals(
                        state->extraTextLabels[i], label) != 0) {
                    found = 1;
                    break;
                }
            }
#endif
        }
    }

    return found;
}

int wolfCose_HdrStateAddLabel(WOLFCOSE_HDR_STATE* state,
    const WOLFCOSE_CBOR_LABEL* label, const uint8_t* encodedLabel)
{
    int ret = WOLFCOSE_SUCCESS;

    if ((state == NULL) || (label == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (label->isText == 0u) {
        ret = wolfCose_HdrStateAdd(state, label->val);
    }
#if defined(WOLFCOSE_COSE_TEXT_LABELS)
    else if (encodedLabel == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (state->extraTextCount >=
             (size_t)WOLFCOSE_MAX_HEADER_LABELS) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    else {
        state->extraTextLabels[state->extraTextCount] = encodedLabel;
        state->extraTextCount++;
    }
#else
    else {
        (void)encodedLabel;
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
#endif

    return ret;
}

static int wolfCose_HdrStateCheckAndAddLabel(WOLFCOSE_HDR_STATE* state,
    const WOLFCOSE_CBOR_LABEL* label, const uint8_t* encodedLabel)
{
    int ret = WOLFCOSE_SUCCESS;

    if ((label != NULL) && (label->isText == 0u)) {
        ret = wolfCose_HdrStateCheckAndAdd(state, label->val);
    }
    else if (wolfCose_HdrStateContainsLabel(state, label) != 0) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    else {
        ret = wolfCose_HdrStateAddLabel(state, label, encodedLabel);
    }

    return ret;
}

/* COSE_Key maps use integer labels. Header maps use the label-aware helpers
 * above because RFC 9052 permits both integer and text-string labels. */
#if defined(WOLFCOSE_KEY_DECODE) || defined(WOLFCOSE_ECDH_ES_DIRECT)
int wolfCose_SkipIfTstrLabel(const WOLFCOSE_CBOR_CTX* ctx, int* skipped)
{
    int ret;

    *skipped = 0;
    if (ctx->idx >= ctx->bufSz) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    else if (wc_CBOR_PeekType(ctx) == WOLFCOSE_CBOR_TSTR) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    else {
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif

#endif /* WOLFCOSE_CBOR_DECODE */

#if defined(WOLFCOSE_CBOR_ENCODE)
int wolfCose_EncodeProtectedHdr(int32_t alg, uint8_t* buf, size_t bufSz,
                                 size_t* outLen)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;

    if ((buf == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ctx.buf = buf;
        ctx.bufSz = bufSz;
        ctx.idx = 0;

        /* Encode map with 1 entry: {1: alg} */
        ret = wc_CBOR_EncodeMapStart(&ctx, 1);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)WOLFCOSE_HDR_ALG);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeInt(&ctx, (int64_t)alg);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            *outLen = ctx.idx;
        }
    }
    return ret;
}
#endif /* WOLFCOSE_CBOR_ENCODE */

#if defined(WOLFCOSE_CBOR_DECODE)
int wolfCose_DecodeProtectedHdr_ex(const uint8_t* data, size_t dataLen,
                                    WOLFCOSE_HDR* hdr,
                                    WOLFCOSE_HDR_STATE* hdrState,
                                    uint32_t decodeFlags)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    size_t mapCount = 0;
    size_t i;
    WOLFCOSE_CBOR_LABEL label;
    int64_t intVal;
    uint64_t contentTypeVal;
    uint32_t critLabels = 0u;

    if ((hdr == NULL) || (hdrState == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (WOLFCOSE_COSE_DECODE_FLAGS_VALID(decodeFlags) == 0) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((data == NULL) && (dataLen != 0u)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (dataLen == 0u) {
        /* Empty protected header is valid */
        wolfCose_HdrStateInit(hdrState);
        ret = WOLFCOSE_SUCCESS;
    }
    else {
        uint8_t contentTypeUnderstood = 0u;

        wolfCose_HdrStateInit(hdrState);
        ret = wc_CBOR_DecoderInit(&ctx, data, dataLen);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_CBOR_DecodeMapStart_ex(&ctx, &mapCount,
                decodeFlags);
        }

        if ((ret == WOLFCOSE_SUCCESS) && (mapCount > (size_t)WOLFCOSE_MAX_MAP_ITEMS)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
            mapCount = 0; /* Coverity: clear tainted loop bound */
        }

        for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < mapCount); i++) {
            const uint8_t* encodedLabel = NULL;

            if ((ctx.cbuf != NULL) && (ctx.idx < ctx.bufSz)) {
                encodedLabel = &ctx.cbuf[ctx.idx];
            }
            ret = wolfCose_CBOR_DecodeLabel_ex(&ctx, &label, decodeFlags);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_HdrStateCheckAndAddLabel(hdrState, &label,
                    encodedLabel);
            }

            if ((ret == WOLFCOSE_SUCCESS) &&
                (wc_CBOR_LabelIsInt(&label, WOLFCOSE_HDR_ALG) != 0)) {
                if ((ctx.idx < ctx.bufSz) &&
                    (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TSTR)) {
                    ret = wolfCose_CBOR_Skip_ex(&ctx, decodeFlags);
                }
                else {
                    ret = wolfCose_CBOR_DecodeInt_ex(&ctx, &intVal,
                        decodeFlags);
                    if ((ret == WOLFCOSE_SUCCESS) &&
                        (wolfCose_InInt32Range(intVal) == 0)) {
                        ret = WOLFCOSE_E_COSE_BAD_ALG;
                    }
                    if (ret == WOLFCOSE_SUCCESS) {
                        hdr->alg = (int32_t)intVal;
                    }
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (wc_CBOR_LabelIsInt(&label,
                         WOLFCOSE_HDR_CRIT) != 0)) {
                size_t critCount = 0;
                size_t k;
                int64_t critLabel;

                ret = wolfCose_CBOR_DecodeArrayStart_ex(&ctx, &critCount,
                    decodeFlags);
                if ((ret == WOLFCOSE_SUCCESS) &&
                    ((critCount == 0u) ||
                     (critCount > (size_t)WOLFCOSE_MAX_MAP_ITEMS))) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
                for (k = 0; (ret == WOLFCOSE_SUCCESS) && (k < critCount); k++) {
                    if ((ctx.idx >= ctx.bufSz) ||
                        (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TSTR)) {
                        ret = WOLFCOSE_E_COSE_BAD_HDR;
                    }
                    else {
                        ret = wolfCose_CBOR_DecodeInt_ex(&ctx, &critLabel,
                            decodeFlags);
                    }
                    if (ret == WOLFCOSE_SUCCESS) {
                        /* crit labels limited to ones wolfCOSE processes. */
                        if ((critLabel < 1) || (critLabel > 6)) {
                            ret = WOLFCOSE_E_COSE_BAD_HDR;
                        }
                        else {
                            uint32_t critBit = wolfCose_LabelBit(critLabel);
                            if (critBit == 0u) {
                                ret = WOLFCOSE_E_COSE_BAD_HDR;
                            }
                            else {
                                critLabels |= critBit;
                            }
                        }
                    }
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (wc_CBOR_LabelIsInt(&label,
                         WOLFCOSE_HDR_CONTENT_TYPE) != 0)) {
                if ((ctx.idx < ctx.bufSz) &&
                    (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TSTR)) {
                    ret = wolfCose_CBOR_Skip_ex(&ctx, decodeFlags);
                }
                else {
                    ret = wolfCose_CBOR_DecodeUint_ex(&ctx, &contentTypeVal,
                        decodeFlags);
                    if ((ret == WOLFCOSE_SUCCESS) &&
                        (contentTypeVal > (uint64_t)INT32_MAX)) {
                        ret = WOLFCOSE_E_COSE_BAD_HDR;
                    }
                    if (ret == WOLFCOSE_SUCCESS) {
                        hdr->contentType = (int32_t)contentTypeVal;
                        contentTypeUnderstood = 1u;
                    }
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (wc_CBOR_LabelIsInt(&label, WOLFCOSE_HDR_KID) != 0)) {
                /* RFC 9052 Section 3.1: kid may appear in the protected
                 * bucket; populate it the same way the unprotected decoder
                 * does instead of skipping it as unknown. */
                const uint8_t* kidData;
                size_t kidBstrLen;
                ret = wolfCose_CBOR_DecodeBstr_ex(&ctx, &kidData, &kidBstrLen,
                    decodeFlags);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->kid = kidData;
                    hdr->kidLen = kidBstrLen;
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (wc_CBOR_LabelIsInt(&label, WOLFCOSE_HDR_IV) != 0)) {
                const uint8_t* ivData;
                size_t ivBstrLen;
                ret = wolfCose_CBOR_DecodeBstr_ex(&ctx, &ivData, &ivBstrLen,
                    decodeFlags);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->iv = ivData;
                    hdr->ivLen = ivBstrLen;
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (wc_CBOR_LabelIsInt(&label,
                         WOLFCOSE_HDR_PARTIAL_IV) != 0)) {
                const uint8_t* pivData;
                size_t pivBstrLen;
                ret = wolfCose_CBOR_DecodeBstr_ex(&ctx, &pivData, &pivBstrLen,
                    decodeFlags);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->partialIv = pivData;
                    hdr->partialIvLen = pivBstrLen;
                }
            }
#if defined(WOLFCOSE_EAT_PSA_VERIFY)
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (wc_CBOR_LabelIsInt(&label, WOLFCOSE_HDR_X5CHAIN) != 0)) {
                hdr->flags |= WOLFCOSE_HDR_FLAG_X5CHAIN;
                ret = wolfCose_CBOR_Skip_ex(&ctx, decodeFlags);
            }
#endif
            else {
                if (ret == WOLFCOSE_SUCCESS) {
                    /* Skip unknown header */
                    ret = wolfCose_CBOR_Skip_ex(&ctx, decodeFlags);
                }
            }
        }

        /* Every label listed in crit must appear in the protected header. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((critLabels & ~hdrState->labelBits) != 0u)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((critLabels & wolfCose_LabelBit(WOLFCOSE_HDR_CONTENT_TYPE)) !=
             0u) && (contentTypeUnderstood == 0u)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }

        /* RFC 9338 Section 3 requires all countersignature parameters to be
         * carried in an unprotected header bucket. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((wolfCose_HdrStateContains(hdrState,
                WOLFCOSE_HDR_COUNTERSIGNATURE_V2) != 0) ||
             (wolfCose_HdrStateContains(hdrState,
                WOLFCOSE_HDR_COUNTERSIGNATURE0_V2) != 0) ||
             (wolfCose_HdrStateContains(hdrState,
                WOLFCOSE_HDR_COUNTERSIGNATURE_LEGACY) != 0) ||
             (wolfCose_HdrStateContains(hdrState,
                WOLFCOSE_HDR_COUNTERSIGNATURE0_LEGACY) != 0))) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }

        /* IV and Partial IV are mutually exclusive. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            (hdr->iv != NULL) && (hdr->partialIv != NULL)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }

        if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != ctx.bufSz)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }
    return ret;
}

int wolfCose_DecodeProtectedHdr(const uint8_t* data, size_t dataLen,
                                 WOLFCOSE_HDR* hdr,
                                 WOLFCOSE_HDR_STATE* hdrState)
{
    return wolfCose_DecodeProtectedHdr_ex(data, dataLen, hdr, hdrState, 0u);
}

/* Decode the unprotected header map. decodeFlags carries the RFC 9783 tolerant
 * path; under HPKE, hpkeHdr receives the ephemeral key when present. */
#if defined(WOLFCOSE_HAVE_HPKE_0)
static int wolfCose_DecodeUnprotectedHdrInternal(WOLFCOSE_CBOR_CTX* ctx,
    WOLFCOSE_HDR* hdr, WOLFCOSE_HDR_STATE* hdrState, uint32_t decodeFlags,
    WOLFCOSE_HPKE_HDR* hpkeHdr)
#else
static int wolfCose_DecodeUnprotectedHdrInternal(WOLFCOSE_CBOR_CTX* ctx,
    WOLFCOSE_HDR* hdr, WOLFCOSE_HDR_STATE* hdrState, uint32_t decodeFlags)
#endif
{
    int ret;
    size_t mapCount = 0;
    WOLFCOSE_CBOR_LABEL label;
    const uint8_t* bstrData;
    size_t bstrLen;

    if ((ctx == NULL) || (hdr == NULL) || (hdrState == NULL) ||
        (WOLFCOSE_COSE_DECODE_FLAGS_VALID(decodeFlags) == 0)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        size_t i;
        WOLFCOSE_HDR_STATE unprotState;

        wolfCose_HdrStateInit(&unprotState);
        ret = wolfCose_CBOR_DecodeMapStart_ex(ctx, &mapCount, decodeFlags);

        if ((ret == WOLFCOSE_SUCCESS) && (mapCount > (size_t)WOLFCOSE_MAX_MAP_ITEMS)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
            mapCount = 0; /* Coverity: clear tainted loop bound */
        }

        for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < mapCount); i++) {
            const uint8_t* encodedLabel = NULL;

            if ((ctx->cbuf != NULL) && (ctx->idx < ctx->bufSz)) {
                encodedLabel = &ctx->cbuf[ctx->idx];
            }
            ret = wolfCose_CBOR_DecodeLabel_ex(ctx, &label, decodeFlags);
            if (ret == WOLFCOSE_SUCCESS) {
                /* crit MUST live in the protected bucket. */
                if (wc_CBOR_LabelIsInt(&label, WOLFCOSE_HDR_CRIT) != 0) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
                else if ((wolfCose_HdrStateContainsLabel(&unprotState,
                                                          &label) != 0) ||
                         (wolfCose_HdrStateContainsLabel(hdrState,
                                                         &label) != 0)) {
                    ret = WOLFCOSE_E_CBOR_MALFORMED;
                }
                else {
                    ret = wolfCose_HdrStateAddLabel(&unprotState, &label,
                        encodedLabel);
                }
            }

            if ((ret == WOLFCOSE_SUCCESS) &&
                (wc_CBOR_LabelIsInt(&label, WOLFCOSE_HDR_KID) != 0)) {
                ret = wolfCose_CBOR_DecodeBstr_ex(ctx, &bstrData, &bstrLen,
                    decodeFlags);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->kid = bstrData;
                    hdr->kidLen = bstrLen;
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (wc_CBOR_LabelIsInt(&label, WOLFCOSE_HDR_IV) != 0)) {
                ret = wolfCose_CBOR_DecodeBstr_ex(ctx, &bstrData, &bstrLen,
                    decodeFlags);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->iv = bstrData;
                    hdr->ivLen = bstrLen;
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (wc_CBOR_LabelIsInt(&label,
                         WOLFCOSE_HDR_PARTIAL_IV) != 0)) {
                ret = wolfCose_CBOR_DecodeBstr_ex(ctx, &bstrData, &bstrLen,
                    decodeFlags);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->partialIv = bstrData;
                    hdr->partialIvLen = bstrLen;
                }
            }
#if defined(WOLFCOSE_HAVE_HPKE_0)
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (wc_CBOR_LabelIsInt(&label,
                         WOLFCOSE_HDR_HPKE_EK) != 0)) {
                if (hpkeHdr == NULL) {
                    ret = wc_CBOR_Skip(ctx);
                }
                else {
                    ret = wc_CBOR_DecodeBstr(ctx, &bstrData, &bstrLen);
                    if (ret == WOLFCOSE_SUCCESS) {
                        hpkeHdr->ek = bstrData;
                        hpkeHdr->ekLen = bstrLen;
                        hpkeHdr->hasEk = 1;
                    }
                }
            }
#endif
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (wc_CBOR_LabelIsInt(&label, WOLFCOSE_HDR_ALG) != 0)) {
                if ((ctx->idx < ctx->bufSz) &&
                    (wc_CBOR_PeekType(ctx) == WOLFCOSE_CBOR_TSTR)) {
                    ret = wolfCose_CBOR_Skip_ex(ctx, decodeFlags);
                }
                else {
                    int64_t algVal;
                    ret = wolfCose_CBOR_DecodeInt_ex(ctx, &algVal,
                        decodeFlags);
                    if ((ret == WOLFCOSE_SUCCESS) &&
                        (wolfCose_InInt32Range(algVal) == 0)) {
                        ret = WOLFCOSE_E_COSE_BAD_ALG;
                    }
                    if (ret == WOLFCOSE_SUCCESS) {
                        hdr->alg = (int32_t)algVal;
                    }
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (wc_CBOR_LabelIsInt(&label,
                         WOLFCOSE_HDR_CONTENT_TYPE) != 0)) {
                hdr->flags |= WOLFCOSE_HDR_FLAG_CONTENT_TYPE_UNPROTECTED;
                if ((ctx->idx < ctx->bufSz) &&
                    (wc_CBOR_PeekType(ctx) == WOLFCOSE_CBOR_TSTR)) {
                    ret = wolfCose_CBOR_Skip_ex(ctx, decodeFlags);
                }
                else {
                    uint64_t contentTypeVal;
                    ret = wolfCose_CBOR_DecodeUint_ex(ctx, &contentTypeVal,
                        decodeFlags);
                    if ((ret == WOLFCOSE_SUCCESS) &&
                        (contentTypeVal > (uint64_t)INT32_MAX)) {
                        ret = WOLFCOSE_E_COSE_BAD_HDR;
                    }
                    if (ret == WOLFCOSE_SUCCESS) {
                        hdr->contentType = (int32_t)contentTypeVal;
                    }
                }
            }
#if defined(WOLFCOSE_EAT_PSA_VERIFY)
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (wc_CBOR_LabelIsInt(&label, WOLFCOSE_HDR_X5CHAIN) != 0)) {
                hdr->flags |= WOLFCOSE_HDR_FLAG_X5CHAIN;
                ret = wolfCose_CBOR_Skip_ex(ctx, decodeFlags);
            }
#endif
            else {
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wolfCose_CBOR_Skip_ex(ctx, decodeFlags);
                }
            }
        }

        /* IV and Partial IV are mutually exclusive. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            (hdr->iv != NULL) && (hdr->partialIv != NULL)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }

        if (ret == WOLFCOSE_SUCCESS) {
            /* Cross-bucket checks above already consumed every unprotected
             * label. Only supported-label presence is needed by callers, so
             * do not retain unknown labels and double the state size. */
            hdrState->labelBits |= unprotState.labelBits;
        }
    }
    return ret;
}

int wolfCose_DecodeUnprotectedHdr_ex(WOLFCOSE_CBOR_CTX* ctx,
    WOLFCOSE_HDR* hdr, WOLFCOSE_HDR_STATE* hdrState, uint32_t decodeFlags)
{
#if defined(WOLFCOSE_HAVE_HPKE_0)
    return wolfCose_DecodeUnprotectedHdrInternal(ctx, hdr, hdrState,
                                                 decodeFlags, NULL);
#else
    return wolfCose_DecodeUnprotectedHdrInternal(ctx, hdr, hdrState,
                                                 decodeFlags);
#endif
}

#if defined(WOLFCOSE_HAVE_HPKE_0)
int wolfCose_DecodeUnprotectedHdrEx(WOLFCOSE_CBOR_CTX* ctx,
    WOLFCOSE_HDR* hdr, WOLFCOSE_HDR_STATE* hdrState,
    WOLFCOSE_HPKE_HDR* hpkeHdr)
{
    return wolfCose_DecodeUnprotectedHdrInternal(ctx, hdr, hdrState, 0u,
                                                 hpkeHdr);
}
#endif

int wolfCose_DecodeUnprotectedHdr(WOLFCOSE_CBOR_CTX* ctx, WOLFCOSE_HDR* hdr,
    WOLFCOSE_HDR_STATE* hdrState)
{
    return wolfCose_DecodeUnprotectedHdr_ex(ctx, hdr, hdrState, 0u);
}
#endif /* WOLFCOSE_CBOR_DECODE */

#if defined(WOLFCOSE_SIGN_VERIFY) || defined(WOLFCOSE_ENCRYPT_DECRYPT) || \
    defined(WOLFCOSE_MAC_VERIFY) || defined(WOLFCOSE_COUNTERSIGN)
/* Decode only the algorithm from an unselected header map. Other labels and
 * values are intentionally left to the application that selected the entry. */
static int wolfCose_DecodeSkippedHdrAlg(WOLFCOSE_CBOR_CTX* ctx,
    int32_t* alg, int* algFound, int* hpkeEkFound)
{
    int ret;
    size_t mapCount = 0u;
    size_t i;

    if ((ctx == NULL) || (alg == NULL) || (algFound == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
#if defined(WOLFCOSE_HPKE_0_KE_DECRYPT)
        if (hpkeEkFound != NULL) {
            *hpkeEkFound = 0;
        }
#else
        (void)hpkeEkFound;
#endif
        ret = wc_CBOR_DecodeMapStart(ctx, &mapCount);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (mapCount > ctx->bufSz)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }

    for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < mapCount); i++) {
        WOLFCOSE_CBOR_LABEL label;

        ret = wc_CBOR_DecodeLabel(ctx, &label);
        if ((ret == WOLFCOSE_SUCCESS) &&
            (wc_CBOR_LabelIsInt(&label, WOLFCOSE_HDR_ALG) != 0)) {
            if (*algFound != 0) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            else {
                int64_t algVal;

                *algFound = 1;
                if ((ctx->idx < ctx->bufSz) &&
                    (wc_CBOR_PeekType(ctx) == WOLFCOSE_CBOR_TSTR)) {
                    ret = wc_CBOR_Skip(ctx);
                }
                else {
                    ret = wc_CBOR_DecodeInt(ctx, &algVal);
                    if ((ret == WOLFCOSE_SUCCESS) &&
                        (wolfCose_InInt32Range(algVal) == 0)) {
                        ret = WOLFCOSE_E_COSE_BAD_ALG;
                    }
                    if (ret == WOLFCOSE_SUCCESS) {
                        *alg = (int32_t)algVal;
                    }
                }
            }
        }
#if defined(WOLFCOSE_HPKE_0_KE_DECRYPT)
        else if ((ret == WOLFCOSE_SUCCESS) &&
                 (wc_CBOR_LabelIsInt(&label, WOLFCOSE_HDR_HPKE_EK) != 0)) {
            if ((hpkeEkFound != NULL) && (*hpkeEkFound != 0)) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            else {
                if (hpkeEkFound != NULL) {
                    *hpkeEkFound = 1;
                }
                ret = wc_CBOR_Skip(ctx);
            }
        }
#endif
        else if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_Skip(ctx);
        }
        else {
            /* No action required */
        }
    }

    return ret;
}

/* Decode and validate the three fields shared by COSE_Signature and
 * COSE_recipient. A signature requires a bstr value. A recipient permits a
 * bstr or null value and may have a fourth nested-recipients field. */
static int wolfCose_DecodeSkippedHeaderEntry(WOLFCOSE_CBOR_CTX* ctx,
    size_t maxArrayCount, size_t* arrayCount, int32_t* alg,
    uint8_t isSignature, int* algFoundOut, int* hpkeEkFound)
{
    int ret;
    const uint8_t* protectedData = NULL;
    const uint8_t* valueData = NULL;
    size_t protectedLen = 0u;
    size_t valueLen = 0u;
    int algFound = 0;

    if ((ctx == NULL) || (arrayCount == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        *arrayCount = 0u;
        if (alg != NULL) {
            *alg = WOLFCOSE_ALG_UNSET;
        }
        if (algFoundOut != NULL) {
            *algFoundOut = 0;
        }
#if defined(WOLFCOSE_HPKE_0_KE_DECRYPT)
        if (hpkeEkFound != NULL) {
            *hpkeEkFound = 0;
        }
#endif
        ret = wc_CBOR_DecodeArrayStart(ctx, arrayCount);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((*arrayCount < 3u) || (*arrayCount > maxArrayCount))) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(ctx, &protectedData, &protectedLen);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (alg != NULL) &&
        (protectedLen > 0u)) {
        WOLFCOSE_CBOR_CTX protectedCtx;

        (void)XMEMSET(&protectedCtx, 0, sizeof(protectedCtx));
        protectedCtx.cbuf = protectedData;
        protectedCtx.bufSz = protectedLen;
        ret = wolfCose_DecodeSkippedHdrAlg(&protectedCtx, alg, &algFound,
                                           NULL);
        if ((ret == WOLFCOSE_SUCCESS) &&
            (protectedCtx.idx != protectedCtx.bufSz)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) && (alg != NULL)) {
        ret = wolfCose_DecodeSkippedHdrAlg(ctx, alg, &algFound,
                                           hpkeEkFound);
    }
    else if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_Skip(ctx);
    }
    else {
        /* No action required */
    }
    /* RFC 9053 Section 6.1 requires an empty protected header bucket for
     * Direct recipients. */
    if ((ret == WOLFCOSE_SUCCESS) && (alg != NULL) &&
        (*alg == WOLFCOSE_ALG_DIRECT) && (protectedLen != 0u)) {
        ret = WOLFCOSE_E_COSE_BAD_HDR;
    }
    if ((ret == WOLFCOSE_SUCCESS) && (algFoundOut != NULL)) {
        *algFoundOut = algFound;
    }
    if ((ret == WOLFCOSE_SUCCESS) && (isSignature != 0u)) {
        ret = wc_CBOR_DecodeBstr(ctx, &valueData, &valueLen);
    }
    else if ((ret == WOLFCOSE_SUCCESS) && (alg != NULL) &&
             (*alg == WOLFCOSE_ALG_DIRECT)) {
        WOLFCOSE_CBOR_ITEM item;

        ret = wolfCose_CBOR_DecodeHead(ctx, &item);
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((item.majorType != WOLFCOSE_CBOR_BSTR) ||
             (item.dataLen != 0u))) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
    }
    else if ((ret == WOLFCOSE_SUCCESS) &&
             (ctx->idx < ctx->bufSz) &&
             (ctx->cbuf[ctx->idx] == WOLFCOSE_CBOR_NULL)) {
        ctx->idx++;
    }
    else if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(ctx, &valueData, &valueLen);
    }
    else {
        /* No action required */
    }

    (void)valueData;
    (void)valueLen;
    return ret;
}

#if defined(WOLFCOSE_SIGN_VERIFY) || defined(WOLFCOSE_COUNTERSIGN)
/* A COSE_Signature has exactly three fields. */
int wolfCose_DecodeSkippedSignature(WOLFCOSE_CBOR_CTX* ctx)
{
    size_t arrayCount = 0u;

    return wolfCose_DecodeSkippedHeaderEntry(ctx, 3u, &arrayCount, NULL, 1u,
                                             NULL, NULL);
}
#endif

#if defined(WOLFCOSE_ENCRYPT_DECRYPT) || defined(WOLFCOSE_MAC_VERIFY) || \
    defined(WOLFCOSE_COUNTERSIGN)
/* Structurally validate one non-selected COSE_recipient and every nested
 * recipient. Use an explicit bounded stack to avoid recursive C calls. */
int wolfCose_DecodeSkippedRecipient(WOLFCOSE_CBOR_CTX* ctx,
    int32_t* recipientAlg)
{
    int ret;
    size_t remaining = 1u;
    size_t stack[WOLFCOSE_CBOR_MAX_DEPTH];
    size_t depth = 0u;
    int firstRecipient = 1;

    if ((ctx == NULL) || (recipientAlg == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        *recipientAlg = WOLFCOSE_ALG_UNSET;
        ret = WOLFCOSE_SUCCESS;
    }

    while ((ret == WOLFCOSE_SUCCESS) && (remaining > 0u)) {
        size_t arrayCount = 0u;
        int32_t decodedAlg = WOLFCOSE_ALG_UNSET;
        int algFound = 0;
#if defined(WOLFCOSE_HPKE_0_KE_DECRYPT)
        int hpkeEkFound = 0;
#endif

        ret = wolfCose_DecodeSkippedHeaderEntry(ctx, 4u, &arrayCount,
                                                 &decodedAlg, 0u,
#if defined(WOLFCOSE_HPKE_0_KE_DECRYPT)
                                                 &algFound, &hpkeEkFound);
#else
                                                 &algFound, NULL);
#endif
        remaining--;
#if defined(WOLFCOSE_HPKE_0_KE_DECRYPT)
        if ((ret == WOLFCOSE_SUCCESS) &&
            (algFound == 0) && (hpkeEkFound != 0)) {
            decodedAlg = WOLFCOSE_ALG_HPKE_0_KE;
        }
#endif
        if ((ret == WOLFCOSE_SUCCESS) && (arrayCount == 4u) &&
            (decodedAlg == WOLFCOSE_ALG_DIRECT)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
        if ((ret == WOLFCOSE_SUCCESS) && (firstRecipient != 0)) {
            *recipientAlg = decodedAlg;
            firstRecipient = 0;
        }

        if ((ret == WOLFCOSE_SUCCESS) && (arrayCount == 4u)) {
            size_t nestedCount = 0u;

            ret = wc_CBOR_DecodeArrayStart(ctx, &nestedCount);
            if ((ret == WOLFCOSE_SUCCESS) &&
                ((nestedCount == 0u) || (nestedCount > ctx->bufSz))) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            if ((ret == WOLFCOSE_SUCCESS) &&
                (depth >= (size_t)WOLFCOSE_CBOR_MAX_DEPTH)) {
                ret = WOLFCOSE_E_CBOR_DEPTH;
            }
            if (ret == WOLFCOSE_SUCCESS) {
                stack[depth] = remaining;
                depth++;
                remaining = nestedCount;
            }
        }

        while ((ret == WOLFCOSE_SUCCESS) && (remaining == 0u) &&
               (depth > 0u)) {
            depth--;
            remaining = stack[depth];
        }
    }

    return ret;
}
#endif
#endif
