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
    uint32_t bit;
    uint32_t shift;
    int64_t shift64;

    if ((label >= 1) && (label <= 16)) {
        shift64 = label;
        shift64--;
        shift = (uint32_t)shift64;
        bit = ((uint32_t)1u) << shift;
    }
    else if ((label <= -1) && (label >= -16)) {
        shift64 = -label;
        shift = (uint32_t)shift64;
        shift += 15u;
        bit = ((uint32_t)1u) << shift;
    }
    else {
        bit = 0u;
    }
    return bit;
}

void wolfCose_HdrStateInit(WOLFCOSE_HDR_STATE* state)
{
    if (state != NULL) {
        state->labelBits = 0u;
        state->extraCount = 0u;
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
            for (i = 0u; i < state->extraCount; i++) {
                if (state->extraLabels[i] == label) {
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
        else if (state->extraCount >= (size_t)WOLFCOSE_MAX_MAP_ITEMS) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
        else {
            state->extraLabels[state->extraCount] = label;
            state->extraCount++;
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

static int wolfCose_HdrStateMerge(WOLFCOSE_HDR_STATE* dst,
    const WOLFCOSE_HDR_STATE* src)
{
    int ret = WOLFCOSE_SUCCESS;

    if ((dst == NULL) || (src == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        size_t i;
        dst->labelBits |= src->labelBits;
        for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < src->extraCount); i++) {
            ret = wolfCose_HdrStateAdd(dst, src->extraLabels[i]);
        }
    }

    return ret;
}

/* If the next decoder item is a tstr label, reject it. The implementation
 * only supports integer labels, and silently skipping text labels breaks
 * duplicate-label enforcement across header and key maps. */
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

int wolfCose_DecodeProtectedHdr(const uint8_t* data, size_t dataLen,
                                 WOLFCOSE_HDR* hdr,
                                 WOLFCOSE_HDR_STATE* hdrState)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    size_t mapCount = 0;
    size_t i;
    int64_t label;
    int64_t intVal;
    uint64_t contentTypeVal;
    uint32_t critLabels = 0u;
    int skipped;

    if ((hdr == NULL) || (hdrState == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((data == NULL) || (dataLen == 0u)) {
        /* Empty protected header is valid */
        wolfCose_HdrStateInit(hdrState);
        ret = WOLFCOSE_SUCCESS;
    }
    else {
        wolfCose_HdrStateInit(hdrState);
        ctx.cbuf = data;
        ctx.bufSz = dataLen;
        ctx.idx = 0;

        ret = wc_CBOR_DecodeMapStart(&ctx, &mapCount);

        if ((ret == WOLFCOSE_SUCCESS) && (mapCount > (size_t)WOLFCOSE_MAX_MAP_ITEMS)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
            mapCount = 0; /* Coverity: clear tainted loop bound */
        }

        for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < mapCount); i++) {
            /* Reject tstr labels: only integer labels are supported. */
            ret = wolfCose_SkipIfTstrLabel(&ctx, &skipped);
            if ((ret == WOLFCOSE_SUCCESS) && (skipped == 0)) {
                ret = wc_CBOR_DecodeInt(&ctx, &label);
            }

            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_HdrStateCheckAndAdd(hdrState, label);
            }

            if ((ret == WOLFCOSE_SUCCESS) && (label == WOLFCOSE_HDR_ALG)) {
                if ((ctx.idx < ctx.bufSz) &&
                    (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TSTR)) {
                    ret = wc_CBOR_Skip(&ctx);
                }
                else {
                    ret = wc_CBOR_DecodeInt(&ctx, &intVal);
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
                     (label == WOLFCOSE_HDR_CRIT)) {
                size_t critCount = 0;
                size_t k;
                int64_t critLabel;

                ret = wc_CBOR_DecodeArrayStart(&ctx, &critCount);
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
                        ret = wc_CBOR_DecodeInt(&ctx, &critLabel);
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
                     (label == WOLFCOSE_HDR_CONTENT_TYPE)) {
                if ((ctx.idx < ctx.bufSz) &&
                    (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TSTR)) {
                    ret = wc_CBOR_Skip(&ctx);
                }
                else {
                    ret = wc_CBOR_DecodeUint(&ctx, &contentTypeVal);
                    if ((ret == WOLFCOSE_SUCCESS) &&
                        (contentTypeVal > (uint64_t)INT32_MAX)) {
                        ret = WOLFCOSE_E_COSE_BAD_HDR;
                    }
                    if (ret == WOLFCOSE_SUCCESS) {
                        hdr->contentType = (int32_t)contentTypeVal;
                    }
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_HDR_KID)) {
                /* RFC 9052 Section 3.1: kid may appear in the protected
                 * bucket; populate it the same way the unprotected decoder
                 * does instead of skipping it as unknown. */
                const uint8_t* kidData;
                size_t kidBstrLen;
                ret = wc_CBOR_DecodeBstr(&ctx, &kidData, &kidBstrLen);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->kid = kidData;
                    hdr->kidLen = kidBstrLen;
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_HDR_IV)) {
                const uint8_t* ivData;
                size_t ivBstrLen;
                ret = wc_CBOR_DecodeBstr(&ctx, &ivData, &ivBstrLen);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->iv = ivData;
                    hdr->ivLen = ivBstrLen;
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_HDR_PARTIAL_IV)) {
                const uint8_t* pivData;
                size_t pivBstrLen;
                ret = wc_CBOR_DecodeBstr(&ctx, &pivData, &pivBstrLen);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->partialIv = pivData;
                    hdr->partialIvLen = pivBstrLen;
                }
            }
            else {
                if (ret == WOLFCOSE_SUCCESS) {
                    /* Skip unknown header */
                    ret = wc_CBOR_Skip(&ctx);
                }
            }
        }

        /* Every label listed in crit must appear in the protected header. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((critLabels & ~hdrState->labelBits) != 0u)) {
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

int wolfCose_DecodeUnprotectedHdr(WOLFCOSE_CBOR_CTX* ctx, WOLFCOSE_HDR* hdr,
    WOLFCOSE_HDR_STATE* hdrState)
{
    int ret;
    size_t mapCount = 0;
    int64_t label;
    const uint8_t* bstrData;
    size_t bstrLen;
    int skipped;

    if ((ctx == NULL) || (hdr == NULL) || (hdrState == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        size_t i;
        WOLFCOSE_HDR_STATE unprotState;

        wolfCose_HdrStateInit(&unprotState);
        ret = wc_CBOR_DecodeMapStart(ctx, &mapCount);

        if ((ret == WOLFCOSE_SUCCESS) && (mapCount > (size_t)WOLFCOSE_MAX_MAP_ITEMS)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
            mapCount = 0; /* Coverity: clear tainted loop bound */
        }

        for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < mapCount); i++) {
            /* Reject tstr labels: only integer labels are supported. */
            ret = wolfCose_SkipIfTstrLabel(ctx, &skipped);
            if ((ret == WOLFCOSE_SUCCESS) && (skipped == 0)) {
                ret = wc_CBOR_DecodeInt(ctx, &label);
            }

            if (ret == WOLFCOSE_SUCCESS) {
                /* crit MUST live in the protected bucket. */
                if (label == WOLFCOSE_HDR_CRIT) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
                else if ((wolfCose_HdrStateContains(&unprotState, label) != 0) ||
                         (wolfCose_HdrStateContains(hdrState, label) != 0)) {
                    ret = WOLFCOSE_E_CBOR_MALFORMED;
                }
                else {
                    ret = wolfCose_HdrStateAdd(&unprotState, label);
                }
            }

            if ((ret == WOLFCOSE_SUCCESS) && (label == WOLFCOSE_HDR_KID)) {
                ret = wc_CBOR_DecodeBstr(ctx, &bstrData, &bstrLen);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->kid = bstrData;
                    hdr->kidLen = bstrLen;
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_HDR_IV)) {
                ret = wc_CBOR_DecodeBstr(ctx, &bstrData, &bstrLen);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->iv = bstrData;
                    hdr->ivLen = bstrLen;
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_HDR_PARTIAL_IV)) {
                ret = wc_CBOR_DecodeBstr(ctx, &bstrData, &bstrLen);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->partialIv = bstrData;
                    hdr->partialIvLen = bstrLen;
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_HDR_ALG)) {
                if ((ctx->idx < ctx->bufSz) &&
                    (wc_CBOR_PeekType(ctx) == WOLFCOSE_CBOR_TSTR)) {
                    ret = wc_CBOR_Skip(ctx);
                }
                else {
                    int64_t algVal;
                    ret = wc_CBOR_DecodeInt(ctx, &algVal);
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
                     (label == WOLFCOSE_HDR_CONTENT_TYPE)) {
                hdr->flags |= WOLFCOSE_HDR_FLAG_CONTENT_TYPE_UNPROTECTED;
                if ((ctx->idx < ctx->bufSz) &&
                    (wc_CBOR_PeekType(ctx) == WOLFCOSE_CBOR_TSTR)) {
                    ret = wc_CBOR_Skip(ctx);
                }
                else {
                    uint64_t contentTypeVal;
                    ret = wc_CBOR_DecodeUint(ctx, &contentTypeVal);
                    if ((ret == WOLFCOSE_SUCCESS) &&
                        (contentTypeVal > (uint64_t)INT32_MAX)) {
                        ret = WOLFCOSE_E_COSE_BAD_HDR;
                    }
                    if (ret == WOLFCOSE_SUCCESS) {
                        hdr->contentType = (int32_t)contentTypeVal;
                    }
                }
            }
            else {
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wc_CBOR_Skip(ctx);
                }
            }
        }

        /* IV and Partial IV are mutually exclusive. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            (hdr->iv != NULL) && (hdr->partialIv != NULL)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }

        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_HdrStateMerge(hdrState, &unprotState);
        }
    }
    return ret;
}

#if defined(WOLFCOSE_SIGN_VERIFY) || defined(WOLFCOSE_ENCRYPT_DECRYPT) || \
    defined(WOLFCOSE_MAC_VERIFY)
/* Decode only the algorithm from an unselected header map. Other labels and
 * values are intentionally left to the application that selected the entry. */
static int wolfCose_DecodeSkippedHdrAlg(WOLFCOSE_CBOR_CTX* ctx,
    int32_t* alg, int* algFound)
{
    int ret;
    size_t mapCount = 0u;
    size_t i;

    if ((ctx == NULL) || (alg == NULL) || (algFound == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
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
        else if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_Skip(ctx);
        }
        else {
            /* No action required */
        }
    }

    return ret;
}

/* Decode the three fields shared by COSE_Signature and COSE_recipient. */
static int wolfCose_DecodeSkippedHeaderEntry(WOLFCOSE_CBOR_CTX* ctx,
    size_t maxArrayCount, size_t* arrayCount, int32_t* alg)
{
    int ret;
    const uint8_t* protectedData = NULL;
    size_t protectedLen = 0u;
    int algFound = 0;

    if ((ctx == NULL) || (arrayCount == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        *arrayCount = 0u;
        if (alg != NULL) {
            *alg = WOLFCOSE_ALG_UNSET;
        }
        ret = wc_CBOR_DecodeArrayStart(ctx, arrayCount);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((*arrayCount < 3u) || (*arrayCount > maxArrayCount))) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    if ((ret == WOLFCOSE_SUCCESS) && (alg == NULL)) {
        size_t i;

        for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < 3u); i++) {
            ret = wc_CBOR_Skip(ctx);
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) && (alg != NULL)) {
        ret = wc_CBOR_DecodeBstr(ctx, &protectedData, &protectedLen);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (alg != NULL) &&
        (protectedLen > 0u)) {
        WOLFCOSE_CBOR_CTX protectedCtx;

        (void)XMEMSET(&protectedCtx, 0, sizeof(protectedCtx));
        protectedCtx.cbuf = protectedData;
        protectedCtx.bufSz = protectedLen;
        ret = wolfCose_DecodeSkippedHdrAlg(&protectedCtx, alg, &algFound);
        if ((ret == WOLFCOSE_SUCCESS) &&
            (protectedCtx.idx != protectedCtx.bufSz)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) && (alg != NULL)) {
        ret = wolfCose_DecodeSkippedHdrAlg(ctx, alg, &algFound);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (alg != NULL)) {
        ret = wc_CBOR_Skip(ctx);
    }

    return ret;
}

#if defined(WOLFCOSE_SIGN_VERIFY)
/* A COSE_Signature has exactly three fields. */
int wolfCose_DecodeSkippedSignature(WOLFCOSE_CBOR_CTX* ctx)
{
    size_t arrayCount = 0u;

    return wolfCose_DecodeSkippedHeaderEntry(ctx, 3u, &arrayCount, NULL);
}
#endif

#if defined(WOLFCOSE_ENCRYPT_DECRYPT) || defined(WOLFCOSE_MAC_VERIFY)
/* Structurally validate one non-selected COSE_recipient and every nested
 * recipient. Use an explicit bounded stack to avoid recursive C calls. */
int wolfCose_DecodeSkippedRecipient(WOLFCOSE_CBOR_CTX* ctx,
    int32_t* recipientAlg)
{
    int ret;
    size_t remaining = 1u;
    size_t stack[WOLFCOSE_CBOR_MAX_DEPTH];
    unsigned int depth = 0u;
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

        ret = wolfCose_DecodeSkippedHeaderEntry(ctx, 4u, &arrayCount,
                                                 &decodedAlg);
        remaining--;
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
            if ((ret == WOLFCOSE_SUCCESS) && (depth >=
                    (unsigned int)WOLFCOSE_CBOR_MAX_DEPTH)) {
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
