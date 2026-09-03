/* wolfcose_cbor.c
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
 * CBOR encoder/decoder per RFC 8949. Pure C99, no wolfCrypt dependency.
 * Zero-copy decode: bstr/tstr data pointers reference the input buffer.
 * Single-pass: decoder advances ctx->idx monotonically through the buffer.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfcose_internal.h"
#include <string.h>  /* memcpy */

/* WOLFCOSE_CBOR_CTX is public, so a caller can pass a context whose idx has
 * been advanced past bufSz. Subtraction-based capacity check that cannot wrap
 * in that case. Returns 1 when at least need bytes remain, 0 otherwise. */
static int wolfCose_CBOR_HasRoom(const WOLFCOSE_CBOR_CTX* ctx, size_t need)
{
    return ((ctx->idx <= ctx->bufSz) &&
            (need <= (ctx->bufSz - ctx->idx))) ? 1 : 0;
}

/* -----
 * Internal: CBOR head encoder
 *
 * RFC 8949 Section 3.1: initial byte encoding
 *   initial_byte = (majorType << 5) | additional_info
 *   val <= 23:         1 byte  (val in low 5 bits)
 *   val <= 0xFF:       2 bytes (AI=24, then uint8)
 *   val <= 0xFFFF:     3 bytes (AI=25, then BE16)
 *   val <= 0xFFFFFFFF: 5 bytes (AI=26, then BE32)
 *   else:              9 bytes (AI=27, then BE64)
 * ----- */
int wolfCose_CBOR_EncodeHead(WOLFCOSE_CBOR_CTX* ctx, uint8_t majorType,
                              uint64_t val)
{
    int ret;

    if ((ctx == NULL) || (ctx->buf == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        uint8_t mt = (uint8_t)(majorType << 5);
        size_t need;

        if (val <= 23u) {
            need = 1;
            if (wolfCose_CBOR_HasRoom(ctx, need) == 0) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            else {
                ctx->buf[ctx->idx] = (uint8_t)(mt | (uint8_t)val);
                ctx->idx += need;
                ret = WOLFCOSE_SUCCESS;
            }
        }
        else if (val <= 0xFFu) {
            need = 2;
            if (wolfCose_CBOR_HasRoom(ctx, need) == 0) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            else {
                ctx->buf[ctx->idx]     = (uint8_t)(mt | WOLFCOSE_CBOR_AI_1BYTE);
                ctx->buf[ctx->idx + 1u] = (uint8_t)val;
                ctx->idx += need;
                ret = WOLFCOSE_SUCCESS;
            }
        }
        else if (val <= 0xFFFFu) {
            need = 3;
            if (wolfCose_CBOR_HasRoom(ctx, need) == 0) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            else {
                ctx->buf[ctx->idx] = (uint8_t)(mt | WOLFCOSE_CBOR_AI_2BYTE);
                wolfCose_StoreBE16(&ctx->buf[ctx->idx + 1u], val);
                ctx->idx += need;
                ret = WOLFCOSE_SUCCESS;
            }
        }
        else if (val <= 0xFFFFFFFFu) {
            need = 5;
            if (wolfCose_CBOR_HasRoom(ctx, need) == 0) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            else {
                ctx->buf[ctx->idx] = (uint8_t)(mt | WOLFCOSE_CBOR_AI_4BYTE);
                wolfCose_StoreBE32(&ctx->buf[ctx->idx + 1u], val);
                ctx->idx += need;
                ret = WOLFCOSE_SUCCESS;
            }
        }
        else {
            need = 9;
            if (wolfCose_CBOR_HasRoom(ctx, need) == 0) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            else {
                ctx->buf[ctx->idx] = (uint8_t)(mt | WOLFCOSE_CBOR_AI_8BYTE);
                wolfCose_StoreBE64(&ctx->buf[ctx->idx + 1u], val);
                ctx->idx += need;
                ret = WOLFCOSE_SUCCESS;
            }
        }
    }
    return ret;
}

/* -----
 * Internal: CBOR head decoder
 *
 * Read initial byte, extract major type (bits 7-5) and AI (bits 4-0).
 * Based on AI: read 0/1/2/4/8 argument bytes.
 * AI 28-30 reserved = WOLFCOSE_E_CBOR_MALFORMED
 * AI 31 = WOLFCOSE_E_UNSUPPORTED (indefinite length -- COSE never uses it)
 *
 * For bstr/tstr: advances past the data and sets item->data/dataLen.
 * ----- */
int wolfCose_CBOR_DecodeHead(WOLFCOSE_CBOR_CTX* ctx, WOLFCOSE_CBOR_ITEM* item)
{
    int ret;
    uint8_t ib;
    uint8_t ai;

    if ((ctx == NULL) || (ctx->cbuf == NULL) || (item == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (ctx->idx >= ctx->bufSz) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    else {
        ib = ctx->cbuf[ctx->idx];
        ctx->idx++;

        item->majorType = (uint8_t)(((uint32_t)ib) >> 5u);
        ai = (uint8_t)(ib & 0x1Fu);
        item->data = NULL;
        item->dataLen = 0;

        if (ai <= 23u) {
            item->val = (uint64_t)ai;
            ret = WOLFCOSE_SUCCESS;
        }
        else if (ai == WOLFCOSE_CBOR_AI_1BYTE) {
            if ((ctx->idx + 1u) > ctx->bufSz) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            else {
                item->val = (uint64_t)ctx->cbuf[ctx->idx];
                ctx->idx += 1u;
                ret = WOLFCOSE_SUCCESS;
            }
        }
        else if (ai == WOLFCOSE_CBOR_AI_2BYTE) {
            if ((ctx->idx + 2u) > ctx->bufSz) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            else {
                item->val = (uint64_t)wolfCose_LoadBE16(&ctx->cbuf[ctx->idx]);
                ctx->idx += 2u;
                ret = WOLFCOSE_SUCCESS;
            }
        }
        else if (ai == WOLFCOSE_CBOR_AI_4BYTE) {
            if ((ctx->idx + 4u) > ctx->bufSz) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            else {
                item->val = (uint64_t)wolfCose_LoadBE32(&ctx->cbuf[ctx->idx]);
                ctx->idx += 4u;
                ret = WOLFCOSE_SUCCESS;
            }
        }
        else if (ai == WOLFCOSE_CBOR_AI_8BYTE) {
            if ((ctx->idx + 8u) > ctx->bufSz) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            else {
                item->val = wolfCose_LoadBE64(&ctx->cbuf[ctx->idx]);
                ctx->idx += 8u;
                ret = WOLFCOSE_SUCCESS;
            }
        }
        else if (ai == WOLFCOSE_CBOR_AI_INDEF) {
            /* Indefinite length -- COSE never uses it */
            ret = WOLFCOSE_E_UNSUPPORTED;
        }
        else {
            /* AI 28-30 are reserved */
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }

        /* RFC 8949: 2-byte simple values with arg < 32 are malformed. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            (item->majorType == WOLFCOSE_CBOR_SIMPLE) &&
            (ai == WOLFCOSE_CBOR_AI_1BYTE) &&
            (item->val < 32u)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }

        /* RFC 8949 Section 4.2.1 (deterministic encoding, required for COSE):
         * the argument must use the shortest additional-info form. This applies
         * to every major type except simple/float (where AI 25/26/27 select
         * float16/32/64 rather than encode an integer). */
        if ((ret == WOLFCOSE_SUCCESS) &&
            (item->majorType != WOLFCOSE_CBOR_SIMPLE)) {
            if (((ai == WOLFCOSE_CBOR_AI_1BYTE) && (item->val < 24u)) ||
                ((ai == WOLFCOSE_CBOR_AI_2BYTE) && (item->val < 256u)) ||
                ((ai == WOLFCOSE_CBOR_AI_4BYTE) && (item->val < 0x10000u)) ||
                ((ai == WOLFCOSE_CBOR_AI_8BYTE) &&
                 (item->val < 0x100000000ULL))) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
        }

        /* Compare the 64-bit length against remaining bytes (no size_t cast). */
        if (ret == WOLFCOSE_SUCCESS) {
            if ((item->majorType == WOLFCOSE_CBOR_BSTR) ||
                (item->majorType == WOLFCOSE_CBOR_TSTR)) {
                if (item->val > (uint64_t)(ctx->bufSz - ctx->idx)) {
                    ret = WOLFCOSE_E_CBOR_MALFORMED;
                }
                else {
                    item->data = &ctx->cbuf[ctx->idx];
                    item->dataLen = (size_t)item->val;
                    ctx->idx += (size_t)item->val;
                }
            }
        }
    }
    return ret;
}

/* -----
 * Public Encode API
 *
 * Guarded by WOLFCOSE_CBOR_ENCODE — can be excluded for decode-only builds.
 * ----- */

#if defined(WOLFCOSE_CBOR_ENCODE)

int wc_CBOR_EncodeUint(WOLFCOSE_CBOR_CTX* ctx, uint64_t val)
{
    return wolfCose_CBOR_EncodeHead(ctx, WOLFCOSE_CBOR_UINT, val);
}

int wc_CBOR_EncodeInt(WOLFCOSE_CBOR_CTX* ctx, int64_t val)
{
    int ret;

    if (ctx == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        if (val >= 0) {
            ret = wolfCose_CBOR_EncodeHead(ctx, WOLFCOSE_CBOR_UINT,
                                            (uint64_t)val);
        }
        else {
            /* RFC 8949: negative integer n is encoded as -(n+1) */
            ret = wolfCose_CBOR_EncodeHead(ctx, WOLFCOSE_CBOR_NEGINT,
                                            (uint64_t)(-(val + 1)));
        }
    }
    return ret;
}

/* Shared encode for bstr (major type 2) and tstr (major type 3) */
static int wolfCose_CBOR_EncodeBytes(WOLFCOSE_CBOR_CTX* ctx,
                                       uint8_t majorType,
                                       const uint8_t* data, size_t len)
{
    int ret;

    if ((data == NULL) && (len > 0u)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wolfCose_CBOR_EncodeHead(ctx, majorType, (uint64_t)len);
        if (ret == WOLFCOSE_SUCCESS) {
            if (len > (ctx->bufSz - ctx->idx)) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            else {
                if (len > 0u) {
                    (void)XMEMMOVE(&ctx->buf[ctx->idx], data, len);
                }
                ctx->idx += len;
            }
        }
    }
    return ret;
}

int wc_CBOR_EncodeBstr(WOLFCOSE_CBOR_CTX* ctx, const uint8_t* data,
                        size_t len)
{
    return wolfCose_CBOR_EncodeBytes(ctx, WOLFCOSE_CBOR_BSTR, data, len);
}

int wc_CBOR_EncodeTstr(WOLFCOSE_CBOR_CTX* ctx, const uint8_t* str,
                        size_t len)
{
    return wolfCose_CBOR_EncodeBytes(ctx, WOLFCOSE_CBOR_TSTR, str, len);
}

int wc_CBOR_EncodeArrayStart(WOLFCOSE_CBOR_CTX* ctx, size_t count)
{
    return wolfCose_CBOR_EncodeHead(ctx, WOLFCOSE_CBOR_ARRAY,
                                     (uint64_t)count);
}

int wc_CBOR_EncodeMapStart(WOLFCOSE_CBOR_CTX* ctx, size_t count)
{
    return wolfCose_CBOR_EncodeHead(ctx, WOLFCOSE_CBOR_MAP,
                                     (uint64_t)count);
}

int wc_CBOR_EncodeTag(WOLFCOSE_CBOR_CTX* ctx, uint64_t tag)
{
    return wolfCose_CBOR_EncodeHead(ctx, WOLFCOSE_CBOR_TAG, tag);
}

/* Shared single-byte simple value encoder (true, false, null) */
static int wolfCose_CBOR_EncodeSimpleVal(WOLFCOSE_CBOR_CTX* ctx, uint8_t val)
{
    int ret;

    if ((ctx == NULL) || (ctx->buf == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (wolfCose_CBOR_HasRoom(ctx, 1u) == 0) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }
    else {
        ctx->buf[ctx->idx] = val;
        ctx->idx++;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}

int wc_CBOR_EncodeTrue(WOLFCOSE_CBOR_CTX* ctx)
{
    return wolfCose_CBOR_EncodeSimpleVal(ctx, (uint8_t)WOLFCOSE_CBOR_TRUE);
}

int wc_CBOR_EncodeFalse(WOLFCOSE_CBOR_CTX* ctx)
{
    return wolfCose_CBOR_EncodeSimpleVal(ctx, (uint8_t)WOLFCOSE_CBOR_FALSE);
}

int wc_CBOR_EncodeNull(WOLFCOSE_CBOR_CTX* ctx)
{
    return wolfCose_CBOR_EncodeSimpleVal(ctx, (uint8_t)WOLFCOSE_CBOR_NULL);
}

#ifdef WOLFCOSE_FLOAT
int wc_CBOR_EncodeFloat(WOLFCOSE_CBOR_CTX* ctx, float val)
{
    int ret;
    uint32_t bits;

    if ((ctx == NULL) || (ctx->buf == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (wolfCose_CBOR_HasRoom(ctx, 5u) == 0) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }
    else {
        (void)XMEMCPY((void*)&bits, (const void*)&val, sizeof(bits));
        ctx->buf[ctx->idx] = (uint8_t)((WOLFCOSE_CBOR_SIMPLE << 5) |
                                         WOLFCOSE_CBOR_AI_FLOAT32);
        wolfCose_StoreBE32(&ctx->buf[ctx->idx + 1u], bits);
        ctx->idx += 5u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}

int wc_CBOR_EncodeDouble(WOLFCOSE_CBOR_CTX* ctx, double val)
{
    int ret;
    uint64_t bits;

    if ((ctx == NULL) || (ctx->buf == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (wolfCose_CBOR_HasRoom(ctx, 9u) == 0) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }
    else {
        (void)XMEMCPY((void*)&bits, (const void*)&val, sizeof(bits));
        ctx->buf[ctx->idx] = (uint8_t)((WOLFCOSE_CBOR_SIMPLE << 5) |
                                         WOLFCOSE_CBOR_AI_FLOAT64);
        wolfCose_StoreBE64(&ctx->buf[ctx->idx + 1u], bits);
        ctx->idx += 9u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif /* WOLFCOSE_FLOAT */

#endif /* WOLFCOSE_CBOR_ENCODE */

/* -----
 * Public Decode API
 *
 * Guarded by WOLFCOSE_CBOR_DECODE — always needed for verify/decrypt builds.
 * ----- */

#if defined(WOLFCOSE_CBOR_DECODE)

int wc_CBOR_DecodeHead(WOLFCOSE_CBOR_CTX* ctx, WOLFCOSE_CBOR_ITEM* item)
{
    return wolfCose_CBOR_DecodeHead(ctx, item);
}

int wc_CBOR_DecodeUint(WOLFCOSE_CBOR_CTX* ctx, uint64_t* val)
{
    int ret;
    WOLFCOSE_CBOR_ITEM item;

    if ((ctx == NULL) || (val == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wolfCose_CBOR_DecodeHead(ctx, &item);
        if (ret == WOLFCOSE_SUCCESS) {
            if (item.majorType != WOLFCOSE_CBOR_UINT) {
                ret = WOLFCOSE_E_CBOR_TYPE;
            }
            else {
                *val = item.val;
            }
        }
    }
    return ret;
}

int wc_CBOR_DecodeInt(WOLFCOSE_CBOR_CTX* ctx, int64_t* val)
{
    int ret;
    WOLFCOSE_CBOR_ITEM item;

    if ((ctx == NULL) || (val == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wolfCose_CBOR_DecodeHead(ctx, &item);
        if (ret == WOLFCOSE_SUCCESS) {
            if (item.majorType == WOLFCOSE_CBOR_UINT) {
                if (item.val > (uint64_t)INT64_MAX) {
                    ret = WOLFCOSE_E_CBOR_OVERFLOW;
                }
                else {
                    *val = (int64_t)item.val;
                }
            }
            else if (item.majorType == WOLFCOSE_CBOR_NEGINT) {
                /* RFC 8949: value = -1 - val */
                if (item.val > (uint64_t)INT64_MAX) {
                    ret = WOLFCOSE_E_CBOR_OVERFLOW;
                }
                else {
                    *val = -1 - (int64_t)item.val;
                }
            }
            else {
                ret = WOLFCOSE_E_CBOR_TYPE;
            }
        }
    }
    return ret;
}

/* Shared decode for bstr (major type 2) and tstr (major type 3) */
static int wolfCose_CBOR_DecodeBytes(WOLFCOSE_CBOR_CTX* ctx,
                                       uint8_t majorType,
                                       const uint8_t** data, size_t* dataLen)
{
    int ret;
    WOLFCOSE_CBOR_ITEM item;

    if ((ctx == NULL) || (data == NULL) || (dataLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wolfCose_CBOR_DecodeHead(ctx, &item);
        if (ret == WOLFCOSE_SUCCESS) {
            if (item.majorType != majorType) {
                ret = WOLFCOSE_E_CBOR_TYPE;
            }
            else {
                *data = item.data;
                *dataLen = item.dataLen;
            }
        }
    }
    return ret;
}

int wc_CBOR_DecodeBstr(WOLFCOSE_CBOR_CTX* ctx, const uint8_t** data,
                        size_t* dataLen)
{
    return wolfCose_CBOR_DecodeBytes(ctx, WOLFCOSE_CBOR_BSTR, data, dataLen);
}

int wc_CBOR_DecodeTstr(WOLFCOSE_CBOR_CTX* ctx, const uint8_t** str,
                        size_t* strLen)
{
    return wolfCose_CBOR_DecodeBytes(ctx, WOLFCOSE_CBOR_TSTR, str, strLen);
}

/* Shared decode for array (major type 4) and map (major type 5) */
static int wolfCose_CBOR_DecodeContainerStart(WOLFCOSE_CBOR_CTX* ctx,
                                                uint8_t majorType,
                                                size_t* count)
{
    int ret;
    WOLFCOSE_CBOR_ITEM item;

    if ((ctx == NULL) || (count == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wolfCose_CBOR_DecodeHead(ctx, &item);
        if (ret == WOLFCOSE_SUCCESS) {
            if (item.majorType != majorType) {
                ret = WOLFCOSE_E_CBOR_TYPE;
            }
            /* A definite-length container needs at least one byte per declared
             * element, so a count larger than the bytes remaining is malformed.
             * This also rejects any count that would not fit in size_t. */
            else if (item.val > (uint64_t)(ctx->bufSz - ctx->idx)) {
                ret = WOLFCOSE_E_CBOR_MALFORMED;
            }
            else {
                *count = (size_t)item.val;
            }
        }
    }
    return ret;
}

int wc_CBOR_DecodeArrayStart(WOLFCOSE_CBOR_CTX* ctx, size_t* count)
{
    return wolfCose_CBOR_DecodeContainerStart(ctx, WOLFCOSE_CBOR_ARRAY, count);
}

int wc_CBOR_DecodeMapStart(WOLFCOSE_CBOR_CTX* ctx, size_t* count)
{
    return wolfCose_CBOR_DecodeContainerStart(ctx, WOLFCOSE_CBOR_MAP, count);
}

int wc_CBOR_DecodeTag(WOLFCOSE_CBOR_CTX* ctx, uint64_t* tag)
{
    int ret;
    WOLFCOSE_CBOR_ITEM item;

    if ((ctx == NULL) || (tag == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wolfCose_CBOR_DecodeHead(ctx, &item);
        if (ret == WOLFCOSE_SUCCESS) {
            if (item.majorType != WOLFCOSE_CBOR_TAG) {
                ret = WOLFCOSE_E_CBOR_TYPE;
            }
            else {
                *tag = item.val;
            }
        }
    }
    return ret;
}

/* -----
 * wc_CBOR_Skip: iterative traversal to skip a complete CBOR item.
 * Uses a bounded stack (no recursion, MISRA Rule 17.2 compliant).
 * ----- */
int wc_CBOR_Skip(WOLFCOSE_CBOR_CTX* ctx)
{
    int ret;
    WOLFCOSE_CBOR_ITEM item;
    /* Stack of remaining items to skip at each nesting level */
    size_t stack[WOLFCOSE_CBOR_MAX_DEPTH];

    if (ctx == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        unsigned int depth = 0u;
        size_t remaining = 1; /* Start: need to skip 1 item */
        ret = WOLFCOSE_SUCCESS;

        while ((remaining > 0u) && (ret == WOLFCOSE_SUCCESS)) {
            ret = wolfCose_CBOR_DecodeHead(ctx, &item);
            if (ret != WOLFCOSE_SUCCESS) {
                break;
            }

            remaining--;

            if (item.majorType == WOLFCOSE_CBOR_ARRAY) {
                if (item.val > 0u) {
                    if (depth >= WOLFCOSE_CBOR_MAX_DEPTH) {
                        ret = WOLFCOSE_E_CBOR_DEPTH;
                    }
                    else if (item.val > ctx->bufSz) {
                        /* Sanitize: can't have more items than bytes */
                        ret = WOLFCOSE_E_CBOR_MALFORMED;
                    }
                    else {
                        stack[depth] = remaining;
                        depth++;
                        remaining = (size_t)item.val;
                    }
                }
            }
            else if (item.majorType == WOLFCOSE_CBOR_MAP) {
                if (item.val > 0u) {
                    if (depth >= WOLFCOSE_CBOR_MAX_DEPTH) {
                        ret = WOLFCOSE_E_CBOR_DEPTH;
                    }
                    else if (item.val > ctx->bufSz) {
                        /* Sanitize: can't have more entries than bytes */
                        ret = WOLFCOSE_E_CBOR_MALFORMED;
                    }
                    else if (item.val > (SIZE_MAX / 2u)) {
                        /* Prevent overflow in item.val * 2 */
                        ret = WOLFCOSE_E_CBOR_MALFORMED;
                    }
                    else {
                        stack[depth] = remaining;
                        depth++;
                        /* Each map entry is key + value = 2 items per pair */
                        remaining = (size_t)(item.val * 2u);
                    }
                }
            }
            else if (item.majorType == WOLFCOSE_CBOR_TAG) {
                /* Tag wraps exactly one item */
                remaining++;
            }
            else {
                /* For uint/negint/bstr/tstr/simple: already consumed by DecodeHead */
            }

            /* Unwind stack when current level is exhausted */
            while ((remaining == 0u) && (depth > 0u)) {
                depth--;
                remaining = stack[depth];
            }
        }
    }
    return ret;
}

int wc_CBOR_SkipItem(WOLFCOSE_CBOR_CTX* ctx, const uint8_t** data,
                      size_t* dataLen)
{
    int ret;

    if ((ctx == NULL) || (ctx->cbuf == NULL) || (data == NULL) ||
        (dataLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        size_t start = ctx->idx;

        ret = wc_CBOR_Skip(ctx);
        if (ret == WOLFCOSE_SUCCESS) {
            /* wc_CBOR_Skip only ever advances idx, and never past bufSz. */
            *data = &ctx->cbuf[start];
            *dataLen = ctx->idx - start;
        }
    }
    return ret;
}

static int wolfCose_CBOR_IsUtf8Continuation(uint8_t value)
{
    return ((value >= 0x80u) && (value <= 0xBFu)) ? 1 : 0;
}

static int wolfCose_CBOR_IsValidUtf8(const uint8_t* text, size_t textLen)
{
    int valid = 1;
    size_t i = 0u;

    if ((text == NULL) && (textLen > 0u)) {
        valid = 0;
    }

    while ((valid != 0) && (i < textLen)) {
        uint8_t first = text[i];
        size_t remaining = textLen - i;

        if (first <= 0x7Fu) {
            i++;
        }
        else if ((first >= 0xC2u) && (first <= 0xDFu)) {
            if ((remaining < 2u) ||
                (wolfCose_CBOR_IsUtf8Continuation(text[i + 1u]) == 0)) {
                valid = 0;
            }
            else {
                i += 2u;
            }
        }
        else if ((first >= 0xE0u) && (first <= 0xEFu)) {
            if ((remaining < 3u) ||
                (wolfCose_CBOR_IsUtf8Continuation(text[i + 1u]) == 0) ||
                (wolfCose_CBOR_IsUtf8Continuation(text[i + 2u]) == 0)) {
                valid = 0;
            }
            else if (((first == 0xE0u) && (text[i + 1u] < 0xA0u)) ||
                     ((first == 0xEDu) && (text[i + 1u] > 0x9Fu))) {
                valid = 0;
            }
            else {
                i += 3u;
            }
        }
        else if ((first >= 0xF0u) && (first <= 0xF4u)) {
            if ((remaining < 4u) ||
                (wolfCose_CBOR_IsUtf8Continuation(text[i + 1u]) == 0) ||
                (wolfCose_CBOR_IsUtf8Continuation(text[i + 2u]) == 0) ||
                (wolfCose_CBOR_IsUtf8Continuation(text[i + 3u]) == 0)) {
                valid = 0;
            }
            else if (((first == 0xF0u) && (text[i + 1u] < 0x90u)) ||
                     ((first == 0xF4u) && (text[i + 1u] > 0x8Fu))) {
                valid = 0;
            }
            else {
                i += 4u;
            }
        }
        else {
            valid = 0;
        }
    }

    return valid;
}

int wc_CBOR_DecodeLabel(WOLFCOSE_CBOR_CTX* ctx, WOLFCOSE_CBOR_LABEL* label)
{
    int ret;
    WOLFCOSE_CBOR_ITEM item;

    if ((ctx == NULL) || (label == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wolfCose_CBOR_DecodeHead(ctx, &item);
        if (ret == WOLFCOSE_SUCCESS) {
            label->val = 0;
            label->text = NULL;
            label->textLen = 0;
            label->isText = 0u;

            if (item.majorType == WOLFCOSE_CBOR_UINT) {
                if (item.val > (uint64_t)INT64_MAX) {
                    ret = WOLFCOSE_E_CBOR_OVERFLOW;
                }
                else {
                    label->val = (int64_t)item.val;
                }
            }
            else if (item.majorType == WOLFCOSE_CBOR_NEGINT) {
                /* RFC 8949: value = -1 - val */
                if (item.val > (uint64_t)INT64_MAX) {
                    ret = WOLFCOSE_E_CBOR_OVERFLOW;
                }
                else {
                    label->val = -1 - (int64_t)item.val;
                }
            }
            else if (item.majorType == WOLFCOSE_CBOR_TSTR) {
                if (wolfCose_CBOR_IsValidUtf8(item.data, item.dataLen) == 0) {
                    ret = WOLFCOSE_E_CBOR_MALFORMED;
                }
                else {
                    label->text = item.data;
                    label->textLen = item.dataLen;
                    label->isText = 1u;
                }
            }
            else {
                /* RFC 9052: label = int / tstr, nothing else. */
                ret = WOLFCOSE_E_CBOR_TYPE;
            }
        }
    }
    return ret;
}

int wc_CBOR_LabelIsInt(const WOLFCOSE_CBOR_LABEL* label, int64_t val)
{
    int match = 0;

    if ((label != NULL) && (label->isText == 0u) && (label->val == val)) {
        match = 1;
    }
    return match;
}

int wc_CBOR_LabelIsText(const WOLFCOSE_CBOR_LABEL* label, const uint8_t* text,
                         size_t textLen)
{
    int match = 0;

    if ((label != NULL) && (label->isText != 0u) &&
        (label->textLen == textLen)) {
        if (textLen == 0u) {
            match = 1;
        }
        else if ((label->text != NULL) && (text != NULL)) {
            /* A map label is public, but the core library takes no
             * variable-time compares at all (.github/semgrep-rules.yml), so
             * this scans the whole label rather than stopping at the first
             * difference. Same OR-accumulate shape as the MAC tag compare in
             * wolfcose.c; volatile keeps the loop from becoming an early
             * exit. */
            volatile uint32_t diff = 0u;
            size_t i;

            for (i = 0u; i < textLen; i++) {
                diff |= ((uint32_t)label->text[i] ^
                         (uint32_t)text[i]);
            }
            if (diff == 0u) {
                match = 1;
            }
        }
        else {
            /* No action required */
        }
    }
    return match;
}

#endif /* WOLFCOSE_CBOR_DECODE */
