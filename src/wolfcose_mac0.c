/* wolfcose_mac0.c
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
 * COSE_Mac0 single-recipient MAC create and verify. RFC 9052 Section 6.2.
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


/* -----
 * COSE_Mac0 API (RFC 9052 Section 6.2)
 * Supports HMAC (RFC 9053 Section 3.1) and AES-CBC-MAC (RFC 9053 Section 3.2)
 * ----- */

#if (defined(WOLFCOSE_MAC0) || defined(WOLFCOSE_MAC)) && \
    (defined(WOLFCOSE_HAVE_HMAC) || defined(WOLFCOSE_HAVE_AESMAC))

#if defined(WOLFCOSE_MAC0)
/**
 * Build the MAC_structure for COSE_Mac0 (wrapper for unified builder):
 *   ["MAC0", body_protected, external_aad, payload]
 */
static int wolfCose_BuildMacStructure(const uint8_t* protectedHdr,
                                       size_t protectedLen,
                                       const uint8_t* extAad,
                                       size_t extAadLen,
                                       const uint8_t* payload,
                                       size_t payloadLen,
                                       uint8_t* scratch, size_t scratchSz,
                                       size_t* structLen)
{
    /* Use unified builder with "MAC0" context, no sign_protected */
    return wolfCose_BuildToBeSignedMaced(
        WOLFCOSE_CTX_MAC0, sizeof(WOLFCOSE_CTX_MAC0),
        protectedHdr, protectedLen,
        NULL, 0,  /* no sign_protected for Mac0 */
        extAad, extAadLen,
        payload, payloadLen,
        scratch, scratchSz, structLen);
}
#endif

/**
 * Get MAC tag size for a COSE MAC algorithm (HMAC or AES-CBC-MAC).
 */
int wolfCose_MacTagSize(int32_t alg, size_t* tagSz)
{
    int ret = WOLFCOSE_SUCCESS;

    if (tagSz == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
#ifdef WOLFCOSE_HAVE_HMAC
#ifdef WOLFCOSE_HAVE_HMAC256
            case WOLFCOSE_ALG_HMAC_256_256:
                *tagSz = 32; /* SHA-256 output */
                break;
#endif
#ifdef WOLFCOSE_HAVE_HMAC384
            case WOLFCOSE_ALG_HMAC_384_384:
                *tagSz = 48; /* SHA-384 output */
                break;
#endif
#ifdef WOLFCOSE_HAVE_HMAC512
            case WOLFCOSE_ALG_HMAC_512_512:
                *tagSz = 64; /* SHA-512 output */
                break;
#endif
#endif /* WOLFCOSE_HAVE_HMAC */
#ifdef WOLFCOSE_HAVE_AESMAC
            case WOLFCOSE_ALG_AES_MAC_128_64:
            case WOLFCOSE_ALG_AES_MAC_256_64:
                *tagSz = 8; /* 64-bit tag */
                break;
            case WOLFCOSE_ALG_AES_MAC_128_128:
            case WOLFCOSE_ALG_AES_MAC_256_128:
                *tagSz = 16; /* 128-bit tag */
                break;
#endif
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

#ifdef WOLFCOSE_HAVE_AESMAC
/**
 * Get AES key size in bytes for AES-CBC-MAC algorithm.
 */
int wolfCose_AesCbcMacKeySize(int32_t alg, size_t* keySz)
{
    int ret = WOLFCOSE_SUCCESS;

    if (keySz == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
            case WOLFCOSE_ALG_AES_MAC_128_64:
            case WOLFCOSE_ALG_AES_MAC_128_128:
                *keySz = 16; /* AES-128 */
                break;
            case WOLFCOSE_ALG_AES_MAC_256_64:
            case WOLFCOSE_ALG_AES_MAC_256_128:
                *keySz = 32; /* AES-256 */
                break;
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

/**
 * Compute AES-CBC-MAC (RFC 9053 Section 3.2).
 *
 * AES-CBC-MAC uses AES in CBC mode with a zero IV. The final ciphertext
 * block is the MAC tag, truncated to the specified size.
 *
 * Implementation note: Uses wc_AesCbcEncrypt for portability. We process
 * one block at a time to extract the final ciphertext block as the MAC.
 */
int wolfCose_AesCbcMac(const uint8_t* key, size_t keyLen,
                               const uint8_t* data, size_t dataLen,
                               uint8_t* tag, size_t tagLen)
{
    int ret = WOLFCOSE_SUCCESS;
    Aes aes;
    int aesInited = 0;
    int aesRet;
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t inBlock[AES_BLOCK_SIZE];
    uint8_t outBlock[AES_BLOCK_SIZE];
    size_t numBlocks = 0;
    size_t lastBlockLen = 0;
    size_t i;

    /* Parameter validation */
    if ((key == NULL) || (tag == NULL) || (tagLen > AES_BLOCK_SIZE) ||
        ((data == NULL) && (dataLen > 0u))) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    /* Initialize with zero IV per RFC 9053 */
    if (ret == WOLFCOSE_SUCCESS) {
        (void)XMEMSET(iv, 0, sizeof(iv));
        (void)XMEMSET(outBlock, 0, sizeof(outBlock));

        aesRet = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (aesRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            aesInited = 1;
        }
    }

    /* Process full blocks */
    if (ret == WOLFCOSE_SUCCESS) {
        numBlocks = dataLen / AES_BLOCK_SIZE;
        lastBlockLen = dataLen % AES_BLOCK_SIZE;

        for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < numBlocks); i++) {
            /* Set key and IV for each block (IV is previous ciphertext block) */
            aesRet = wc_AesSetKey(&aes, key, (word32)keyLen, iv,
                                   AES_ENCRYPTION);
            if (aesRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }

            /* Encrypt this block - CBC mode XORs with IV internally */
            if (ret == WOLFCOSE_SUCCESS) {
                aesRet = wc_AesCbcEncrypt(&aes, outBlock,
                                           &data[i * AES_BLOCK_SIZE],
                                           AES_BLOCK_SIZE);
                if (aesRet != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }

            /* Use output as next IV */
            if (ret == WOLFCOSE_SUCCESS) {
                (void)XMEMCPY(iv, outBlock, AES_BLOCK_SIZE);
            }
        }
    }

    /* FIPS-113 zero pad partial trailing blocks only. */
    if ((ret == WOLFCOSE_SUCCESS) && (lastBlockLen > 0u)) {
        (void)XMEMSET(inBlock, 0, sizeof(inBlock));
        for (i = 0; i < lastBlockLen; i++) {
            inBlock[i] = data[(numBlocks * AES_BLOCK_SIZE) + i];
        }

        aesRet = wc_AesSetKey(&aes, key, (word32)keyLen, iv, AES_ENCRYPTION);
        if (aesRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }

        if (ret == WOLFCOSE_SUCCESS) {
            aesRet = wc_AesCbcEncrypt(&aes, outBlock, inBlock, AES_BLOCK_SIZE);
            if (aesRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
    }

    /* Copy truncated tag on success */
    if (ret == WOLFCOSE_SUCCESS) {
        (void)XMEMCPY(tag, outBlock, tagLen);
    }

    /* Cleanup: always executed */
    if (aesInited != 0) {
        (void)wc_AesFree(&aes);
    }
    (void)wolfCose_ForceZero(inBlock, sizeof(inBlock));
    (void)wolfCose_ForceZero(outBlock, sizeof(outBlock));
    (void)wolfCose_ForceZero(iv, sizeof(iv));

    return ret;
}
#endif /* WOLFCOSE_HAVE_AESMAC */

#ifdef WOLFCOSE_HAVE_HMAC
/**
 * Check if algorithm is HMAC-based.
 */
int wolfCose_IsHmacAlg(int32_t alg)
{
    int isHmac = 0;

    switch (alg) {
#ifdef WOLFCOSE_HAVE_HMAC256
        case WOLFCOSE_ALG_HMAC_256_256:
#endif
#ifdef WOLFCOSE_HAVE_HMAC384
        case WOLFCOSE_ALG_HMAC_384_384:
#endif
#ifdef WOLFCOSE_HAVE_HMAC512
        case WOLFCOSE_ALG_HMAC_512_512:
#endif
            isHmac = 1;
            break;
        default:
            /* No action required. */
            break;
    }

    return isHmac;
}
#endif /* WOLFCOSE_HAVE_HMAC */

#ifdef WOLFCOSE_HAVE_AESMAC
/**
 * Check if algorithm is AES-CBC-MAC based.
 */
int wolfCose_IsAesCbcMacAlg(int32_t alg)
{
    return ((alg == WOLFCOSE_ALG_AES_MAC_128_64) ||
            (alg == WOLFCOSE_ALG_AES_MAC_256_64) ||
            (alg == WOLFCOSE_ALG_AES_MAC_128_128) ||
            (alg == WOLFCOSE_ALG_AES_MAC_256_128)) ? 1 : 0;
}
#endif /* WOLFCOSE_HAVE_AESMAC */

#if defined(WOLFCOSE_MAC0_CREATE)
int wc_CoseMac0_Create(const WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen)
{
    int ret = WOLFCOSE_SUCCESS;
#ifdef WOLFCOSE_HAVE_HMAC
    Hmac hmac;
    int hmacInited = 0;
    int hmacType = 0;
#endif
    uint8_t protectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t protectedLen = 0;
    size_t macStructLen = 0;
    size_t tagSz = 0;
    uint8_t tagBuf[WC_MAX_DIGEST_SIZE];
    WOLFCOSE_CBOR_CTX outCtx;
    const uint8_t* macPayload = NULL;
    size_t macPayloadLen = 0;
    uint8_t isDetached;
    size_t unprotectedEntries;

    /* Determine which payload to use for MAC. A caller wanting to authenticate
     * an empty payload passes a non-NULL zero-length buffer; an all-NULL
     * payload/detached pair is rejected below to match the other create APIs. */
    if (detachedPayload != NULL) {
        macPayload = detachedPayload;
        macPayloadLen = detachedLen;
        isDetached = 1u;
    }
    else {
        macPayload = payload;
        macPayloadLen = payloadLen;
        isDetached = 0u;
    }

    if ((key == NULL) || (scratch == NULL) ||
        (out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#ifdef WOLFCOSE_CHECK_WORD32_LEN
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((wolfCose_LenFitsWord32(payloadLen) == 0) ||
         (wolfCose_LenFitsWord32(detachedLen) == 0) ||
         (wolfCose_LenFitsWord32(extAadLen) == 0) ||
         (wolfCose_LenFitsWord32(scratchSz) == 0) ||
         (wolfCose_LenFitsWord32(outSz) == 0))) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#endif
    /* Reject ambiguous inline+detached input. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (payload != NULL) && (detachedPayload != NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    /* Require an explicit payload (inline or detached); do not silently MAC an
     * omitted payload. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (payload == NULL) && (detachedPayload == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    /* Reject inconsistent (kid, kidLen) so the kid is never silently dropped. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (((kid != NULL) && (kidLen == 0u)) ||
         ((kid == NULL) && (kidLen != 0u)))) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    if ((ret == WOLFCOSE_SUCCESS) && (key->kty != WOLFCOSE_KTY_SYMMETRIC)) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
    /* RFC 9052 §7: when key->alg is set it MUST match the message alg. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (key->alg != WOLFCOSE_ALG_UNSET) && (key->alg != alg)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

    /* Get tag size for this algorithm (works for both HMAC and AES-CBC-MAC) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_MacTagSize(alg, &tagSz);
    }

    /* Encode protected headers: {1: alg} */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EncodeProtectedHdr(alg, protectedBuf,
                                           sizeof(protectedBuf), &protectedLen);
    }

    /* Build MAC_structure in scratch using appropriate payload */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildMacStructure(protectedBuf, protectedLen,
                                          extAad, extAadLen,
                                          macPayload, macPayloadLen,
                                          scratch, scratchSz, &macStructLen);
    }

    /* Compute MAC based on algorithm type */
#ifdef WOLFCOSE_HAVE_HMAC
    if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_IsHmacAlg(alg) != 0)) {
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_HmacType(alg, &hmacType);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                hmacInited = 1;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_HmacCheckKeyLen(alg, key->key.symm.keyLen);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_HMAC_SET_KEY, -1,
                ret = wc_HmacSetKey(&hmac, hmacType, key->key.symm.key,
                                     (word32)key->key.symm.keyLen));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_HMAC_UPDATE, -1,
                ret = wc_HmacUpdate(&hmac, scratch, (word32)macStructLen));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_HMAC_FINAL, -1,
                ret = wc_HmacFinal(&hmac, tagBuf));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
    }
    else
#endif /* WOLFCOSE_HAVE_HMAC */
#ifdef WOLFCOSE_HAVE_AESMAC
    if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_IsAesCbcMacAlg(alg) != 0)) {
        size_t expectedKeyLen = 0;
        ret = wolfCose_AesCbcMacKeySize(alg, &expectedKeyLen);
        if ((ret == WOLFCOSE_SUCCESS) && (key->key.symm.keyLen != expectedKeyLen)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AesCbcMac(key->key.symm.key, key->key.symm.keyLen,
                                      scratch, macStructLen,
                                      tagBuf, tagSz);
        }
    }
    else
#endif /* WOLFCOSE_HAVE_AESMAC */
    if (ret == WOLFCOSE_SUCCESS) {
        /* Unknown algorithm */
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        /* No action required */
    }

    /* Encode COSE_Mac0 output:
     * Tag(17) [protected_bstr, unprotected_map, payload_bstr, tag_bstr]
     */
    if (ret == WOLFCOSE_SUCCESS) {
        outCtx.buf = out;
        outCtx.bufSz = outSz;
        outCtx.idx = 0;
        ret = wc_CBOR_EncodeTag(&outCtx, WOLFCOSE_TAG_MAC0);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&outCtx, 4);
    }

    /* protected headers as bstr */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&outCtx, protectedBuf, protectedLen);
    }

    /* unprotected headers map (with kid if present) */
    if (ret == WOLFCOSE_SUCCESS) {
        unprotectedEntries = (size_t)(((kid != NULL) && (kidLen > 0u)) ? 1u : 0u);
        ret = wc_CBOR_EncodeMapStart(&outCtx, unprotectedEntries);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (kid != NULL) && (kidLen > 0u)) {
        ret = wc_CBOR_EncodeUint(&outCtx, (uint64_t)WOLFCOSE_HDR_KID);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&outCtx, kid, kidLen);
        }
    }

    /* payload (nil if detached) */
    if (ret == WOLFCOSE_SUCCESS) {
        if (isDetached != 0u) {
            ret = wc_CBOR_EncodeNull(&outCtx);
        }
        else {
            ret = wc_CBOR_EncodeBstr(&outCtx, payload, payloadLen);
        }
    }

    /* tag (MAC) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&outCtx, tagBuf, tagSz);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = outCtx.idx;
    }

    /* Cleanup: always executed */
#ifdef WOLFCOSE_HAVE_HMAC
    if (hmacInited != 0) {
        (void)wc_HmacFree(&hmac);
    }
#endif
    (void)wolfCose_ForceZero(tagBuf, sizeof(tagBuf));
    if (scratch != NULL) {
        (void)wolfCose_ForceZero(scratch, scratchSz);
    }
    if ((ret != WOLFCOSE_SUCCESS) && (out != NULL)) {
        (void)wolfCose_ForceZero(out, outSz);
    }

    return ret;
}
#endif /* WOLFCOSE_MAC0_CREATE */

#if defined(WOLFCOSE_MAC0_VERIFY)
int wc_CoseMac0_Verify(const WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen)
{
    int ret = WOLFCOSE_SUCCESS;
#ifdef WOLFCOSE_HAVE_HMAC
    Hmac hmac;
    int hmacInited = 0;
    int hmacType = 0;
#endif
    WOLFCOSE_CBOR_CTX ctx;
    uint64_t tag;
    size_t arrayCount = 0;
    const uint8_t* protectedData = NULL;
    size_t protectedLen = 0;
    const uint8_t* payloadData = NULL;
    size_t payloadDataLen = 0;
    const uint8_t* macTag = NULL;
    size_t macTagLen = 0;
    size_t macStructLen = 0;
    size_t expectedTagSz = 0;
    uint8_t computedTag[WC_MAX_DIGEST_SIZE];
    int32_t alg = 0;
    WOLFCOSE_HDR_STATE hdrState;
    const uint8_t* verifyPayload = NULL;
    size_t verifyPayloadLen = 0;
    int algProtected = 0;

    if ((key == NULL) || (in == NULL) || (scratch == NULL) || (hdr == NULL) ||
        (payload == NULL) || (payloadLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#ifdef WOLFCOSE_CHECK_WORD32_LEN
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((wolfCose_LenFitsWord32(inSz) == 0) ||
         (wolfCose_LenFitsWord32(detachedLen) == 0) ||
         (wolfCose_LenFitsWord32(extAadLen) == 0) ||
         (wolfCose_LenFitsWord32(scratchSz) == 0))) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#endif

    if ((ret == WOLFCOSE_SUCCESS) && (key->kty != WOLFCOSE_KTY_SYMMETRIC)) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        (void)XMEMSET(hdr, 0, sizeof(WOLFCOSE_HDR));

        ctx.cbuf = in;
        ctx.bufSz = inSz;
        ctx.idx = 0;

        /* Optional Tag(17) */
        if ((ctx.idx < ctx.bufSz) &&
            (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TAG)) {
            ret = wc_CBOR_DecodeTag(&ctx, &tag);
            if ((ret == WOLFCOSE_SUCCESS) && (tag != WOLFCOSE_TAG_MAC0)) {
                ret = WOLFCOSE_E_COSE_BAD_TAG;
            }
        }
    }

    /* Array of 4 elements */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
        if ((ret == WOLFCOSE_SUCCESS) && (arrayCount != 4u)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }

    /* 1. Protected headers (bstr) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &protectedData, &protectedLen);
    }

    /* Parse protected headers */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeProtectedHdr(protectedData, protectedLen, hdr,
                                          &hdrState);
        if (ret == WOLFCOSE_SUCCESS) {
            algProtected = wolfCose_HdrStateContains(&hdrState,
                                                      WOLFCOSE_HDR_ALG);
        }
    }

    /* 2. Unprotected headers (map) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr, &hdrState);
    }

    /* 3. Payload (bstr or null if detached) */
    if (ret == WOLFCOSE_SUCCESS) {
        if ((ctx.idx < ctx.bufSz) && (ctx.cbuf[ctx.idx] == WOLFCOSE_CBOR_NULL)) {
            /* Payload is null - detached mode (RFC 9052 Section 2) */
            ctx.idx++; /* consume the null byte */
            payloadData = NULL;
            payloadDataLen = 0;
            hdr->flags |= WOLFCOSE_HDR_FLAG_DETACHED;

            /* Must have detached payload provided */
            if (detachedPayload == NULL) {
                ret = WOLFCOSE_E_DETACHED_PAYLOAD;
            }
            else {
                verifyPayload = detachedPayload;
                verifyPayloadLen = detachedLen;
            }
        }
        else {
            ret = wc_CBOR_DecodeBstr(&ctx, &payloadData, &payloadDataLen);
            if (ret == WOLFCOSE_SUCCESS) {
                verifyPayload = payloadData;
                verifyPayloadLen = payloadDataLen;
            }
        }
    }

    /* 4. Tag (bstr) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &macTag, &macTagLen);
    }

    /* RFC 8949 Section 5.3.1: reject trailing data after the COSE object. */
    if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != ctx.bufSz)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        alg = hdr->alg;
        /* RFC 9052 §7: key->alg, when set, must match message alg. */
        if ((key->alg != WOLFCOSE_ALG_UNSET) && (key->alg != alg)) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (key->alg == WOLFCOSE_ALG_UNSET) && (algProtected == 0)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_MacTagSize(alg, &expectedTagSz);
    }

    if ((ret == WOLFCOSE_SUCCESS) && (macTagLen != expectedTagSz)) {
        ret = WOLFCOSE_E_MAC_FAIL;
    }

    /* Rebuild MAC_structure in scratch using appropriate payload */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildMacStructure(protectedData, protectedLen,
                                          extAad, extAadLen,
                                          verifyPayload, verifyPayloadLen,
                                          scratch, scratchSz, &macStructLen);
    }

    /* Compute MAC based on algorithm type */
#ifdef WOLFCOSE_HAVE_HMAC
    if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_IsHmacAlg(alg) != 0)) {
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_HmacType(alg, &hmacType);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                hmacInited = 1;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_HmacCheckKeyLen(alg, key->key.symm.keyLen);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_HmacSetKey(&hmac, hmacType, key->key.symm.key,
                                 (word32)key->key.symm.keyLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_HmacUpdate(&hmac, scratch, (word32)macStructLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_HmacFinal(&hmac, computedTag);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
    }
    else
#endif /* WOLFCOSE_HAVE_HMAC */
#ifdef WOLFCOSE_HAVE_AESMAC
    if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_IsAesCbcMacAlg(alg) != 0)) {
        size_t expectedKeyLen = 0;
        ret = wolfCose_AesCbcMacKeySize(alg, &expectedKeyLen);
        if ((ret == WOLFCOSE_SUCCESS) && (key->key.symm.keyLen != expectedKeyLen)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AesCbcMac(key->key.symm.key, key->key.symm.keyLen,
                                      scratch, macStructLen,
                                      computedTag, expectedTagSz);
        }
    }
    else
#endif /* WOLFCOSE_HAVE_AESMAC */
    if (ret == WOLFCOSE_SUCCESS) {
        /* Unknown algorithm */
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        /* No action required */
    }

    /* Constant-time comparison */
    if (ret == WOLFCOSE_SUCCESS) {
        if (wolfCose_ConstantCompare(computedTag, macTag, (word32)expectedTagSz) != 0) {
            ret = WOLFCOSE_E_MAC_FAIL;
        }
    }

    /* Return zero-copy payload pointer into input buffer. Clear on
     * failure so callers that skip the return code do not consume
     * stale data. */
    if (ret == WOLFCOSE_SUCCESS) {
        *payload = payloadData;
        *payloadLen = payloadDataLen;
    }
    else if ((payload != NULL) && (payloadLen != NULL)) {
        *payload = NULL;
        *payloadLen = 0;
    }
    else {
        /* No action required */
    }

    wolfCose_HdrClearOnFail(ret, hdr);

    /* Cleanup: always executed */
#ifdef WOLFCOSE_HAVE_HMAC
    if (hmacInited != 0) {
        (void)wc_HmacFree(&hmac);
    }
#endif
    (void)wolfCose_ForceZero(computedTag, sizeof(computedTag));
    if (scratch != NULL) {
        (void)wolfCose_ForceZero(scratch, scratchSz);
    }

    return ret;
}
#endif /* WOLFCOSE_MAC0_VERIFY */

#endif /* (WOLFCOSE_MAC0 || WOLFCOSE_MAC) && MAC algorithm */
