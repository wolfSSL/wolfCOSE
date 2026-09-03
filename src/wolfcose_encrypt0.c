/* wolfcose_encrypt0.c
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
 * COSE_Encrypt0 single-recipient encrypt and decrypt. RFC 9052 Section 5.2.
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


/* ----- COSE_Encrypt0 API ----- */

#if defined(WOLFCOSE_ENCRYPT0) && (defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM) || \
    (defined(WOLFCOSE_HAVE_CHACHA20)))

/**
 * Build the Enc_structure for COSE_Encrypt0 (wrapper for unified builder):
 *   ["Encrypt0", body_protected, external_aad]
 */
static int wolfCose_BuildEncStructure0(const uint8_t* protectedHdr,
                                        size_t protectedLen,
                                        const uint8_t* extAad,
                                        size_t extAadLen,
                                        uint8_t* scratch, size_t scratchSz,
                                        size_t* structLen)
{
    /* Use unified builder with "Encrypt0" context */
    return wolfCose_BuildEncStructure(
        WOLFCOSE_CTX_ENCRYPT0, sizeof(WOLFCOSE_CTX_ENCRYPT0),
        protectedHdr, protectedLen,
        extAad, extAadLen,
        scratch, scratchSz, structLen);
}

#if defined(WOLFCOSE_ENCRYPT0_ENCRYPT)
int wc_CoseEncrypt0_Encrypt(const WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* iv, size_t ivLen,
    const uint8_t* payload, size_t payloadLen,
    uint8_t* detachedPayload, size_t detachedSz, size_t* detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen)
{
    int ret = WOLFCOSE_SUCCESS;
#if defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM)
    Aes aes;
    int aesInited = 0;
#endif
    uint8_t protectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t protectedLen = 0;
    size_t encStructLen = 0;
    size_t aeadKeyLen = 0;
    size_t aeadTagLen = 0;
    WOLFCOSE_CBOR_CTX outCtx;
    size_t ciphertextTotalLen = 0;
    size_t ciphertextOffset;
    int isDetached;

    /* Determine if detached mode */
    if (detachedPayload != NULL) {
        isDetached = 1;
    }
    else {
        isDetached = 0;
    }

    if ((key == NULL) || (iv == NULL) || (payload == NULL) || (scratch == NULL) ||
        (out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

#ifdef WOLFCOSE_CHECK_WORD32_LEN
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((wolfCose_LenFitsWord32(payloadLen) == 0) ||
         (wolfCose_LenFitsWord32(extAadLen) == 0) ||
         (wolfCose_LenFitsWord32(detachedSz) == 0) ||
         (wolfCose_LenFitsWord32(outSz) == 0) ||
         (wolfCose_LenFitsWord32(scratchSz) == 0))) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#endif

    if ((ret == WOLFCOSE_SUCCESS) && (key->kty != WOLFCOSE_KTY_SYMMETRIC)) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
    /* Honour the key->alg pin. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (key->alg != WOLFCOSE_ALG_UNSET) && (key->alg != alg)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_AeadKeyLen(alg, &aeadKeyLen);
    }

    if ((ret == WOLFCOSE_SUCCESS) && (key->key.symm.keyLen != aeadKeyLen)) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_AeadTagLen(alg, &aeadTagLen);
    }

#ifdef WOLFCOSE_HAVE_AESCCM
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_AeadCheckPayloadLen(alg, payloadLen);
    }
#endif

    /* For detached mode, need detachedLen output and sufficient buffer */
    if ((ret == WOLFCOSE_SUCCESS) && (isDetached != 0) && ((detachedLen == NULL) ||
        (detachedSz < (payloadLen + aeadTagLen)))) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }

    /* Validate nonce length matches algorithm spec */
    if (ret == WOLFCOSE_SUCCESS) {
        size_t expectedNonceLen;
        ret = wolfCose_AeadNonceLen(alg, &expectedNonceLen);
        if ((ret == WOLFCOSE_SUCCESS) && (ivLen != expectedNonceLen)) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
    }

    /* Encode protected headers */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EncodeProtectedHdr(alg, protectedBuf,
                                           sizeof(protectedBuf), &protectedLen);
    }

    /* Build Enc_structure in scratch (used as AAD for AES-GCM) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildEncStructure0(protectedBuf, protectedLen,
                                          extAad, extAadLen,
                                          scratch, scratchSz, &encStructLen);
    }

    /* Build output COSE_Encrypt0 structure up to ciphertext */
    if (ret == WOLFCOSE_SUCCESS) {
        outCtx.buf = out;
        outCtx.bufSz = outSz;
        outCtx.idx = 0;
        ret = wc_CBOR_EncodeTag(&outCtx, WOLFCOSE_TAG_ENCRYPT0);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&outCtx, 3);
    }

    /* protected headers as bstr */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&outCtx, protectedBuf, protectedLen);
    }

    /* unprotected headers: {5: iv} */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&outCtx, 1);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&outCtx, (uint64_t)WOLFCOSE_HDR_IV);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&outCtx, iv, ivLen);
    }

    /* Ciphertext handling: attached or detached */
    if ((ret == WOLFCOSE_SUCCESS) && (payloadLen > (SIZE_MAX - aeadTagLen))) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ciphertextTotalLen = payloadLen + aeadTagLen;
    }

    /* Dispatch encryption by algorithm */
#ifdef WOLFCOSE_HAVE_AESGCM
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_A128GCM) || (alg == WOLFCOSE_ALG_A192GCM) ||
         (alg == WOLFCOSE_ALG_A256GCM))) {
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            aesInited = 1;
            INJECT_FAILURE(WOLF_FAIL_AES_GCM_SET_KEY, -1,
                ret = wc_AesGcmSetKey(&aes, key->key.symm.key, (word32)aeadKeyLen));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }

        if ((ret == WOLFCOSE_SUCCESS) && (isDetached != 0)) {
            /* Detached mode: ciphertext goes to detachedPayload buffer */
            INJECT_FAILURE(WOLF_FAIL_AES_GCM_ENCRYPT, -1,
                ret = wc_AesGcmEncrypt(&aes,
                    detachedPayload,                      /* ciphertext output */
                    payload, (word32)payloadLen,          /* plaintext input */
                    iv, (word32)ivLen,                    /* nonce */
                    &detachedPayload[payloadLen],         /* auth tag (after ct) */
                    (word32)aeadTagLen,
                    scratch, (word32)encStructLen)       /* AAD = Enc_structure */);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                /* Encode null in the message, then publish detachedLen
                 * only after the structural encode succeeds so callers
                 * never see a positive length on a failing return. */
                ret = wc_CBOR_EncodeNull(&outCtx);
                if (ret == WOLFCOSE_SUCCESS) {
                    *detachedLen = ciphertextTotalLen;
                }
            }
        }
        else if (ret == WOLFCOSE_SUCCESS) {
            /* Attached mode: ciphertext in message */
            ret = wolfCose_CBOR_EncodeHead(&outCtx, WOLFCOSE_CBOR_BSTR,
                                            (uint64_t)ciphertextTotalLen);
            /* Check there's room for ciphertext + tag */
            if ((ret == WOLFCOSE_SUCCESS) &&
                ((outCtx.idx + ciphertextTotalLen) > outCtx.bufSz)) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ciphertextOffset = outCtx.idx;
                INJECT_FAILURE(WOLF_FAIL_AES_GCM_ENCRYPT, -1,
                    ret = wc_AesGcmEncrypt(&aes,
                        &out[ciphertextOffset],              /* ciphertext output */
                        payload, (word32)payloadLen,          /* plaintext input */
                        iv, (word32)ivLen,                    /* nonce */
                        &out[ciphertextOffset + payloadLen],  /* auth tag */
                        (word32)aeadTagLen,
                        scratch, (word32)encStructLen)       /* AAD */);
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else {
                    outCtx.idx += ciphertextTotalLen;
                }
            }
        }
        else {
            /* No action required */
        }
    }
    else
#endif /* WOLFCOSE_HAVE_AESGCM */
#ifdef WOLFCOSE_HAVE_AESCCM
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_AES_CCM_16_64_128)  ||
         (alg == WOLFCOSE_ALG_AES_CCM_16_64_256)  ||
         (alg == WOLFCOSE_ALG_AES_CCM_64_64_128)  ||
         (alg == WOLFCOSE_ALG_AES_CCM_64_64_256)  ||
         (alg == WOLFCOSE_ALG_AES_CCM_16_128_128) ||
         (alg == WOLFCOSE_ALG_AES_CCM_16_128_256) ||
         (alg == WOLFCOSE_ALG_AES_CCM_64_128_128) ||
         (alg == WOLFCOSE_ALG_AES_CCM_64_128_256))) {
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            aesInited = 1;
            INJECT_FAILURE(WOLF_FAIL_AES_CCM_SET_KEY, -1,
                ret = wc_AesCcmSetKey(&aes, key->key.symm.key, (word32)aeadKeyLen));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }

        if ((ret == WOLFCOSE_SUCCESS) && (isDetached != 0)) {
            INJECT_FAILURE(WOLF_FAIL_AES_CCM_ENCRYPT, -1,
                ret = wc_AesCcmEncrypt(&aes,
                    detachedPayload,
                    payload, (word32)payloadLen,
                    iv, (word32)ivLen,
                    &detachedPayload[payloadLen],
                    (word32)aeadTagLen,
                    scratch, (word32)encStructLen));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                ret = wc_CBOR_EncodeNull(&outCtx);
                if (ret == WOLFCOSE_SUCCESS) {
                    *detachedLen = ciphertextTotalLen;
                }
            }
        }
        else if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_CBOR_EncodeHead(&outCtx, WOLFCOSE_CBOR_BSTR,
                                            (uint64_t)ciphertextTotalLen);
            if ((ret == WOLFCOSE_SUCCESS) &&
                ((outCtx.idx + ciphertextTotalLen) > outCtx.bufSz)) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ciphertextOffset = outCtx.idx;
                INJECT_FAILURE(WOLF_FAIL_AES_CCM_ENCRYPT, -1,
                    ret = wc_AesCcmEncrypt(&aes,
                        &out[ciphertextOffset],
                        payload, (word32)payloadLen,
                        iv, (word32)ivLen,
                        &out[ciphertextOffset + payloadLen],
                        (word32)aeadTagLen,
                        scratch, (word32)encStructLen));
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else {
                    outCtx.idx += ciphertextTotalLen;
                }
            }
        }
        else {
            /* No action required */
        }
    }
    else
#endif /* WOLFCOSE_HAVE_AESCCM */
#if defined(WOLFCOSE_HAVE_CHACHA20)
    if ((ret == WOLFCOSE_SUCCESS) && (alg == WOLFCOSE_ALG_CHACHA20_POLY1305)) {
        if (isDetached != 0) {
            ret = wc_ChaCha20Poly1305_Encrypt(
                key->key.symm.key, iv,
                scratch, (word32)encStructLen,
                payload, (word32)payloadLen,
                detachedPayload,
                &detachedPayload[payloadLen]);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                ret = wc_CBOR_EncodeNull(&outCtx);
                if (ret == WOLFCOSE_SUCCESS) {
                    *detachedLen = ciphertextTotalLen;
                }
            }
        }
        else {
            ret = wolfCose_CBOR_EncodeHead(&outCtx, WOLFCOSE_CBOR_BSTR,
                                            (uint64_t)ciphertextTotalLen);
            if ((ret == WOLFCOSE_SUCCESS) &&
                ((outCtx.idx + ciphertextTotalLen) > outCtx.bufSz)) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ciphertextOffset = outCtx.idx;
                ret = wc_ChaCha20Poly1305_Encrypt(
                    key->key.symm.key, iv,
                    scratch, (word32)encStructLen,
                    payload, (word32)payloadLen,
                    &out[ciphertextOffset],
                    &out[ciphertextOffset + payloadLen]);
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else {
                    outCtx.idx += ciphertextTotalLen;
                }
            }
        }
    }
    else
#endif /* WOLFCOSE_HAVE_CHACHA20 */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        /* No action required */
    }

    if ((ret == WOLFCOSE_SUCCESS) && (outLen != NULL)) {
        *outLen = outCtx.idx;
    }

    /* Cleanup: always executed */
#if defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM)
    if (aesInited != 0) {
        (void)wc_AesFree(&aes);
    }
#endif
    if (scratch != NULL) {
        (void)wolfCose_ForceZero(scratch, scratchSz);
    }
    if (ret != WOLFCOSE_SUCCESS) {
        if (out != NULL) {
            (void)wolfCose_ForceZero(out, outSz);
        }
        /* Avoid leaking partial ciphertext through the caller's detached
         * buffer; matches the symmetric guarantee on the decrypt side. */
        if ((isDetached != 0) && (detachedPayload != NULL)) {
            (void)wolfCose_ForceZero(detachedPayload, detachedSz);
        }
    }

    return ret;
}
#endif /* WOLFCOSE_ENCRYPT0_ENCRYPT */

#if defined(WOLFCOSE_ENCRYPT0_DECRYPT)
int wc_CoseEncrypt0_Decrypt(const WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedCt, size_t detachedCtLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    uint8_t* plaintext, size_t plaintextSz, size_t* plaintextLen)
{
    int ret = WOLFCOSE_SUCCESS;
#if defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM)
    Aes aes;
    int aesInited = 0;
#endif
    WOLFCOSE_CBOR_CTX ctx;
    uint64_t tag;
    size_t arrayCount = 0;
    const uint8_t* protectedData = NULL;
    size_t protectedLen = 0;
    const uint8_t* ciphertext = NULL;
    size_t ciphertextLen = 0;
    WOLFCOSE_HDR_STATE hdrState;
    size_t encStructLen = 0;
    size_t aeadKeyLen = 0;
    size_t aeadTagLen = 0;
    size_t payloadSz = 0;
    int32_t alg = 0;
    int algProtected = 0;

    if ((key == NULL) || (in == NULL) || (scratch == NULL) || (hdr == NULL) ||
        (plaintext == NULL) || (plaintextLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

#ifdef WOLFCOSE_CHECK_WORD32_LEN
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((wolfCose_LenFitsWord32(inSz) == 0) ||
         (wolfCose_LenFitsWord32(detachedCtLen) == 0) ||
         (wolfCose_LenFitsWord32(extAadLen) == 0) ||
         (wolfCose_LenFitsWord32(plaintextSz) == 0) ||
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

        /* Optional Tag(16) */
        if ((ctx.idx < ctx.bufSz) &&
            (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TAG)) {
            ret = wc_CBOR_DecodeTag(&ctx, &tag);
            if ((ret == WOLFCOSE_SUCCESS) && (tag != WOLFCOSE_TAG_ENCRYPT0)) {
                ret = WOLFCOSE_E_COSE_BAD_TAG;
            }
        }
    }

    /* Array of 3 */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
        if ((ret == WOLFCOSE_SUCCESS) && (arrayCount != 3u)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }

    /* 1. Protected headers */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &protectedData, &protectedLen);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeProtectedHdr(protectedData, protectedLen, hdr,
                                          &hdrState);
        if (ret == WOLFCOSE_SUCCESS) {
            algProtected = wolfCose_HdrStateContains(&hdrState,
                                                      WOLFCOSE_HDR_ALG);
        }
    }

    /* 2. Unprotected headers */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr, &hdrState);
    }

    /* 3. Ciphertext (bstr or null if detached) */
    if (ret == WOLFCOSE_SUCCESS) {
        if ((ctx.idx < ctx.bufSz) && (ctx.cbuf[ctx.idx] == WOLFCOSE_CBOR_NULL)) {
            /* Ciphertext is null - detached mode */
            ctx.idx++; /* consume the null byte */
            hdr->flags |= WOLFCOSE_HDR_FLAG_DETACHED;

            /* Must have detached ciphertext provided */
            if ((detachedCt == NULL) || (detachedCtLen == 0u)) {
                ret = WOLFCOSE_E_DETACHED_PAYLOAD;
            }
            else {
                ciphertext = detachedCt;
                ciphertextLen = detachedCtLen;
            }
        }
        else {
            ret = wc_CBOR_DecodeBstr(&ctx, &ciphertext, &ciphertextLen);
        }
    }

    /* RFC 8949 Section 5.3.1: reject trailing data after the COSE object. */
    if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != ctx.bufSz)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        alg = hdr->alg;
    }

    /* Honour the key->alg pin on the decrypt path. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (key->alg != WOLFCOSE_ALG_UNSET) && (key->alg != alg)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (key->alg == WOLFCOSE_ALG_UNSET) && (algProtected == 0)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_AeadKeyLen(alg, &aeadKeyLen);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_AeadTagLen(alg, &aeadTagLen);
    }

    if ((ret == WOLFCOSE_SUCCESS) && (ciphertextLen < aeadTagLen)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }

    if ((ret == WOLFCOSE_SUCCESS) && (key->key.symm.keyLen != aeadKeyLen)) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }

    /* Payload size = ciphertext minus tag */
    if (ret == WOLFCOSE_SUCCESS) {
        payloadSz = ciphertextLen - aeadTagLen;
#ifdef WOLFCOSE_HAVE_AESCCM
        if (wolfCose_AeadCheckPayloadLen(alg, payloadSz) !=
                WOLFCOSE_SUCCESS) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
#endif
        if ((ret == WOLFCOSE_SUCCESS) && (payloadSz > plaintextSz)) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }
    }

    if ((ret == WOLFCOSE_SUCCESS) &&
        ((hdr->iv == NULL) || (hdr->ivLen == 0u))) {
        ret = WOLFCOSE_E_COSE_BAD_HDR;
    }

    /* Validate nonce length matches algorithm spec */
    if (ret == WOLFCOSE_SUCCESS) {
        size_t expectedNonceLen;
        ret = wolfCose_AeadNonceLen(alg, &expectedNonceLen);
        if ((ret == WOLFCOSE_SUCCESS) && (hdr->ivLen != expectedNonceLen)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
    }

    /* Build Enc_structure as AAD */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildEncStructure0(protectedData, protectedLen,
                                          extAad, extAadLen,
                                          scratch, scratchSz, &encStructLen);
    }

    /* Dispatch decryption by algorithm */
#ifdef WOLFCOSE_HAVE_AESGCM
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_A128GCM) || (alg == WOLFCOSE_ALG_A192GCM) ||
         (alg == WOLFCOSE_ALG_A256GCM))) {
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            aesInited = 1;
            INJECT_FAILURE(WOLF_FAIL_AES_GCM_SET_KEY, -1,
                ret = wc_AesGcmSetKey(&aes, key->key.symm.key, (word32)aeadKeyLen));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_AES_GCM_DECRYPT, -1,
                ret = wc_AesGcmDecrypt(&aes,
                    plaintext,
                    ciphertext, (word32)payloadSz,
                    hdr->iv, (word32)hdr->ivLen,
                    &ciphertext[payloadSz], (word32)aeadTagLen,
                    scratch, (word32)encStructLen));
            if (ret != 0) {
                ret = WOLFCOSE_E_COSE_DECRYPT_FAIL;
            }
        }
    }
    else
#endif /* WOLFCOSE_HAVE_AESGCM */
#ifdef WOLFCOSE_HAVE_AESCCM
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_AES_CCM_16_64_128)  ||
         (alg == WOLFCOSE_ALG_AES_CCM_16_64_256)  ||
         (alg == WOLFCOSE_ALG_AES_CCM_64_64_128)  ||
         (alg == WOLFCOSE_ALG_AES_CCM_64_64_256)  ||
         (alg == WOLFCOSE_ALG_AES_CCM_16_128_128) ||
         (alg == WOLFCOSE_ALG_AES_CCM_16_128_256) ||
         (alg == WOLFCOSE_ALG_AES_CCM_64_128_128) ||
         (alg == WOLFCOSE_ALG_AES_CCM_64_128_256))) {
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            aesInited = 1;
            INJECT_FAILURE(WOLF_FAIL_AES_CCM_SET_KEY, -1,
                ret = wc_AesCcmSetKey(&aes, key->key.symm.key, (word32)aeadKeyLen));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_AES_CCM_DECRYPT, -1,
                ret = wc_AesCcmDecrypt(&aes,
                    plaintext,
                    ciphertext, (word32)payloadSz,
                    hdr->iv, (word32)hdr->ivLen,
                    &ciphertext[payloadSz], (word32)aeadTagLen,
                    scratch, (word32)encStructLen));
            if (ret != 0) {
                ret = WOLFCOSE_E_COSE_DECRYPT_FAIL;
            }
        }
    }
    else
#endif /* WOLFCOSE_HAVE_AESCCM */
#if defined(WOLFCOSE_HAVE_CHACHA20)
    if ((ret == WOLFCOSE_SUCCESS) && (alg == WOLFCOSE_ALG_CHACHA20_POLY1305)) {
        ret = wc_ChaCha20Poly1305_Decrypt(
            key->key.symm.key, hdr->iv,
            scratch, (word32)encStructLen,
            ciphertext, (word32)payloadSz,
            &ciphertext[payloadSz],
            plaintext);
        if (ret != 0) {
            ret = WOLFCOSE_E_COSE_DECRYPT_FAIL;
        }
    }
    else
#endif /* WOLFCOSE_HAVE_CHACHA20 */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        /* No action required */
    }

    if (ret == WOLFCOSE_SUCCESS) {
        *plaintextLen = payloadSz;
    }
    else if (plaintextLen != NULL) {
        *plaintextLen = 0u;
    }
    else {
        /* No action required */
    }

    wolfCose_HdrClearOnFail(ret, hdr);

    /* Cleanup: always executed */
#if defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM)
    if (aesInited != 0) {
        (void)wc_AesFree(&aes);
    }
#endif
    if (scratch != NULL) {
        (void)wolfCose_ForceZero(scratch, scratchSz);
    }
    /* Zero plaintext on failure to prevent unauthenticated data leak */
    if ((ret != WOLFCOSE_SUCCESS) && (plaintext != NULL)) {
        (void)wolfCose_ForceZero(plaintext, plaintextSz);
    }

    return ret;
}
#endif /* WOLFCOSE_ENCRYPT0_DECRYPT */

#endif /* WOLFCOSE_ENCRYPT0 && (WOLFCOSE_HAVE_AESGCM || WOLFCOSE_HAVE_AESCCM || (WOLFCOSE_HAVE_CHACHA20)) */
