/* wolfcose_encrypt.c
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
 * COSE_Encrypt multi-recipient encrypt and decrypt. RFC 9052 Section 5.1.
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


/* ----- COSE_Encrypt Multi-Recipient API (RFC 9052 Section 5.1) ----- */

#if defined(WOLFCOSE_ENCRYPT) && \
    (defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM) || \
     (defined(WOLFCOSE_HAVE_CHACHA20)))

/**
 * Build the Enc_structure for COSE_Encrypt (context = "Encrypt"):
 *   ["Encrypt", body_protected, external_aad]
 */
static int wolfCose_BuildEncStructureMulti(const uint8_t* protectedHdr,
                                            size_t protectedLen,
                                            const uint8_t* extAad,
                                            size_t extAadLen,
                                            uint8_t* scratch, size_t scratchSz,
                                            size_t* structLen)
{
    return wolfCose_BuildEncStructure(WOLFCOSE_CTX_ENCRYPT,
                                       sizeof(WOLFCOSE_CTX_ENCRYPT),
                                       protectedHdr, protectedLen,
                                       extAad, extAadLen,
                                       scratch, scratchSz, structLen);
}

static int wolfCose_ValidateRecipientKeyAlg(const WOLFCOSE_KEY* key,
    int32_t recipientAlgId, int32_t contentAlgId)
{
    int ret = WOLFCOSE_SUCCESS;

    if ((key != NULL) && (key->alg != WOLFCOSE_ALG_UNSET)) {
        int32_t expectedAlg = recipientAlgId;

        if ((expectedAlg == WOLFCOSE_ALG_UNSET) ||
            (expectedAlg == WOLFCOSE_ALG_DIRECT)) {
            expectedAlg = contentAlgId;
        }
        if (key->alg != expectedAlg) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
    }

    return ret;
}

#if defined(WOLFCOSE_ENCRYPT_ENCRYPT)
/**
 * wc_CoseEncrypt_Encrypt - Create a COSE_Encrypt message (RFC 9052 Section 5.1)
 *
 * Structure: [Headers, ciphertext, recipients: [+ COSE_recipient]]
 * Each COSE_recipient: [protected, unprotected, ciphertext]
 *
 * Recipient key management supports direct, AES Key Wrap, and ECDH-ES direct
 * modes when enabled. Direct uses a pre-shared CEK. AES Key Wrap generates one
 * CEK and wraps it separately for each recipient. ECDH-ES derives the CEK for
 * one recipient and carries the ephemeral public key in its unprotected header.
 */
int wc_CoseEncrypt_Encrypt(const WOLFCOSE_RECIPIENT* recipients,
    size_t recipientCount,
    int32_t contentAlgId,
    const uint8_t* iv, size_t ivLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_CBOR_CTX ctx;
    uint8_t protectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t protectedLen = 0;
    uint8_t recipientProtectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t recipientProtectedLen = 0;
    size_t encStructLen = 0;
#if defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM)
    Aes aes;
    int aesInited = 0;
#endif
    size_t keyLen = 0;
    size_t aeadTagLen = 0;
    size_t ciphertextLen = 0;
    const uint8_t* encryptPayload = NULL;
    size_t encryptPayloadLen = 0;
    size_t i;
    const uint8_t* encKey = NULL;
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    uint8_t cek[32];           /* Derived CEK for ECDH-ES (max 256-bit) */
    uint8_t ephemPubX[66];     /* Max for P-521 */
    uint8_t ephemPubY[66];
    size_t ephemPubLen = 0;
    int useEcdhEs = 0;
    int recipientCrv = 0;
#endif
#if defined(WOLFCOSE_KEY_WRAP)
    uint8_t cekKeyWrap[32];    /* Random CEK for key wrap (max 256-bit) */
    uint8_t wrappedCek[40];    /* Wrapped CEK (CEK + 8 bytes for wrap) */
    size_t wrappedCekLen = 0;
    int useKeyWrap = 0;
#endif

    /* Parameter validation */
    if ((recipients == NULL) || (recipientCount == 0u) ||
        (out == NULL) || (outLen == NULL) || (scratch == NULL) ||
        (iv == NULL) || (ivLen == 0u)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

#ifdef WOLFCOSE_CHECK_WORD32_LEN
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((wolfCose_LenFitsWord32(payloadLen) == 0) ||
         (wolfCose_LenFitsWord32(extAadLen) == 0) ||
         (wolfCose_LenFitsWord32(detachedLen) == 0) ||
         (wolfCose_LenFitsWord32(outSz) == 0) ||
         (wolfCose_LenFitsWord32(scratchSz) == 0))) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#endif

    /* Reject inconsistent (kid, kidLen) per recipient to avoid silently
     * dropping the identifier. */
    if (ret == WOLFCOSE_SUCCESS) {
        for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < recipientCount); i++) {
            if (((recipients[i].kid != NULL) && (recipients[i].kidLen == 0u)) ||
                ((recipients[i].kid == NULL) && (recipients[i].kidLen != 0u))) {
                ret = WOLFCOSE_E_INVALID_ARG;
            }
        }
    }

    /* Must have either payload or detached */
    if ((ret == WOLFCOSE_SUCCESS) && (payload == NULL) && (detachedPayload == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    /* Get the payload to encrypt */
    if (ret == WOLFCOSE_SUCCESS) {
        if (detachedPayload != NULL) {
            encryptPayload = detachedPayload;
            encryptPayloadLen = detachedLen;
        } else {
            encryptPayload = payload;
            encryptPayloadLen = payloadLen;
        }
    }

    /* Get key length and tag length for algorithm */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_AeadKeyLen(contentAlgId, &keyLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_AeadTagLen(contentAlgId, &aeadTagLen);
    }

#ifdef WOLFCOSE_HAVE_AESCCM
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_AeadCheckPayloadLen(contentAlgId, encryptPayloadLen);
    }
#endif

    /* Validate nonce length matches algorithm spec */
    if (ret == WOLFCOSE_SUCCESS) {
        size_t expectedNonceLen;
        ret = wolfCose_AeadNonceLen(contentAlgId, &expectedNonceLen);
        if ((ret == WOLFCOSE_SUCCESS) && (ivLen != expectedNonceLen)) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
    }

    /* Validate first recipient and determine key mode */
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_IsEcdhEsDirectAlg(recipients[0].algId) != 0)) {
        /* ECDH-ES direct is single-recipient only */
        if (recipientCount > 1u) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
        /* ECDH-ES: recipient key is EC2 public key */
        else if ((recipients[0].key == NULL) ||
            (recipients[0].key->kty != WOLFCOSE_KTY_EC2) ||
            (recipients[0].key->key.ecc == NULL)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        else if (rng == NULL) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
        else if ((recipients[0].key->alg != WOLFCOSE_ALG_UNSET) &&
                 (recipients[0].key->alg != recipients[0].algId)) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
        else {
            WOLFCOSE_KEY* recipientKey = recipients[0].key;

            recipientCrv = recipientKey->crv;

            /* Pre-encode recipient protected hdr for KDF context. */
            ret = wolfCose_EncodeProtectedHdr(recipients[0].algId,
                recipientProtectedBuf, sizeof(recipientProtectedBuf),
                &recipientProtectedLen);

            /* Derive CEK from ephemeral-static ECDH */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_EcdhEsDirect(
                    recipients[0].algId,
                    recipientKey,
                    contentAlgId,
                    keyLen,
                    recipientProtectedBuf, recipientProtectedLen,
                    ephemPubX, ephemPubY,
                    sizeof(ephemPubX), &ephemPubLen,
                    cek, sizeof(cek),
                    rng);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                useEcdhEs = 1;
                encKey = cek;
            }
        }
    }
    else
#endif
#if defined(WOLFCOSE_KEY_WRAP)
    if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_IsKeyWrapAlg(recipients[0].algId) != 0)) {
        /* AES Key Wrap: validate every recipient's KEK matches its
         * algId. Each recipient must hold its own KEK so the per-recipient
         * wrap inside the encoding loop succeeds. */
        if (rng == NULL) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
        for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < recipientCount); i++) {
            size_t kekLen = 0;
            if (wolfCose_IsKeyWrapAlg(recipients[i].algId) == 0) {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }
            else if ((recipients[i].key != NULL) &&
                     (recipients[i].key->alg != WOLFCOSE_ALG_UNSET) &&
                     (recipients[i].key->alg != recipients[i].algId)) {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }
            else if ((recipients[i].key == NULL) ||
                     (recipients[i].key->kty != WOLFCOSE_KTY_SYMMETRIC)) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else {
                ret = wolfCose_KeyWrapKeySize(recipients[i].algId, &kekLen);
                if ((ret == WOLFCOSE_SUCCESS) &&
                    (recipients[i].key->key.symm.keyLen != kekLen)) {
                    ret = WOLFCOSE_E_COSE_KEY_TYPE;
                }
            }
        }

        /* Generate one random CEK that every recipient will receive
         * wrapped under their own KEK. */
        if (ret == WOLFCOSE_SUCCESS) {
            int rngRet = wc_RNG_GenerateBlock(rng, cekKeyWrap, (word32)keyLen);
            if (rngRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            useKeyWrap = 1;
            encKey = cekKeyWrap;
        }
    }
    else
#endif
    if (ret == WOLFCOSE_SUCCESS) {
        /* Direct key: recipient key is symmetric */
        if ((recipients[0].key == NULL) ||
            (recipients[0].key->kty != WOLFCOSE_KTY_SYMMETRIC) ||
            (recipients[0].key->key.symm.keyLen != keyLen)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        else if ((recipients[0].key->alg != WOLFCOSE_ALG_UNSET) &&
                 (recipients[0].key->alg != contentAlgId)) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
        else {
            encKey = recipients[0].key->key.symm.key;
        }
        for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < recipientCount); i++) {
            /* Direct mode requires an explicit WOLFCOSE_ALG_DIRECT so a
             * zero-initialized (WOLFCOSE_ALG_UNSET) algId cannot silently
             * select the direct-CEK construction. */
            if (recipients[i].algId != WOLFCOSE_ALG_DIRECT) {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }
            else if ((recipients[i].key != NULL) &&
                     (wolfCose_ValidateRecipientKeyAlg(recipients[i].key,
                        recipients[i].algId, contentAlgId) !=
                        WOLFCOSE_SUCCESS)) {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }
            else {
                /* No action required */
            }
        }
        (void)rng;
    }
    else {
        /* No action required */
    }

    /* Encode body protected header: {1: alg} */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EncodeProtectedHdr(contentAlgId, protectedBuf,
                                           sizeof(protectedBuf), &protectedLen);
    }

    /* Build Enc_structure for AAD */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildEncStructureMulti(protectedBuf, protectedLen,
                                               extAad, extAadLen,
                                               scratch, scratchSz, &encStructLen);
    }

    /* Initialize CBOR encoder */
    if (ret == WOLFCOSE_SUCCESS) {
        ctx.buf = out;
        ctx.bufSz = outSz;
        ctx.idx = 0;

        /* Encode COSE_Encrypt tag (96) */
        ret = wc_CBOR_EncodeTag(&ctx, WOLFCOSE_TAG_ENCRYPT);
    }

    /* Start outer array [protected, unprotected, ciphertext, recipients] */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, 4u);
    }

    /* [0] protected header bstr */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, protectedBuf, protectedLen);
    }

    /* [1] unprotected header map with IV */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&ctx, 1u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, WOLFCOSE_HDR_IV);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, iv, ivLen);
    }

    /* Detached mode not supported for multi-recipient encryption */
    if ((ret == WOLFCOSE_SUCCESS) && (detachedPayload != NULL)) {
        ret = WOLFCOSE_E_UNSUPPORTED;
    }

    /* Calculate ciphertext size (plaintext + tag) */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (encryptPayloadLen > (SIZE_MAX - aeadTagLen))) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ciphertextLen = encryptPayloadLen + aeadTagLen;
    }

    /* [2] ciphertext bstr header, then encrypt in place. */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CBOR_EncodeHead(&ctx, WOLFCOSE_CBOR_BSTR, ciphertextLen);
    }
    if ((ret == WOLFCOSE_SUCCESS) && ((ctx.idx + ciphertextLen) > ctx.bufSz)) {
        ret = WOLFCOSE_E_CBOR_OVERFLOW;
    }

#ifdef WOLFCOSE_HAVE_AESGCM
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((contentAlgId == WOLFCOSE_ALG_A128GCM) ||
         (contentAlgId == WOLFCOSE_ALG_A192GCM) ||
         (contentAlgId == WOLFCOSE_ALG_A256GCM))) {
        int aesRet = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (aesRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            aesInited = 1;
            aesRet = wc_AesGcmSetKey(&aes, encKey, (word32)keyLen);
            if (aesRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                aesRet = wc_AesGcmEncrypt(&aes,
                    &ctx.buf[ctx.idx],
                    encryptPayload, (word32)encryptPayloadLen,
                    iv, (word32)ivLen,
                    &ctx.buf[ctx.idx + encryptPayloadLen],
                    (word32)aeadTagLen,
                    scratch, (word32)encStructLen);
                if (aesRet != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }
        }
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_AESCCM
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((contentAlgId == WOLFCOSE_ALG_AES_CCM_16_64_128)  ||
         (contentAlgId == WOLFCOSE_ALG_AES_CCM_16_64_256)  ||
         (contentAlgId == WOLFCOSE_ALG_AES_CCM_64_64_128)  ||
         (contentAlgId == WOLFCOSE_ALG_AES_CCM_64_64_256)  ||
         (contentAlgId == WOLFCOSE_ALG_AES_CCM_16_128_128) ||
         (contentAlgId == WOLFCOSE_ALG_AES_CCM_16_128_256) ||
         (contentAlgId == WOLFCOSE_ALG_AES_CCM_64_128_128) ||
         (contentAlgId == WOLFCOSE_ALG_AES_CCM_64_128_256))) {
        int aesRet = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (aesRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            aesInited = 1;
            aesRet = wc_AesCcmSetKey(&aes, encKey, (word32)keyLen);
            if (aesRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                aesRet = wc_AesCcmEncrypt(&aes,
                    &ctx.buf[ctx.idx],
                    encryptPayload, (word32)encryptPayloadLen,
                    iv, (word32)ivLen,
                    &ctx.buf[ctx.idx + encryptPayloadLen],
                    (word32)aeadTagLen,
                    scratch, (word32)encStructLen);
                if (aesRet != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }
        }
    }
    else
#endif
#if defined(WOLFCOSE_HAVE_CHACHA20)
    if ((ret == WOLFCOSE_SUCCESS) &&
        (contentAlgId == WOLFCOSE_ALG_CHACHA20_POLY1305)) {
        int chRet = wc_ChaCha20Poly1305_Encrypt(
            encKey, iv,
            scratch, (word32)encStructLen,
            encryptPayload, (word32)encryptPayloadLen,
            &ctx.buf[ctx.idx],
            &ctx.buf[ctx.idx + encryptPayloadLen]);
        if (chRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
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
        ctx.idx += ciphertextLen;
    }

    /* [3] recipients array */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, (uint64_t)recipientCount);
    }

    /* Encode each recipient */
    for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < recipientCount); i++) {
        /* For direct key agreement, the wrapped CEK is empty */
        /* COSE_recipient = [protected, unprotected, ciphertext] */

        /* Encode recipient protected header. RFC 9053 Section 6.1: the direct
         * key algorithm uses a zero-length protected header, so treat an
         * explicit WOLFCOSE_ALG_DIRECT the same as the unset direct case. */
        if (recipients[i].algId != WOLFCOSE_ALG_DIRECT) {
            ret = wolfCose_EncodeProtectedHdr(recipients[i].algId,
                recipientProtectedBuf, sizeof(recipientProtectedBuf),
                &recipientProtectedLen);
        } else {
            /* Direct key - no alg in protected, use empty bstr */
            recipientProtectedLen = 0;
        }

        /* Start recipient array [protected, unprotected, ciphertext] */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeArrayStart(&ctx, 3u);
        }

        /* [0] protected header bstr */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, recipientProtectedBuf, recipientProtectedLen);
        }

        /* [1] unprotected header map */
        if (ret == WOLFCOSE_SUCCESS) {
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
            if (useEcdhEs != 0) {
                /* ECDH-ES: encode kid (label 4 -> 0x04) before ephemeral
                 * key (label -1 -> 0x20) per CBOR deterministic encoding
                 * (RFC 8949 Section 4.2.1, bytewise lexicographic). */
                size_t mapEntries = 1;  /* ephemeral key always present */
                if ((recipients[i].kid != NULL) && (recipients[i].kidLen > 0u)) {
                    mapEntries++;
                }
                ret = wc_CBOR_EncodeMapStart(&ctx, mapEntries);
                if ((ret == WOLFCOSE_SUCCESS) && (recipients[i].kid != NULL) &&
                    (recipients[i].kidLen > 0u)) {
                    ret = wc_CBOR_EncodeInt(&ctx, WOLFCOSE_HDR_KID);
                    if (ret == WOLFCOSE_SUCCESS) {
                        ret = wc_CBOR_EncodeBstr(&ctx, recipients[i].kid,
                                                  recipients[i].kidLen);
                    }
                }
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wc_CBOR_EncodeInt(&ctx, WOLFCOSE_HDR_EPHEMERAL_KEY);
                }
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wolfCose_EncodeEphemeralKey(&ctx, recipientCrv,
                        ephemPubX, ephemPubLen, ephemPubY, ephemPubLen);
                }
            }
            else
#endif
            if (ret == WOLFCOSE_SUCCESS) {
                size_t mapEntries = 0u;

                if (recipients[i].algId == WOLFCOSE_ALG_DIRECT) {
                    mapEntries++;
                }
                if ((recipients[i].kid != NULL) &&
                    (recipients[i].kidLen > 0u)) {
                    mapEntries++;
                }
                ret = wc_CBOR_EncodeMapStart(&ctx, mapEntries);
                if ((ret == WOLFCOSE_SUCCESS) &&
                    (recipients[i].algId == WOLFCOSE_ALG_DIRECT)) {
                    ret = wc_CBOR_EncodeInt(&ctx, WOLFCOSE_HDR_ALG);
                    if (ret == WOLFCOSE_SUCCESS) {
                        ret = wc_CBOR_EncodeInt(&ctx, WOLFCOSE_ALG_DIRECT);
                    }
                }
                if ((ret == WOLFCOSE_SUCCESS) &&
                    (recipients[i].kid != NULL) &&
                    (recipients[i].kidLen > 0u)) {
                    ret = wc_CBOR_EncodeInt(&ctx, WOLFCOSE_HDR_KID);
                    if (ret == WOLFCOSE_SUCCESS) {
                        ret = wc_CBOR_EncodeBstr(&ctx, recipients[i].kid,
                                                recipients[i].kidLen);
                    }
                }
            }
            else {
                /* Encoding stopped after an earlier error. */
            }
        }

        /* [2] wrapped CEK (empty for direct key and ECDH-ES, computed
         * per-recipient for key wrap). */
        if (ret == WOLFCOSE_SUCCESS) {
#if defined(WOLFCOSE_KEY_WRAP)
            if (useKeyWrap != 0) {
                ret = wolfCose_KeyWrap(recipients[i].algId,
                                        recipients[i].key,
                                        cekKeyWrap, keyLen,
                                        wrappedCek, sizeof(wrappedCek),
                                        &wrappedCekLen);
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wc_CBOR_EncodeBstr(&ctx, wrappedCek, wrappedCekLen);
                }
            }
            else
#endif
            {
                ret = wc_CBOR_EncodeBstr(&ctx, NULL, 0);
            }
        }
    }

    /* Set output length on success */
    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = ctx.idx;
    }

    /* Cleanup: always scrub CEK material unconditionally */
#if defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM)
    if (aesInited != 0) {
        (void)wc_AesFree(&aes);
    }
#endif
#if defined(WOLFCOSE_KEY_WRAP)
    (void)wolfCose_ForceZero(cekKeyWrap, sizeof(cekKeyWrap));
    (void)wolfCose_ForceZero(wrappedCek, sizeof(wrappedCek));
#endif
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    (void)wolfCose_ForceZero(cek, sizeof(cek));
#endif
    if (scratch != NULL) {
        (void)wolfCose_ForceZero(scratch, scratchSz);
    }
    if ((ret != WOLFCOSE_SUCCESS) && (out != NULL)) {
        (void)wolfCose_ForceZero(out, outSz);
    }

    return ret;
}
#endif /* WOLFCOSE_ENCRYPT_ENCRYPT */

#if defined(WOLFCOSE_ENCRYPT_DECRYPT)
/**
 * wc_CoseEncrypt_Decrypt - Decrypt a COSE_Encrypt message
 */
int wc_CoseEncrypt_Decrypt(const WOLFCOSE_RECIPIENT* recipient,
    size_t recipientIndex,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedCt, size_t detachedCtLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    uint8_t* plaintext, size_t plaintextSz, size_t* plaintextLen)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_CBOR_CTX ctx;
    WOLFCOSE_CBOR_ITEM item;
    uint64_t tag = 0;
    size_t arrayCount = 0;
    const uint8_t* protectedData = NULL;
    size_t protectedLen = 0;
    const uint8_t* ciphertext = NULL;
    size_t ciphertextLen = 0;
    int ciphertextIsNull = 0;
    size_t encStructLen = 0;
    size_t recipientsCount = 0;
    size_t i;
#if defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM)
    Aes aes;
    int aesInited = 0;
#endif
    int32_t alg = 0;
    size_t keyLen = 0;
    size_t aeadTagLen = 0;
    size_t payloadLen = 0;
    const uint8_t* decKey = NULL;
    const uint8_t* recipientProtectedData = NULL;
    size_t recipientProtectedLen = 0;
    int32_t recipientAlgId = 0;
    int recipientMode = 0;
    WOLFCOSE_HDR recipientHdr;
    WOLFCOSE_HDR_STATE hdrState;
    WOLFCOSE_HDR_STATE recipientHdrState;
    int bodyAlgProtected = 0;
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    uint8_t cek[32];
    uint8_t ephemPubX[66];
    uint8_t ephemPubY[66];
    size_t ephemPubXLen = 0;
    size_t ephemPubYLen = 0;
    int ephemCrv = 0;
    int useEcdhEs = 0;
    int haveEphemKey = 0;
#endif
#if defined(WOLFCOSE_KEY_WRAP)
    uint8_t cekKeyWrap[32];
    const uint8_t* wrappedCekData = NULL;
    size_t wrappedCekLen = 0;
    size_t unwrappedCekLen = 0;
    int useKeyWrap = 0;
#endif

    /* Parameter validation */
    if ((recipient == NULL) || (in == NULL) || (inSz == 0u) ||
        (hdr == NULL) || (plaintext == NULL) || (plaintextLen == NULL) ||
        (scratch == NULL)) {
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

    if (ret == WOLFCOSE_SUCCESS) {
        (void)XMEMSET(hdr, 0, sizeof(*hdr));
        ctx.cbuf = in;
        ctx.bufSz = inSz;
        ctx.idx = 0;

        /* Optional Tag(96) */
        if ((ctx.idx < ctx.bufSz) &&
            (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TAG)) {
            ret = wc_CBOR_DecodeTag(&ctx, &tag);
            if ((ret == WOLFCOSE_SUCCESS) && (tag != WOLFCOSE_TAG_ENCRYPT)) {
                ret = WOLFCOSE_E_COSE_BAD_TAG;
            }
        }
    }

    /* Decode outer array */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (arrayCount != 4u)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }

    /* [0] protected header */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &protectedData, &protectedLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeProtectedHdr(protectedData, protectedLen, hdr,
                                          &hdrState);
        if (ret == WOLFCOSE_SUCCESS) {
            bodyAlgProtected = wolfCose_HdrStateContains(&hdrState,
                WOLFCOSE_HDR_ALG);
        }
    }

    /* [1] unprotected header */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr, &hdrState);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        alg = hdr->alg;
    }

    /* Validate IV */
    if (ret == WOLFCOSE_SUCCESS) {
        size_t expectedNonceLen;
        ret = wolfCose_AeadNonceLen(alg, &expectedNonceLen);
        if ((ret == WOLFCOSE_SUCCESS) && (hdr->ivLen != expectedNonceLen)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
    }

    /* [2] ciphertext */
    if (ret == WOLFCOSE_SUCCESS) {
        ciphertextIsNull = 0;
        if ((ctx.idx < ctx.bufSz) &&
            (ctx.cbuf[ctx.idx] == WOLFCOSE_CBOR_NULL)) {
            ciphertextIsNull = 1;
        }
        ret = wolfCose_CBOR_DecodeHead(&ctx, &item);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        if (ciphertextIsNull != 0) {
            if (detachedCt == NULL) {
                hdr->flags |= WOLFCOSE_HDR_FLAG_DETACHED;
                ret = WOLFCOSE_E_DETACHED_PAYLOAD;
            }
            else {
                ciphertext = detachedCt;
                ciphertextLen = detachedCtLen;
                hdr->flags |= WOLFCOSE_HDR_FLAG_DETACHED;
            }
        }
        else if (item.majorType == WOLFCOSE_CBOR_BSTR) {
            ciphertext = item.data;
            ciphertextLen = item.dataLen;
        }
        else {
            ret = WOLFCOSE_E_CBOR_TYPE;
        }
    }

    /* [3] recipients array */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &recipientsCount);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (recipientIndex >= recipientsCount)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    /* Skip to requested recipient */
    for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < recipientIndex); i++) {
        int32_t skippedAlg = WOLFCOSE_ALG_UNSET;

        ret = wolfCose_DecodeSkippedRecipient(&ctx, &skippedAlg);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_UpdateRecipientMode(skippedAlg, &recipientMode);
        }
    }

    /* Parse recipient array */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (arrayCount != 3u)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }

    /* [0] recipient protected header. Initialize the header state so the
     * unprotected decode below can run cross-bucket duplicate checks even when
     * the protected bucket is an empty bstr. */
    if (ret == WOLFCOSE_SUCCESS) {
        (void)XMEMSET(&recipientHdr, 0, sizeof(recipientHdr));
        wolfCose_HdrStateInit(&recipientHdrState);
        ret = wc_CBOR_DecodeBstr(&ctx, &recipientProtectedData, &recipientProtectedLen);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (recipientProtectedLen > 0u)) {
        ret = wolfCose_DecodeProtectedHdr(recipientProtectedData,
                                          recipientProtectedLen,
                                          &recipientHdr, &recipientHdrState);
    }

    /* [1] recipient unprotected header */
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    if ((ret == WOLFCOSE_SUCCESS) &&
        (wolfCose_IsEcdhEsDirectAlg(recipientHdr.alg) != 0)) {
        size_t mapCount = 0;
        size_t j;

        ret = wc_CBOR_DecodeMapStart(&ctx, &mapCount);

        if ((ret == WOLFCOSE_SUCCESS) && (mapCount > (size_t)WOLFCOSE_MAX_MAP_ITEMS)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
            mapCount = 0; /* Coverity: clear tainted loop bound */
        }

        for (j = 0; (ret == WOLFCOSE_SUCCESS) && (j < mapCount); j++) {
            int64_t label = 0;
            int recipSkipped = 0;

            ret = wolfCose_SkipIfTstrLabel(&ctx, &recipSkipped);
            if ((ret == WOLFCOSE_SUCCESS) && (recipSkipped == 0)) {
                ret = wc_CBOR_DecodeInt(&ctx, &label);
            }

            /* Reject duplicate labels within the unprotected map and labels
             * also present in the recipient protected bucket. */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_HdrStateCheckAndAdd(&recipientHdrState, label);
            }

            if ((ret == WOLFCOSE_SUCCESS) &&
                (label == WOLFCOSE_HDR_EPHEMERAL_KEY)) {
                if (haveEphemKey != 0) {
                    ret = WOLFCOSE_E_CBOR_MALFORMED;
                }
                else {
                    ret = wolfCose_DecodeEphemeralKey(&ctx, &ephemCrv,
                        ephemPubX, sizeof(ephemPubX), &ephemPubXLen,
                        ephemPubY, sizeof(ephemPubY), &ephemPubYLen);
                    if (ret == WOLFCOSE_SUCCESS) {
                        haveEphemKey = 1;
                    }
                }
            }
            else {
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wc_CBOR_Skip(&ctx);
                }
            }
        }

        if ((ret == WOLFCOSE_SUCCESS) &&
            ((ephemPubXLen == 0u) || (ephemPubYLen == 0u))) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
        if ((ret == WOLFCOSE_SUCCESS) &&
            (recipient->key != NULL) && (ephemCrv != recipient->key->crv)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            useEcdhEs = 1;
        }
    }
    else
#endif
    if (ret == WOLFCOSE_SUCCESS) {
        /* Decode the recipient unprotected map with duplicate-label tracking
         * (within the map and against the recipient protected bucket). */
        ret = wolfCose_DecodeUnprotectedHdr(&ctx, &recipientHdr,
                                            &recipientHdrState);
    }
    else {
        /* No action required */
    }

    if (ret == WOLFCOSE_SUCCESS) {
        recipientAlgId = recipientHdr.alg;
        ret = wolfCose_ValidateRecipientKeyAlg(recipient->key, recipientAlgId,
            alg);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_UpdateRecipientMode(recipientAlgId, &recipientMode);
    }

    /* Classify the recipient key-management algorithm. Only direct, ECDH-ES
     * direct, and AES key wrap are supported; reject anything else instead of
     * silently treating it as direct-key decryption. */
    if (ret == WOLFCOSE_SUCCESS) {
        int recipModeOk = 0;
        if (recipientAlgId == WOLFCOSE_ALG_DIRECT) {
            recipModeOk = 1;
        }
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
        else if (wolfCose_IsEcdhEsDirectAlg(recipientAlgId) != 0) {
            recipModeOk = 1;
        }
#endif
#if defined(WOLFCOSE_KEY_WRAP)
        else if (wolfCose_IsKeyWrapAlg(recipientAlgId) != 0) {
            recipModeOk = 1;
        }
#endif
        else {
            /* No action required */
        }
        if (recipModeOk == 0) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
    }

#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && \
    defined(HAVE_HKDF)
    /* The ECDH parser must have consumed an ephemeral key before the merged
     * unprotected alg can classify this recipient as ECDH-ES. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (wolfCose_IsEcdhEsDirectAlg(recipientAlgId) != 0) &&
        (useEcdhEs == 0)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
#endif

    /* Enforce the caller's recipient->algId policy when set. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (recipient->algId != WOLFCOSE_ALG_UNSET)) {
        if (recipient->algId != recipientAlgId) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
    }

    /* An unprotected content algorithm is safe only when direct-key policy
     * independently pins the same algorithm. Other recipient modes pin their
     * key-management algorithm, not the content algorithm. */
    if ((ret == WOLFCOSE_SUCCESS) && (bodyAlgProtected == 0) &&
        ((recipientAlgId != WOLFCOSE_ALG_DIRECT) ||
         (recipient->key == NULL) || (recipient->key->alg != alg))) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    /* RFC 9052 Section 8.5.5: direct key agreement carries exactly one
     * recipient. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (wolfCose_IsEcdhEsDirectAlg(recipientAlgId) != 0) &&
        ((recipientsCount != 1u) || (recipientIndex != 0u))) {
        ret = WOLFCOSE_E_COSE_BAD_HDR;
    }
#endif

    /* [2] wrapped CEK */
#if defined(WOLFCOSE_KEY_WRAP)
    if ((ret == WOLFCOSE_SUCCESS) &&
        (wolfCose_IsKeyWrapAlg(recipientAlgId) != 0)) {
        ret = wc_CBOR_DecodeBstr(&ctx, &wrappedCekData, &wrappedCekLen);
        if ((ret == WOLFCOSE_SUCCESS) && (wrappedCekLen < 24u)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            useKeyWrap = 1;
        }
    }
    else
#endif
    if (ret == WOLFCOSE_SUCCESS) {
        int recipientValueIsNull = 0;

        if ((ctx.idx < ctx.bufSz) &&
            (ctx.cbuf[ctx.idx] == WOLFCOSE_CBOR_NULL)) {
            recipientValueIsNull = 1;
        }
        ret = wolfCose_CBOR_DecodeHead(&ctx, &item);
        if ((ret == WOLFCOSE_SUCCESS) &&
            (recipientValueIsNull == 0) &&
            (item.majorType != WOLFCOSE_CBOR_BSTR)) {
            ret = WOLFCOSE_E_CBOR_TYPE;
        }
        else if ((ret == WOLFCOSE_SUCCESS) &&
                 (recipientValueIsNull == 0) && (item.dataLen != 0u)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
        else {
            /* No action required */
        }
    }
    else {
        /* No action required */
    }

    /* Skip remaining recipients, then reject trailing data (RFC 8949 5.3.1). */
    for (i = recipientIndex + 1u;
         (ret == WOLFCOSE_SUCCESS) && (i < recipientsCount); i++) {
        int32_t skippedAlg = WOLFCOSE_ALG_UNSET;

        ret = wolfCose_DecodeSkippedRecipient(&ctx, &skippedAlg);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_UpdateRecipientMode(skippedAlg, &recipientMode);
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != ctx.bufSz)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }

    /* Get key/tag lengths */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_AeadKeyLen(alg, &keyLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_AeadTagLen(alg, &aeadTagLen);
    }

    /* Derive/validate decryption key */
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    if ((ret == WOLFCOSE_SUCCESS) && (useEcdhEs != 0)) {
        WOLFCOSE_KEY* recipientKey = recipient->key;

        if ((recipientKey == NULL) ||
            (recipientKey->kty != WOLFCOSE_KTY_EC2) ||
            (recipientKey->key.ecc == NULL) ||
            (recipientKey->hasPrivate != 1u)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        /* X and Y coordinates for the ephemeral key must have matching
         * lengths so the same length parameter passed to the receive
         * helper applies to both. */
        if ((ret == WOLFCOSE_SUCCESS) && (ephemPubXLen != ephemPubYLen)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_EcdhEsDirectRecv(
                recipientAlgId, recipientKey,
                ephemPubX, ephemPubY, ephemPubXLen,
                alg, keyLen,
                recipientProtectedData, recipientProtectedLen,
                scratch, scratchSz,
                cek, sizeof(cek));
        }
        if (ret == WOLFCOSE_SUCCESS) {
            decKey = cek;
        }
    }
    else
#endif
#if defined(WOLFCOSE_KEY_WRAP)
    if ((ret == WOLFCOSE_SUCCESS) && (useKeyWrap != 0)) {
        if ((recipient->key == NULL) ||
            (recipient->key->kty != WOLFCOSE_KTY_SYMMETRIC)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_KeyUnwrap(recipientAlgId, recipient->key,
                                      wrappedCekData, wrappedCekLen,
                                      cekKeyWrap, sizeof(cekKeyWrap),
                                      &unwrappedCekLen);
        }
        if ((ret == WOLFCOSE_SUCCESS) && (unwrappedCekLen != keyLen)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            decKey = cekKeyWrap;
        }
    }
    else
#endif
    if (ret == WOLFCOSE_SUCCESS) {
        if ((recipient->key == NULL) ||
            (recipient->key->kty != WOLFCOSE_KTY_SYMMETRIC) ||
            (recipient->key->key.symm.keyLen != keyLen)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        else {
            decKey = recipient->key->key.symm.key;
        }
    }
    else {
        /* No action required */
    }

    /* Validate ciphertext length. Empty plaintext is valid, so the
     * ciphertext minimum is exactly the AEAD tag size. */
    if ((ret == WOLFCOSE_SUCCESS) && (ciphertextLen < aeadTagLen)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        payloadLen = ciphertextLen - aeadTagLen;
#ifdef WOLFCOSE_HAVE_AESCCM
        if (wolfCose_AeadCheckPayloadLen(alg, payloadLen) !=
                WOLFCOSE_SUCCESS) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
#endif
        if ((ret == WOLFCOSE_SUCCESS) && (payloadLen > plaintextSz)) {
            ret = WOLFCOSE_E_CBOR_OVERFLOW;
        }
    }

    /* Build Enc_structure */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildEncStructureMulti(protectedData, protectedLen,
                                               extAad, extAadLen,
                                               scratch, scratchSz, &encStructLen);
    }

    /* Decrypt with the algorithm declared in the protected header. */
#ifdef WOLFCOSE_HAVE_AESGCM
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_A128GCM) || (alg == WOLFCOSE_ALG_A192GCM) ||
         (alg == WOLFCOSE_ALG_A256GCM))) {
        int aesRet = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (aesRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            aesInited = 1;
            aesRet = wc_AesGcmSetKey(&aes, decKey, (word32)keyLen);
            if (aesRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                aesRet = wc_AesGcmDecrypt(&aes,
                    plaintext, ciphertext, (word32)payloadLen,
                    hdr->iv, (word32)hdr->ivLen,
                    &ciphertext[payloadLen], (word32)aeadTagLen,
                    scratch, (word32)encStructLen);
                if (aesRet != 0) {
                    ret = WOLFCOSE_E_COSE_DECRYPT_FAIL;
                }
            }
        }
    }
    else
#endif
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
        int aesRet = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (aesRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            aesInited = 1;
            aesRet = wc_AesCcmSetKey(&aes, decKey, (word32)keyLen);
            if (aesRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                aesRet = wc_AesCcmDecrypt(&aes,
                    plaintext, ciphertext, (word32)payloadLen,
                    hdr->iv, (word32)hdr->ivLen,
                    &ciphertext[payloadLen], (word32)aeadTagLen,
                    scratch, (word32)encStructLen);
                if (aesRet != 0) {
                    ret = WOLFCOSE_E_COSE_DECRYPT_FAIL;
                }
            }
        }
    }
    else
#endif
#if defined(WOLFCOSE_HAVE_CHACHA20)
    if ((ret == WOLFCOSE_SUCCESS) &&
        (alg == WOLFCOSE_ALG_CHACHA20_POLY1305)) {
        int chRet = wc_ChaCha20Poly1305_Decrypt(
            decKey, hdr->iv,
            scratch, (word32)encStructLen,
            ciphertext, (word32)payloadLen,
            &ciphertext[payloadLen],
            plaintext);
        if (chRet != 0) {
            ret = WOLFCOSE_E_COSE_DECRYPT_FAIL;
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

    /* Cleanup — always runs */
#if defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM)
    if (aesInited != 0) {
        (void)wc_AesFree(&aes);
    }
#endif
#if defined(WOLFCOSE_KEY_WRAP)
    (void)wolfCose_ForceZero(cekKeyWrap, sizeof(cekKeyWrap));
#endif
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    (void)wolfCose_ForceZero(cek, sizeof(cek));
#endif
    if (scratch != NULL) {
        (void)wolfCose_ForceZero(scratch, scratchSz);
    }

    if (ret != WOLFCOSE_SUCCESS) {
        if (plaintext != NULL) {
            (void)wolfCose_ForceZero(plaintext, plaintextSz);
        }
        if (plaintextLen != NULL) {
            *plaintextLen = 0u;
        }
    }
    else {
        *plaintextLen = payloadLen;
    }
    wolfCose_HdrClearOnFail(ret, hdr);

    return ret;
}
#endif /* WOLFCOSE_ENCRYPT_DECRYPT */

#endif /* WOLFCOSE_ENCRYPT && any supported AEAD */
