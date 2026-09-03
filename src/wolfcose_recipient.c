/* wolfcose_recipient.c
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
 * Key distribution: AES key wrap and ECDH-ES key agreement for
 * multi-recipient messages. RFC 9053 Section 6.
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
 * Key Distribution Algorithms (RFC 9053 Section 6)
 *
 * These helpers implement key wrapping and key agreement for multi-recipient
 * COSE_Encrypt and COSE_Mac messages.
 * ----- */

#if defined(WOLFCOSE_KEY_WRAP)
/**
 * Get AES key wrap key size for algorithm.
 * RFC 9053 Table 17: A128KW=16, A192KW=24, A256KW=32
 */
int wolfCose_KeyWrapKeySize(int32_t alg, size_t* keySz)
{
    int ret = WOLFCOSE_SUCCESS;

    if (keySz == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
            case WOLFCOSE_ALG_A128KW:
                *keySz = 16;
                break;
            case WOLFCOSE_ALG_A192KW:
                *keySz = 24;
                break;
            case WOLFCOSE_ALG_A256KW:
                *keySz = 32;
                break;
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

/**
 * Wrap a CEK using AES Key Wrap (RFC 3394).
 *
 * \param alg       Key wrap algorithm (A128KW, A192KW, A256KW)
 * \param kek       Key encryption key
 * \param cek       Content encryption key to wrap
 * \param cekLen    CEK length (must be multiple of 8, >= 16)
 * \param out       Output buffer for wrapped key
 * \param outSz     Output buffer size
 * \param outLen    Output: wrapped key length (cekLen + 8)
 * \return WOLFCOSE_SUCCESS or error code
 */
int wolfCose_KeyWrap(int32_t alg, const WOLFCOSE_KEY* kek,
                             const uint8_t* cek, size_t cekLen,
                             uint8_t* out, size_t outSz, size_t* outLen)
{
    int ret;
    size_t expectedKeySz;

    if ((kek == NULL) || (cek == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (kek->kty != WOLFCOSE_KTY_SYMMETRIC) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
    else {
        ret = wolfCose_KeyWrapKeySize(alg, &expectedKeySz);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        if (kek->key.symm.keyLen != expectedKeySz) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        else if (outSz < (cekLen + 8u)) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }
        else {
            /* No action required */
        }
    }

    if (ret == WOLFCOSE_SUCCESS) {
        int wrapRet;
        wrapRet = wc_AesKeyWrap(kek->key.symm.key, (word32)kek->key.symm.keyLen,
                                 cek, (word32)cekLen,
                                 out, (word32)outSz, NULL);
        if (wrapRet > 0) {
            *outLen = (size_t)wrapRet;
            ret = WOLFCOSE_SUCCESS;
        }
        else {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    return ret;
}

/**
 * Unwrap a CEK using AES Key Wrap (RFC 3394).
 *
 * \param alg           Key wrap algorithm
 * \param kek           Key encryption key
 * \param wrappedCek    Wrapped CEK
 * \param wrappedLen    Wrapped CEK length
 * \param cekOut        Output buffer for unwrapped CEK
 * \param cekOutSz      Output buffer size
 * \param cekLen        Output: unwrapped CEK length
 * \return WOLFCOSE_SUCCESS or error code
 */
int wolfCose_KeyUnwrap(int32_t alg, const WOLFCOSE_KEY* kek,
                               const uint8_t* wrappedCek, size_t wrappedLen,
                               uint8_t* cekOut, size_t cekOutSz, size_t* cekLen)
{
    int ret;
    size_t expectedKeySz;

    if ((kek == NULL) || (wrappedCek == NULL) || (cekOut == NULL) || (cekLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (kek->kty != WOLFCOSE_KTY_SYMMETRIC) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
    else if (wrappedLen < 24u) {
        /* Minimum wrapped key is 24 bytes (16 byte CEK + 8 byte IV) */
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    else {
        ret = wolfCose_KeyWrapKeySize(alg, &expectedKeySz);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        if (kek->key.symm.keyLen != expectedKeySz) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        else if (cekOutSz < (wrappedLen - 8u)) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }
        else {
            /* No action required */
        }
    }

    if (ret == WOLFCOSE_SUCCESS) {
        int unwrapRet;
        unwrapRet = wc_AesKeyUnWrap(kek->key.symm.key,
                                     (word32)kek->key.symm.keyLen,
                                     wrappedCek, (word32)wrappedLen,
                                     cekOut, (word32)cekOutSz, NULL);
        if (unwrapRet > 0) {
            *cekLen = (size_t)unwrapRet;
            ret = WOLFCOSE_SUCCESS;
        }
        else {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    return ret;
}
#endif /* WOLFCOSE_KEY_WRAP */

#if defined(WOLFCOSE_KEY_WRAP)
/**
 * Check if algorithm is AES Key Wrap (A128KW, A192KW, A256KW).
 */
int wolfCose_IsKeyWrapAlg(int32_t alg)
{
    return ((alg == WOLFCOSE_ALG_A128KW) ||
            (alg == WOLFCOSE_ALG_A192KW) ||
            (alg == WOLFCOSE_ALG_A256KW)) ? 1 : 0;
}
#endif /* WOLFCOSE_KEY_WRAP */

/* ECDH-ES Direct key agreement (RFC 9053 Section 6.3.1).
 * Enabled when ECC and HKDF are available. */
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
/**
 * Build COSE_KDF_Context for ECDH key derivation (RFC 9053 Section 5.2).
 *
 * PartyUInfo and PartyVInfo are each [nil, nil, nil]. SuppPubInfo contains
 * keyDataLength and the caller-supplied recipient protected header, encoded
 * as {1: algId} by the ECDH-ES callers.
 *
 * \param contentAlgId      Content encryption algorithm for derived key
 * \param keyDataLengthBits Key length in bits
 * \param recipientProtected Encoded {1: algId} recipient protected header
 * \param recipientProtectedLen Recipient protected header length
 * \param out               Output buffer
 * \param outSz             Output buffer size
 * \param outLen            Output: bytes written
 * \return WOLFCOSE_SUCCESS or error code
 */
static int wolfCose_KdfContextEncode(int32_t contentAlgId,
                                      size_t keyDataLengthBits,
                                      const uint8_t* recipientProtected,
                                      size_t recipientProtectedLen,
                                      uint8_t* out, size_t outSz,
                                      size_t* outLen)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;

    if ((out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ctx.buf = out;
        ctx.bufSz = outSz;
        ctx.idx = 0;

        /* COSE_KDF_Context = [
         *   AlgorithmID,
         *   PartyUInfo : [nil, nil, nil],
         *   PartyVInfo : [nil, nil, nil],
         *   SuppPubInfo : [keyDataLength, recipient protected]
         * ] */
        ret = wc_CBOR_EncodeArrayStart(&ctx, 4);

        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeInt(&ctx, (int64_t)contentAlgId);
        }

        /* PartyUInfo: [nil, nil, nil] */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeArrayStart(&ctx, 3);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeNull(&ctx);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeNull(&ctx);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeNull(&ctx);
        }

        /* PartyVInfo: [nil, nil, nil] */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeArrayStart(&ctx, 3);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeNull(&ctx);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeNull(&ctx);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeNull(&ctx);
        }

        /* SuppPubInfo: [keyDataLength, recipient_protected] */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeArrayStart(&ctx, 2);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)keyDataLengthBits);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, recipientProtected,
                                      recipientProtectedLen);
        }

        if (ret == WOLFCOSE_SUCCESS) {
            *outLen = ctx.idx;
        }
    }
    return ret;
}

/**
 * Perform ECDH-ES key derivation (RFC 9053 Section 6.3.1).
 *
 * Generates an ephemeral key pair, performs ECDH with recipient's public key,
 * and derives the CEK using HKDF.
 *
 * \param alg             ECDH algorithm (-25 or -26)
 * \param recipientPub    Recipient's public key
 * \param contentAlgId    Content encryption algorithm
 * \param cekLenBytes     Required CEK length in bytes
 * \param ephemPubX       Output: ephemeral public key X coordinate
 * \param ephemPubY       Output: ephemeral public key Y coordinate
 * \param ephemPubSz      Size of X/Y buffers
 * \param ephemPubLen     Output: actual coordinate length
 * \param cekOut          Output: derived CEK
 * \param cekOutSz        CEK buffer size
 * \param rng             Initialized RNG
 * \return WOLFCOSE_SUCCESS or error code
 */
int wolfCose_EcdhEsDirect(int32_t alg,
                                  WOLFCOSE_KEY* recipientPub,
                                  int32_t contentAlgId,
                                  size_t cekLenBytes,
                                  const uint8_t* recipientProtected,
                                  size_t recipientProtectedLen,
                                  uint8_t* ephemPubX, uint8_t* ephemPubY,
                                  size_t ephemPubSz, size_t* ephemPubLen,
                                  uint8_t* cekOut, size_t cekOutSz,
                                  WC_RNG* rng)
{
    int ret = WOLFCOSE_SUCCESS;
    ecc_key ephemKey;
    int ephemInited = 0;
    WC_RNG* priorRecipientRng = NULL;
    int recipientRngSwapped = 0;
    uint8_t sharedSecret[66]; /* Max for P-521 */
    word32 sharedSecretLen = sizeof(sharedSecret);
    uint8_t kdfContext[64];
    size_t kdfContextLen = 0;
    int hashType = 0;
    int wcCurve = 0;
    word32 xLen;
    word32 yLen;

    /* Parameter validation */
    if ((recipientPub == NULL) || (ephemPubX == NULL) || (ephemPubY == NULL) ||
        (ephemPubLen == NULL) || (cekOut == NULL) || (rng == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    if ((ret == WOLFCOSE_SUCCESS) && (cekLenBytes > cekOutSz)) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }

    if ((ret == WOLFCOSE_SUCCESS) &&
        ((recipientPub->kty != WOLFCOSE_KTY_EC2) ||
         (recipientPub->key.ecc == NULL))) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EccKeyCheckCurve(recipientPub->crv,
                                         recipientPub->key.ecc);
    }

    /* Determine hash type from algorithm */
    if (ret == WOLFCOSE_SUCCESS) {
        if (alg == WOLFCOSE_ALG_ECDH_ES_HKDF_256) {
            hashType = WC_SHA256;
        }
        else if (alg == WOLFCOSE_ALG_ECDH_ES_HKDF_512) {
            hashType = WC_SHA512;
        }
        else {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
    }

    /* Get wolfCrypt curve ID */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CrvToWcCurve(recipientPub->crv, &wcCurve);
    }

    /* Initialize ephemeral key */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = wc_ecc_init(&ephemKey);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            ephemInited = 1;
        }
    }

    /* Set RNG on ephemeral key for ECDH */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = wc_ecc_set_rng(&ephemKey, rng);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* Generate ephemeral key pair on same curve */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = wc_ecc_make_key_ex(rng, 0, &ephemKey, wcCurve);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* Save/restore caller's RNG slot so we do not mutate caller state. */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet;
        priorRecipientRng = recipientPub->key.ecc->rng;
        eccRet = wc_ecc_set_rng(recipientPub->key.ecc, rng);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            recipientRngSwapped = 1;
        }
    }

    /* Perform ECDH */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = -1;  /* Initialize to failure for injection testing */
        INJECT_FAILURE(WOLF_FAIL_ECDH_SHARED_SECRET, eccRet,
            eccRet = wc_ecc_shared_secret(&ephemKey, recipientPub->key.ecc,
                                           sharedSecret, &sharedSecretLen));
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* Build KDF context */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_KdfContextEncode(contentAlgId, cekLenBytes * 8u,
                                         recipientProtected,
                                         recipientProtectedLen,
                                         kdfContext, sizeof(kdfContext),
                                         &kdfContextLen);
    }

    /* Derive CEK using HKDF */
    if (ret == WOLFCOSE_SUCCESS) {
        int hkdfRet = wc_HKDF(hashType,
                               sharedSecret, sharedSecretLen,
                               NULL, 0,  /* No salt for ECDH-ES */
                               kdfContext, (word32)kdfContextLen,
                               cekOut, (word32)cekLenBytes);
        if (hkdfRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* Export ephemeral public X/Y at full curve length. */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet;
        xLen = (word32)ephemPubSz;
        yLen = (word32)ephemPubSz;
        eccRet = wc_ecc_export_public_raw(&ephemKey, ephemPubX, &xLen,
                                           ephemPubY, &yLen);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else if (xLen != yLen) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            *ephemPubLen = (size_t)xLen;
        }
    }

    /* Cleanup: always executed */
    if (ephemInited != 0) {
        int closeRet = wc_ecc_free(&ephemKey);
        if ((ret == WOLFCOSE_SUCCESS) && (closeRet != 0)) {
            ret = closeRet;
        }
    }
    if ((recipientRngSwapped != 0) && (recipientPub != NULL) &&
        (recipientPub->key.ecc != NULL)) {
        recipientPub->key.ecc->rng = priorRecipientRng;
    }
    (void)wolfCose_ForceZero(sharedSecret, sizeof(sharedSecret));

    return ret;
}

/**
 * Receive side of ECDH-ES key derivation.
 *
 * Uses recipient's private key and sender's ephemeral public key to
 * derive the CEK.
 *
 * \param alg             ECDH algorithm (-25 or -26)
 * \param recipientKey    Recipient's key (with private key)
 * \param ephemPubX       Sender's ephemeral public key X coordinate
 * \param ephemPubY       Sender's ephemeral public key Y coordinate
 * \param ephemPubLen     Coordinate length
 * \param contentAlgId    Content encryption algorithm
 * \param cekLenBytes     Required CEK length in bytes
 * \param recipientProtected Encoded recipient protected header
 * \param recipientProtectedLen Recipient protected header length
 * \param kdfContext      Scratch buffer for the encoded KDF context
 * \param kdfContextSz    KDF context scratch buffer size
 * \param cekOut          Output: derived CEK
 * \param cekOutSz        CEK buffer size
 * \return WOLFCOSE_SUCCESS or error code
 */
int wolfCose_EcdhEsDirectRecv(int32_t alg,
                                      WOLFCOSE_KEY* recipientKey,
                                      const uint8_t* ephemPubX,
                                      const uint8_t* ephemPubY,
                                      size_t ephemPubLen,
                                      int32_t contentAlgId,
                                      size_t cekLenBytes,
                                      const uint8_t* recipientProtected,
                                      size_t recipientProtectedLen,
                                      uint8_t* kdfContext,
                                      size_t kdfContextSz,
                                      uint8_t* cekOut, size_t cekOutSz)
{
    int ret = WOLFCOSE_SUCCESS;
    ecc_key ephemPub;
    int ephemInited = 0;
    uint8_t sharedSecret[66];
    word32 sharedSecretLen = sizeof(sharedSecret);
    size_t kdfContextLen = 0;
    int hashType = 0;
    int wcCurve = 0;
    WC_RNG rng;
    int rngInited = 0;
    int rngSetOnRecipient = 0;
    WC_RNG* priorRecipientRng = NULL;

    /* Parameter validation */
    if ((recipientKey == NULL) || (ephemPubX == NULL) || (ephemPubY == NULL) ||
        (kdfContext == NULL) || (cekOut == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    if ((ret == WOLFCOSE_SUCCESS) && (cekLenBytes > cekOutSz)) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }

    if ((ret == WOLFCOSE_SUCCESS) &&
        ((recipientKey->kty != WOLFCOSE_KTY_EC2) ||
         (recipientKey->key.ecc == NULL) ||
         (recipientKey->hasPrivate != 1u))) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EccKeyCheckCurve(recipientKey->crv,
                                         recipientKey->key.ecc);
    }

    /* Determine hash type from algorithm */
    if (ret == WOLFCOSE_SUCCESS) {
        if (alg == WOLFCOSE_ALG_ECDH_ES_HKDF_256) {
            hashType = WC_SHA256;
        }
        else if (alg == WOLFCOSE_ALG_ECDH_ES_HKDF_512) {
            hashType = WC_SHA512;
        }
        else {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
    }

    /* Get wolfCrypt curve ID */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CrvToWcCurve(recipientKey->crv, &wcCurve);
    }

    /* Initialize RNG for ECDH (required by wolfSSL) */
    if (ret == WOLFCOSE_SUCCESS) {
        int rngRet = wc_InitRng(&rng);
        if (rngRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            rngInited = 1;
        }
    }

    /* Import ephemeral public key */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = wc_ecc_init(&ephemPub);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            ephemInited = 1;
        }
    }

    /* Set RNG on ephemeral key */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = wc_ecc_set_rng(&ephemPub, &rng);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    if (ret == WOLFCOSE_SUCCESS) {
        byte tmpX[MAX_ECC_BYTES];
        byte tmpY[MAX_ECC_BYTES];
        size_t coordSz = 0;

        /* Accept shorter coordinates and right-justify them before import. */
        ret = wolfCose_CrvKeySize(recipientKey->crv, &coordSz);
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((ephemPubLen > coordSz) || (coordSz > sizeof(tmpX)))) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            int eccRet;
            (void)XMEMSET(tmpX, 0, sizeof(tmpX));
            (void)XMEMSET(tmpY, 0, sizeof(tmpY));
            (void)XMEMCPY(&tmpX[coordSz - ephemPubLen], ephemPubX,
                          ephemPubLen);
            (void)XMEMCPY(&tmpY[coordSz - ephemPubLen], ephemPubY,
                          ephemPubLen);
            eccRet = wc_ecc_import_unsigned(&ephemPub,
                                             tmpX, tmpY,
                                             NULL, wcCurve);
            if (eccRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                eccRet = wc_ecc_check_key(&ephemPub);
                if (eccRet != 0) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
            }
        }
    }

    /* Swap in our stack-local rng for ECDH; restore caller's on exit. */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet;
        priorRecipientRng = recipientKey->key.ecc->rng;
        eccRet = wc_ecc_set_rng(recipientKey->key.ecc, &rng);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            rngSetOnRecipient = 1;
        }
    }

    /* Perform ECDH */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = wc_ecc_shared_secret(recipientKey->key.ecc, &ephemPub,
                                           sharedSecret, &sharedSecretLen);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* Build KDF context */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_KdfContextEncode(contentAlgId, cekLenBytes * 8u,
                                         recipientProtected,
                                         recipientProtectedLen,
                                         kdfContext, kdfContextSz,
                                         &kdfContextLen);
    }

    /* Derive CEK using HKDF */
    if (ret == WOLFCOSE_SUCCESS) {
        int hkdfRet = wc_HKDF(hashType,
                               sharedSecret, sharedSecretLen,
                               NULL, 0,
                               kdfContext, (word32)kdfContextLen,
                               cekOut, (word32)cekLenBytes);
        if (hkdfRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* Cleanup: always executed */
    if (ephemInited != 0) {
        int closeRet = wc_ecc_free(&ephemPub);
        if ((ret == WOLFCOSE_SUCCESS) && (closeRet != 0)) {
            ret = closeRet;
        }
    }
    if ((rngSetOnRecipient != 0) && (recipientKey != NULL) &&
        (recipientKey->key.ecc != NULL)) {
        recipientKey->key.ecc->rng = priorRecipientRng;
    }
    if (rngInited != 0) {
        int closeRet = wc_FreeRng(&rng);
        if ((ret == WOLFCOSE_SUCCESS) && (closeRet != 0)) {
            ret = closeRet;
        }
    }
    (void)wolfCose_ForceZero(sharedSecret, sizeof(sharedSecret));

    return ret;
}

/**
 * Check if algorithm is an ECDH-ES direct algorithm.
 */
int wolfCose_IsEcdhEsDirectAlg(int32_t alg)
{
    return ((alg == WOLFCOSE_ALG_ECDH_ES_HKDF_256) ||
            (alg == WOLFCOSE_ALG_ECDH_ES_HKDF_512)) ? 1 : 0;
}

/**
 * Encode ephemeral public key as COSE_Key in recipient unprotected header.
 *
 * COSE_Key: {1: 2, -1: crv, -2: x, -3: y}
 */
int wolfCose_EncodeEphemeralKey(WOLFCOSE_CBOR_CTX* ctx,
                                        int crv,
                                        const uint8_t* x, size_t xLen,
                                        const uint8_t* y, size_t yLen)
{
    int ret;

    /* COSE_Key map with 4 entries */
    ret = wc_CBOR_EncodeMapStart(ctx, 4);
    if (ret == WOLFCOSE_SUCCESS) {
        /* kty = EC2 (2) */
        ret = wc_CBOR_EncodeInt(ctx, 1);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(ctx, WOLFCOSE_KTY_EC2);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        /* crv */
        ret = wc_CBOR_EncodeInt(ctx, -1);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(ctx, crv);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        /* x coordinate */
        ret = wc_CBOR_EncodeInt(ctx, -2);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(ctx, x, xLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        /* y coordinate */
        ret = wc_CBOR_EncodeInt(ctx, -3);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(ctx, y, yLen);
    }

    return ret;
}

/**
 * Decode ephemeral public key from COSE_Key in recipient unprotected header.
 *
 * Parses: {1: 2, -1: crv, -2: x, -3: y}
 */
int wolfCose_DecodeEphemeralKey(WOLFCOSE_CBOR_CTX* ctx,
                                        int* crv,
                                        uint8_t* x, size_t xSz, size_t* xLen,
                                        uint8_t* y, size_t ySz, size_t* yLen)
{
    int ret;
    size_t mapCount = 0;
    size_t i;
    int64_t label = 0;
    int haveCrv = 0;
    int haveX = 0;
    int haveY = 0;
    int haveKty = 0;
    const uint8_t* data;
    size_t dataLen;
    int64_t intVal;
    WOLFCOSE_HDR_STATE ephemState;
    int skipped;

    wolfCose_HdrStateInit(&ephemState);
    ret = wc_CBOR_DecodeMapStart(ctx, &mapCount);

    if ((ret == WOLFCOSE_SUCCESS) && (mapCount > (size_t)WOLFCOSE_MAX_MAP_ITEMS)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
        mapCount = 0; /* Coverity: clear tainted loop bound */
    }

    for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < mapCount); i++) {
        ret = wolfCose_SkipIfTstrLabel(ctx, &skipped);
        if ((ret == WOLFCOSE_SUCCESS) && (skipped == 0)) {
            ret = wc_CBOR_DecodeInt(ctx, &label);
        }

        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_HdrStateCheckAndAdd(&ephemState, label);
        }

        if ((ret == WOLFCOSE_SUCCESS) && (label == 1)) {
            /* kty - verify it's EC2 */
            ret = wc_CBOR_DecodeInt(ctx, &intVal);
            if ((ret == WOLFCOSE_SUCCESS) &&
                (intVal != WOLFCOSE_KTY_EC2)) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            if (ret == WOLFCOSE_SUCCESS) {
                haveKty = 1;
            }
        }
        else if ((ret == WOLFCOSE_SUCCESS) && (label == -1)) {
            /* crv */
            ret = wc_CBOR_DecodeInt(ctx, &intVal);
            if ((ret == WOLFCOSE_SUCCESS) &&
                (wolfCose_InInt32Range(intVal) == 0)) {
                ret = WOLFCOSE_E_COSE_BAD_HDR;
            }
            if (ret == WOLFCOSE_SUCCESS) {
                *crv = (int)intVal;
                haveCrv = 1;
            }
        }
        else if ((ret == WOLFCOSE_SUCCESS) && (label == -2)) {
            /* x coordinate */
            ret = wc_CBOR_DecodeBstr(ctx, &data, &dataLen);
            if (ret == WOLFCOSE_SUCCESS) {
                if (dataLen > xSz) {
                    ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                }
                else {
                    (void)XMEMCPY(x, data, dataLen);
                    *xLen = dataLen;
                    haveX = 1;
                }
            }
        }
        else if ((ret == WOLFCOSE_SUCCESS) && (label == -3)) {
            /* y coordinate */
            ret = wc_CBOR_DecodeBstr(ctx, &data, &dataLen);
            if (ret == WOLFCOSE_SUCCESS) {
                if (dataLen > ySz) {
                    ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                }
                else {
                    (void)XMEMCPY(y, data, dataLen);
                    *yLen = dataLen;
                    haveY = 1;
                }
            }
        }
        else {
            if (ret == WOLFCOSE_SUCCESS) {
                /* Unknown label - skip */
                ret = wc_CBOR_Skip(ctx);
            }
        }
    }

    if (ret == WOLFCOSE_SUCCESS) {
        if ((haveKty == 0) || (haveCrv == 0) ||
            (haveX == 0) || (haveY == 0)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
    }

    /* RFC 9053 Section 7.1.1: ephemeral EC2 coordinates are fixed length with
     * leading zeros preserved; require exact-length x and y. */
    if (ret == WOLFCOSE_SUCCESS) {
        size_t coordSz = 0;
        ret = wolfCose_CrvKeySize(*crv, &coordSz);
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((*xLen != coordSz) || (*yLen != coordSz))) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
    }

    return ret;
}

#endif /* WOLFCOSE_ECDH_ES_DIRECT && HAVE_ECC && HAVE_HKDF */

#if defined(WOLFCOSE_ENCRYPT_DECRYPT) || defined(WOLFCOSE_MAC_VERIFY)
#define WOLFCOSE_RECIP_MODE_DIRECT_ENCRYPTION 1
#define WOLFCOSE_RECIP_MODE_DIRECT_AGREEMENT  2
#define WOLFCOSE_RECIP_MODE_KEY_TRANSPORT      3

/* Enforce the recipient combinations allowed by RFC 9052 Section 8.5. */
int wolfCose_UpdateRecipientMode(int32_t alg, int* commonMode)
{
    int ret = WOLFCOSE_SUCCESS;
    int mode = 0;

    if (commonMode == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (alg == WOLFCOSE_ALG_UNSET) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else if ((alg == WOLFCOSE_ALG_DIRECT) ||
             (alg == WOLFCOSE_ALG_DIRECT_HKDF_SHA_256) ||
             (alg == WOLFCOSE_ALG_DIRECT_HKDF_SHA_512) ||
             (alg == WOLFCOSE_ALG_DIRECT_HKDF_AES_128) ||
             (alg == WOLFCOSE_ALG_DIRECT_HKDF_AES_256)) {
        mode = WOLFCOSE_RECIP_MODE_DIRECT_ENCRYPTION;
    }
    else if ((alg == WOLFCOSE_ALG_ECDH_ES_HKDF_256) ||
             (alg == WOLFCOSE_ALG_ECDH_ES_HKDF_512) ||
             (alg == WOLFCOSE_ALG_ECDH_SS_HKDF_256) ||
             (alg == WOLFCOSE_ALG_ECDH_SS_HKDF_512)) {
        mode = WOLFCOSE_RECIP_MODE_DIRECT_AGREEMENT;
    }
    else {
        mode = WOLFCOSE_RECIP_MODE_KEY_TRANSPORT;
    }

    if ((ret == WOLFCOSE_SUCCESS) && (*commonMode == 0)) {
        *commonMode = mode;
    }
    else if ((ret == WOLFCOSE_SUCCESS) &&
             ((*commonMode != mode) ||
              (mode == WOLFCOSE_RECIP_MODE_DIRECT_AGREEMENT))) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        /* No action required */
    }

    return ret;
}
#endif

/* Only meaningful where size_t can exceed word32; on smaller-or-equal size_t
 * platforms the cast cannot truncate, so the guard and helper are omitted (and
 * the condition would otherwise be a compile-time constant). */
#if (defined(WOLFCOSE_KEY_DECODE) || defined(WOLFCOSE_SIGN1) || \
     defined(WOLFCOSE_SIGN) || \
     defined(WOLFCOSE_MAC0) || defined(WOLFCOSE_MAC) || \
     defined(WOLFCOSE_ENCRYPT0) || defined(WOLFCOSE_ENCRYPT)) && \
    defined(SIZE_MAX) && (SIZE_MAX > 0xFFFFFFFFUL)
/* Reject a size_t length that cannot be represented as word32, so a structure,
 * payload, or key length fails cleanly instead of truncating when cast for
 * wolfCrypt. */
int wolfCose_LenFitsWord32(size_t n)
{
    int ret = 1;
    if (n > (size_t)0xFFFFFFFFUL) {
        ret = 0;
    }
    return ret;
}
#endif
