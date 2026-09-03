/* wolfcose_sign.c
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
 * COSE_Sign multi-signer sign and verify. RFC 9052 Section 4.1.
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
 * COSE_Sign Multi-signer API (RFC 9052 Section 4.1)
 *
 * COSE_Sign = [ Headers, payload : bstr / nil, signatures : [+ COSE_Signature] ]
 * COSE_Signature = [ Headers, signature : bstr ]
 * ----- */

#if defined(WOLFCOSE_SIGN)

#if defined(WOLFCOSE_SIGN_SIGN)
/**
 * Create a multi-signer COSE_Sign message.
 *
 * \param signers       Array of signer configurations
 * \param signerCount   Number of signers (must be >= 1)
 * \param payload       Payload to sign
 * \param payloadLen    Payload length
 * \param detachedPayload  Detached payload (NULL if payload is embedded)
 * \param detachedLen   Detached payload length
 * \param extAad        External AAD (may be NULL)
 * \param extAadLen     External AAD length
 * \param scratch       Scratch buffer for Sig_structure
 * \param scratchSz     Scratch buffer size
 * \param out           Output buffer for COSE_Sign message
 * \param outSz         Output buffer size
 * \param outLen        Output: message length
 * \param rng           Initialized RNG
 * \return WOLFCOSE_SUCCESS or error code
 */
int wc_CoseSign_Sign(const WOLFCOSE_SIGNATURE* signers, size_t signerCount,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng)
{
    int ret = WOLFCOSE_SUCCESS;
    /* Body-protected header is always empty for multi-signer (RFC 9052
     * Section 4.1). Passing NULL with length 0 to the encoder is safe and
     * keeps the encoder's NULL-with-positive-length guard happy. */
    const uint8_t* bodyProtectedBuf = NULL;
    size_t bodyProtectedLen = 0;
    uint8_t signerProtectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t signerProtectedLen = 0;
    size_t sigStructLen = 0;
    uint8_t hashBuf[WC_MAX_DIGEST_SIZE];
    uint8_t sigBuf[132]; /* ECC/EdDSA max: ES512 = 66+66 = 132 */
    size_t sigSz = 0;
    WOLFCOSE_CBOR_CTX outCtx;
    const uint8_t* sigPayload;
    size_t sigPayloadLen;
    uint8_t isDetached;
    size_t i;
    size_t unprotectedEntries;

    /* Determine which payload to use for signature */
    if (detachedPayload != NULL) {
        sigPayload = detachedPayload;
        sigPayloadLen = detachedLen;
        isDetached = 1u;
    }
    else {
        sigPayload = payload;
        sigPayloadLen = payloadLen;
        isDetached = 0u;
    }

    if ((signers == NULL) || (signerCount == 0u) || (sigPayload == NULL) ||
        (scratch == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    /* rng is required only when a signer signs locally; a delegated signer owns
     * its randomness. */
    if ((ret == WOLFCOSE_SUCCESS) && (rng == NULL)) {
#if defined(WOLFCOSE_EXT_SIGN)
        size_t s;
        int needRng = 0;
        for (s = 0; (s < signerCount) && (needRng == 0); s++) {
            if ((signers[s].key == NULL) || (signers[s].key->signCb == NULL)) {
                needRng = 1;
            }
        }
        if (needRng != 0) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
#else
        ret = WOLFCOSE_E_INVALID_ARG;
#endif
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

    /* Fail-fast key/alg checks before any hashing. */
    for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < signerCount); i++) {
        WOLFCOSE_KEY* signerKey = signers[i].key;

        if ((signerKey == NULL) ||
            (wolfCose_KeyCanSign(signerKey) == 0)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        else if (((signers[i].kid != NULL) && (signers[i].kidLen == 0u)) ||
                 ((signers[i].kid == NULL) && (signers[i].kidLen != 0u))) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
        else if ((signerKey->alg != WOLFCOSE_ALG_UNSET) &&
                 (signerKey->alg != signers[i].algId)) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
#if defined(WOLFCOSE_EXT_SIGN)
        /* A delegated signer holds no local wolfCrypt key, so the kty and crv
         * bindings below describe something that is not here. Matches the
         * order wc_CoseSign1_Sign uses, where the ext-sign branch precedes
         * the per-algorithm ones. */
        else if (signerKey->signCb != NULL) {
            /* No action required */
        }
#endif
#ifdef WOLFCOSE_HAVE_ECDSA
        else if ((signers[i].algId == WOLFCOSE_ALG_ES256) ||
                 (signers[i].algId == WOLFCOSE_ALG_ES384) ||
                 (signers[i].algId == WOLFCOSE_ALG_ES512)) {
            int32_t expectedCrv;
            if (signers[i].algId == WOLFCOSE_ALG_ES256) {
                expectedCrv = WOLFCOSE_CRV_P256;
            }
            else if (signers[i].algId == WOLFCOSE_ALG_ES384) {
                expectedCrv = WOLFCOSE_CRV_P384;
            }
            else {
                expectedCrv = WOLFCOSE_CRV_P521;
            }
            if (signerKey->kty != WOLFCOSE_KTY_EC2) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else if (signerKey->crv != expectedCrv) {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }
            else if (wolfCose_EccKeyCheckCurve(signerKey->crv,
                        signerKey->key.ecc) != WOLFCOSE_SUCCESS) {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }
            else {
                /* No action required */
            }
        }
#endif
#if defined(WOLFCOSE_HAVE_EDDSA) || defined(WOLFCOSE_HAVE_ED448)
        else if ((signers[i].algId == WOLFCOSE_ALG_EDDSA) &&
                 (signerKey->kty != WOLFCOSE_KTY_OKP)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
#endif
#ifdef WOLFCOSE_HAVE_RSAPSS
        else if (((signers[i].algId == WOLFCOSE_ALG_PS256) ||
                  (signers[i].algId == WOLFCOSE_ALG_PS384) ||
                  (signers[i].algId == WOLFCOSE_ALG_PS512)) &&
                 (signerKey->kty != WOLFCOSE_KTY_RSA)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
#endif
#ifdef WOLFCOSE_HAVE_MLDSA
        /* RFC 9964: ML-DSA signer must be an AKP key at the algId's level. */
        else if (((signers[i].algId == WOLFCOSE_ALG_ML_DSA_44) ||
                  (signers[i].algId == WOLFCOSE_ALG_ML_DSA_65) ||
                  (signers[i].algId == WOLFCOSE_ALG_ML_DSA_87)) &&
                 (wolfCose_MlDsaCheckKey(signerKey, signers[i].algId)
                      != WOLFCOSE_SUCCESS)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
#endif
        else {
            /* No action required */
        }
    }

    /* Body protected headers: zero-length bstr for multi-signer (RFC 9052 §3.1) */
    if (ret == WOLFCOSE_SUCCESS) {
        bodyProtectedLen = 0;

        /* Start encoding COSE_Sign output */
        outCtx.buf = out;
        outCtx.bufSz = outSz;
        outCtx.idx = 0;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeTag(&outCtx, WOLFCOSE_TAG_SIGN);
    }

    /* COSE_Sign = [protected, unprotected, payload, signatures] */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&outCtx, 4);
    }

    /* 1. Body protected headers as bstr */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&outCtx, bodyProtectedBuf, bodyProtectedLen);
    }

    /* 2. Unprotected headers: empty map */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&outCtx, 0);
    }

    /* 3. Payload (nil if detached) */
    if (ret == WOLFCOSE_SUCCESS) {
        if (isDetached != 0u) {
            ret = wc_CBOR_EncodeNull(&outCtx);
        }
        else {
            ret = wc_CBOR_EncodeBstr(&outCtx, payload, payloadLen);
        }
    }

    /* 4. Signatures array */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&outCtx, signerCount);
    }

    /* Create each COSE_Signature */
    for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < signerCount); i++) {
        const WOLFCOSE_SIGNATURE* signer = &signers[i];
        WOLFCOSE_KEY* signerKey = signer->key;
        enum wc_HashType hashType = WC_HASH_TYPE_NONE;
        size_t hashLen = 0;
        const uint8_t* sigPtr = sigBuf;

        /* Hash type for the signer's algorithm. SigSize is queried
         * inside each algorithm branch so this dispatch tolerates
         * algorithms whose signature size is computed dynamically
         * (RSA-PSS) or whose entry is gated by a different feature
         * macro (ML-DSA). ML-DSA signs the Sig_structure directly
         * without a pre-hash so the hash type lookup is skipped. */
        if ((ret == WOLFCOSE_SUCCESS) &&
#if defined(WOLFCOSE_EXT_SIGN)
            (signerKey->signCb == NULL) &&
#endif
            (signer->algId != WOLFCOSE_ALG_ML_DSA_44) &&
            (signer->algId != WOLFCOSE_ALG_ML_DSA_65) &&
            (signer->algId != WOLFCOSE_ALG_ML_DSA_87)) {
            ret = wolfCose_AlgToHashType(signer->algId, &hashType);
        }

        /* Encode signer's protected headers: {1: alg} */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_EncodeProtectedHdr(signer->algId, signerProtectedBuf,
                                               sizeof(signerProtectedBuf),
                                               &signerProtectedLen);
        }

        /* Build Sig_structure for this signer (context = "Signature") */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_BuildToBeSignedMaced(
                WOLFCOSE_CTX_SIGNATURE, sizeof(WOLFCOSE_CTX_SIGNATURE),
                bodyProtectedBuf, bodyProtectedLen,
                signerProtectedBuf, signerProtectedLen,
                extAad, extAadLen,
                sigPayload, sigPayloadLen,
                scratch, scratchSz, &sigStructLen);
        }

        /* Hash the Sig_structure for algorithms that pre-hash. EdDSA
         * and ML-DSA sign the structure directly, and a delegated signer
         * does its own hashing inside wolfCose_ExtSign. */
        if ((ret == WOLFCOSE_SUCCESS) &&
#if defined(WOLFCOSE_EXT_SIGN)
            (signerKey->signCb == NULL) &&
#endif
            (signer->algId != WOLFCOSE_ALG_EDDSA) &&
            (signer->algId != WOLFCOSE_ALG_ML_DSA_44) &&
            (signer->algId != WOLFCOSE_ALG_ML_DSA_65) &&
            (signer->algId != WOLFCOSE_ALG_ML_DSA_87)) {
            int digestSz = wc_HashGetDigestSize(hashType);
            if (digestSz <= 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                hashLen = (size_t)digestSz;
                ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                               hashBuf, (word32)hashLen);
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }
        }

        /* Sign the hash */
#if defined(WOLFCOSE_EXT_SIGN)
        if ((ret == WOLFCOSE_SUCCESS) && (signerKey->signCb != NULL)) {
            size_t extSigLen = 0;
            size_t sigOff = 0;
            int extPreHash = 0;

            /* Same placement rule as wc_CoseSign1_Sign: only an in-place
             * Sig_structure signer needs the structure kept intact. */
            ret = wolfCose_ExtSignAlg(signer->algId, &extPreHash);
            if (ret == WOLFCOSE_SUCCESS) {
                sigOff = (extPreHash != 0) ? 0u : sigStructLen;
                if (scratchSz <= sigOff) {
                    ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                }
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_ExtSign(signerKey, signer->algId,
                                        scratch, sigStructLen,
                                        &scratch[sigOff],
                                        scratchSz - sigOff, &extSigLen);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                sigPtr = &scratch[sigOff];
                sigSz = extSigLen;
            }
        }
        else
#endif
#ifdef WOLFCOSE_HAVE_ECDSA
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((signer->algId == WOLFCOSE_ALG_ES256) ||
             (signer->algId == WOLFCOSE_ALG_ES384) ||
             (signer->algId == WOLFCOSE_ALG_ES512))) {
            size_t coordSz = 0;
            ret = wolfCose_CrvKeySize(signerKey->crv, &coordSz);
            if (ret == WOLFCOSE_SUCCESS) {
                sigSz = coordSz * 2u;
                ret = wolfCose_EccSignRaw(hashBuf, hashLen,
                                           sigBuf, &sigSz, coordSz,
                                           hashType, rng,
                                           signerKey->key.ecc);
            }
        }
        else
#endif
#if defined(WOLFCOSE_HAVE_EDDSA) || defined(WOLFCOSE_HAVE_ED448)
        if ((ret == WOLFCOSE_SUCCESS) &&
            (signer->algId == WOLFCOSE_ALG_EDDSA)) {
            word32 edSigSz = (word32)sizeof(sigBuf);
#ifdef WOLFCOSE_HAVE_EDDSA
            if (signerKey->crv == WOLFCOSE_CRV_ED25519) {
                if (signerKey->key.ed25519 == NULL) {
                    ret = WOLFCOSE_E_COSE_KEY_TYPE;
                }
                else {
                    ret = wc_ed25519_sign_msg(scratch, (word32)sigStructLen,
                                               sigBuf, &edSigSz,
                                               signerKey->key.ed25519);
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
                    else {
                        sigSz = (size_t)edSigSz;
                    }
                }
            }
            else
#endif
#ifdef WOLFCOSE_HAVE_ED448
            if (signerKey->crv == WOLFCOSE_CRV_ED448) {
                if (signerKey->key.ed448 == NULL) {
                    ret = WOLFCOSE_E_COSE_KEY_TYPE;
                }
                else {
                    ret = wc_ed448_sign_msg(scratch, (word32)sigStructLen,
                                             sigBuf, &edSigSz,
                                             signerKey->key.ed448, NULL, 0);
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
                    else {
                        sigSz = (size_t)edSigSz;
                    }
                }
            }
            else
#endif
            {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }
        }
        else
#endif /* WOLFCOSE_HAVE_EDDSA || WOLFCOSE_HAVE_ED448 */
#ifdef WOLFCOSE_HAVE_RSAPSS
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((signer->algId == WOLFCOSE_ALG_PS256) ||
             (signer->algId == WOLFCOSE_ALG_PS384) ||
             (signer->algId == WOLFCOSE_ALG_PS512))) {
            int mgf = 0;
            ret = wolfCose_RsaPssCheckKey(signerKey, NULL);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_HashToMgf(hashType, &mgf);
            }
            /* hash has been computed into hashBuf; scratch is free for
             * the signature output. */
            if (ret == WOLFCOSE_SUCCESS) {
                word32 rsaSigLen = (word32)scratchSz;
                ret = wc_RsaPSS_Sign_ex(hashBuf, (word32)hashLen,
                                          scratch, rsaSigLen,
                                          hashType, mgf, (int)hashLen,
                                          signerKey->key.rsa, rng);
                if (ret <= 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else {
                    sigSz = (size_t)ret;
                    sigPtr = scratch;
                    ret = WOLFCOSE_SUCCESS;
                }
            }
        }
        else
#endif /* WOLFCOSE_HAVE_RSAPSS */
#ifdef WOLFCOSE_HAVE_MLDSA
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((signer->algId == WOLFCOSE_ALG_ML_DSA_44) ||
             (signer->algId == WOLFCOSE_ALG_ML_DSA_65) ||
             (signer->algId == WOLFCOSE_ALG_ML_DSA_87))) {
            size_t expectedSigSz = 0;
            /* RFC 9964: AKP key whose level matches the algorithm. */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_MlDsaCheckKey(signerKey, signer->algId);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_SigSize(signer->algId, &expectedSigSz);
            }
            /* Sig output goes after Sig_structure in scratch. */
            if ((ret == WOLFCOSE_SUCCESS) &&
                ((sigStructLen + expectedSigSz) > scratchSz)) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            if (ret == WOLFCOSE_SUCCESS) {
                word32 dlSigLen = (word32)expectedSigSz;
                ret = wc_MlDsaKey_SignCtx(
                    signerKey->key.mldsa, NULL, 0,
                    &scratch[sigStructLen], &dlSigLen,
                    scratch, (word32)sigStructLen, rng);
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else {
                    sigPtr = &scratch[sigStructLen];
                    sigSz = (size_t)dlSigLen;
                }
            }
        }
        else
#endif /* WOLFCOSE_HAVE_MLDSA */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
        else {
            /* No action required */
        }

        /* Encode COSE_Signature: [protected, unprotected, signature] */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeArrayStart(&outCtx, 3);
        }

        /* Signer protected headers */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&outCtx, signerProtectedBuf,
                                      signerProtectedLen);
        }

        /* Signer unprotected headers (may include kid). Match Sign1/Mac0
         * by requiring both kid and kidLen to be present. */
        if (ret == WOLFCOSE_SUCCESS) {
            unprotectedEntries = (size_t)(((signer->kid != NULL) &&
                                            (signer->kidLen > 0u))
                                          ? 1u : 0u);
            ret = wc_CBOR_EncodeMapStart(&outCtx, unprotectedEntries);
        }

        if ((ret == WOLFCOSE_SUCCESS) &&
            (signer->kid != NULL) && (signer->kidLen > 0u)) {
            ret = wc_CBOR_EncodeUint(&outCtx, WOLFCOSE_HDR_KID);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeBstr(&outCtx, signer->kid, signer->kidLen);
            }
        }

        /* Signature */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&outCtx, sigPtr, sigSz);
        }
    }

    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = outCtx.idx;
    }

    /* Cleanup: always executed */
    (void)wolfCose_ForceZero(hashBuf, sizeof(hashBuf));
    (void)wolfCose_ForceZero(sigBuf, sizeof(sigBuf));
    if (scratch != NULL) {
        (void)wolfCose_ForceZero(scratch, scratchSz);
    }
    if (ret != WOLFCOSE_SUCCESS) {
        if (out != NULL) {
            (void)wolfCose_ForceZero(out, outSz);
        }
        /* out is zeroed above, so a stale length would describe nothing. */
        if (outLen != NULL) {
            *outLen = 0;
        }
    }

    return ret;
}
#endif /* WOLFCOSE_SIGN_SIGN */

#if defined(WOLFCOSE_SIGN_VERIFY)
/**
 * Verify a specific signer's signature in a COSE_Sign message.
 *
 * \param verifyKey     Key to verify with
 * \param signerIndex   Index of signer to verify (0-based)
 * \param in            COSE_Sign message
 * \param inSz          Message length
 * \param detachedPayload  Detached payload (NULL if embedded)
 * \param detachedLen   Detached payload length
 * \param extAad        External AAD (may be NULL)
 * \param extAadLen     External AAD length
 * \param scratch       Scratch buffer
 * \param scratchSz     Scratch buffer size
 * \param hdr           Output: parsed headers
 * \param payload       Output: pointer to payload in buffer
 * \param payloadLen    Output: payload length
 * \return WOLFCOSE_SUCCESS or error code
 */
int wc_CoseSign_Verify(const WOLFCOSE_KEY* verifyKey,
    size_t signerIndex,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_CBOR_CTX ctx;
    uint64_t tag;
    size_t arrayCount = 0;
    const uint8_t* bodyProtectedData = NULL;
    size_t bodyProtectedLen = 0;
    const uint8_t* payloadData = NULL;
    size_t payloadDataLen = 0;
    size_t signatureCount = 0;
    const uint8_t* signerProtectedData = NULL;
    size_t signerProtectedLen = 0;
    const uint8_t* signature = NULL;
    size_t signatureLen = 0;
    size_t sigStructLen = 0;
    uint8_t hashBuf[WC_MAX_DIGEST_SIZE];
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    size_t hashLen = 0;
    int32_t alg = 0;
    const uint8_t* verifyPayload = NULL;
    size_t verifyPayloadLen = 0;
    size_t i;
    WOLFCOSE_HDR signerHdr;
    WOLFCOSE_HDR_STATE hdrState;
    WOLFCOSE_HDR_STATE signerHdrState;
    int signerAlgProtected = 0;

    if ((verifyKey == NULL) || (in == NULL) || (scratch == NULL) || (hdr == NULL) ||
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

    if (ret == WOLFCOSE_SUCCESS) {
        (void)XMEMSET(hdr, 0, sizeof(WOLFCOSE_HDR));

        ctx.cbuf = in;
        ctx.bufSz = inSz;
        ctx.idx = 0;

        /* Optional Tag(98) */
        if ((ctx.idx < ctx.bufSz) &&
            (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TAG)) {
            ret = wc_CBOR_DecodeTag(&ctx, &tag);
            if ((ret == WOLFCOSE_SUCCESS) && (tag != WOLFCOSE_TAG_SIGN)) {
                ret = WOLFCOSE_E_COSE_BAD_TAG;
            }
        }
    }

    /* Array of 4 elements: [protected, unprotected, payload, signatures] */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (arrayCount != 4u)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }

    /* 1. Body protected headers (bstr) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &bodyProtectedData, &bodyProtectedLen);
    }

    /* Parse body protected headers */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeProtectedHdr(bodyProtectedData, bodyProtectedLen,
                                          hdr, &hdrState);
    }

    /* 2. Body unprotected headers (map) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr, &hdrState);
    }

    /* 3. Payload (bstr or null if detached) */
    if (ret == WOLFCOSE_SUCCESS) {
        if ((ctx.idx < ctx.bufSz) && (ctx.cbuf[ctx.idx] == WOLFCOSE_CBOR_NULL)) {
            ctx.idx++;
            payloadData = NULL;
            payloadDataLen = 0;
            hdr->flags |= WOLFCOSE_HDR_FLAG_DETACHED;

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

    /* 4. Signatures array */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &signatureCount);
        if ((ret == WOLFCOSE_SUCCESS) && (signerIndex >= signatureCount)) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
    }

    /* Skip to the requested signer */
    for (i = 0; (i < signerIndex) && (ret == WOLFCOSE_SUCCESS); i++) {
        ret = wolfCose_DecodeSkippedSignature(&ctx);
    }

    /* Parse the target COSE_Signature: [protected, unprotected, signature] */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
        if ((ret == WOLFCOSE_SUCCESS) && (arrayCount != 3u)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }

    /* Signer protected headers */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &signerProtectedData, &signerProtectedLen);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        (void)XMEMSET(&signerHdr, 0, sizeof(signerHdr));
        ret = wolfCose_DecodeProtectedHdr(signerProtectedData, signerProtectedLen,
                                          &signerHdr, &signerHdrState);
        if (ret == WOLFCOSE_SUCCESS) {
            signerAlgProtected = wolfCose_HdrStateContains(&signerHdrState,
                WOLFCOSE_HDR_ALG);
        }
    }

    /* Signer unprotected headers. Decode with duplicate-label tracking so a
     * malformed signer header (repeated labels, or labels also present in the
     * signer protected bucket) is rejected. */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeUnprotectedHdr(&ctx, &signerHdr, &signerHdrState);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        alg = signerHdr.alg;
    }

    /* An unprotected alg is safe only when constrained by key policy. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (verifyKey->alg == WOLFCOSE_ALG_UNSET) &&
        (signerAlgProtected == 0)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

    /* Honour the verifyKey->alg pin. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (verifyKey->alg != WOLFCOSE_ALG_UNSET) &&
        (verifyKey->alg != alg)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

    /* Signature */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &signature, &signatureLen);
    }

    /* Skip remaining signers, then reject trailing data (RFC 8949 5.3.1). */
    for (i = signerIndex + 1u; (i < signatureCount) && (ret == WOLFCOSE_SUCCESS);
         i++) {
        ret = wolfCose_DecodeSkippedSignature(&ctx);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != ctx.bufSz)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }

    /* Build Sig_structure for verification */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildToBeSignedMaced(
            WOLFCOSE_CTX_SIGNATURE, sizeof(WOLFCOSE_CTX_SIGNATURE),
            bodyProtectedData, bodyProtectedLen,
            signerProtectedData, signerProtectedLen,
            extAad, extAadLen,
            verifyPayload, verifyPayloadLen,
            scratch, scratchSz, &sigStructLen);
    }

    /* Get hash type for algorithms that pre-hash. EdDSA and ML-DSA
     * verify against the raw Sig_structure so the hash type lookup is
     * skipped (also avoids WOLFCOSE_E_COSE_BAD_ALG for ML-DSA since
     * the algorithm has no external hash). */
    if ((ret == WOLFCOSE_SUCCESS) && (alg != WOLFCOSE_ALG_EDDSA) &&
        (alg != WOLFCOSE_ALG_ML_DSA_44) &&
        (alg != WOLFCOSE_ALG_ML_DSA_65) &&
        (alg != WOLFCOSE_ALG_ML_DSA_87)) {
        ret = wolfCose_AlgToHashType(alg, &hashType);
    }

    /* Hash the Sig_structure for algorithms that pre-hash. EdDSA and
     * ML-DSA verify the structure directly. */
    if ((ret == WOLFCOSE_SUCCESS) && (alg != WOLFCOSE_ALG_EDDSA) &&
        (alg != WOLFCOSE_ALG_ML_DSA_44) &&
        (alg != WOLFCOSE_ALG_ML_DSA_65) &&
        (alg != WOLFCOSE_ALG_ML_DSA_87)) {
        int digestSz = wc_HashGetDigestSize(hashType);
        if (digestSz <= 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            hashLen = (size_t)digestSz;
            ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                           hashBuf, (word32)hashLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
    }

    /* Verify signature. Dispatch by alg (consistent with Sign1_Verify) and
     * cross-validate the verify-key type against the algorithm. */
#ifdef WOLFCOSE_HAVE_ECDSA
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_ES256) || (alg == WOLFCOSE_ALG_ES384) ||
         (alg == WOLFCOSE_ALG_ES512))) {
        ecc_key* eccKey = NULL;
        int verified = 0;
        size_t coordSz = 0;
        int32_t expectedCrv;
        if (verifyKey->kty != WOLFCOSE_KTY_EC2) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (alg == WOLFCOSE_ALG_ES256) {
            expectedCrv = WOLFCOSE_CRV_P256;
        }
        else if (alg == WOLFCOSE_ALG_ES384) {
            expectedCrv = WOLFCOSE_CRV_P384;
        }
        else {
            expectedCrv = WOLFCOSE_CRV_P521;
        }
        if ((ret == WOLFCOSE_SUCCESS) && (verifyKey->crv != expectedCrv)) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            eccKey = verifyKey->key.ecc;
            ret = wolfCose_EccKeyCheckCurve(verifyKey->crv,
                                             eccKey);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_CrvKeySize(verifyKey->crv, &coordSz);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_EccVerifyRaw(signature, signatureLen,
                                         hashBuf, hashLen, coordSz,
                                         eccKey, &verified);
        }
        if ((ret == WOLFCOSE_SUCCESS) && (verified != 1)) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
        }
    }
    else
#endif
#if defined(WOLFCOSE_HAVE_EDDSA) || defined(WOLFCOSE_HAVE_ED448)
    if ((ret == WOLFCOSE_SUCCESS) && (alg == WOLFCOSE_ALG_EDDSA)) {
        int verified = 0;
        if (verifyKey->kty != WOLFCOSE_KTY_OKP) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
#ifdef WOLFCOSE_HAVE_EDDSA
        if ((ret == WOLFCOSE_SUCCESS) &&
            (verifyKey->crv == WOLFCOSE_CRV_ED25519)) {
            ed25519_key* ed25519Key = verifyKey->key.ed25519;

            if (ed25519Key == NULL) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else {
                ret = wc_ed25519_verify_msg(signature, (word32)signatureLen,
                                             scratch, (word32)sigStructLen,
                                             &verified, ed25519Key);
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }
        }
        else
#endif
#ifdef WOLFCOSE_HAVE_ED448
        if ((ret == WOLFCOSE_SUCCESS) &&
            (verifyKey->crv == WOLFCOSE_CRV_ED448)) {
            ed448_key* ed448Key = verifyKey->key.ed448;

            if (ed448Key == NULL) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else {
                ret = wc_ed448_verify_msg(signature, (word32)signatureLen,
                                           scratch, (word32)sigStructLen,
                                           &verified, ed448Key,
                                           NULL, 0);
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
#endif /* WOLFCOSE_HAVE_EDDSA || WOLFCOSE_HAVE_ED448 */
#ifdef WOLFCOSE_HAVE_RSAPSS
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_PS256) || (alg == WOLFCOSE_ALG_PS384) ||
         (alg == WOLFCOSE_ALG_PS512))) {
        RsaKey* rsaKey = NULL;
        int mgf = 0;
        ret = wolfCose_RsaPssCheckKey(verifyKey, NULL);
        if (ret == WOLFCOSE_SUCCESS) {
            rsaKey = verifyKey->key.rsa;
            ret = wolfCose_HashToMgf(hashType, &mgf);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            if (signatureLen > scratchSz) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            (void)XMEMCPY(scratch, signature, signatureLen);
            ret = wc_RsaPSS_VerifyCheck(scratch, (word32)signatureLen,
                                          scratch, (word32)scratchSz,
                                          hashBuf, (word32)hashLen,
                                          hashType, mgf, rsaKey);
            if (ret < 0) {
                ret = WOLFCOSE_E_COSE_SIG_FAIL;
            }
            else {
                ret = WOLFCOSE_SUCCESS;
            }
        }
    }
    else
#endif /* WOLFCOSE_HAVE_RSAPSS */
#ifdef WOLFCOSE_HAVE_MLDSA
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_ML_DSA_44) || (alg == WOLFCOSE_ALG_ML_DSA_65) ||
         (alg == WOLFCOSE_ALG_ML_DSA_87))) {
        wc_MlDsaKey* mldsaKey = NULL;
        int verified = 0;
        /* RFC 9964: AKP key whose level matches the algorithm. */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_MlDsaCheckKey(verifyKey, alg);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            mldsaKey = verifyKey->key.mldsa;
            ret = wc_MlDsaKey_VerifyCtx(
                mldsaKey,
                signature, (word32)signatureLen,
                NULL, 0,
                scratch, (word32)sigStructLen,
                &verified);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if ((ret == WOLFCOSE_SUCCESS) && (verified != 1)) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
        }
    }
    else
#endif /* WOLFCOSE_HAVE_MLDSA */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        /* No action required */
    }

    /* Success - return payload pointer. On failure clear outputs so a
     * caller that skips the return-code check does not consume stale
     * data from a prior invocation. */
    if (ret == WOLFCOSE_SUCCESS) {
        *payload = payloadData;
        *payloadLen = payloadDataLen;
        hdr->alg = alg; /* Set algorithm from verified signer */
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
    (void)wolfCose_ForceZero(hashBuf, sizeof(hashBuf));
    if (scratch != NULL) {
        (void)wolfCose_ForceZero(scratch, scratchSz);
    }

    return ret;
}
#endif /* WOLFCOSE_SIGN_VERIFY */

#endif /* WOLFCOSE_SIGN */
