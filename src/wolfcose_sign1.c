/* wolfcose_sign1.c
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
 * COSE_Sign1 single-signer sign and verify. RFC 9052 Section 4.2.
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
#include <limits.h>


/* ----- COSE_Sign1 API ----- */

/* Used by both COSE_Sign1 and COSE_Sign, so kept outside the
 * WOLFCOSE_SIGN1 region below, but narrowed to the signing and verifying
 * operations that actually call them. */
#if defined(WOLFCOSE_HAVE_MLDSA) && \
    (defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_SIGN1_VERIFY) || \
     defined(WOLFCOSE_SIGN_SIGN) || defined(WOLFCOSE_SIGN_VERIFY) || \
     defined(WOLFCOSE_COUNTERSIGN_SIGN) || \
     defined(WOLFCOSE_COUNTERSIGN_VERIFY))
/* Map an ML-DSA COSE algorithm to the FIPS 204 security level its key must
 * report, so a key of the wrong level cannot satisfy a higher-level alg. */
static int wolfCose_MlDsaAlgLevel(int32_t alg, byte* level)
{
    int ret = WOLFCOSE_SUCCESS;

    switch (alg) {
        case WOLFCOSE_ALG_ML_DSA_44:
            *level = 2;
            break;
        case WOLFCOSE_ALG_ML_DSA_65:
            *level = 3;
            break;
        case WOLFCOSE_ALG_ML_DSA_87:
            *level = 5;
            break;
        default:
            ret = WOLFCOSE_E_COSE_BAD_ALG;
            break;
    }
    return ret;
}

/* RFC 9964: validate that an ML-DSA key is AKP-typed and reports the level
 * required by alg. Replaces the old OKP+crv level binding. */
int wolfCose_MlDsaCheckKey(const WOLFCOSE_KEY* key, int32_t alg)
{
    int ret;
    byte reqLevel = 0;

    if ((key == NULL) || (key->kty != WOLFCOSE_KTY_AKP) ||
        (key->attachedType != WOLFCOSE_ATT_MLDSA) ||
        (key->key.mldsa == NULL)) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
    else {
        ret = wolfCose_MlDsaAlgLevel(alg, &reqLevel);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((byte)key->key.mldsa->level != reqLevel)) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_MLDSA */

#if defined(WOLFCOSE_HAVE_LMS) && \
    (defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_SIGN1_VERIFY) || \
     defined(WOLFCOSE_SIGN_SIGN) || defined(WOLFCOSE_SIGN_VERIFY) || \
     defined(WOLFCOSE_COUNTERSIGN_SIGN) || defined(WOLFCOSE_EXT_SIGN))
/* RFC 8778: validate that the key is HSS-LMS-typed and was attached through
 * wc_CoseKey_SetLms() so the union member is known to be an LmsKey. */
int wolfCose_LmsCheckKey(const WOLFCOSE_KEY* key)
{
    int ret = WOLFCOSE_SUCCESS;

    if ((key == NULL) || (key->kty != WOLFCOSE_KTY_HSS_LMS) ||
        (key->attachedType != WOLFCOSE_ATT_LMS) || (key->key.lms == NULL)) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_LMS */

#if defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_SIGN_SIGN) || \
    defined(WOLFCOSE_COUNTERSIGN_SIGN) || defined(WOLFCOSE_EXT_SIGN)
/* Exact signature length for this key and algorithm. wolfCose_SigSize() alone
 * reports EdDSA's worst case rather than the key's curve, and has no RSA case.
 * Fails closed when the exact length cannot be determined. */
int wolfCose_SignSigLen(const WOLFCOSE_KEY* key, int32_t alg,
                        size_t* expSigLen)
{
    int ret;

    (void)key;

    switch (alg) {
#if (defined(WOLFCOSE_HAVE_EDDSA) || defined(WOLFCOSE_HAVE_ED448)) && \
    defined(WOLFCOSE_HAVE_DEPRECATED_ALGS)
        case WOLFCOSE_ALG_EDDSA:
            if (key == NULL) {
#if defined(WOLFCOSE_HAVE_EDDSA) && defined(WOLFCOSE_HAVE_ED448)
                ret = WOLFCOSE_E_INVALID_ARG;
#elif defined(WOLFCOSE_HAVE_EDDSA)
                *expSigLen = 64;
                ret = WOLFCOSE_SUCCESS;
#else
                *expSigLen = 114;
                ret = WOLFCOSE_SUCCESS;
#endif
            }
            else if (key->kty != WOLFCOSE_KTY_OKP) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
#ifdef WOLFCOSE_HAVE_EDDSA
            else if (key->crv == WOLFCOSE_CRV_ED25519) {
                *expSigLen = 64;
                ret = WOLFCOSE_SUCCESS;
            }
#endif
#ifdef WOLFCOSE_HAVE_ED448
            else if (key->crv == WOLFCOSE_CRV_ED448) {
                *expSigLen = 114;
                ret = WOLFCOSE_SUCCESS;
            }
#endif
            else {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            break;
#endif
#ifdef WOLFCOSE_HAVE_RSAPSS
#ifdef WOLFCOSE_HAVE_PS256
        case WOLFCOSE_ALG_PS256:
#endif
#ifdef WOLFCOSE_HAVE_PS384
        case WOLFCOSE_ALG_PS384:
#endif
#ifdef WOLFCOSE_HAVE_PS512
        case WOLFCOSE_ALG_PS512:
#endif
        {
            ret = wolfCose_RsaPssCheckKey(key, expSigLen);
        }
        break;
#endif
#if defined(WOLFCOSE_HAVE_LMS) && \
    (defined(WOLFCOSE_EXT_SIGN) || !defined(WOLFSSL_LMS_VERIFY_ONLY))
        case WOLFCOSE_ALG_HSS_LMS:
        {
            /* The exact length lives in the attached key's parameter set,
             * so an LMS key must be attached even for a delegated signer.
             * wc_LmsKey_GetSigLen is available in verify-only builds, so a
             * delegated signer can size an LMS signature there too. */
            ret = wolfCose_LmsCheckKey(key);
            if (ret == WOLFCOSE_SUCCESS) {
                word32 lmsSigLen = 0;
                if (wc_LmsKey_GetSigLen(key->key.lms, &lmsSigLen) != 0) {
                    ret = WOLFCOSE_E_COSE_KEY_TYPE;
                }
                else {
                    *expSigLen = (size_t)lmsSigLen;
                }
            }
        }
        break;
#endif
        default:
            ret = wolfCose_SigSize(alg, expSigLen);
#if defined(WOLFCOSE_HAVE_ECDSA) || defined(WOLFCOSE_HAVE_EDDSA) || \
    defined(WOLFCOSE_HAVE_ED448)
            /* Lengths come from alg alone, so a declared curve would
             * otherwise be ignored here while the local path rejects it.
             * kty or crv 0 means the caller declared none, which stays legal;
             * an alg outside the ECDSA and EdDSA families binds no curve. */
            if ((ret == WOLFCOSE_SUCCESS) && (key != NULL)) {
                int32_t expectedCrv = 0;
                int32_t expectedKty = 0;
                int bound = wolfCose_AlgToCrv(alg, &expectedCrv);

                if (wolfCose_AlgIsEcdsa(alg) != 0) {
                    expectedKty = WOLFCOSE_KTY_EC2;
                }
                else if (wolfCose_AlgIsEddsa(alg) != 0) {
                    expectedKty = WOLFCOSE_KTY_OKP;
                }
                else {
                    /* No action required: alg binds no key type. */
                }
                if ((bound == WOLFCOSE_SUCCESS) && (expectedCrv != 0) &&
                    (expectedKty != 0)) {
                    if ((key->kty != 0) && (key->kty != expectedKty)) {
                        ret = WOLFCOSE_E_COSE_KEY_TYPE;
                    }
                    else if ((key->crv != 0) && (key->crv != expectedCrv)) {
                        ret = WOLFCOSE_E_COSE_BAD_ALG;
                    }
                    else {
                        /* No action required */
                    }
                }
            }
#endif
            break;
    }
    return ret;
}
#endif

/* Delegated signing is reachable from COSE_Sign1 and COSE_Sign alike,
 * so these live outside the WOLFCOSE_SIGN1 region below. */
#if defined(WOLFCOSE_EXT_SIGN)
/* Reject algorithms this build lacks; report whether alg pre-hashes. */
int wolfCose_ExtSignAlg(int32_t alg, WOLFCOSE_PREHASH_FLAG* preHashes)
{
    int ret = WOLFCOSE_SUCCESS;

    switch (alg) {
#if defined(WOLFCOSE_HAVE_ES256)
#ifdef WOLFCOSE_HAVE_DEPRECATED_ALGS
        case WOLFCOSE_ALG_ES256:
#endif
        case WOLFCOSE_ALG_ESP256:
            *preHashes = (WOLFCOSE_PREHASH_FLAG)1u;
            break;
#endif
#if defined(WOLFCOSE_HAVE_ES384)
#ifdef WOLFCOSE_HAVE_DEPRECATED_ALGS
        case WOLFCOSE_ALG_ES384:
#endif
        case WOLFCOSE_ALG_ESP384:
            *preHashes = (WOLFCOSE_PREHASH_FLAG)1u;
            break;
#endif
#if defined(WOLFCOSE_HAVE_ES512)
#ifdef WOLFCOSE_HAVE_DEPRECATED_ALGS
        case WOLFCOSE_ALG_ES512:
#endif
        case WOLFCOSE_ALG_ESP512:
            *preHashes = (WOLFCOSE_PREHASH_FLAG)1u;
            break;
#endif
#if defined(WOLFCOSE_HAVE_PS256)
        case WOLFCOSE_ALG_PS256:
            *preHashes = (WOLFCOSE_PREHASH_FLAG)1u;
            break;
#endif
#if defined(WOLFCOSE_HAVE_PS384)
        case WOLFCOSE_ALG_PS384:
            *preHashes = (WOLFCOSE_PREHASH_FLAG)1u;
            break;
#endif
#if defined(WOLFCOSE_HAVE_PS512)
        case WOLFCOSE_ALG_PS512:
            *preHashes = (WOLFCOSE_PREHASH_FLAG)1u;
            break;
#endif
#if (defined(WOLFCOSE_HAVE_EDDSA) || defined(WOLFCOSE_HAVE_ED448)) && \
    defined(WOLFCOSE_HAVE_DEPRECATED_ALGS)
        case WOLFCOSE_ALG_EDDSA:
#endif
#if defined(WOLFCOSE_HAVE_EDDSA)
        case WOLFCOSE_ALG_ED25519:
#endif
#if defined(WOLFCOSE_HAVE_ED448)
        case WOLFCOSE_ALG_ED448:
#endif
#if defined(WOLFCOSE_HAVE_EDDSA) || defined(WOLFCOSE_HAVE_ED448)
            *preHashes = (WOLFCOSE_PREHASH_FLAG)0u;
            break;
#endif
#if defined(WOLFCOSE_HAVE_MLDSA)
        case WOLFCOSE_ALG_ML_DSA_44:
        case WOLFCOSE_ALG_ML_DSA_65:
        case WOLFCOSE_ALG_ML_DSA_87:
            *preHashes = (WOLFCOSE_PREHASH_FLAG)0u;
            break;
#endif
#if defined(WOLFCOSE_HAVE_LMS)
        /* Delegated signing only needs the length and dispatch, not the local
         * wc_LmsKey_Sign, so this stays available in verify-only builds. */
        case WOLFCOSE_ALG_HSS_LMS:
            *preHashes = (WOLFCOSE_PREHASH_FLAG)0u;
            break;
#endif
        default:
            ret = WOLFCOSE_E_COSE_BAD_ALG;
            break;
    }
    return ret;
}

int wolfCose_ExtSign(const WOLFCOSE_KEY* key, int32_t alg,
                      const uint8_t* sigStruct, size_t sigStructLen,
                      uint8_t* sig, size_t sigSz, size_t* sigLen)
{
    int ret = WOLFCOSE_SUCCESS;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    uint8_t hashBuf[WC_MAX_DIGEST_SIZE];
    const uint8_t* tbs = sigStruct;
    size_t tbsLen = sigStructLen;
    size_t expSigLen = 0;
    WOLFCOSE_PREHASH_FLAG preHashes = (WOLFCOSE_PREHASH_FLAG)0u;

    if ((key == NULL) || (key->signCb == NULL) || (sigStruct == NULL) ||
        (sig == NULL) || (sigLen == NULL) || (sigSz == 0u)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    /* Reject algorithms this build does not support. */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_ExtSignAlg(alg, &preHashes);
    }

    if ((ret == WOLFCOSE_SUCCESS) && (preHashes != 0u)) {
        int digestSz = 0;

        ret = wolfCose_AlgToHashType(alg, &hashType);

        if (ret == WOLFCOSE_SUCCESS) {
            digestSz = wc_HashGetDigestSize(hashType);
            if (digestSz <= 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_HASH, -1,
                ret = wc_Hash(hashType, sigStruct, (word32)sigStructLen,
                               hashBuf, (word32)digestSz));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            tbs = hashBuf;
            tbsLen = (size_t)digestSz;
        }
    }

    /* Reject an undersized buffer before handing it to caller code, so a
     * fixed-output callback cannot overrun it. Every algorithm the seam
     * accepts has a determinable length, so an error here is fatal rather
     * than a reason to skip the check. */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_SignSigLen(key, alg, &expSigLen);
        if ((ret == WOLFCOSE_SUCCESS) && (sigSz < expSigLen)) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }
    }

    if (ret == WOLFCOSE_SUCCESS) {
        int cbRet = 0;

        *sigLen = 0;
        /* This buffer usually overlaps the Sig_structure, which embeds the
         * payload. A callback that reports the full length but writes fewer
         * bytes would otherwise publish that plaintext as signature bytes. */
        (void)wolfCose_ForceZero(sig, expSigLen);
        /* Offer exactly the expected length, not the whole scratch, so a
         * callback that pads to its capacity cannot reach the rest of it.
         * INJECT_FAILURE assigns ret, not cbRet, hence the normalised code. */
        INJECT_FAILURE(WOLF_FAIL_EXT_SIGN, WOLFCOSE_E_CRYPTO,
            cbRet = key->signCb(key->signCtx, alg, tbs, tbsLen,
                                 sig, expSigLen, sigLen));
        if (cbRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* A callback is caller code: do not trust its length. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((*sigLen == 0u) || (*sigLen > sigSz))) {
        ret = WOLFCOSE_E_CRYPTO;
    }

    /* Every supported algorithm emits a fixed length, so a mismatch means the
     * callback is wrong regardless of which family it belongs to. */
    if ((ret == WOLFCOSE_SUCCESS) && (*sigLen != expSigLen)) {
        ret = WOLFCOSE_E_CRYPTO;
    }

    (void)wolfCose_ForceZero(hashBuf, sizeof(hashBuf));
    return ret;
}
#endif /* WOLFCOSE_EXT_SIGN */

#if defined(WOLFCOSE_SIGN1)

/**
 * Build the Sig_structure for COSE_Sign1 (wrapper for unified builder):
 *   ["Signature1", body_protected, external_aad, payload]
 */
static int wolfCose_BuildSigStructure(const uint8_t* protectedHdr,
                                       size_t protectedLen,
                                       const uint8_t* extAad, size_t extAadLen,
                                       const uint8_t* payload,
                                       size_t payloadLen,
                                       uint8_t* scratch, size_t scratchSz,
                                       size_t* structLen)
{
    /* Use unified builder with "Signature1" context, no sign_protected */
    return wolfCose_BuildToBeSignedMaced(
        WOLFCOSE_CTX_SIGNATURE1, sizeof(WOLFCOSE_CTX_SIGNATURE1),
        protectedHdr, protectedLen,
        NULL, 0,  /* no sign_protected for Sign1 */
        extAad, extAadLen,
        payload, payloadLen,
        scratch, scratchSz, structLen);
}



#if defined(WOLFCOSE_SIGN1_SIGN)
int wc_CoseSign1_SignSize_ex(const WOLFCOSE_KEY* key, int32_t alg,
    size_t kidLen, size_t payloadLen, size_t detachedLen,
    uint32_t flags, size_t* outLen)
{
    uint8_t protectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t protectedLen = 0u;
    size_t sigLen = 0u;
    size_t itemLen = 0u;
    size_t total = 0u;
    int ret = WOLFCOSE_SUCCESS;

    if (outLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        *outLen = 0u;
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & ~(uint32_t)WOLFCOSE_SIGN1_UNTAGGED) != 0u)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    if ((ret == WOLFCOSE_SUCCESS) && (payloadLen != 0u) &&
        (detachedLen != 0u)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#ifdef WOLFCOSE_CHECK_WORD32_LEN
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((wolfCose_LenFitsWord32(payloadLen) == 0) ||
         (wolfCose_LenFitsWord32(detachedLen) == 0))) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#endif
    if ((ret == WOLFCOSE_SUCCESS) && (key != NULL) &&
        (key->alg != WOLFCOSE_ALG_UNSET) && (key->alg != alg)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_SignSigLen(key, alg, &sigLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EncodeProtectedHdr(alg, protectedBuf,
                                          sizeof(protectedBuf),
                                          &protectedLen);
    }

    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & WOLFCOSE_SIGN1_UNTAGGED) == 0u)) {
        ret = wolfCose_SizeAdd(&total, 1u); /* tag 18 */
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_SizeAdd(&total, 1u); /* array(4) */
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CborStringSize(protectedLen, &itemLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_SizeAdd(&total, itemLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_SizeAdd(&total, 1u); /* map(0) or map(1) */
    }
    if ((ret == WOLFCOSE_SUCCESS) && (kidLen != 0u)) {
        ret = wolfCose_SizeAdd(&total, 1u); /* kid label 4 */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_CborStringSize(kidLen, &itemLen);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_SizeAdd(&total, itemLen);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        if (detachedLen != 0u) {
            ret = wolfCose_SizeAdd(&total, 1u); /* null payload */
        }
        else {
            ret = wolfCose_CborStringSize(payloadLen, &itemLen);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_SizeAdd(&total, itemLen);
            }
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CborStringSize(sigLen, &itemLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_SizeAdd(&total, itemLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = total;
    }

    return ret;
}

int wc_CoseSign1_Sign(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng)
{
    return wc_CoseSign1_Sign_ex(key, alg, kid, kidLen, payload, payloadLen,
                                detachedPayload, detachedLen, extAad,
                                extAadLen, scratch, scratchSz, out, outSz,
                                outLen, rng, 0u);
}

int wc_CoseSign1_Sign_ex(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng, uint32_t flags)
{
    int ret = WOLFCOSE_SUCCESS;
    uint8_t protectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t protectedLen = 0;
    size_t sigStructLen = 0;
    size_t sigSz = 0;
    uint8_t hashBuf[WC_MAX_DIGEST_SIZE];
    uint8_t sigBuf[132]; /* ECC/EdDSA max: ES512 = 66+66 = 132 */
    const uint8_t* sigPtr = sigBuf; /* points to sigBuf or scratch for RSA */
    WOLFCOSE_CBOR_CTX outCtx;
    size_t unprotectedEntries;
    const uint8_t* sigPayload;
    size_t sigPayloadLen;
    uint8_t isDetached;

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

#if defined(WOLFCOSE_EXT_SIGN)
    if ((key == NULL) || (sigPayload == NULL) || (scratch == NULL) ||
        (out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    /* An external signer owns its own randomness, so rng is required only when
     * wolfCrypt does the signing. */
    if ((ret == WOLFCOSE_SUCCESS) && (key->signCb == NULL) && (rng == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#else
    if ((key == NULL) || (sigPayload == NULL) || (scratch == NULL) ||
        (out == NULL) || (outLen == NULL) || (rng == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#endif
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & ~(uint32_t)WOLFCOSE_SIGN1_UNTAGGED) != 0u)) {
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
    /* Reject inconsistent (kid, kidLen) pairs to surface caller mistakes
     * instead of silently dropping the kid header. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (((kid != NULL) && (kidLen == 0u)) ||
         ((kid == NULL) && (kidLen != 0u)))) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    /* Caller may not pass both an inline payload and a detached payload. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (payload != NULL) && (detachedPayload != NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_KeyCanSign(key) == 0)) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
    /* Honour the key->alg pin. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (key->alg != WOLFCOSE_ALG_UNSET) && (key->alg != alg)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

    /* Encode protected headers: {1: alg} */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EncodeProtectedHdr(alg, protectedBuf,
                                           sizeof(protectedBuf), &protectedLen);
    }

    /* Build Sig_structure in scratch using appropriate payload */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildSigStructure(protectedBuf, protectedLen,
                                          extAad, extAadLen,
                                          sigPayload, sigPayloadLen,
                                          scratch, scratchSz, &sigStructLen);
    }

#if defined(WOLFCOSE_HAVE_LMS)
    /* HSS-LMS is one-time state whether signed locally or through a delegated
     * callback. A too-small out is otherwise caught only at the encode step
     * below, after the signature is spent and a retry burns another. Reject it
     * before any signing runs, ahead of the local-vs-delegated dispatch. */
    if ((ret == WOLFCOSE_SUCCESS) && (alg == WOLFCOSE_ALG_HSS_LMS)) {
        size_t neededOut = 0;
        ret = wc_CoseSign1_SignSize_ex(key, alg, kidLen, payloadLen,
                                       detachedLen, flags, &neededOut);
        if ((ret == WOLFCOSE_SUCCESS) && (outSz < neededOut)) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }
    }
#endif /* WOLFCOSE_HAVE_LMS */

    /* Sign based on algorithm */
#if defined(WOLFCOSE_EXT_SIGN)
    if ((ret == WOLFCOSE_SUCCESS) && (key->signCb != NULL)) {
        size_t extSigLen = 0;
        size_t sigOff = 0;
        WOLFCOSE_PREHASH_FLAG extPreHash =
            (WOLFCOSE_PREHASH_FLAG)0u;

        /* A pre-hashing algorithm has its digest copied out before the
         * callback runs, so the signature may reuse the whole scratch.
         * EdDSA and ML-DSA sign the Sig_structure in place, so there the
         * signature has to start past it. */
        ret = wolfCose_ExtSignAlg(alg, &extPreHash);
        if (ret == WOLFCOSE_SUCCESS) {
            sigOff = (extPreHash != 0u) ? 0u : sigStructLen;
            if (scratchSz <= sigOff) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_ExtSign(key, alg, scratch, sigStructLen,
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
#if defined(WOLFCOSE_HAVE_EDDSA) || defined(WOLFCOSE_HAVE_ED448)
    if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_AlgIsEddsa(alg) != 0)) {
        word32 edSigLen = (word32)sizeof(sigBuf);
        if (key->kty != WOLFCOSE_KTY_OKP) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AlgCheckCrv(alg, key->crv);
        }
        /* EdDSA signs raw Sig_structure (no pre-hash) */
        if (ret == WOLFCOSE_SUCCESS) {
#ifdef WOLFCOSE_HAVE_EDDSA
            if (key->crv == WOLFCOSE_CRV_ED25519) {
                if ((key->attachedType != WOLFCOSE_ATT_ED25519) ||
                    (key->key.ed25519 == NULL)) {
                    ret = WOLFCOSE_E_COSE_KEY_TYPE;
                }
                else {
                    INJECT_FAILURE(WOLF_FAIL_ED25519_SIGN, -1,
                        ret = wc_ed25519_sign_msg(scratch,
                            (word32)sigStructLen,
                            sigBuf, &edSigLen, key->key.ed25519));
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
                    else {
                        sigSz = (size_t)edSigLen;
                    }
                }
            }
            else
#endif
#ifdef WOLFCOSE_HAVE_ED448
            if (key->crv == WOLFCOSE_CRV_ED448) {
                if ((key->attachedType != WOLFCOSE_ATT_ED448) ||
                    (key->key.ed448 == NULL)) {
                    ret = WOLFCOSE_E_COSE_KEY_TYPE;
                }
                else {
                    INJECT_FAILURE(WOLF_FAIL_ED448_SIGN, -1,
                        ret = wc_ed448_sign_msg(scratch,
                            (word32)sigStructLen,
                            sigBuf, &edSigLen, key->key.ed448, NULL, 0));
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
                    else {
                        sigSz = (size_t)edSigLen;
                    }
                }
            }
            else
#endif
            {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }
        }
    }
    else
#endif /* WOLFCOSE_HAVE_EDDSA || WOLFCOSE_HAVE_ED448 */
#ifdef WOLFCOSE_HAVE_ECDSA
    if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_AlgIsEcdsa(alg) != 0)) {
        enum wc_HashType hashType;
        int digestSz = 0;
        size_t coordSz = 0;

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
                ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                               hashBuf, (word32)digestSz));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }

        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_CrvKeySize(key->crv, &coordSz);
        }

        if (ret == WOLFCOSE_SUCCESS) {
            size_t rawSigLen = sizeof(sigBuf);
            ret = wolfCose_EccSignRaw(hashBuf, (size_t)digestSz,
                                       sigBuf, &rawSigLen, coordSz,
                                       hashType, rng, key->key.ecc);
            if (ret == WOLFCOSE_SUCCESS) {
                sigSz = rawSigLen;
            }
        }
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_RSAPSS
    if ((ret == WOLFCOSE_SUCCESS) && ((alg == WOLFCOSE_ALG_PS256) ||
        (alg == WOLFCOSE_ALG_PS384) || (alg == WOLFCOSE_ALG_PS512))) {
        enum wc_HashType hashType;
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

        /* Hash Sig_structure */
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_HASH, -1,
                ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                               hashBuf, (word32)digestSz));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }

        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_HashToMgf(hashType, &mgf);
        }

        /* RSA sig goes into scratch (after hashing, scratch is free) */
        if (ret == WOLFCOSE_SUCCESS) {
            word32 rsaSigLen = (word32)scratchSz;
            INJECT_FAILURE(WOLF_FAIL_RSA_SSL_SIGN, -1,
                ret = wc_RsaPSS_Sign_ex(hashBuf, (word32)digestSz,
                                          scratch, rsaSigLen,
                                          hashType, mgf, digestSz,
                                          key->key.rsa, rng));
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
    if ((ret == WOLFCOSE_SUCCESS) && ((alg == WOLFCOSE_ALG_ML_DSA_44) ||
        (alg == WOLFCOSE_ALG_ML_DSA_65) || (alg == WOLFCOSE_ALG_ML_DSA_87))) {
        size_t expectedSigSz = 0;

        /* RFC 9964: AKP key whose level matches the algorithm. */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_MlDsaCheckKey(key, alg);
        }

        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_SigSize(alg, &expectedSigSz);
        }

        /* Sig output goes after Sig_structure in scratch */
        if ((ret == WOLFCOSE_SUCCESS) && ((sigStructLen + expectedSigSz) > scratchSz)) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }

        if (ret == WOLFCOSE_SUCCESS) {
            word32 dlSigLen = (word32)expectedSigSz;
            /* FIPS 204 signing with an empty context; COSE has no
             * application context string. */
            INJECT_FAILURE(WOLF_FAIL_MLDSA_SIGN, -1,
                ret = wc_MlDsaKey_SignCtx(
                    key->key.mldsa, NULL, 0,
                    &scratch[sigStructLen], &dlSigLen,
                    scratch, (word32)sigStructLen, rng));
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
#if defined(WOLFCOSE_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY)
    if ((ret == WOLFCOSE_SUCCESS) && (alg == WOLFCOSE_ALG_HSS_LMS)) {
        size_t expectedSigSz = 0;

        /* RFC 8778: HSS-LMS key attached via wc_CoseKey_SetLms(). The
         * signature length comes from the key's parameter set. Signing
         * consumes one-time-signature state; the caller-installed wolfCrypt
         * write callback persists it. The out-buffer capacity was already
         * checked above, before the local-vs-delegated dispatch. */
        ret = wolfCose_LmsCheckKey(key);

        /* Must be able to sign now: reject a non-OK (for example a key wolfSSL
         * marked bad after a persistence failure) or exhausted key before the
         * backend runs, matching wc_CoseSign_Sign and leaving wolfSSL's own
         * state for the caller to inspect. SigsLeft returns 1 while any remain,
         * 0 when exhausted. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((key->key.lms->state != WC_LMS_STATE_OK) ||
             (wc_LmsKey_SigsLeft(key->key.lms) != 1))) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }

        if (ret == WOLFCOSE_SUCCESS) {
            word32 lmsSigLen = 0;
            if (wc_LmsKey_GetSigLen(key->key.lms, &lmsSigLen) != 0) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else {
                expectedSigSz = (size_t)lmsSigLen;
            }
        }

        /* wolfSSL takes the message length as int. */
        if ((ret == WOLFCOSE_SUCCESS) && (sigStructLen > (size_t)INT_MAX)) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
        /* Sig output goes after Sig_structure in scratch. LMS signs the
         * raw Sig_structure directly (no pre-hash). Subtraction form so the
         * capacity check cannot wrap. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((expectedSigSz > scratchSz) ||
             (sigStructLen > (scratchSz - expectedSigSz)))) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }

        if (ret == WOLFCOSE_SUCCESS) {
            word32 lmsSigLen = (word32)expectedSigSz;
            INJECT_FAILURE(WOLF_FAIL_LMS_SIGN, -1,
                ret = wc_LmsKey_Sign(key->key.lms,
                    &scratch[sigStructLen], &lmsSigLen,
                    scratch, (int)sigStructLen));
            if (ret != 0) {
                /* wolfSSL 5.9.2 can leave the key WC_LMS_STATE_OK after a
                 * persistence-write failure, so mark it bad here to stop later
                 * signing from state that may not have been persisted; the
                 * pre-sign check above then refuses it. Keep an exhausted key
                 * as WC_LMS_STATE_NOSIGS so exhaustion stays distinguishable
                 * and its public key can still be exported. */
                if (key->key.lms->state != WC_LMS_STATE_NOSIGS) {
                    key->key.lms->state = WC_LMS_STATE_BAD;
                }
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                sigPtr = &scratch[sigStructLen];
                sigSz = (size_t)lmsSigLen;
            }
        }
    }
    else
#endif /* WOLFCOSE_HAVE_LMS && !WOLFSSL_LMS_VERIFY_ONLY */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        /* No action required */
    }

    /* Encode an optional tag 18 followed by the four Sign1 fields. */
    outCtx.buf = out;
    outCtx.cbuf = NULL;
    outCtx.bufSz = outSz;
    outCtx.idx = 0;

    /* Encode COSE_Sign1 output */
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & WOLFCOSE_SIGN1_UNTAGGED) == 0u)) {
        ret = wc_CBOR_EncodeTag(&outCtx, WOLFCOSE_TAG_SIGN1);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&outCtx, 4);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&outCtx, protectedBuf, protectedLen);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        unprotectedEntries = ((kid != NULL) && (kidLen > 0u)) ?
                             (size_t)1u : (size_t)0u;
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

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&outCtx, sigPtr, sigSz);
    }

    if ((ret == WOLFCOSE_SUCCESS) && (outLen != NULL)) {
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
#endif /* WOLFCOSE_SIGN1_SIGN */

#if defined(WOLFCOSE_SIGN1_VERIFY)
int wolfCose_Sign1_Verify_ex(const WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen,
    uint32_t flags)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_CBOR_CTX ctx;
    uint64_t tag;
    size_t arrayCount = 0;
    const uint8_t* protectedData = NULL;
    size_t protectedLen = 0;
    const uint8_t* payloadData = NULL;
    size_t payloadDataLen = 0;
    const uint8_t* sigData = NULL;
    size_t sigDataLen = 0;
    size_t sigStructLen = 0;
    uint8_t hashBuf[WC_MAX_DIGEST_SIZE];
    int32_t alg = 0;
    WOLFCOSE_HDR_STATE hdrState;
    const uint8_t* verifyPayload = NULL;
    size_t verifyPayloadLen = 0;
    int algProtected = 0;

    if ((key == NULL) || (in == NULL) || (scratch == NULL) || (hdr == NULL) ||
        (payload == NULL) || (payloadLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (WOLFCOSE_COSE_DECODE_FLAGS_VALID(flags) == 0)) {
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

        ret = wc_CBOR_DecoderInit(&ctx, in, inSz);

        /* Optional Tag(18) */
        if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx < ctx.bufSz) &&
            (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TAG)) {
            ret = wolfCose_CBOR_DecodeTag_ex(&ctx, &tag, flags);
            if ((ret == WOLFCOSE_SUCCESS) && (tag != WOLFCOSE_TAG_SIGN1)) {
                ret = WOLFCOSE_E_COSE_BAD_TAG;
            }
        }
    }

    /* Array of 4 elements */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CBOR_DecodeArrayStart_ex(&ctx, &arrayCount, flags);
        if ((ret == WOLFCOSE_SUCCESS) && (arrayCount != 4u)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }

    /* 1. Protected headers (bstr) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CBOR_DecodeBstr_ex(&ctx, &protectedData, &protectedLen,
            flags);
    }

    /* Parse protected headers */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeProtectedHdr_ex(protectedData, protectedLen, hdr,
                                             &hdrState, flags);
        if (ret == WOLFCOSE_SUCCESS) {
            algProtected = wolfCose_HdrStateContains(&hdrState,
                                                      WOLFCOSE_HDR_ALG);
        }
    }

    /* 2. Unprotected headers (map) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeUnprotectedHdr_ex(&ctx, hdr, &hdrState, flags);
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
            ret = wolfCose_CBOR_DecodeBstr_ex(&ctx, &payloadData,
                &payloadDataLen, flags);
            if (ret == WOLFCOSE_SUCCESS) {
                verifyPayload = payloadData;
                verifyPayloadLen = payloadDataLen;
            }
        }
    }

    /* 4. Signature (bstr) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CBOR_DecodeBstr_ex(&ctx, &sigData, &sigDataLen, flags);
    }

    /* RFC 8949 Section 5.3.1: reject trailing data after the COSE object. */
    if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != ctx.bufSz)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        alg = hdr->alg;
    }

    /* Honour the key->alg pin on the verify path too. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (key->alg != WOLFCOSE_ALG_UNSET) && (key->alg != alg)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (key->alg == WOLFCOSE_ALG_UNSET) && (algProtected == 0)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        /* Rebuild Sig_structure in scratch using appropriate payload */
        ret = wolfCose_BuildSigStructure(protectedData, protectedLen,
                                          extAad, extAadLen,
                                          verifyPayload, verifyPayloadLen,
                                          scratch, scratchSz, &sigStructLen);
    }

    /* Verify based on algorithm */
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
        if ((ret == WOLFCOSE_SUCCESS) && (key->crv == WOLFCOSE_CRV_ED25519)) {
            if (key->attachedType != WOLFCOSE_ATT_ED25519) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else {
                ed25519_key* ed25519Key = key->key.ed25519;

                if (ed25519Key == NULL) {
                    ret = WOLFCOSE_E_COSE_KEY_TYPE;
                }
                else {
                    INJECT_FAILURE(WOLF_FAIL_ED25519_VERIFY, -1,
                        ret = wc_ed25519_verify_msg(sigData,
                            (word32)sigDataLen, scratch,
                            (word32)sigStructLen, &verified, ed25519Key));
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
                }
            }
        }
        else
#endif
#ifdef WOLFCOSE_HAVE_ED448
        if ((ret == WOLFCOSE_SUCCESS) && (key->crv == WOLFCOSE_CRV_ED448)) {
            if (key->attachedType != WOLFCOSE_ATT_ED448) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else {
                ed448_key* ed448Key = key->key.ed448;

                if (ed448Key == NULL) {
                    ret = WOLFCOSE_E_COSE_KEY_TYPE;
                }
                else {
                    INJECT_FAILURE(WOLF_FAIL_ED448_VERIFY, -1,
                        ret = wc_ed448_verify_msg(sigData,
                            (word32)sigDataLen, scratch,
                            (word32)sigStructLen, &verified, ed448Key,
                            NULL, 0));
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
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
        int verified = 0;
        size_t coordSz = 0;
        enum wc_HashType hashType = WC_HASH_TYPE_NONE;
        int digestSz = 0;

        if ((key->kty != WOLFCOSE_KTY_EC2) ||
            (key->attachedType != WOLFCOSE_ATT_ECC)) {
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
                ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                               hashBuf, (word32)digestSz));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_CrvKeySize(key->crv, &coordSz);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_EccVerifyRaw(sigData, sigDataLen,
                                         hashBuf, (size_t)digestSz,
                                         coordSz, eccKey, &verified);
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
                ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                               hashBuf, (word32)digestSz));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_HashToMgf(hashType, &mgf);
        }
        /* Copy sig into scratch — wc_RsaPSS_VerifyCheck modifies its
         * input buffer in-place; sigData points into the caller's
         * const COSE message and must not be written to. */
        if (ret == WOLFCOSE_SUCCESS) {
            if (sigDataLen > scratchSz) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            (void)XMEMCPY(scratch, sigData, sigDataLen);
            INJECT_FAILURE(WOLF_FAIL_RSA_SSL_VERIFY, -1,
                ret = wc_RsaPSS_VerifyCheck(scratch, (word32)sigDataLen,
                                              scratch, (word32)scratchSz,
                                              hashBuf, (word32)digestSz,
                                              hashType, mgf, rsaKey));
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
            ret = wolfCose_MlDsaCheckKey(key, alg);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            mldsaKey = key->key.mldsa;
            INJECT_FAILURE(WOLF_FAIL_MLDSA_VERIFY, -1,
                ret = wc_MlDsaKey_VerifyCtx(
                    mldsaKey,
                    sigData, (word32)sigDataLen,
                    NULL, 0,
                    scratch, (word32)sigStructLen,
                    &verified));
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
#ifdef WOLFCOSE_HAVE_LMS
    if ((ret == WOLFCOSE_SUCCESS) && (alg == WOLFCOSE_ALG_HSS_LMS)) {
        /* RFC 8778: HSS-LMS verifies the raw Sig_structure (no pre-hash).
         * Only a genuine signature mismatch (SIG_VERIFY_E) is an auth
         * failure; a bad-arg/state/length error is an operational fault. */
        ret = wolfCose_LmsCheckKey(key);
        if ((ret == WOLFCOSE_SUCCESS) && (sigStructLen > (size_t)INT_MAX)) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            LmsKey* lmsKey = key->key.lms;
            INJECT_FAILURE(WOLF_FAIL_LMS_VERIFY, SIG_VERIFY_E,
                ret = wc_LmsKey_Verify(lmsKey,
                    sigData, (word32)sigDataLen,
                    scratch, (int)sigStructLen));
            if (ret == (int)SIG_VERIFY_E) {
                ret = WOLFCOSE_E_COSE_SIG_FAIL;
            }
            else if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                /* No action required */
            }
        }
    }
    else
#endif /* WOLFCOSE_HAVE_LMS */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        /* No action required */
    }

    /* Return zero-copy payload pointer into input buffer. Clear on failure
     * so callers that skip the return-code check do not see a stale value. */
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
    (void)wolfCose_ForceZero(hashBuf, sizeof(hashBuf));
    if (scratch != NULL) {
        (void)wolfCose_ForceZero(scratch, scratchSz);
    }

    return ret;
}

int wc_CoseSign1_Verify(const WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen)
{
    return wolfCose_Sign1_Verify_ex(key, in, inSz, detachedPayload, detachedLen,
        extAad, extAadLen, scratch, scratchSz, hdr, payload, payloadLen, 0u);
}
#endif /* WOLFCOSE_SIGN1_VERIFY */

#endif /* WOLFCOSE_SIGN1 */
