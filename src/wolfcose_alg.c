/* wolfcose_alg.c
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
 * Algorithm dispatch: hash/signature/curve mapping, AEAD and HMAC
 * parameter dispatch, RSA-PSS key checks. RFC 9053.
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


/* ----- Internal helpers: algorithm dispatch ----- */

int wolfCose_AlgToHashType(int32_t alg, enum wc_HashType* hashType)
{
    int ret = WOLFCOSE_SUCCESS;

    if (hashType == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
#ifdef WOLFCOSE_HAVE_ES256
            case WOLFCOSE_ALG_ES256:
                *hashType = WC_HASH_TYPE_SHA256;
                break;
#endif
#ifdef WOLFCOSE_HAVE_ES384
            case WOLFCOSE_ALG_ES384:
                *hashType = WC_HASH_TYPE_SHA384;
                break;
#endif
#ifdef WOLFCOSE_HAVE_ES512
            case WOLFCOSE_ALG_ES512:
                *hashType = WC_HASH_TYPE_SHA512;
                break;
#endif
#if defined(WOLFCOSE_HAVE_EDDSA) || defined(WOLFCOSE_HAVE_ED448)
            case WOLFCOSE_ALG_EDDSA:
                /* RFC 9053 Section 2.2: EdDSA hashes the message internally
                 * with SHA-512 (Ed25519) or SHAKE-256 (Ed448). The "external"
                 * hash type is unused; SHA-512 stands in for both. */
                *hashType = WC_HASH_TYPE_SHA512;
                break;
#endif
#ifdef WOLFCOSE_HAVE_PS256
            case WOLFCOSE_ALG_PS256:
                *hashType = WC_HASH_TYPE_SHA256;
                break;
#endif
#ifdef WOLFCOSE_HAVE_PS384
            case WOLFCOSE_ALG_PS384:
                *hashType = WC_HASH_TYPE_SHA384;
                break;
#endif
#ifdef WOLFCOSE_HAVE_PS512
            case WOLFCOSE_ALG_PS512:
                *hashType = WC_HASH_TYPE_SHA512;
                break;
#endif
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

WOLFCOSE_LOCAL int wolfCose_SigSize(int32_t alg, size_t* sigSz)
{
    int ret = WOLFCOSE_SUCCESS;

    if (sigSz == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
#ifdef WOLFCOSE_HAVE_ES256
            case WOLFCOSE_ALG_ES256:
                *sigSz = 64;  /* r(32) || s(32) */
                break;
#endif
#ifdef WOLFCOSE_HAVE_ES384
            case WOLFCOSE_ALG_ES384:
                *sigSz = 96;  /* r(48) || s(48) */
                break;
#endif
#ifdef WOLFCOSE_HAVE_ES512
            case WOLFCOSE_ALG_ES512:
                *sigSz = 132; /* r(66) || s(66) */
                break;
#endif
#if defined(WOLFCOSE_HAVE_EDDSA) || defined(WOLFCOSE_HAVE_ED448)
            case WOLFCOSE_ALG_EDDSA:
                /* Returns the worst-case signature size when both curves
                 * are available so caller buffers are always sufficient. */
    #ifdef WOLFCOSE_HAVE_ED448
                *sigSz = 114;
    #else
                *sigSz = 64;
    #endif
                break;
#endif
#ifdef WOLFCOSE_HAVE_MLDSA
            case WOLFCOSE_ALG_ML_DSA_44:
                *sigSz = 2420;
                break;
            case WOLFCOSE_ALG_ML_DSA_65:
                *sigSz = 3309;
                break;
            case WOLFCOSE_ALG_ML_DSA_87:
                *sigSz = 4627;
                break;
#endif
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

int wolfCose_CrvKeySize(int32_t crv, size_t* keySz)
{
    int ret = WOLFCOSE_SUCCESS;

    if (keySz == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (crv) {
            case WOLFCOSE_CRV_P256:
                *keySz = 32;
                break;
            case WOLFCOSE_CRV_P384:
                *keySz = 48;
                break;
            case WOLFCOSE_CRV_P521:
                *keySz = 66;
                break;
            case WOLFCOSE_CRV_ED25519:
                *keySz = 32;
                break;
            case WOLFCOSE_CRV_ED448:
                *keySz = 57;
                break;
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

#ifdef HAVE_ECC
int wolfCose_CrvToWcCurve(int32_t crv, int* wcCrv)
{
    int ret = WOLFCOSE_SUCCESS;

    if (wcCrv == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (crv) {
            case WOLFCOSE_CRV_P256:
                *wcCrv = ECC_SECP256R1;
                break;
            case WOLFCOSE_CRV_P384:
                *wcCrv = ECC_SECP384R1;
                break;
            case WOLFCOSE_CRV_P521:
                *wcCrv = ECC_SECP521R1;
                break;
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

int wolfCose_EccKeyCheckCurve(int32_t crv, ecc_key* eccKey)
{
    int ret = WOLFCOSE_SUCCESS;
    int expectedCrv = ECC_CURVE_INVALID;
    int actualSz = 0;
    size_t expectedSz = 0;

    if (eccKey == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CrvToWcCurve(crv, &expectedCrv);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CrvKeySize(crv, &expectedSz);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        actualSz = wc_ecc_size(eccKey);
        /* An initialized, empty key may be attached as a decode target. */
        if (actualSz != 0) {
            if ((actualSz < 0) || ((size_t)actualSz != expectedSz)) {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) && (actualSz != 0) &&
        (eccKey->dp != NULL)) {
        int actualCrv = wc_ecc_get_curve_id(eccKey->idx);

        if (actualCrv == (int)ECC_CURVE_INVALID) {
            actualCrv = wc_ecc_get_curve_id_from_dp_params(eccKey->dp);
        }
        if ((actualCrv == (int)ECC_CURVE_INVALID) ||
            (actualCrv != expectedCrv)) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
    }

    return ret;
}
#endif

/* ----- Internal: AEAD dispatch helpers (AES-GCM, ChaCha20-Poly1305, AES-CCM) ----- */

int wolfCose_AeadKeyLen(int32_t alg, size_t* keyLen)
{
    int ret = WOLFCOSE_SUCCESS;

    if (keyLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
#ifdef WOLFCOSE_HAVE_AESGCM
            case WOLFCOSE_ALG_A128GCM:
                *keyLen = 16;
                break;
            case WOLFCOSE_ALG_A192GCM:
                *keyLen = 24;
                break;
            case WOLFCOSE_ALG_A256GCM:
                *keyLen = 32;
                break;
#endif
#if defined(WOLFCOSE_HAVE_CHACHA20)
            case WOLFCOSE_ALG_CHACHA20_POLY1305:
                *keyLen = WOLFCOSE_CHACHA_KEY_SZ;
                break;
#endif
#ifdef WOLFCOSE_HAVE_AESCCM
            case WOLFCOSE_ALG_AES_CCM_16_64_128:  /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_64_128:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_16_128_128:  /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_128_128:
                *keyLen = 16;
                break;
            case WOLFCOSE_ALG_AES_CCM_16_64_256:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_64_256:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_16_128_256:  /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_128_256:
                *keyLen = 32;
                break;
#endif
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

int wolfCose_AeadNonceLen(int32_t alg, size_t* nonceLen)
{
    int ret = WOLFCOSE_SUCCESS;

    if (nonceLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
#ifdef WOLFCOSE_HAVE_AESGCM
            case WOLFCOSE_ALG_A128GCM:  /* fall through */
            case WOLFCOSE_ALG_A192GCM:  /* fall through */
            case WOLFCOSE_ALG_A256GCM:
                *nonceLen = WOLFCOSE_AES_GCM_NONCE_SZ;
                break;
#endif
#if defined(WOLFCOSE_HAVE_CHACHA20)
            case WOLFCOSE_ALG_CHACHA20_POLY1305:
                *nonceLen = WOLFCOSE_CHACHA_NONCE_SZ;
                break;
#endif
#ifdef WOLFCOSE_HAVE_AESCCM
            case WOLFCOSE_ALG_AES_CCM_16_64_128:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_16_64_256:    /* fall through */
            case WOLFCOSE_ALG_AES_CCM_16_128_128:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_16_128_256:
                *nonceLen = 13;  /* L=2 */
                break;
            case WOLFCOSE_ALG_AES_CCM_64_64_128:    /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_64_256:    /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_128_128:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_128_256:
                *nonceLen = 7;   /* L=8 */
                break;
#endif
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

int wolfCose_AeadTagLen(int32_t alg, size_t* tagLen)
{
    int ret = WOLFCOSE_SUCCESS;

    if (tagLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
#ifdef WOLFCOSE_HAVE_AESGCM
            case WOLFCOSE_ALG_A128GCM:  /* fall through */
            case WOLFCOSE_ALG_A192GCM:  /* fall through */
            case WOLFCOSE_ALG_A256GCM:
                *tagLen = WOLFCOSE_AES_GCM_TAG_SZ;
                break;
#endif
#if defined(WOLFCOSE_HAVE_CHACHA20)
            case WOLFCOSE_ALG_CHACHA20_POLY1305:
                *tagLen = WOLFCOSE_CHACHA_TAG_SZ;
                break;
#endif
#ifdef WOLFCOSE_HAVE_AESCCM
            case WOLFCOSE_ALG_AES_CCM_16_64_128:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_16_64_256:    /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_64_128:    /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_64_256:
                *tagLen = 8;
                break;
            case WOLFCOSE_ALG_AES_CCM_16_128_128:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_16_128_256:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_128_128:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_128_256:
                *tagLen = 16;
                break;
#endif
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

#if defined(WOLFCOSE_HAVE_AESCCM) && \
    (defined(WOLFCOSE_ENCRYPT0_ENCRYPT) || \
     defined(WOLFCOSE_ENCRYPT0_DECRYPT) || \
     defined(WOLFCOSE_ENCRYPT_ENCRYPT) || \
     defined(WOLFCOSE_ENCRYPT_DECRYPT))
int wolfCose_AeadCheckPayloadLen(int32_t alg, size_t payloadLen)
{
    int ret = WOLFCOSE_SUCCESS;

    switch (alg) {
        case WOLFCOSE_ALG_AES_CCM_16_64_128:   /* fall through */
        case WOLFCOSE_ALG_AES_CCM_16_64_256:   /* fall through */
        case WOLFCOSE_ALG_AES_CCM_16_128_128:  /* fall through */
        case WOLFCOSE_ALG_AES_CCM_16_128_256:
            if (payloadLen > (size_t)UINT16_MAX) {
                ret = WOLFCOSE_E_INVALID_ARG;
            }
            break;
        default:
            break;
    }

    return ret;
}
#endif

/* ----- Internal: HMAC helpers ----- */

#if defined(WOLFCOSE_HAVE_HMAC)
int wolfCose_HmacType(int32_t alg, int* hmacType)
{
    int ret = WOLFCOSE_SUCCESS;

    if (hmacType == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
#ifdef WOLFCOSE_HAVE_HMAC256
            case WOLFCOSE_ALG_HMAC_256_256:
                *hmacType = WC_SHA256;
                break;
#endif
#ifdef WOLFCOSE_HAVE_HMAC384
            case WOLFCOSE_ALG_HMAC_384_384:
                *hmacType = WC_SHA384;
                break;
#endif
#ifdef WOLFCOSE_HAVE_HMAC512
            case WOLFCOSE_ALG_HMAC_512_512:
                *hmacType = WC_SHA512;
                break;
#endif
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

#if defined(WOLFCOSE_MAC0_CREATE) || defined(WOLFCOSE_MAC0_VERIFY) || \
    defined(WOLFCOSE_MAC_CREATE) || defined(WOLFCOSE_MAC_VERIFY)
/* RFC 9053 Section 3.1: an HMAC key should be at least the hash output size.
 * Reject shorter keys unless the caller explicitly opts in. */
int wolfCose_HmacCheckKeyLen(int32_t alg, size_t keyLen)
{
    int ret = WOLFCOSE_SUCCESS;
#ifndef WOLFCOSE_ALLOW_SHORT_HMAC_KEY
    size_t minLen = 0;

    switch (alg) {
#ifdef WOLFCOSE_HAVE_HMAC256
        case WOLFCOSE_ALG_HMAC_256_256:
            minLen = 32u;
            break;
#endif
#ifdef WOLFCOSE_HAVE_HMAC384
        case WOLFCOSE_ALG_HMAC_384_384:
            minLen = 48u;
            break;
#endif
#ifdef WOLFCOSE_HAVE_HMAC512
        case WOLFCOSE_ALG_HMAC_512_512:
            minLen = 64u;
            break;
#endif
        default:
            ret = WOLFCOSE_E_COSE_BAD_ALG;
            break;
    }
    if ((ret == WOLFCOSE_SUCCESS) && (keyLen < minLen)) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
#else
    (void)alg;
    (void)keyLen;
#endif
#if defined(SIZE_MAX) && (SIZE_MAX > 0xFFFFFFFFUL)
    if ((ret == WOLFCOSE_SUCCESS) &&
        (keyLen > (size_t)0xFFFFFFFFUL)) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
#endif
    return ret;
}
#endif /* MAC0/MAC create or verify */
#endif /* WOLFCOSE_HAVE_HMAC */

/* ----- Internal: RSA-PSS hash-to-MGF mapping ----- */
#if defined(WOLFCOSE_HAVE_RSAPSS) && \
    (defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_SIGN1_VERIFY) || \
     defined(WOLFCOSE_SIGN_SIGN) || defined(WOLFCOSE_SIGN_VERIFY))
/* RFC 8230 Section 6.1 requires RSA-PSS keys of at least 2048 bits. */
int wolfCose_RsaPssCheckKey(const WOLFCOSE_KEY* key,
                                   size_t* modulusLen)
{
    int ret = WOLFCOSE_SUCCESS;

    if (key == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((key->kty != WOLFCOSE_KTY_RSA) ||
             (key->attachedType != WOLFCOSE_ATT_RSA) ||
             (key->key.rsa == NULL)) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
    else {
        RsaKey* rsaKey = key->key.rsa;
        int modulusSz = wc_RsaEncryptSize(rsaKey);
        int opaqueKey = 0;

#ifdef WOLF_CRYPTO_CB
        if (rsaKey->devId != INVALID_DEVID) {
            opaqueKey = 1;
        }
#endif
#ifdef WOLFSSL_MICROCHIP_TA100
        if ((rsaKey->rKeyH != 0u) || (rsaKey->uKeyH != 0u)) {
            opaqueKey = 1;
        }
#endif
        if (modulusSz < (int)WOLFCOSE_RSA_PSS_MIN_SZ) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        else if (modulusSz == (int)WOLFCOSE_RSA_PSS_MIN_SZ) {
            int modulusMaterialized = 0;
            uint8_t modulus[WOLFCOSE_RSA_PSS_MIN_SZ] = {0};
            word32 modulusLen32 = (word32)sizeof(modulus);
#if !defined(HAVE_ECC) && !defined(WOLFSSL_EXPORT_INT) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY)
            word32 exponentLen = (word32)sizeof(modulus);
#endif
#if defined(HAVE_ECC) || defined(WOLFSSL_EXPORT_INT)
            int modulusExportRet = wc_export_int(&rsaKey->n, modulus,
                &modulusLen32, (word32)sizeof(modulus),
                WC_TYPE_UNSIGNED_BIN);
#elif defined(WOLFSSL_RSA_VERIFY_ONLY)
            int modulusExportRet = -1;
#else
            /* The modulus output overwrites the unused exponent output. */
            int modulusExportRet = wc_RsaFlattenPublicKey(rsaKey,
                modulus, &exponentLen, modulus, &modulusLen32);
#endif
            if (modulusExportRet == 0) {
                if (modulusLen32 > (word32)sizeof(modulus)) {
                    modulusMaterialized = 1;
                }
                else {
                    size_t i = 0u;

                    for (; i < (size_t)modulusLen32; i++) {
                        if (modulus[i] != 0u) {
                            modulusMaterialized = 1;
                        }
                    }
                }
            }
            if (modulusMaterialized != 0) {
                if ((modulusLen32 != (word32)sizeof(modulus)) ||
                    ((modulus[0] & 0x80u) == 0u)) {
                    ret = WOLFCOSE_E_COSE_KEY_TYPE;
                }
            }
            else if (opaqueKey == 0) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else {
                /* The backend-reported size is authoritative for an opaque
                 * key whose modulus is unavailable to the caller. */
            }
        }
        else {
            /* A wider modulus is above the required minimum. */
        }
        if ((ret == WOLFCOSE_SUCCESS) && (modulusLen != NULL)) {
            *modulusLen = (size_t)modulusSz;
        }
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_RSAPSS && RSA-PSS operations */

#if defined(WOLFCOSE_HAVE_RSAPSS) && \
    (defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_SIGN1_VERIFY) || \
     defined(WOLFCOSE_SIGN_SIGN) || defined(WOLFCOSE_SIGN_VERIFY))
int wolfCose_HashToMgf(enum wc_HashType hashType, int* mgf)
{
    int ret = WOLFCOSE_SUCCESS;

    if (mgf == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (hashType == WC_HASH_TYPE_SHA256) {
        *mgf = WC_MGF1SHA256;
    }
#ifdef WOLFCOSE_HAVE_PS384
    else if (hashType == WC_HASH_TYPE_SHA384) {
        *mgf = WC_MGF1SHA384;
    }
#endif
#ifdef WOLFCOSE_HAVE_PS512
    else if (hashType == WC_HASH_TYPE_SHA512) {
        *mgf = WC_MGF1SHA512;
    }
#endif
    else {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    return ret;
}
#endif
