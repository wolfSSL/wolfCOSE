/* wolfcose_ecc.c
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
 * ECC DER <-> raw r||s signature conversion helpers.
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


/* ----- Internal: ECC DER <-> raw r||s conversion ----- */

#ifdef WOLFCOSE_HAVE_ECDSA
#if defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_SIGN_SIGN)
int wolfCose_EccSignRaw(const uint8_t* hash, size_t hashLen,
                         uint8_t* sigBuf, size_t* sigLen,
                         size_t coordSz, enum wc_HashType hashType,
                         WC_RNG* rng, ecc_key* eccKey)
{
    int ret;
    uint8_t derSig[ECC_MAX_SIG_SIZE];
    word32 derSigLen = (word32)sizeof(derSig);
    word32 rLen;
    word32 sLen;
#ifdef WOLFCOSE_HAVE_DETERMINISTIC_ECDSA
    byte savedDeterministic = 0u;
    enum wc_HashType savedHashType = WC_HASH_TYPE_NONE;
#endif

    if ((hash == NULL) || (sigBuf == NULL) || (sigLen == NULL) ||
        (rng == NULL) || (eccKey == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (*sigLen < (coordSz * 2u)) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }
    else {
#ifdef WOLFCOSE_HAVE_DETERMINISTIC_ECDSA
        savedDeterministic = (byte)eccKey->deterministic;
        savedHashType = eccKey->hashType;
#if defined(WOLF_CRYPTO_CB) && !defined(WOLF_CRYPTO_CB_FIND)
        if (eccKey->devId != INVALID_DEVID) {
            ret = WOLFCOSE_E_UNSUPPORTED;
        }
        else
#endif
#if defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_ONLY_KEY_ID)
        if (eccKey->keyIdSet != 0) {
            ret = WOLFCOSE_E_UNSUPPORTED;
        }
        else
#endif
        {
            ret = wc_ecc_set_deterministic_ex(eccKey, 1u, hashType);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
#else
        (void)hashType;
        ret = WOLFCOSE_SUCCESS;
#endif
        /* Sign producing DER-encoded signature */
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_ECC_SIGN, -1,
                ret = wc_ecc_sign_hash(hash, (word32)hashLen, derSig,
                                        &derSigLen, rng, eccKey));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            /* Extract raw r and s from DER */
            rLen = (word32)coordSz;
            sLen = (word32)coordSz;

            /* Zero the output buffer for left-padding */
            (void)XMEMSET(sigBuf, 0, coordSz * 2u);

            /* wc_ecc_sig_to_rs extracts r and s as raw bytes */
            INJECT_FAILURE(WOLF_FAIL_ECC_SIG_TO_RS, -1,
                ret = wc_ecc_sig_to_rs(derSig, derSigLen,
                                        sigBuf, &rLen,
                                        &sigBuf[coordSz], &sLen));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else if (((size_t)rLen > coordSz) ||
                     ((size_t)sLen > coordSz)) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                /* Right-justify r and s unconditionally to avoid a
                 * branch on the leading-zero count. */
                (void)XMEMMOVE(&sigBuf[coordSz - (size_t)rLen], sigBuf,
                               (size_t)rLen);
                (void)XMEMSET(sigBuf, 0, coordSz - (size_t)rLen);
                (void)XMEMMOVE(&sigBuf[coordSz + (coordSz - (size_t)sLen)],
                               &sigBuf[coordSz], (size_t)sLen);
                (void)XMEMSET(&sigBuf[coordSz], 0,
                              coordSz - (size_t)sLen);
                *sigLen = coordSz * 2u;
            }
        }
        (void)wolfCose_ForceZero(derSig, sizeof(derSig));
#ifdef WOLFCOSE_HAVE_DETERMINISTIC_ECDSA
        eccKey->deterministic = savedDeterministic;
        eccKey->hashType = savedHashType;
#endif
    }
    return ret;
}
#endif /* WOLFCOSE_SIGN1_SIGN || WOLFCOSE_SIGN_SIGN */

int wolfCose_EccVerifyRaw(const uint8_t* sigBuf, size_t sigLen,
                           const uint8_t* hash, size_t hashLen,
                           size_t coordSz, ecc_key* eccKey, int* verified)
{
    int ret;
#ifndef NO_ASN
    uint8_t derSig[ECC_MAX_SIG_SIZE];
    word32 derSigLen = (word32)sizeof(derSig);
#endif

    if ((sigBuf == NULL) || (hash == NULL) || (eccKey == NULL) ||
        (verified == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (sigLen != (coordSz * 2u)) {
        ret = WOLFCOSE_E_COSE_SIG_FAIL;
    }
    else {
        *verified = 0;

#ifdef NO_ASN
        /* NO_ASN wolfCrypt (e.g. wolfBoot): wc_ecc_verify_hash consumes the raw
         * r||s signature directly, so no DER conversion is needed and the
         * sign-side helper wc_ecc_rs_raw_to_sig (gated on ASN) is not required.
         * wolfCOSE holds no mp_int itself, keeping the verify path allocation
         * free at this layer. */
        INJECT_FAILURE(WOLF_FAIL_ECC_VERIFY, -1,
            ret = wc_ecc_verify_hash(sigBuf, (word32)sigLen, hash,
                                      (word32)hashLen, verified, eccKey));
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
#else
        /* Convert raw r||s to DER, then verify. */
        INJECT_FAILURE(WOLF_FAIL_ECC_RS_TO_SIG, -1,
            ret = wc_ecc_rs_raw_to_sig(sigBuf, (word32)coordSz,
                                         &sigBuf[coordSz], (word32)coordSz,
                                         derSig, &derSigLen));
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            INJECT_FAILURE(WOLF_FAIL_ECC_VERIFY, -1,
                ret = wc_ecc_verify_hash(derSig, derSigLen, hash,
                                          (word32)hashLen, verified, eccKey));
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        (void)wolfCose_ForceZero(derSig, sizeof(derSig));
#endif
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_ECDSA */
