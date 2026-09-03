/* wolfcose.c
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
 * COSE Sign1/Encrypt0/Key implementation per RFC 9052.
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

/* ----- Forced failure injection for testing error paths ----- */
#ifdef WOLFCOSE_FORCE_FAILURE
    #include "../tests/force_failure.h"
    /* Inject a forced failure when armed; otherwise run stmt. */
    #define INJECT_FAILURE(failure_type, error_code, stmt) \
        do { \
            if (wolfForceFailure_Check((failure_type)) != 0) { \
                ret = (error_code); \
            } \
            else { \
                (stmt); \
            } \
        } while (0)
#else
    /* No-op wrapper when not testing; stmt runs unconditionally. */
    #define INJECT_FAILURE(failure_type, error_code, stmt) \
        do { \
            (stmt); \
        } while (0)
#endif

/* ----- Secure memory zero ----- */

/**
 * Portable secure-zero. Volatile pointer prevents the compiler optimising
 * the writes away when the buffer is dead at function exit. Used in place
 * of wc_ForceZero so wolfCOSE links against the full wolfSSL 5.x range
 * (wc_ForceZero only became a public WOLFSSL_API symbol in v5.8.4).
 */
#ifdef WOLFCOSE_TEST_ZEROIZE_HOOK
/* Test build records every scrub (pointer, length) so unit tests can assert a
 * given call site ran. Defined by the test translation unit. */
extern void wolfCose_TestZeroizeRecord(const void* mem, size_t len);
#endif

WOLFCOSE_LOCAL void wolfCose_ForceZero(void* mem, size_t len)
{
    if ((mem != NULL) && (len > 0u)) {
        volatile unsigned char* p = (volatile unsigned char*)mem;
        size_t i;
        for (i = 0u; i < len; i++) {
            p[i] = 0u;
        }
    }
#ifdef WOLFCOSE_TEST_ZEROIZE_HOOK
    wolfCose_TestZeroizeRecord(mem, len);
#endif
}

#if defined(WOLFCOSE_HAVE_MLDSA) && defined(WOLFCOSE_KEY_DECODE) && \
    !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MLDSA_ASSIGN_KEY)
/* Clear a failed software import without freeing the caller-owned key object.
 * SetParams releases dynamic key buffers and caches while preserving heap,
 * device and private-key identifier configuration. Wipe the private buffer
 * here as well so cleanup does not depend on allocator behavior; static key
 * buffers need it because wolfCrypt deliberately retains their storage. */
static void wolfCose_MlDsaImportRollback(wc_MlDsaKey* key, byte level)
{
#if defined(WOLFSSL_MLDSA_DYNAMIC_KEYS)
    if ((key->k != NULL) && (key->kSz > 0u)) {
        (void)wolfCose_ForceZero(key->k, (size_t)key->kSz);
    }
#else
    (void)wolfCose_ForceZero(key->k, sizeof(key->k));
#endif
#if defined(WC_MLDSA_FIXED_ARRAY) && \
    defined(WC_MLDSA_CACHE_PRIV_VECTORS)
    (void)wolfCose_ForceZero(key->s1, sizeof(key->s1));
    (void)wolfCose_ForceZero(key->s2, sizeof(key->s2));
    (void)wolfCose_ForceZero(key->t0, sizeof(key->t0));
#endif
#ifndef USE_INTEL_SPEEDUP
    wc_Shake256_Free(&key->shake);
#endif
    (void)wolfCose_ForceZero(&key->shake, sizeof(key->shake));
    (void)wc_MlDsaKey_SetParams(key, level);
}
#endif /* MLDSA && KEY_DECODE && !NO_MAKE_KEY && !ASSIGN_KEY */

#if defined(HAVE_ECC) && defined(WOLFCOSE_KEY_DECODE)
/* Clear initialized multiprecision storage without releasing it. wolfSSL's
 * MP cleanup symbols are not exported by every supported build. */
#if !defined(ALT_ECC_SIZE) && !defined(WOLFSSL_SP_MATH_ALL) && \
    !defined(WOLFSSL_SP_MATH) && !defined(USE_FAST_MATH)
static void wolfCose_MpClearDigits(mp_digit* digits, size_t digitCount)
{
    if ((digits != NULL) && (digitCount > 0u) &&
        (digitCount <= ((size_t)-1 / sizeof(digits[0])))) {
        (void)wolfCose_ForceZero(digits,
            digitCount * sizeof(digits[0]));
    }
}
#endif

#ifdef ALT_ECC_SIZE
/* ALT_ECC_SIZE points ecc_key members at smaller alt_fp_int objects. Access
 * that real layout directly so a full-size mp_int view cannot run past it. */
static int wolfCose_AltMpValueIsZero(const alt_fp_int* value)
{
    int isZero = 0;

    if ((value != NULL) && ((size_t)value->used == 0u)) {
        isZero = 1;
    }

    return isZero;
}

static void wolfCose_AltMpClearValue(alt_fp_int* value)
{
    if (value != NULL) {
        (void)wolfCose_ForceZero(value->dp, sizeof(value->dp));
#if defined(HAVE_WOLF_BIGINT) && !defined(USE_FAST_MATH)
        if ((value->raw.buf != NULL) && (value->raw.len > 0u)) {
            (void)wolfCose_ForceZero(value->raw.buf, value->raw.len);
        }
#endif
        value->used = 0;
#if defined(USE_FAST_MATH) || defined(WOLFSSL_SP_INT_NEGATIVE)
        value->sign = MP_ZPOS;
#endif
    }
}
#else
static int wolfCose_MpValueIsZero(const mp_int* value)
{
    int isZero = 0;

    if ((value != NULL) && ((size_t)value->used == 0u)) {
        isZero = 1;
    }

    return isZero;
}

static void wolfCose_MpClearValue(mp_int* value)
{
    if (value != NULL) {
#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_SP_MATH) || \
    defined(USE_FAST_MATH)
        (void)wolfCose_ForceZero(value->dp, sizeof(value->dp));
#else
        if (value->alloc > 0) {
            wolfCose_MpClearDigits(value->dp, (size_t)value->alloc);
        }
#endif
#ifdef HAVE_WOLF_BIGINT
        if ((value->raw.buf != NULL) && (value->raw.len > 0u)) {
            (void)wolfCose_ForceZero(value->raw.buf, value->raw.len);
        }
#endif
        value->used = 0;
#if defined(USE_FAST_MATH) || defined(USE_INTEGER_HEAP_MATH) || \
    defined(WOLFSSL_SP_INT_NEGATIVE)
        value->sign = MP_ZPOS;
#endif
    }
}
#endif /* ALT_ECC_SIZE */

static int wolfCose_EccPrivateValuesAreZero(const ecc_key* ecc)
{
    int areZero;

#ifdef ALT_ECC_SIZE
    areZero = wolfCose_AltMpValueIsZero(&ecc->ka[0]);
    #ifdef WOLFSSL_ECC_BLIND_K
    if (wolfCose_AltMpValueIsZero(&ecc->kba[0]) == 0) {
        areZero = 0;
    }
    if (wolfCose_AltMpValueIsZero(&ecc->kua[0]) == 0) {
        areZero = 0;
    }
    #endif
#else
    areZero = wolfCose_MpValueIsZero(ecc->k);
    #ifdef WOLFSSL_ECC_BLIND_K
    if (wolfCose_MpValueIsZero(ecc->kb) == 0) {
        areZero = 0;
    }
    if (wolfCose_MpValueIsZero(ecc->ku) == 0) {
        areZero = 0;
    }
    #endif
#endif

    return areZero;
}

static void wolfCose_EccClearPrivateValues(ecc_key* ecc)
{
#ifdef ALT_ECC_SIZE
    wolfCose_AltMpClearValue(&ecc->ka[0]);
    #ifdef WOLFSSL_ECC_BLIND_K
    wolfCose_AltMpClearValue(&ecc->kba[0]);
    wolfCose_AltMpClearValue(&ecc->kua[0]);
    #endif
#else
    wolfCose_MpClearValue(ecc->k);
    #ifdef WOLFSSL_ECC_BLIND_K
    wolfCose_MpClearValue(ecc->kb);
    wolfCose_MpClearValue(ecc->ku);
    #endif
#endif
}

static int wolfCose_EccPrivateImportSupported(const ecc_key* ecc)
{
    int supported = 1;

    (void)ecc;

#ifdef WOLFCOSE_ECC_PRIVATE_IMPORT_ALWAYS_UNSUPPORTED
    supported = 0;
#else
    #if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_SETKEY)
    if (ecc->devId != INVALID_DEVID) {
        supported = 0;
    }
    #endif
#endif

    return supported;
}

typedef struct WOLFCOSE_ECC_IMPORT_STATE {
    int type;
    int idx;
    int state;
    const ecc_set_type* dp;
} WOLFCOSE_ECC_IMPORT_STATE;

static int wolfCose_EccPrivateImportBegin(ecc_key* ecc,
    WOLFCOSE_ECC_IMPORT_STATE* saved)
{
    int ret = WOLFCOSE_SUCCESS;

    saved->type = ecc->type;
    saved->idx = ecc->idx;
    saved->state = ecc->state;
    saved->dp = ecc->dp;

    /* wolfCrypt has no transactional ECC-key replacement API. Require an
     * initialized but empty destination so a failed import cannot overwrite
     * caller-owned key or custom-curve state. */
    if ((saved->type != 0) || (saved->idx != 0) || (saved->state != 0) ||
        (saved->dp != NULL)
#ifdef WOLFSSL_CUSTOM_CURVES
        || (ecc->deallocSet != 0)
#endif
        ) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#ifdef ALT_ECC_SIZE
    else if (((const void*)ecc->k != (const void*)&ecc->ka[0])
    #ifdef WOLFSSL_ECC_BLIND_K
             || ((const void*)ecc->kb != (const void*)&ecc->kba[0])
             || ((const void*)ecc->ku != (const void*)&ecc->kua[0])
    #endif
             ) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#endif
    else if (wolfCose_EccPrivateValuesAreZero(ecc) == 0) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (wolfCose_EccPrivateImportSupported(ecc) == 0) {
        ret = WOLFCOSE_E_UNSUPPORTED;
    }
    else {
        /* No action required */
    }

    return ret;
}

static void wolfCose_EccPrivateImportRollback(ecc_key* ecc,
    const WOLFCOSE_ECC_IMPORT_STATE* saved)
{
    wolfCose_EccClearPrivateValues(ecc);
    ecc->type = saved->type;
    ecc->idx = saved->idx;
    ecc->state = saved->state;
    ecc->dp = saved->dp;
}
#endif /* HAVE_ECC && WOLFCOSE_KEY_DECODE */

/* On a failed verify/decrypt, clear the header so unauthenticated metadata is
 * not exposed to callers that inspect hdr without gating on the return code. */
#if defined(WOLFCOSE_SIGN1_VERIFY) || defined(WOLFCOSE_SIGN_VERIFY) || \
    defined(WOLFCOSE_ENCRYPT0_DECRYPT) || defined(WOLFCOSE_MAC0_VERIFY) || \
    defined(WOLFCOSE_ENCRYPT_DECRYPT) || defined(WOLFCOSE_MAC_VERIFY)
static void wolfCose_HdrClearOnFail(int ret, WOLFCOSE_HDR* hdr)
{
    if ((ret != WOLFCOSE_SUCCESS) && (hdr != NULL)) {
        (void)XMEMSET(hdr, 0, sizeof(*hdr));
    }
}
#endif /* any verify/decrypt path */

/* ----- Constant-time comparison (side-channel safe) ----- */

/* Only the MAC verify paths compare secret tags, so this helper is compiled
 * only when one of them is enabled. This keeps sign-only and verify-only
 * builds free of an unused-function warning. */
#if defined(WOLFCOSE_MAC0_VERIFY) || defined(WOLFCOSE_MAC_VERIFY)
/**
 * Constant-time memory comparison (matches wolfSSL ConstantCompare pattern).
 * Returns 0 if equal, non-zero otherwise.
 * Timing is independent of comparison result.
 */
static int wolfCose_ConstantCompare(const byte* a, const byte* b,
                                     word32 length)
{
    word32 i;
    /* volatile prevents the compiler from converting the OR-accumulate
     * loop into an early-exit comparison once result is non-zero. */
    volatile unsigned int result = 0;

    for (i = 0; i < length; i++) {
        result |= (unsigned int)a[i] ^ (unsigned int)b[i];
    }
    return (int)result;
}
#endif /* WOLFCOSE_MAC0_VERIFY || WOLFCOSE_MAC_VERIFY */

/* ----- RFC 9052 context strings ----- */
WOLFCOSE_LOCAL const uint8_t WOLFCOSE_CTX_SIGNATURE1[10] = {
    0x53u, 0x69u, 0x67u, 0x6Eu, 0x61u, 0x74u, 0x75u, 0x72u, 0x65u, 0x31u
};
WOLFCOSE_LOCAL const uint8_t WOLFCOSE_CTX_SIGNATURE[9] = {
    0x53u, 0x69u, 0x67u, 0x6Eu, 0x61u, 0x74u, 0x75u, 0x72u, 0x65u
};
WOLFCOSE_LOCAL const uint8_t WOLFCOSE_CTX_MAC0[4] = {
    0x4Du, 0x41u, 0x43u, 0x30u
};
WOLFCOSE_LOCAL const uint8_t WOLFCOSE_CTX_MAC[3] = {
    0x4Du, 0x41u, 0x43u
};
WOLFCOSE_LOCAL const uint8_t WOLFCOSE_CTX_ENCRYPT0[8] = {
    0x45u, 0x6Eu, 0x63u, 0x72u, 0x79u, 0x70u, 0x74u, 0x30u
};
WOLFCOSE_LOCAL const uint8_t WOLFCOSE_CTX_ENCRYPT[7] = {
    0x45u, 0x6Eu, 0x63u, 0x72u, 0x79u, 0x70u, 0x74u
};

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

static int wolfCose_EccKeyCheckCurve(int32_t crv, ecc_key* eccKey)
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
static int wolfCose_AeadCheckPayloadLen(int32_t alg, size_t payloadLen)
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
static int wolfCose_HmacCheckKeyLen(int32_t alg, size_t keyLen)
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

/* ----- Internal: Protected/Unprotected header encode/decode ----- */

/* COSE algorithm, key type, and curve identifiers are stored in int32_t
 * fields. Reject decoded CBOR integers that do not fit before narrowing so a
 * non-representable value cannot alias a valid identifier. */
static int wolfCose_InInt32Range(int64_t val)
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

static void wolfCose_HdrStateInit(WOLFCOSE_HDR_STATE* state)
{
    if (state != NULL) {
        state->labelBits = 0u;
        state->extraCount = 0u;
    }
}

static int wolfCose_HdrStateContains(const WOLFCOSE_HDR_STATE* state,
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

static int wolfCose_HdrStateCheckAndAdd(WOLFCOSE_HDR_STATE* state,
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
static int wolfCose_SkipIfTstrLabel(const WOLFCOSE_CBOR_CTX* ctx, int* skipped)
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
static int wolfCose_DecodeSkippedSignature(WOLFCOSE_CBOR_CTX* ctx)
{
    size_t arrayCount = 0u;

    return wolfCose_DecodeSkippedHeaderEntry(ctx, 3u, &arrayCount, NULL);
}
#endif

#if defined(WOLFCOSE_ENCRYPT_DECRYPT) || defined(WOLFCOSE_MAC_VERIFY)
/* Structurally validate one non-selected COSE_recipient and every nested
 * recipient. Use an explicit bounded stack to avoid recursive C calls. */
static int wolfCose_DecodeSkippedRecipient(WOLFCOSE_CBOR_CTX* ctx,
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

/* ----- COSE Key API ----- */

int wc_CoseKey_Init(WOLFCOSE_KEY* key)
{
    int ret;

    if (key == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        (void)XMEMSET(key, 0, sizeof(WOLFCOSE_KEY));
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}

void wc_CoseKey_Free(WOLFCOSE_KEY* key)
{
    if (key != NULL) {
        /* Does NOT free the underlying wolfCrypt key -- caller owns it */
        (void)wolfCose_ForceZero(key, sizeof(WOLFCOSE_KEY));
    }
}

#ifdef HAVE_ECC
int wc_CoseKey_SetEcc(WOLFCOSE_KEY* key, int32_t crv, ecc_key* eccKey)
{
    int ret;

    if ((key == NULL) || (eccKey == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    /* Only RFC 9053 EC2 curves are valid here. Catch misuse such as
     * passing an OKP curve identifier at the point of mistake rather
     * than several layers later when a coordinate size is needed. */
    else if ((crv != WOLFCOSE_CRV_P256) && (crv != WOLFCOSE_CRV_P384) &&
             (crv != WOLFCOSE_CRV_P521)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (wolfCose_EccKeyCheckCurve(crv, eccKey) != WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        key->kty = WOLFCOSE_KTY_EC2;
        key->crv = crv;
        key->alg = WOLFCOSE_ALG_UNSET;
        key->key.ecc = eccKey;
        key->attachedType = WOLFCOSE_ATT_ECC;
#if defined(WOLFCOSE_EXT_SIGN)
        /* Attaching local material replaces a delegated signer; keeping it
         * would silently sign with the previous external signer. */
        key->signCb = NULL;
        key->signCtx = NULL;
#endif
        /* Check if private key is present */
        key->hasPrivate = ((wc_ecc_size(eccKey) > 0) &&
                           (eccKey->type == ECC_PRIVATEKEY)) ? 1u : 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif

#ifdef WOLFCOSE_HAVE_EDDSA
int wc_CoseKey_SetEd25519(WOLFCOSE_KEY* key, ed25519_key* edKey)
{
    int ret;

    if ((key == NULL) || (edKey == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        key->kty = WOLFCOSE_KTY_OKP;
        key->crv = WOLFCOSE_CRV_ED25519;
        key->alg = WOLFCOSE_ALG_UNSET;
        key->key.ed25519 = edKey;
        key->attachedType = WOLFCOSE_ATT_ED25519;
#if defined(WOLFCOSE_EXT_SIGN)
        /* Attaching local material replaces a delegated signer; keeping it
         * would silently sign with the previous external signer. */
        key->signCb = NULL;
        key->signCtx = NULL;
#endif
        key->hasPrivate = (edKey->privKeySet != 0u) ? 1u : 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif

#ifdef WOLFCOSE_HAVE_ED448
int wc_CoseKey_SetEd448(WOLFCOSE_KEY* key, ed448_key* edKey)
{
    int ret;

    if ((key == NULL) || (edKey == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        key->kty = WOLFCOSE_KTY_OKP;
        key->crv = WOLFCOSE_CRV_ED448;
        key->alg = WOLFCOSE_ALG_UNSET;
        key->key.ed448 = edKey;
        key->attachedType = WOLFCOSE_ATT_ED448;
#if defined(WOLFCOSE_EXT_SIGN)
        /* Attaching local material replaces a delegated signer; keeping it
         * would silently sign with the previous external signer. */
        key->signCb = NULL;
        key->signCtx = NULL;
#endif
        key->hasPrivate = (edKey->privKeySet != 0u) ? 1u : 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_ED448 */

#ifdef WOLFCOSE_HAVE_MLDSA
int wc_CoseKey_SetMlDsa_ex(WOLFCOSE_KEY* key, int32_t alg,
                          wc_MlDsaKey* mlDsaKey,
                          const uint8_t* seed, size_t seedLen)
{
    int ret;

    if ((key == NULL) || (mlDsaKey == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((alg != WOLFCOSE_ALG_ML_DSA_44) &&
             (alg != WOLFCOSE_ALG_ML_DSA_65) &&
             (alg != WOLFCOSE_ALG_ML_DSA_87)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else if ((seed != NULL) && (seedLen != WOLFCOSE_MLDSA_SEED_SZ)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        /* RFC 9964: ML-DSA uses the AKP key type, carries the level in alg, and
         * has no crv. crv is left unset (internal mapping only). */
        key->kty = WOLFCOSE_KTY_AKP;
        key->alg = alg;
        key->crv = 0;
        key->key.mldsa = mlDsaKey;
        key->attachedType = WOLFCOSE_ATT_MLDSA;
#if defined(WOLFCOSE_EXT_SIGN)
        /* Attaching local material replaces a delegated signer; keeping it
         * would silently sign with the previous external signer. */
        key->signCb = NULL;
        key->signCtx = NULL;
#endif
        key->mldsaSeed = seed;
        key->mldsaSeedLen = (seed != NULL) ? seedLen : (size_t)0;
        key->hasPrivate = (mlDsaKey->prvKeySet != 0u) ? 1u : 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}

int wc_CoseKey_SetMlDsa(WOLFCOSE_KEY* key, int32_t alg,
                          wc_MlDsaKey* mlDsaKey)
{
    return wc_CoseKey_SetMlDsa_ex(key, alg, mlDsaKey, NULL, 0);
}
#endif /* WOLFCOSE_HAVE_MLDSA */

#ifdef WOLFCOSE_HAVE_LMS
int wc_CoseKey_SetLms(WOLFCOSE_KEY* key, LmsKey* lmsKey)
{
    int ret;

    if ((key == NULL) || (lmsKey == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        /* RFC 8778: kty HSS-LMS (5), single algorithm HSS-LMS (-46), no crv.
         * The parameter set travels inside the RFC 8554 public key bytes. */
        key->kty = WOLFCOSE_KTY_HSS_LMS;
        key->alg = WOLFCOSE_ALG_HSS_LMS;
        key->crv = 0;
        key->key.lms = lmsKey;
        key->attachedType = WOLFCOSE_ATT_LMS;
#if defined(WOLFCOSE_EXT_SIGN)
        /* Attaching local material replaces a delegated signer; keeping it
         * would silently sign with the previous external signer. */
        key->signCb = NULL;
        key->signCtx = NULL;
#endif
        /* WC_LMS_STATE_OK (public wc_lms.h enum) means a private key is
         * loaded and able to sign. wc_LmsKey_SigsLeft() is not used here:
         * it dereferences private state and faults on a public-only or
         * not-yet-loaded key, which SetLms accepts for verification. */
        key->hasPrivate = (lmsKey->state == WC_LMS_STATE_OK) ? 1u : 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_LMS */

#ifdef WOLFCOSE_HAVE_RSAPSS
int wc_CoseKey_SetRsa(WOLFCOSE_KEY* key, RsaKey* rsaKey)
{
    int ret;

    if ((key == NULL) || (rsaKey == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        key->kty = WOLFCOSE_KTY_RSA;
        key->alg = WOLFCOSE_ALG_UNSET;
        key->key.rsa = rsaKey;
        key->attachedType = WOLFCOSE_ATT_RSA;
#if defined(WOLFCOSE_EXT_SIGN)
        /* Attaching local material replaces a delegated signer; keeping it
         * would silently sign with the previous external signer. */
        key->signCb = NULL;
        key->signCtx = NULL;
#endif
        key->hasPrivate = ((wc_RsaEncryptSize(rsaKey) > 0) &&
                           (rsaKey->type == RSA_PRIVATE)) ? 1u : 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_RSAPSS */

#ifdef WOLFCOSE_HAVE_RSAPSS
/* Widest RSA public exponent wolfCOSE emits and the RFC 8230 RSA-PSS
 * minimum modulus width. These are shared by COSE_Key encoding and message
 * operations, including builds that disable COSE_Key encoding. */
#define WOLFCOSE_RSA_E_MAX_SZ    8u
#define WOLFCOSE_RSA_PSS_MIN_SZ  256u
#endif

int wc_CoseKey_SetSymmetric(WOLFCOSE_KEY* key, const uint8_t* data,
                             size_t dataLen)
{
    int ret;

    if ((key == NULL) || (data == NULL) || (dataLen == 0u)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        key->kty = WOLFCOSE_KTY_SYMMETRIC;
        key->alg = WOLFCOSE_ALG_UNSET;
        key->key.symm.key = data;
        key->key.symm.keyLen = dataLen;
        key->attachedType = WOLFCOSE_ATT_SYMMETRIC;
#if defined(WOLFCOSE_EXT_SIGN)
        /* Attaching local material replaces a delegated signer; keeping it
         * would silently sign with the previous external signer. */
        key->signCb = NULL;
        key->signCtx = NULL;
#endif
        key->hasPrivate = 1;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}

#if defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_SIGN_SIGN)
/* Signing needs either private key material in wolfCOSE or a delegated signer;
 * hasPrivate alone conflates that with "the private key is here", which
 * governs whether wc_CoseKey_Encode may serialise it. */
static int wolfCose_KeyCanSign(const WOLFCOSE_KEY* key)
{
    int can = 0;

    if (key->hasPrivate == 1u) {
        can = 1;
    }
#if defined(WOLFCOSE_EXT_SIGN)
    if (key->signCb != NULL) {
        can = 1;
    }
#endif
    return can;
}
#endif /* WOLFCOSE_SIGN1_SIGN || WOLFCOSE_SIGN_SIGN */

#if defined(WOLFCOSE_EXT_SIGN)
int wc_CoseKey_SetExtSigner(WOLFCOSE_KEY* key, WOLFCOSE_SIGN_CB cb,
                             void* cbCtx)
{
    int ret;

    if (key == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        /* hasPrivate is deliberately untouched: clearing it here would not
         * be restored on detach, leaving attached local material unusable. */
        key->signCb = cb;
        key->signCtx = (cb != NULL) ? cbCtx : NULL;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif

/* ----- Internal: encoded-size arithmetic -----
 * Shared by the COSE_Key and COSE_Sign1 size queries. Every add is checked so
 * a size computation can never wrap into a too-small buffer request. */
#if defined(WOLFCOSE_KEY_ENCODE) || defined(WOLFCOSE_SIGN1_SIGN)
static int wolfCose_SizeAdd(size_t* total, size_t add)
{
    int ret = WOLFCOSE_SUCCESS;

    if ((total == NULL) || (add > ((size_t)-1 - *total))) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        *total += add;
    }
    return ret;
}

static size_t wolfCose_CborHeadSize(uint64_t val)
{
    size_t len;

    if (val <= 23u) {
        len = 1u;
    }
    else if (val <= 0xFFu) {
        len = 2u;
    }
    else if (val <= 0xFFFFu) {
        len = 3u;
    }
    else if (val <= 0xFFFFFFFFu) {
        len = 5u;
    }
    else {
        len = 9u;
    }
    return len;
}

static int wolfCose_CborStringSize(size_t len, size_t* encodedLen)
{
    size_t total = wolfCose_CborHeadSize((uint64_t)len);
    int ret;

    ret = wolfCose_SizeAdd(&total, len);
    if (ret == WOLFCOSE_SUCCESS) {
        *encodedLen = total;
    }
    return ret;
}
#endif /* WOLFCOSE_KEY_ENCODE || WOLFCOSE_SIGN1_SIGN */

#if defined(WOLFCOSE_KEY_ENCODE)

#if defined(HAVE_ECC) || defined(WOLFCOSE_HAVE_RSA_PRIVATE_KEY) || \
    defined(WOLFCOSE_HAVE_MLDSA) || defined(WOLFCOSE_HAVE_EDDSA) || \
    defined(WOLFCOSE_HAVE_ED448)
/* A delegated key may still carry local material, but its private half
 * belongs to the external signer and must not be serialised. A caller can
 * also demand a public-only encoding outright. Guarded to match its call
 * sites, which are all per-algorithm. */
static int wolfCose_KeyEmitsPrivate(const WOLFCOSE_KEY* key, uint32_t flags)
{
    int emits = 0;

    if (key->hasPrivate != 0u) {
        emits = 1;
    }
    if ((flags & WOLFCOSE_KEY_PUBLIC_ONLY) != 0u) {
        emits = 0;
    }
#if defined(WOLFCOSE_EXT_SIGN)
    if (key->signCb != NULL) {
        emits = 0;
    }
#endif
    return emits;
}

#endif /* any asymmetric key type */

static size_t wolfCose_KeyOptionalEntries(const WOLFCOSE_KEY* key)
{
    size_t count = 0u;

    if ((key != NULL) && (key->kid != NULL) && (key->kidLen > 0u)) {
        count++;
    }
    if ((key != NULL) && (key->alg != WOLFCOSE_ALG_UNSET)) {
        count++;
    }

    return count;
}

static int wolfCose_EncodeKeyOptionalFields(WOLFCOSE_CBOR_CTX* ctx,
    const WOLFCOSE_KEY* key)
{
    int ret = WOLFCOSE_SUCCESS;

    if ((ctx == NULL) || (key == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((key->kid != NULL) && (key->kidLen > 0u)) {
        ret = wc_CBOR_EncodeUint(ctx, (uint64_t)WOLFCOSE_KEY_LABEL_KID);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(ctx, key->kid, key->kidLen);
        }
    }
    else {
        /* No action required */
    }

    if ((ret == WOLFCOSE_SUCCESS) && (key->alg != WOLFCOSE_ALG_UNSET)) {
        ret = wc_CBOR_EncodeUint(ctx, (uint64_t)WOLFCOSE_KEY_LABEL_ALG);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeInt(ctx, (int64_t)key->alg);
        }
    }

    return ret;
}

#ifdef WOLFCOSE_HAVE_RSAPSS
/* Measure the RSA public exponent without mp_unsigned_bin_size(): that is
 * declared MP_API, which wolfSSL exports only when built with
 * WOLFSSL_PUBLIC_MP, so calling it here fails to link (undefined reference
 * to sp_unsigned_bin_size) against a stock library. */
static int wolfCose_RsaExponentSize(RsaKey* rsa, size_t* eLen)
{
    uint8_t eBuf[WOLFCOSE_RSA_E_MAX_SZ];
    word32 len = (word32)sizeof(eBuf);
    size_t lead = 0u;
    int ret = WOLFCOSE_SUCCESS;
#if !defined(HAVE_ECC) && !defined(WOLFSSL_EXPORT_INT)
    uint8_t nBuf[WOLFCOSE_MAX_SCRATCH_SZ];
    word32 nLen = (word32)sizeof(nBuf);
#endif

#if defined(HAVE_ECC) || defined(WOLFSSL_EXPORT_INT)
    /* wc_export_int() zero-pads to keySz, so the natural width is what is
     * left once the leading zeros are dropped. */
    if (wc_export_int(&rsa->e, eBuf, &len, (word32)sizeof(eBuf),
                      WC_TYPE_UNSIGNED_BIN) != 0) {
        ret = WOLFCOSE_E_CRYPTO;
    }
#else
    /* Without wc_export_int() the only public reader of e also wants the
     * modulus; take it into scratch and drop it. n is public, but there is
     * no reason to leave a copy on the stack.
     *
     * wc_RsaFlattenPublicKey() has no way to decline the modulus, so this
     * caps the size query at a WOLFCOSE_MAX_SCRATCH_SZ modulus while the
     * encoder, which flattens n straight into the caller's output buffer,
     * handles any modulus that fits there. A key wider than scratch (e.g.
     * RSA-8192 with the 512-byte WOLFCOSE_MIN_BUFFERS scratch) therefore
     * sizes as WOLFCOSE_E_CRYPTO but still encodes. Documented on
     * wc_CoseKey_EncodeSize_ex(); it costs nothing in a build with ECC or
     * WOLFSSL_EXPORT_INT, which is every build that reaches the branch above. */
    if (wc_RsaFlattenPublicKey(rsa, eBuf, &len, nBuf, &nLen) != 0) {
        ret = WOLFCOSE_E_CRYPTO;
    }
    wolfCose_ForceZero(nBuf, sizeof(nBuf));
#endif

    if (ret == WOLFCOSE_SUCCESS) {
        while ((lead < (size_t)len) && (eBuf[lead] == 0x00u)) {
            lead++;
        }
        if (lead == (size_t)len) {
            ret = WOLFCOSE_E_CRYPTO; /* e == 0 is not a usable key */
        }
        else {
            *eLen = (size_t)len - lead;
        }
    }
    return ret;
}

/* Finalize a directly-exported RSA bstr (n or d). The caller reserved a 3-byte
 * header at hdrPos and wrote the payload at hdrPos+3; emit the preferred CBOR
 * length form (0x58 for <256, shifting the payload left over the unused byte;
 * 0x59 otherwise) and advance ctx->idx past the value. */
static void wolfCose_FinalizeRsaBstr(WOLFCOSE_CBOR_CTX* ctx, size_t hdrPos,
                                      size_t payloadLen)
{
    if (payloadLen < 256u) {
        (void)XMEMMOVE(&ctx->buf[hdrPos + 2u], &ctx->buf[hdrPos + 3u],
                       payloadLen);
        ctx->buf[hdrPos] = 0x58u;
        ctx->buf[hdrPos + 1u] = (uint8_t)payloadLen;
        ctx->idx = hdrPos + 2u + payloadLen;
    }
    else {
        ctx->buf[hdrPos] = 0x59u;
        ctx->buf[hdrPos + 1u] = (uint8_t)((uint32_t)payloadLen >> 8u);
        ctx->buf[hdrPos + 2u] = (uint8_t)((uint32_t)payloadLen & 0xFFu);
        ctx->idx = hdrPos + 3u + payloadLen;
    }
}
#endif /* WOLFCOSE_HAVE_RSAPSS */

#ifdef WOLFCOSE_HAVE_RSA_PRIVATE_KEY
/* RFC 8230: write one RSA component (label + bstr) from its mp_int. */
static int wolfCose_EncodeRsaMp(WOLFCOSE_CBOR_CTX* ctx, int64_t label,
                                 mp_int* a, word32 keySz)
{
    int ret = WOLFCOSE_SUCCESS;
    word32 len = keySz;

    if (keySz == 0u) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(ctx, label);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CBOR_EncodeHead(ctx, WOLFCOSE_CBOR_BSTR,
            (uint64_t)keySz);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        if ((ctx->idx + (size_t)keySz) > ctx->bufSz) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }
        else if (wc_export_int(a, &ctx->buf[ctx->idx], &len, keySz,
                WC_TYPE_UNSIGNED_BIN) != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            ctx->idx += (size_t)len;
        }
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_RSA_PRIVATE_KEY */

#ifdef HAVE_ECC
/* Emit an EC2 COSE_Key map from raw affine coordinates:
 *   {1: kty [, 2: kid] [, 3: alg], -1: crv, -2: x, -3: y [, -4: d]}
 * Shared by wc_CoseKey_Encode_ex(), which exports the coordinates out of an
 * ecc_key first, and wc_CoseKey_EncodeEccRaw(), where the caller supplies
 * them. d == NULL selects the public-only form. */
static int wolfCose_EncodeEc2Map(WOLFCOSE_CBOR_CTX* ctx,
    const WOLFCOSE_KEY* key,
    const uint8_t* x, size_t xLen, const uint8_t* y, size_t yLen,
    const uint8_t* d, size_t dLen)
{
    int ret;
    /* Map: kty [, kid] [, alg], crv, x, y [, d]. Optional kid and alg are
     * emitted when set so the decode/encode roundtrip preserves them. */
    size_t mapEntries = (d != NULL) ? (size_t)5 : (size_t)4;

    mapEntries += wolfCose_KeyOptionalEntries(key);
    ret = wc_CBOR_EncodeMapStart(ctx, mapEntries);

    /* 1: kty */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(ctx, (uint64_t)WOLFCOSE_KEY_LABEL_KTY);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(ctx, (uint64_t)key->kty);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EncodeKeyOptionalFields(ctx, key);
    }
    /* -1: crv */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(ctx, (int64_t)WOLFCOSE_KEY_LABEL_CRV);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(ctx, (uint64_t)key->crv);
    }
    /* -2: x */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(ctx, (int64_t)WOLFCOSE_KEY_LABEL_X);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(ctx, x, xLen);
    }
    /* -3: y */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(ctx, (int64_t)WOLFCOSE_KEY_LABEL_Y);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(ctx, y, yLen);
    }
    /* -4: d (private key, optional) */
    if ((ret == WOLFCOSE_SUCCESS) && (d != NULL)) {
        ret = wc_CBOR_EncodeInt(ctx, (int64_t)WOLFCOSE_KEY_LABEL_D);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(ctx, d, dLen);
        }
    }

    return ret;
}
#endif /* HAVE_ECC */

int wc_CoseKey_Encode(WOLFCOSE_KEY* key, uint8_t* out, size_t outSz,
                       size_t* outLen)
{
    return wc_CoseKey_Encode_ex(key, out, outSz, outLen, 0u);
}

int wc_CoseKey_Encode_ex(WOLFCOSE_KEY* key, uint8_t* out, size_t outSz,
                          size_t* outLen, uint32_t flags)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_CBOR_CTX ctx;

    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((flags & ~(uint32_t)WOLFCOSE_KEY_PUBLIC_ONLY) != 0u) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        (void)wc_CBOR_EncoderInit(&ctx, out, outSz);

#ifdef HAVE_ECC
        if (key->kty == WOLFCOSE_KTY_EC2) {
            uint8_t xBuf[66]; /* Max P-521 coordinate */
            uint8_t yBuf[66];
            uint8_t dBuf[66];
            word32 xLen = (word32)sizeof(xBuf);
            word32 yLen = (word32)sizeof(yBuf);
            word32 dLen = (word32)sizeof(dBuf);
            size_t coordSz;
            int emitPriv = 0;

            if (key->key.ecc == NULL) {
                ret = WOLFCOSE_E_INVALID_ARG;
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_CrvKeySize(key->crv, &coordSz);
            }

            if (ret == WOLFCOSE_SUCCESS) {
                INJECT_FAILURE(WOLF_FAIL_ECC_EXPORT_X963, -1,
                    ret = wc_ecc_export_public_raw(key->key.ecc, xBuf, &xLen,
                                                   yBuf, &yLen));
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else if (((size_t)xLen != coordSz) ||
                         ((size_t)yLen != coordSz)) {
                    ret = WOLFCOSE_E_COSE_KEY_TYPE;
                }
                else {
                    /* No action required. */
                }
            }
            if (ret == WOLFCOSE_SUCCESS) {
                emitPriv = wolfCose_KeyEmitsPrivate(key, flags);
            }
            if ((ret == WOLFCOSE_SUCCESS) && (emitPriv != 0)) {
                INJECT_FAILURE(WOLF_FAIL_ECC_EXPORT_PRIVATE, -1,
                    ret = wc_ecc_export_private_only(key->key.ecc, dBuf,
                                                     &dLen));
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else if ((size_t)dLen != coordSz) {
                    ret = WOLFCOSE_E_COSE_KEY_TYPE;
                }
                else {
                    /* No action required. */
                }
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_EncodeEc2Map(&ctx, key, xBuf, (size_t)xLen,
                                            yBuf, (size_t)yLen,
                                            (emitPriv != 0) ? dBuf : NULL,
                                            (size_t)dLen);
            }

            if (ret == WOLFCOSE_SUCCESS) {
                *outLen = ctx.idx;
            }
            (void)wolfCose_ForceZero(xBuf, sizeof(xBuf));
            (void)wolfCose_ForceZero(yBuf, sizeof(yBuf));
            (void)wolfCose_ForceZero(dBuf, sizeof(dBuf));
        }
        else
#endif /* HAVE_ECC */
#ifdef WOLFCOSE_HAVE_RSAPSS
        if (key->kty == WOLFCOSE_KTY_RSA) {
            /* RFC 8230: {1:3, -1:n, -2:e [, -3:d, -4:p, -5:q, -8:qInv]}.
             * Export large components straight into the output buffer to
             * avoid stack copies (RSA-4096 modulus = 512 bytes). */
            uint8_t eBuf[WOLFCOSE_RSA_E_MAX_SZ]; /* typically 3 bytes */
            word32 eLen = (word32)sizeof(eBuf);
            word32 nLen;
            size_t hdrPos;
            size_t mapEntries;
            int rsaPriv = 0;
#ifdef WOLFCOSE_HAVE_RSA_PRIVATE_KEY
            word32 halfSz = 0;
#endif

            if (key->key.rsa == NULL) {
                ret = WOLFCOSE_E_INVALID_ARG;
            }
            /* Private round-trip needs the CRT export; else public-only. */
#ifdef WOLFCOSE_HAVE_RSA_PRIVATE_KEY
            if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_KeyEmitsPrivate(key, flags) != 0)) {
                rsaPriv = 1;
#ifdef WOLF_CRYPTO_CB
                /* Device-backed keys have no local CRT to export. */
                if (key->key.rsa->devId != INVALID_DEVID) {
                    rsaPriv = 0;
                }
#endif
            }
#endif
            /* Get n directly into output buffer, e into small stack buf */
            mapEntries = (rsaPriv != 0) ? (size_t)9 : (size_t)3;
            mapEntries += wolfCose_KeyOptionalEntries(key);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeMapStart(&ctx, mapEntries);
            }

            /* 1: kty */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx,
                                          (uint64_t)WOLFCOSE_KEY_LABEL_KTY);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)key->kty);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_EncodeKeyOptionalFields(&ctx, key);
            }
            /* -1: n (modulus) — direct export into output buffer */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_CRV);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                hdrPos = ctx.idx;
                if ((ctx.idx + 3u) > ctx.bufSz) {
                    ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                }
                else {
                    ctx.idx += 3u; /* reserve bstr header */
                    nLen = (word32)(ctx.bufSz - ctx.idx);
                    ret = wc_RsaFlattenPublicKey(key->key.rsa,
                        eBuf, &eLen, &ctx.buf[ctx.idx], &nLen);
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
                    else if ((nLen == 0u) || (nLen > 65535u)) {
                        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                    }
                    else {
                        wolfCose_FinalizeRsaBstr(&ctx, hdrPos, (size_t)nLen);
                    }
                }
            }
            /* -2: e (exponent, small — from stack buffer) */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_X);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeBstr(&ctx, eBuf, (size_t)eLen);
            }
            /* -3: d (private exponent, optional) — direct export */
            if ((ret == WOLFCOSE_SUCCESS) && (rsaPriv != 0)) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_Y);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdrPos = ctx.idx;
                    if ((ctx.idx + 3u) > ctx.bufSz) {
                        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                    }
                    else {
                        /* Use output buffer tail for d, then scratch
                         * space for e2/n2/p/q that RsaExportKey requires */
                        word32 dSz;
                        word32 eSz2;
                        word32 nSz2;
                        word32 pSz;
                        word32 qSz;
                        int rsaEncSz = 0;

                        INJECT_FAILURE(WOLF_FAIL_RSA_ENCRYPT_SIZE, rsaEncSz,
                            rsaEncSz = wc_RsaEncryptSize(key->key.rsa));
                        if (rsaEncSz <= 0) {
                            /* cppcheck-suppress redundantAssignment */
                            ret = WOLFCOSE_E_CRYPTO;
                        }
                        else {
                            size_t dOff;
                            size_t scrOff;
                            size_t needed;
                            ctx.idx += 3u;
                            dOff = ctx.idx;
                            /* After d: scratch for e2+n2+p+q */
                            scrOff = dOff + (size_t)rsaEncSz;
                            needed = scrOff + 8u + (size_t)rsaEncSz +
                                     (size_t)rsaEncSz; /* e2+n2+p+q */
                            if (needed > ctx.bufSz) {
                                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                            }
                            else {
                                dSz = (word32)rsaEncSz;
                                eSz2 = 8;
                                nSz2 = (word32)rsaEncSz;
                                pSz = (word32)((word32)rsaEncSz / 2u);
                                qSz = (word32)((word32)rsaEncSz / 2u);
                                INJECT_FAILURE(WOLF_FAIL_RSA_EXPORT_KEY, -1,
                                    ret = wc_RsaExportKey(
                                        key->key.rsa,
                                        &ctx.buf[scrOff], &eSz2,
                                        &ctx.buf[scrOff + 8u], &nSz2,
                                        &ctx.buf[dOff], &dSz,
                                        &ctx.buf[scrOff + 8u + nSz2], &pSz,
                                        &ctx.buf[scrOff + 8u + nSz2 + pSz],
                                        &qSz));
                                if (ret != 0) {
                                    ret = WOLFCOSE_E_CRYPTO;
                                }
                                else if ((dSz == 0u) || (dSz > 65535u)) {
                                    ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                                }
                                else {
                                    /* Left-pad d to the full modulus width: a
                                     * leading-zero byte would otherwise yield a
                                     * short bstr that stricter RSA decoders
                                     * reject (RFC 8230 octet-string width). */
                                    if (dSz < (word32)rsaEncSz) {
                                        size_t pad = (size_t)rsaEncSz -
                                                     (size_t)dSz;
                                        (void)XMEMMOVE(&ctx.buf[dOff + pad],
                                            &ctx.buf[dOff], (size_t)dSz);
                                        (void)XMEMSET(&ctx.buf[dOff], 0, pad);
                                        dSz = (word32)rsaEncSz;
                                    }
                                    wolfCose_FinalizeRsaBstr(&ctx, hdrPos,
                                        (size_t)dSz);
                                }
                                /* Zero scratch (e2/n2/p/q) */
                                (void)wolfCose_ForceZero(&ctx.buf[scrOff],
                                    needed - scrOff);
                            }
                        }
                    }
                }
            }
#ifdef WOLFCOSE_HAVE_RSA_PRIVATE_KEY
            /* -4 p, -5 q, -8 qInv: CRT factors so a decoded key can sign. */
            if ((ret == WOLFCOSE_SUCCESS) && (rsaPriv != 0)) {
                int modSz = wc_RsaEncryptSize(key->key.rsa);
                if (modSz <= 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else {
                    halfSz = ((word32)modSz + 1u) / 2u;
                }
            }
            if ((ret == WOLFCOSE_SUCCESS) && (rsaPriv != 0)) {
                ret = wolfCose_EncodeRsaMp(&ctx, WOLFCOSE_KEY_LABEL_RSA_P,
                    &key->key.rsa->p, halfSz);
            }
            if ((ret == WOLFCOSE_SUCCESS) && (rsaPriv != 0)) {
                ret = wolfCose_EncodeRsaMp(&ctx, WOLFCOSE_KEY_LABEL_RSA_Q,
                    &key->key.rsa->q, halfSz);
            }
            /* RFC 8230: dP and dQ are MUST-present for a two-prime private key.
             * Emitting them also avoids wolfCrypt recomputing the CRT exponents
             * on decode, which is fragile for some key values. */
            if ((ret == WOLFCOSE_SUCCESS) && (rsaPriv != 0)) {
                ret = wolfCose_EncodeRsaMp(&ctx, WOLFCOSE_KEY_LABEL_RSA_DP,
                    &key->key.rsa->dP, halfSz);
            }
            if ((ret == WOLFCOSE_SUCCESS) && (rsaPriv != 0)) {
                ret = wolfCose_EncodeRsaMp(&ctx, WOLFCOSE_KEY_LABEL_RSA_DQ,
                    &key->key.rsa->dQ, halfSz);
            }
            if ((ret == WOLFCOSE_SUCCESS) && (rsaPriv != 0)) {
                ret = wolfCose_EncodeRsaMp(&ctx, WOLFCOSE_KEY_LABEL_RSA_QINV,
                    &key->key.rsa->u, halfSz);
            }
#endif /* WOLFCOSE_HAVE_RSA_PRIVATE_KEY */

            if (ret == WOLFCOSE_SUCCESS) {
                *outLen = ctx.idx;
            }
            (void)wolfCose_ForceZero(eBuf, sizeof(eBuf));
        }
        else
#endif /* WOLFCOSE_HAVE_RSAPSS */
#ifdef WOLFCOSE_HAVE_MLDSA
        if (key->kty == WOLFCOSE_KTY_AKP) {
            /* RFC 9964 AKP COSE_Key: kty=AKP(7), required alg, public key at
             * pub(-1), 32-byte private seed at priv(-2). The public key is
             * large (1312-2592B) so it is exported directly into the output
             * buffer to avoid a large stack copy; the seed is small. */
            int emitPriv = 0;

            /* Emit priv only when a valid 32-byte seed is attached; wolfCrypt
             * does not retain the seed, so a keypair without one (e.g. from
             * wc_MlDsaKey_MakeKey) is exported as a public-only AKP key. */
            if ((wolfCose_KeyEmitsPrivate(key, flags) != 0) && (key->mldsaSeed != NULL) &&
                (key->mldsaSeedLen == WOLFCOSE_MLDSA_SEED_SZ)) {
                emitPriv = 1;
            }

            if (key->alg == WOLFCOSE_ALG_UNSET) {
                /* RFC 9964: alg is REQUIRED for AKP keys (it carries the
                 * ML-DSA level). Never emit a key without it. */
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }
            else {
                size_t dlMapEntries = (emitPriv != 0) ? (size_t)3 : (size_t)2;
                dlMapEntries += wolfCose_KeyOptionalEntries(key);
                ret = wc_CBOR_EncodeMapStart(&ctx, dlMapEntries);
            }

            /* 1: kty = AKP (7) */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx,
                                          (uint64_t)WOLFCOSE_KEY_LABEL_KTY);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)key->kty);
            }
            /* optional kid and the RFC 9964 required alg */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_EncodeKeyOptionalFields(&ctx, key);
            }
            /* -1: pub (public key bstr) - direct export into output */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_PUB);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                /* Reserve 3 bytes for CBOR bstr header (2-byte length).
                 * All ML-DSA pub sizes (1312-2592) need this form. */
                size_t hdrPos = ctx.idx;
                word32 dlKeyLen;
                if ((ctx.idx + 3u) > ctx.bufSz) {
                    ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                }
                else {
                    ctx.idx += 3u;
                    dlKeyLen = (word32)(ctx.bufSz - ctx.idx);
                    INJECT_FAILURE(WOLF_FAIL_MLDSA_EXPORT_PUB, -1,
                        ret = wc_MlDsaKey_ExportPubRaw(key->key.mldsa,
                            &ctx.buf[ctx.idx], &dlKeyLen));
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
                    else if ((dlKeyLen < 256u) || (dlKeyLen > 65535u)) {
                        /* Reserved 3 bytes for 2-byte AI; guard against
                         * future variants outside this range. */
                        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                    }
                    else {
                        /* bstr header: major type 2, AI 25 (2-byte len) */
                        ctx.buf[hdrPos] = 0x59u;
                        ctx.buf[hdrPos + 1u] =
                            (uint8_t)((uint32_t)dlKeyLen >> 8u);
                        ctx.buf[hdrPos + 2u] =
                            (uint8_t)((uint32_t)dlKeyLen & 0xFFu);
                        ctx.idx += (size_t)dlKeyLen;
                    }
                }
            }
            /* -2: priv (32-byte seed, only when a seed is attached) */
            if ((ret == WOLFCOSE_SUCCESS) && (emitPriv != 0)) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_PRIV);
                if (ret == WOLFCOSE_SUCCESS) {
                    INJECT_FAILURE(WOLF_FAIL_MLDSA_EXPORT_PRIV,
                        WOLFCOSE_E_CRYPTO,
                        ret = wc_CBOR_EncodeBstr(&ctx, key->mldsaSeed,
                            key->mldsaSeedLen));
                }
            }

            if (ret == WOLFCOSE_SUCCESS) {
                *outLen = ctx.idx;
            }
        }
        else
#endif /* WOLFCOSE_HAVE_MLDSA */
#ifdef WOLFCOSE_HAVE_LMS
        if (key->kty == WOLFCOSE_KTY_HSS_LMS) {
            /* RFC 8778 COSE_Key: {1: 5, [2: kid], [3: alg], -1: pub}. The
             * RFC defines no private-key labels, so the encoding is always
             * public-only; the parameter set is embedded in the RFC 8554
             * public key bytes. */
            uint8_t lmsPubBuf[HSS_MAX_PUBLIC_KEY_LEN];
            word32 lmsPubLen = (word32)sizeof(lmsPubBuf);
            size_t lmsMapEntries;

            /* kty alone does not prove the union holds an LmsKey: a key left
             * at kty 5 by a failed decode may still hold another type. Gate
             * on the attach discriminator before reading key.lms. */
            if (key->attachedType != WOLFCOSE_ATT_LMS) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else if (key->key.lms == NULL) {
                ret = WOLFCOSE_E_INVALID_ARG;
            }
            else {
                /* No action required */
            }
            if (ret == WOLFCOSE_SUCCESS) {
                INJECT_FAILURE(WOLF_FAIL_LMS_EXPORT_PUB, -1,
                    ret = wc_LmsKey_ExportPubRaw(key->key.lms,
                                                 lmsPubBuf, &lmsPubLen));
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }

            lmsMapEntries = 2u + wolfCose_KeyOptionalEntries(key);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeMapStart(&ctx, lmsMapEntries);
            }

            /* 1: kty = HSS-LMS (5) */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx,
                                          (uint64_t)WOLFCOSE_KEY_LABEL_KTY);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)key->kty);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_EncodeKeyOptionalFields(&ctx, key);
            }
            /* -1: pub (RFC 8554 HSS public key bstr) */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_PUB);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeBstr(&ctx, lmsPubBuf, (size_t)lmsPubLen);
            }

            if (ret == WOLFCOSE_SUCCESS) {
                *outLen = ctx.idx;
            }
            (void)wolfCose_ForceZero(lmsPubBuf, sizeof(lmsPubBuf));
        }
        else
#endif /* WOLFCOSE_HAVE_LMS */
#if defined(WOLFCOSE_HAVE_EDDSA) || defined(WOLFCOSE_HAVE_ED448)
        if (key->kty == WOLFCOSE_KTY_OKP) {
            uint8_t pubBuf[57]; /* Ed448 pub = 57 bytes, Ed25519 = 32 */
            word32 pubLen = (word32)sizeof(pubBuf);
            size_t mapEntries;

#ifdef WOLFCOSE_HAVE_EDDSA
            if (key->crv == WOLFCOSE_CRV_ED25519) {
                INJECT_FAILURE(WOLF_FAIL_ED25519_EXPORT_PUB, -1,
                    ret = wc_ed25519_export_public(key->key.ed25519,
                                                    pubBuf, &pubLen));
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }
            else
#endif
#ifdef WOLFCOSE_HAVE_ED448
            if (key->crv == WOLFCOSE_CRV_ED448) {
                INJECT_FAILURE(WOLF_FAIL_ED448_EXPORT_PUB, -1,
                    ret = wc_ed448_export_public(key->key.ed448,
                                                  pubBuf, &pubLen));
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }
            else
#endif
            {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }

            mapEntries = (wolfCose_KeyEmitsPrivate(key, flags) != 0) ? (size_t)4 : (size_t)3;
            mapEntries += wolfCose_KeyOptionalEntries(key);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeMapStart(&ctx, mapEntries);
            }

            /* 1: kty */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)WOLFCOSE_KEY_LABEL_KTY);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)key->kty);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_EncodeKeyOptionalFields(&ctx, key);
            }
            /* -1: crv */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx, (int64_t)WOLFCOSE_KEY_LABEL_CRV);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)key->crv);
            }
            /* -2: x (public key) */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx, (int64_t)WOLFCOSE_KEY_LABEL_X);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeBstr(&ctx, pubBuf, (size_t)pubLen);
            }
            /* -4: d (private key, optional) */
            if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_KeyEmitsPrivate(key, flags) != 0)) {
                uint8_t privBuf[57]; /* Ed448 priv = 57 bytes */
                word32 privLen = (word32)sizeof(privBuf);
#ifdef WOLFCOSE_HAVE_EDDSA
                if (key->crv == WOLFCOSE_CRV_ED25519) {
                    INJECT_FAILURE(WOLF_FAIL_ED25519_EXPORT_PRIV, -1,
                        ret = wc_ed25519_export_private_only(key->key.ed25519,
                                                              privBuf, &privLen));
                }
                else
#endif
#ifdef WOLFCOSE_HAVE_ED448
                if (key->crv == WOLFCOSE_CRV_ED448) {
                    INJECT_FAILURE(WOLF_FAIL_ED448_EXPORT_PRIV, -1,
                        ret = wc_ed448_export_private_only(key->key.ed448,
                                                            privBuf, &privLen));
                }
                else
#endif
                {
                    ret = WOLFCOSE_E_COSE_BAD_ALG;
                }
                if ((ret != 0) && (ret != WOLFCOSE_E_COSE_BAD_ALG)) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else if (ret == 0) {
                    ret = wc_CBOR_EncodeInt(&ctx,
                                             (int64_t)WOLFCOSE_KEY_LABEL_D);
                    if (ret == WOLFCOSE_SUCCESS) {
                        ret = wc_CBOR_EncodeBstr(&ctx, privBuf,
                                                  (size_t)privLen);
                    }
                }
                else {
                    /* No action required */
                }
                (void)wolfCose_ForceZero(privBuf, sizeof(privBuf));
            }

            if (ret == WOLFCOSE_SUCCESS) {
                *outLen = ctx.idx;
            }
            (void)wolfCose_ForceZero(pubBuf, sizeof(pubBuf));
        }
        else
#endif /* WOLFCOSE_HAVE_EDDSA || WOLFCOSE_HAVE_ED448 */
        if (key->kty == WOLFCOSE_KTY_SYMMETRIC) {
            /* {1: 4, -1: k_bytes} */
            size_t mapEntries = 2u + wolfCose_KeyOptionalEntries(key);

            /* k is the whole key, so there is no public-only form to fall
             * back on the way the asymmetric types have. */
            if ((flags & WOLFCOSE_KEY_PUBLIC_ONLY) != 0u) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
#if defined(WOLFCOSE_EXT_SIGN)
            if ((ret == WOLFCOSE_SUCCESS) && (key->signCb != NULL)) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
#endif
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeMapStart(&ctx, mapEntries);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)WOLFCOSE_KEY_LABEL_KTY);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)key->kty);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_EncodeKeyOptionalFields(&ctx, key);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx, (int64_t)WOLFCOSE_KEY_LABEL_K);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeBstr(&ctx, key->key.symm.key,
                                          key->key.symm.keyLen);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                *outLen = ctx.idx;
            }
        }
        else {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
    }

    /* Cleanup: zero output buffer on error */
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

#ifdef HAVE_ECC
int wc_CoseKey_EncodeEccRaw(int32_t crv, const uint8_t* x, const uint8_t* y,
                             const uint8_t* d, size_t coordLen,
                             const uint8_t* kid, size_t kidLen, int32_t alg,
                             uint8_t* out, size_t outSz, size_t* outLen)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_CBOR_CTX ctx;
    WOLFCOSE_KEY meta;
    size_t coordSz = 0u;

    if ((x == NULL) || (y == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    /* Only RFC 9053 EC2 curves belong in this map; wolfCose_CrvKeySize()
     * also answers for the OKP curves, which do not. */
    else if ((crv != WOLFCOSE_CRV_P256) && (crv != WOLFCOSE_CRV_P384) &&
             (crv != WOLFCOSE_CRV_P521)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        /* No action required */
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CrvKeySize(crv, &coordSz);
    }
    /* RFC 9053 Section 7.1.1: EC2 coordinates are fixed length with leading
     * zeros preserved, so a short buffer is a caller error, not a value to
     * pad here. */
    if ((ret == WOLFCOSE_SUCCESS) && (coordLen != coordSz)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    if ((ret == WOLFCOSE_SUCCESS) && (kid == NULL) && (kidLen != 0u)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        /* Metadata carrier only: no wolfCrypt key is attached or needed. */
        ret = wc_CoseKey_Init(&meta);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        meta.kty = WOLFCOSE_KTY_EC2;
        meta.crv = crv;
        meta.alg = alg;
        meta.kid = kid;
        meta.kidLen = kidLen;

        ctx.buf = out;
        ctx.cbuf = NULL;
        ctx.bufSz = outSz;
        ctx.idx = 0;

        ret = wolfCose_EncodeEc2Map(&ctx, &meta, x, coordLen, y, coordLen,
                                    d, coordLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = ctx.idx;
    }

    /* Cleanup: zero output buffer on error */
    if (ret != WOLFCOSE_SUCCESS) {
        if (out != NULL) {
            (void)wolfCose_ForceZero(out, outSz);
        }
        if (outLen != NULL) {
            *outLen = 0;
        }
    }

    return ret;
}
#endif /* HAVE_ECC */

/* Size of a CBOR integer as wc_CBOR_EncodeInt() would emit it. */
static size_t wolfCose_CborIntSize(int64_t val)
{
    size_t len;

    if (val >= 0) {
        len = wolfCose_CborHeadSize((uint64_t)val);
    }
    else {
        /* RFC 8949: negative integer n is encoded as -(n+1) */
        len = wolfCose_CborHeadSize((uint64_t)(-(val + 1)));
    }
    return len;
}

#if defined(WOLFCOSE_HAVE_RSAPSS) || defined(WOLFCOSE_HAVE_MLDSA)
/* Size of a bstr written through the reserved-header path (RSA n/d, ML-DSA
 * pub), which always emits the 1-byte-length form or wider -- never the
 * 1-byte immediate head. Mirrors wolfCose_FinalizeRsaBstr(). */
static int wolfCose_ReservedBstrSize(size_t payloadLen, size_t* encodedLen)
{
    size_t total = (payloadLen < 256u) ? (size_t)2 : (size_t)3;
    int ret;

    ret = wolfCose_SizeAdd(&total, payloadLen);
    if (ret == WOLFCOSE_SUCCESS) {
        *encodedLen = total;
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_RSAPSS || WOLFCOSE_HAVE_MLDSA */

/* Map head, 1: kty, and the optional 2: kid / 3: alg entries. entries counts
 * the mandatory members only; the optional ones are added here so the head
 * width matches what wc_CoseKey_Encode_ex() emits. */
static int wolfCose_KeyCommonSize(const WOLFCOSE_KEY* key, size_t entries,
                                   size_t* total)
{
    int ret;
    size_t itemLen = 0u;
    size_t sz = 0u;

    ret = wolfCose_SizeAdd(&entries, wolfCose_KeyOptionalEntries(key));
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_SizeAdd(&sz, wolfCose_CborHeadSize((uint64_t)entries));
    }
    /* 1: kty */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_SizeAdd(&sz, 1u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_SizeAdd(&sz, wolfCose_CborHeadSize((uint64_t)key->kty));
    }
    /* 2: kid */
    if ((ret == WOLFCOSE_SUCCESS) && (key->kid != NULL) && (key->kidLen > 0u)) {
        ret = wolfCose_SizeAdd(&sz, 1u);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_CborStringSize(key->kidLen, &itemLen);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_SizeAdd(&sz, itemLen);
        }
    }
    /* 3: alg */
    if ((ret == WOLFCOSE_SUCCESS) && (key->alg != WOLFCOSE_ALG_UNSET)) {
        ret = wolfCose_SizeAdd(&sz, 1u);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_SizeAdd(&sz,
                                   wolfCose_CborIntSize((int64_t)key->alg));
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        *total = sz;
    }
    return ret;
}

/* One "negative single-byte label + bstr" map entry. */
static int wolfCose_KeyBstrEntrySize(size_t payloadLen, size_t* total)
{
    size_t itemLen = 0u;
    int ret = wolfCose_SizeAdd(total, 1u);

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CborStringSize(payloadLen, &itemLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_SizeAdd(total, itemLen);
    }
    return ret;
}

int wc_CoseKey_EncodeSize(const WOLFCOSE_KEY* key, size_t* outLen)
{
    return wc_CoseKey_EncodeSize_ex(key, outLen, 0u);
}

int wc_CoseKey_EncodeSize_ex(const WOLFCOSE_KEY* key, size_t* outLen,
                              uint32_t flags)
{
    int ret = WOLFCOSE_SUCCESS;
    size_t total = 0u;

    if ((key == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((flags & ~(uint32_t)WOLFCOSE_KEY_PUBLIC_ONLY) != 0u) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        *outLen = 0u;

#ifdef HAVE_ECC
        if (key->kty == WOLFCOSE_KTY_EC2) {
            ecc_key* eccKey = key->key.ecc;
            size_t coordSz = 0u;
            int emitPriv;

            if (eccKey == NULL) {
                ret = WOLFCOSE_E_INVALID_ARG;
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_CrvKeySize(key->crv, &coordSz);
            }
            if ((ret == WOLFCOSE_SUCCESS) &&
                (wc_ecc_size(eccKey) != (int)coordSz)) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            emitPriv = (ret == WOLFCOSE_SUCCESS) ?
                wolfCose_KeyEmitsPrivate(key, flags) : 0;
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_KeyCommonSize(key,
                    (emitPriv != 0) ? (size_t)5 : (size_t)4, &total);
            }
            /* -1: crv */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_SizeAdd(&total, 1u);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_SizeAdd(&total,
                    wolfCose_CborHeadSize((uint64_t)key->crv));
            }
            /* -2: x, -3: y [, -4: d] */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_KeyBstrEntrySize(coordSz, &total);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_KeyBstrEntrySize(coordSz, &total);
            }
            if ((ret == WOLFCOSE_SUCCESS) && (emitPriv != 0)) {
                ret = wolfCose_KeyBstrEntrySize(coordSz, &total);
            }
        }
        else
#endif /* HAVE_ECC */
#ifdef WOLFCOSE_HAVE_RSAPSS
        if (key->kty == WOLFCOSE_KTY_RSA) {
            RsaKey* rsaKey = key->key.rsa;
            size_t itemLen = 0u;
            size_t modSz = 0u;
            size_t eSz = 0u;
            int rsaPriv = 0;
            int rsaEncSz;

            if (rsaKey == NULL) {
                ret = WOLFCOSE_E_INVALID_ARG;
            }
            if (ret == WOLFCOSE_SUCCESS) {
                /* Same value wc_RsaFlattenPublicKey() reports for n. */
                rsaEncSz = wc_RsaEncryptSize(rsaKey);
                if (rsaEncSz <= 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else {
                    modSz = (size_t)rsaEncSz;
                }
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_RsaExponentSize(rsaKey, &eSz);
            }
#ifdef WOLFCOSE_HAVE_RSA_PRIVATE_KEY
            if ((ret == WOLFCOSE_SUCCESS) &&
                (wolfCose_KeyEmitsPrivate(key, flags) != 0)) {
                rsaPriv = 1;
#ifdef WOLF_CRYPTO_CB
                /* Device-backed keys have no local CRT to export. */
                if (rsaKey->devId != INVALID_DEVID) {
                    rsaPriv = 0;
                }
#endif
            }
#endif /* WOLFCOSE_HAVE_RSA_PRIVATE_KEY */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_KeyCommonSize(key,
                    (rsaPriv != 0) ? (size_t)9 : (size_t)3, &total);
            }
            /* -1: n (reserved-header direct export) */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_SizeAdd(&total, 1u);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_ReservedBstrSize(modSz, &itemLen);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_SizeAdd(&total, itemLen);
            }
            /* -2: e */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_KeyBstrEntrySize(eSz, &total);
            }
            /* -3: d (reserved-header, left-padded to the modulus width) */
            if ((ret == WOLFCOSE_SUCCESS) && (rsaPriv != 0)) {
                ret = wolfCose_SizeAdd(&total, 1u);
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wolfCose_ReservedBstrSize(modSz, &itemLen);
                }
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wolfCose_SizeAdd(&total, itemLen);
                }
            }
#ifdef WOLFCOSE_HAVE_RSA_PRIVATE_KEY
            /* -4 p, -5 q, -6 dP, -7 dQ, -8 qInv: all half-modulus width */
            if ((ret == WOLFCOSE_SUCCESS) && (rsaPriv != 0)) {
                size_t halfSz = (modSz + 1u) / 2u;
                size_t i;
                for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < 5u); i++) {
                    ret = wolfCose_KeyBstrEntrySize(halfSz, &total);
                }
            }
#endif /* WOLFCOSE_HAVE_RSA_PRIVATE_KEY */
        }
        else
#endif /* WOLFCOSE_HAVE_RSAPSS */
#ifdef WOLFCOSE_HAVE_MLDSA
        if (key->kty == WOLFCOSE_KTY_AKP) {
            wc_MlDsaKey* mldsaKey = key->key.mldsa;
            size_t itemLen = 0u;
            size_t pubSz = 0u;
            int emitPriv = 0;

            if (mldsaKey == NULL) {
                ret = WOLFCOSE_E_INVALID_ARG;
            }
            /* Read the FIPS 204 public key length from the key itself, not
             * from alg: alg is caller-supplied and wc_CoseKey_SetMlDsa() does
             * not cross-check it against the attached parameter set, so an
             * alg-derived length would disagree with the wc_MlDsaKey_ExportPubRaw()
             * length the encoder writes. Mirrors the encoder's alg and range
             * checks so the size is exact whenever the encode succeeds. */
            if (ret == WOLFCOSE_SUCCESS) {
                int dlPubLen = 0;

                if (key->alg == WOLFCOSE_ALG_UNSET) {
                    /* RFC 9964: alg is REQUIRED for AKP keys. */
                    ret = WOLFCOSE_E_COSE_BAD_ALG;
                }
                else if (wc_MlDsaKey_GetPubLen(mldsaKey,
                                               &dlPubLen) != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else if ((dlPubLen < 256) || (dlPubLen > 65535)) {
                    /* Encoder reserves a 3-byte header for a 2-byte AI. */
                    ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                }
                else {
                    pubSz = (size_t)dlPubLen;
                }
            }
            if ((ret == WOLFCOSE_SUCCESS) &&
                (wolfCose_KeyEmitsPrivate(key, flags) != 0) &&
                (key->mldsaSeed != NULL) &&
                (key->mldsaSeedLen == WOLFCOSE_MLDSA_SEED_SZ)) {
                emitPriv = 1;
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_KeyCommonSize(key,
                    (emitPriv != 0) ? (size_t)3 : (size_t)2, &total);
            }
            /* -1: pub (reserved-header direct export) */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_SizeAdd(&total, 1u);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_ReservedBstrSize(pubSz, &itemLen);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_SizeAdd(&total, itemLen);
            }
            /* -2: priv (32-byte seed) */
            if ((ret == WOLFCOSE_SUCCESS) && (emitPriv != 0)) {
                ret = wolfCose_KeyBstrEntrySize(
                    (size_t)WOLFCOSE_MLDSA_SEED_SZ, &total);
            }
        }
        else
#endif /* WOLFCOSE_HAVE_MLDSA */
#ifdef WOLFCOSE_HAVE_LMS
        if (key->kty == WOLFCOSE_KTY_HSS_LMS) {
            size_t lmsPubSz = 0u;

            /* Match wc_CoseKey_Encode_ex: reject a kty 5 key whose union does
             * not actually hold an LmsKey before reading key.lms. */
            if (key->attachedType != WOLFCOSE_ATT_LMS) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else if (key->key.lms == NULL) {
                ret = WOLFCOSE_E_INVALID_ARG;
            }
            else {
                /* No action required */
            }
            if (ret == WOLFCOSE_SUCCESS) {
                word32 lmsPubLen = 0;
                if (wc_LmsKey_GetPubLen(key->key.lms, &lmsPubLen) != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else {
                    lmsPubSz = (size_t)lmsPubLen;
                }
            }
            /* {1: kty, [2: kid], [3: alg], -1: pub}: RFC 8778 defines no
             * private-key labels, so the size never includes one. */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_KeyCommonSize(key, (size_t)2, &total);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_KeyBstrEntrySize(lmsPubSz, &total);
            }
        }
        else
#endif /* WOLFCOSE_HAVE_LMS */
#if defined(WOLFCOSE_HAVE_EDDSA) || defined(WOLFCOSE_HAVE_ED448)
        if (key->kty == WOLFCOSE_KTY_OKP) {
            size_t okpSz = 0u;
            int emitPriv;

#ifdef WOLFCOSE_HAVE_EDDSA
            if (key->crv == WOLFCOSE_CRV_ED25519) {
                if (key->key.ed25519 == NULL) {
                    ret = WOLFCOSE_E_INVALID_ARG;
                }
                okpSz = (size_t)ED25519_PUB_KEY_SIZE;
            }
            else
#endif
#ifdef WOLFCOSE_HAVE_ED448
            if (key->crv == WOLFCOSE_CRV_ED448) {
                if (key->key.ed448 == NULL) {
                    ret = WOLFCOSE_E_INVALID_ARG;
                }
                okpSz = (size_t)ED448_PUB_KEY_SIZE;
            }
            else
#endif
            {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }

            emitPriv = (ret == WOLFCOSE_SUCCESS) ?
                wolfCose_KeyEmitsPrivate(key, flags) : 0;
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_KeyCommonSize(key,
                    (emitPriv != 0) ? (size_t)4 : (size_t)3, &total);
            }
            /* -1: crv */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_SizeAdd(&total, 1u);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_SizeAdd(&total,
                    wolfCose_CborHeadSize((uint64_t)key->crv));
            }
            /* -2: x [, -4: d]. Both Edwards curves use one width. */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_KeyBstrEntrySize(okpSz, &total);
            }
            if ((ret == WOLFCOSE_SUCCESS) && (emitPriv != 0)) {
                ret = wolfCose_KeyBstrEntrySize(okpSz, &total);
            }
        }
        else
#endif /* WOLFCOSE_HAVE_EDDSA || WOLFCOSE_HAVE_ED448 */
        if (key->kty == WOLFCOSE_KTY_SYMMETRIC) {
            if ((flags & WOLFCOSE_KEY_PUBLIC_ONLY) != 0u) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
#if defined(WOLFCOSE_EXT_SIGN)
            if ((ret == WOLFCOSE_SUCCESS) && (key->signCb != NULL)) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
#endif
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_KeyCommonSize(key, (size_t)2, &total);
            }
            /* -1: k */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_KeyBstrEntrySize(key->key.symm.keyLen, &total);
            }
        }
        else {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }

        if (ret == WOLFCOSE_SUCCESS) {
            *outLen = total;
        }
    }

    return ret;
}
#endif /* WOLFCOSE_KEY_ENCODE */

#if defined(WOLFCOSE_KEY_DECODE)
#if defined(SIZE_MAX) && (SIZE_MAX > 0xFFFFFFFFUL)
static int wolfCose_LenFitsWord32(size_t n);
#endif

/* Decoded kty/crv select the importer, so they must name the type the caller
 * attached; a non-NULL key.* union member cannot tell them apart. */
static int wolfCose_KeyAttachedTypeCheck(const WOLFCOSE_KEY* key)
{
    int ret = WOLFCOSE_SUCCESS;

    switch (key->attachedType) {
        case WOLFCOSE_ATT_NONE:
            break;
        case WOLFCOSE_ATT_ECC:
            if (key->kty != WOLFCOSE_KTY_EC2) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            break;
        case WOLFCOSE_ATT_ED25519:
            if ((key->kty != WOLFCOSE_KTY_OKP) ||
                (key->crv != WOLFCOSE_CRV_ED25519)) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            break;
        case WOLFCOSE_ATT_ED448:
            if ((key->kty != WOLFCOSE_KTY_OKP) ||
                (key->crv != WOLFCOSE_CRV_ED448)) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            break;
        case WOLFCOSE_ATT_RSA:
            if (key->kty != WOLFCOSE_KTY_RSA) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            break;
        case WOLFCOSE_ATT_MLDSA:
            if (key->kty != WOLFCOSE_KTY_AKP) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            break;
        case WOLFCOSE_ATT_SYMMETRIC:
            if (key->kty != WOLFCOSE_KTY_SYMMETRIC) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            break;
        case WOLFCOSE_ATT_LMS:
            if (key->kty != WOLFCOSE_KTY_HSS_LMS) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            break;
        default:
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
            break;
    }

    return ret;
}

int wc_CoseKey_PeekInfo(const uint8_t* in, size_t inSz,
                         WOLFCOSE_KEY_INFO* info)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    WOLFCOSE_HDR_STATE keyLabelState;
    size_t mapCount = 0;
    int64_t label;

    if ((in == NULL) || (inSz == 0u) || (info == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        size_t i;

        ctx.buf = NULL;
        ctx.cbuf = in;
        ctx.bufSz = inSz;
        ctx.idx = 0;
        wolfCose_HdrStateInit(&keyLabelState);

        info->kty = 0;
        info->alg = WOLFCOSE_ALG_UNSET;
        info->crv = 0;
        info->kid = NULL;
        info->kidLen = 0;

        ret = wc_CBOR_DecodeMapStart(&ctx, &mapCount);

        if ((ret == WOLFCOSE_SUCCESS) &&
            (mapCount > (size_t)WOLFCOSE_MAX_MAP_ITEMS)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
            mapCount = 0; /* Coverity: clear tainted loop bound */
        }

        for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < mapCount); i++) {
            int keySkipped = 0;

            /* RFC 9052: COSE_Key labels follow label = int / tstr; the
             * decoder supports the integer form only, so mirror it here. */
            ret = wolfCose_SkipIfTstrLabel(&ctx, &keySkipped);
            if ((ret == WOLFCOSE_SUCCESS) && (keySkipped == 0)) {
                ret = wc_CBOR_DecodeInt(&ctx, &label);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_HdrStateCheckAndAdd(&keyLabelState, label);
            }

            if ((ret == WOLFCOSE_SUCCESS) &&
                (label == WOLFCOSE_KEY_LABEL_KTY)) {
                uint64_t uval;
                ret = wc_CBOR_DecodeUint(&ctx, &uval);
                if ((ret == WOLFCOSE_SUCCESS) &&
                    (uval > (uint64_t)INT32_MAX)) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
                if (ret == WOLFCOSE_SUCCESS) {
                    info->kty = (int32_t)uval;
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_KEY_LABEL_KID)) {
                ret = wc_CBOR_DecodeBstr(&ctx, &info->kid, &info->kidLen);
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_KEY_LABEL_ALG)) {
                int64_t algVal;
                ret = wc_CBOR_DecodeInt(&ctx, &algVal);
                if ((ret == WOLFCOSE_SUCCESS) &&
                    (wolfCose_InInt32Range(algVal) == 0)) {
                    ret = WOLFCOSE_E_COSE_BAD_ALG;
                }
                if (ret == WOLFCOSE_SUCCESS) {
                    info->alg = (int32_t)algVal;
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_KEY_LABEL_KEY_OPS)) {
                ret = WOLFCOSE_E_UNSUPPORTED;
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_KEY_LABEL_CRV)) {
                /* -1 is crv for EC2/OKP but k (bstr) for Symmetric and n
                 * (bstr) for RSA, so dispatch on the CBOR type -- kty may
                 * not have been seen yet. */
                if ((ctx.idx < ctx.bufSz) &&
                    (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_BSTR)) {
                    ret = wc_CBOR_Skip(&ctx);
                }
                else {
                    int64_t crvVal;
                    ret = wc_CBOR_DecodeInt(&ctx, &crvVal);
                    if ((ret == WOLFCOSE_SUCCESS) &&
                        (wolfCose_InInt32Range(crvVal) == 0)) {
                        ret = WOLFCOSE_E_COSE_BAD_HDR;
                    }
                    if (ret == WOLFCOSE_SUCCESS) {
                        info->crv = (int32_t)crvVal;
                    }
                }
            }
            else {
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wc_CBOR_Skip(&ctx);
                }
            }
        }

        /* kty is mandatory: without it there is nothing to dispatch on. */
        if ((ret == WOLFCOSE_SUCCESS) && (info->kty == 0)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
        /* RFC 8949 Section 5.3.1: reject trailing data, as wc_CoseKey_Decode
         * does, so a successful peek predicts a successful decode. */
        if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != ctx.bufSz)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }

        if (ret != WOLFCOSE_SUCCESS) {
            /* Never leave a half-parsed key looking usable. */
            info->kty = 0;
            info->alg = WOLFCOSE_ALG_UNSET;
            info->crv = 0;
            info->kid = NULL;
            info->kidLen = 0;
        }
    }

    return ret;
}

int wc_CoseKey_Decode(WOLFCOSE_KEY* key, const uint8_t* in, size_t inSz)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    size_t mapCount = 0;
    size_t i;
    int64_t label;
    uint64_t uval;
    const uint8_t* bstrData;
    size_t bstrLen;
    const uint8_t* xData = NULL;  /* EC2: x coord, RSA: e (exponent) */
    size_t xLen = 0;
    const uint8_t* yData = NULL;  /* EC2: y coord, RSA: d (private exp) */
    size_t yLen = 0;
    const uint8_t* dData = NULL;  /* EC2/OKP: private key, RSA: p */
    size_t dLen = 0;
    const uint8_t* nData = NULL;  /* RSA: n (modulus) */
    size_t nLen = 0;
#ifdef WOLFCOSE_HAVE_RSA_PRIVATE_KEY
    const uint8_t* qData = NULL;  /* RSA: q (second prime) */
    size_t qLen = 0;
    const uint8_t* dpData = NULL; /* RSA: dP = d mod (p-1) */
    size_t dpLen = 0;
    const uint8_t* dqData = NULL; /* RSA: dQ = d mod (q-1) */
    size_t dqLen = 0;
    const uint8_t* qiData = NULL; /* RSA: qInv (CRT coefficient) */
    size_t qiLen = 0;
#endif
    WOLFCOSE_HDR_STATE keyLabelState;

    if ((key == NULL) || (in == NULL) || (inSz == 0u)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
#if defined(WOLFCOSE_EXT_SIGN)
    else if (key->signCb != NULL) {
        /* Decoding here would import private material into a key whose whole
         * point is that wolfCOSE holds none, and silently sign locally with
         * it. Detach first if the key is genuinely being re-purposed. */
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
#endif
    else {
        ctx.cbuf = in;
        ctx.bufSz = inSz;
        ctx.idx = 0;
        wolfCose_HdrStateInit(&keyLabelState);

        /* Reset decoded metadata so a malformed key cannot reuse caller state
         * (e.g. a prior kty/hasPrivate). The key.* union is left untouched: it
         * holds the caller-attached wolfCrypt object used for import. */
        key->kty = 0;
        key->alg = WOLFCOSE_ALG_UNSET;
        key->crv = 0;
        key->kid = NULL;
        key->kidLen = 0;
        key->hasPrivate = 0;
#ifdef WOLFSSL_HAVE_MLDSA
        key->mldsaSeed = NULL;
        key->mldsaSeedLen = 0;
#endif

        ret = wc_CBOR_DecodeMapStart(&ctx, &mapCount);

        if ((ret == WOLFCOSE_SUCCESS) && (mapCount > (size_t)WOLFCOSE_MAX_MAP_ITEMS)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
            mapCount = 0; /* Coverity: clear tainted loop bound */
        }

        for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < mapCount); i++) {
            int keySkipped = 0;

            /* RFC 9052: COSE_Key labels follow label = int / tstr. */
            ret = wolfCose_SkipIfTstrLabel(&ctx, &keySkipped);
            if ((ret == WOLFCOSE_SUCCESS) && (keySkipped == 0)) {
                ret = wc_CBOR_DecodeInt(&ctx, &label);
            }

            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_HdrStateCheckAndAdd(&keyLabelState, label);
            }

            if ((ret == WOLFCOSE_SUCCESS) &&
                (label == WOLFCOSE_KEY_LABEL_KTY)) {
                ret = wc_CBOR_DecodeUint(&ctx, &uval);
                if ((ret == WOLFCOSE_SUCCESS) &&
                    (uval > (uint64_t)INT32_MAX)) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
                if (ret == WOLFCOSE_SUCCESS) {
                    key->kty = (int32_t)uval;
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_KEY_LABEL_KID)) {
                ret = wc_CBOR_DecodeBstr(&ctx, &bstrData, &bstrLen);
                if (ret == WOLFCOSE_SUCCESS) {
                    key->kid = bstrData;
                    key->kidLen = bstrLen;
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_KEY_LABEL_ALG)) {
                if ((ctx.idx < ctx.bufSz) &&
                    (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TSTR)) {
                    ret = WOLFCOSE_E_COSE_BAD_ALG;
                }
                else {
                    int64_t algVal;
                    ret = wc_CBOR_DecodeInt(&ctx, &algVal);
                    if ((ret == WOLFCOSE_SUCCESS) &&
                        (wolfCose_InInt32Range(algVal) == 0)) {
                        ret = WOLFCOSE_E_COSE_BAD_ALG;
                    }
                    if (ret == WOLFCOSE_SUCCESS) {
                        key->alg = (int32_t)algVal;
                    }
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_KEY_LABEL_KEY_OPS)) {
                ret = WOLFCOSE_E_UNSUPPORTED;
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_KEY_LABEL_CRV)) {
                /* -1: crv(uint/negint) for EC2/OKP, k(bstr) for Symmetric,
                 *     n(bstr) for RSA (RFC 8230).
                 * Peek at CBOR type so decode is order-independent --
                 * kty may not have been parsed yet (non-canonical CBOR). */
                if ((ctx.idx < ctx.bufSz) &&
                    (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_BSTR)) {
                    /* bstr: either symmetric k or RSA n.
                     * Route to correct field in import phase via kty. */
                    ret = wc_CBOR_DecodeBstr(&ctx, &bstrData, &bstrLen);
                    if (ret == WOLFCOSE_SUCCESS) {
                        /* Stash in nData; import phase dispatches on kty */
                        nData = bstrData;
                        nLen = bstrLen;
                    }
                }
                else {
                    /* uint or negint: EC2/OKP crv */
                    int64_t crvVal;
                    ret = wc_CBOR_DecodeInt(&ctx, &crvVal);
                    if ((ret == WOLFCOSE_SUCCESS) &&
                        (wolfCose_InInt32Range(crvVal) == 0)) {
                        ret = WOLFCOSE_E_COSE_BAD_HDR;
                    }
                    if (ret == WOLFCOSE_SUCCESS) {
                        key->crv = (int32_t)crvVal;
                    }
                }
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_KEY_LABEL_X)) {
                ret = wc_CBOR_DecodeBstr(&ctx, &xData, &xLen);
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_KEY_LABEL_Y)) {
                ret = wc_CBOR_DecodeBstr(&ctx, &yData, &yLen);
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_KEY_LABEL_D)) {
                ret = wc_CBOR_DecodeBstr(&ctx, &dData, &dLen);
            }
#ifdef WOLFCOSE_HAVE_RSA_PRIVATE_KEY
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_KEY_LABEL_RSA_Q)) {
                ret = wc_CBOR_DecodeBstr(&ctx, &qData, &qLen);
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_KEY_LABEL_RSA_DP)) {
                ret = wc_CBOR_DecodeBstr(&ctx, &dpData, &dpLen);
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_KEY_LABEL_RSA_DQ)) {
                ret = wc_CBOR_DecodeBstr(&ctx, &dqData, &dqLen);
            }
            else if ((ret == WOLFCOSE_SUCCESS) &&
                     (label == WOLFCOSE_KEY_LABEL_RSA_QINV)) {
                ret = wc_CBOR_DecodeBstr(&ctx, &qiData, &qiLen);
            }
#endif
            else {
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wc_CBOR_Skip(&ctx);
                }
            }
        }

        /* kty is mandatory. Validate before import so an absent kty cannot
         * fall through to a stale key type. */
        if ((ret == WOLFCOSE_SUCCESS) && (key->kty == 0)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }

        /* RFC 8949 Section 5.3.1: reject trailing data before importing any
         * key material so a failed decode leaves no key populated. */
        if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != ctx.bufSz)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }

#if defined(SIZE_MAX) && (SIZE_MAX > 0xFFFFFFFFUL)
        /* wolfCrypt key import APIs take word32 lengths. Reject every parsed
         * component before any conversion can truncate it. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((wolfCose_LenFitsWord32(nLen) == 0) ||
             (wolfCose_LenFitsWord32(xLen) == 0) ||
             (wolfCose_LenFitsWord32(yLen) == 0) ||
             (wolfCose_LenFitsWord32(dLen) == 0))) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
#ifdef WOLFCOSE_HAVE_RSA_PRIVATE_KEY
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((wolfCose_LenFitsWord32(qLen) == 0) ||
             (wolfCose_LenFitsWord32(dpLen) == 0) ||
             (wolfCose_LenFitsWord32(dqLen) == 0) ||
             (wolfCose_LenFitsWord32(qiLen) == 0))) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
#endif
#endif

        /* An EC2 key must contain either a complete public point or a private
         * scalar. Validate this independently of whether a wolfCrypt key is
         * attached for import. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            (key->kty == WOLFCOSE_KTY_EC2) &&
            (((xData == NULL) || (yData == NULL)) && (dData == NULL))) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }

#ifdef HAVE_ECC
        /* RFC 9053 Section 7.1.1: EC2 coordinates are fixed length with
         * leading zeros preserved. Reject any present coordinate that does not
         * equal the curve size, even when no key is attached for import. */
        if ((ret == WOLFCOSE_SUCCESS) && (key->kty == WOLFCOSE_KTY_EC2)) {
            size_t coordSz = 0;
            ret = wolfCose_CrvKeySize(key->crv, &coordSz);
            if ((ret == WOLFCOSE_SUCCESS) &&
                (((xData != NULL) && (xLen != coordSz)) ||
                 ((yData != NULL) && (yLen != coordSz)) ||
                 ((dData != NULL) && (dLen != coordSz)))) {
                ret = WOLFCOSE_E_COSE_BAD_HDR;
            }
        }
#endif

        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_KeyAttachedTypeCheck(key);
        }

        /* RFC 9964 requires alg to select an ML-DSA parameter set. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            (key->kty == WOLFCOSE_KTY_AKP) &&
            (key->alg != WOLFCOSE_ALG_ML_DSA_44) &&
            (key->alg != WOLFCOSE_ALG_ML_DSA_65) &&
            (key->alg != WOLFCOSE_ALG_ML_DSA_87)) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
        /* RFC 9964 requires pub for both public and private AKP keys. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            (key->kty == WOLFCOSE_KTY_AKP) && (nData == NULL)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
        /* RFC 9964 encodes an ML-DSA private key as a 32-byte seed. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            (key->kty == WOLFCOSE_KTY_AKP) && (xData != NULL) &&
            (xLen != WOLFCOSE_MLDSA_SEED_SZ)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
#ifdef WOLFSSL_MLDSA_NO_MAKE_KEY
        /* This wolfSSL configuration has no private-seed expansion API.
         * Metadata-only decode can still validate the representation, while
         * an attached key cannot import it. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            (key->kty == WOLFCOSE_KTY_AKP) && (xData != NULL) &&
            (key->attachedType == WOLFCOSE_ATT_MLDSA)) {
            ret = WOLFCOSE_E_UNSUPPORTED;
        }
#endif
        /* RFC 8778 registers only the HSS-LMS algorithm for kty HSS-LMS. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            (key->kty == WOLFCOSE_KTY_HSS_LMS) &&
            (key->alg != WOLFCOSE_ALG_UNSET) &&
            (key->alg != WOLFCOSE_ALG_HSS_LMS)) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
        /* RFC 8778 defines exactly one key member: the public key at -1.
         * It arrives as a bstr, so the label loop stashed it in nData. */
        if ((ret == WOLFCOSE_SUCCESS) &&
            (key->kty == WOLFCOSE_KTY_HSS_LMS) &&
            ((nData == NULL) || (xData != NULL) || (yData != NULL) ||
             (dData != NULL))) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }

        /* Import key data into wolfCrypt key structs */
        if (ret == WOLFCOSE_SUCCESS) {
#ifdef HAVE_ECC
            if ((key->kty == WOLFCOSE_KTY_EC2) &&
                (key->attachedType == WOLFCOSE_ATT_ECC)) {
                if ((xData == NULL) || (yData == NULL)) {
                    /* RFC 9052: x/y are recommended, not required, for a
                     * private EC2 key, so accept {kty, crv, d} alone. */
                    if (dData != NULL) {
                        int wcCrv = 0;
                        WOLFCOSE_ECC_IMPORT_STATE importState;

                        ret = wolfCose_EccPrivateImportBegin(key->key.ecc,
                                                             &importState);
                        if (ret == WOLFCOSE_SUCCESS) {
                            ret = wolfCose_CrvToWcCurve(key->crv, &wcCrv);
                        }
                        if (ret == WOLFCOSE_SUCCESS) {
                            INJECT_FAILURE(WOLF_FAIL_ECC_IMPORT_X963, -1,
                                ret = wc_ecc_import_private_key_ex(dData,
                                    (word32)dLen, NULL, 0, key->key.ecc, wcCrv));
#ifdef WOLFCOSE_FORCE_FAILURE
                            if (ret == 0) {
                                INJECT_FAILURE(
                                    WOLF_FAIL_ECC_IMPORT_PRIVATE_POST, -1,
                                    ret = WOLFCOSE_SUCCESS);
                            }
#endif
                            if (ret == 0) {
                                key->hasPrivate = 1;
                            }
                            else {
                                wolfCose_EccPrivateImportRollback(key->key.ecc,
                                                                 &importState);
                                key->hasPrivate = 0;
                                ret = WOLFCOSE_E_CRYPTO;
                            }
                        }
                    }
                    else {
                        ret = WOLFCOSE_E_COSE_BAD_HDR;
                    }
                }
                else {
                    int wcCrv;
                    size_t coordSz = 0;
                    WOLFCOSE_ECC_IMPORT_STATE importState;

                    if (dData != NULL) {
                        ret = wolfCose_EccPrivateImportBegin(key->key.ecc,
                                                             &importState);
                    }
                    if (ret == WOLFCOSE_SUCCESS) {
                        ret = wolfCose_CrvToWcCurve(key->crv, &wcCrv);
                    }
                    if (ret == WOLFCOSE_SUCCESS) {
                        ret = wolfCose_CrvKeySize(key->crv, &coordSz);
                    }
                    if (ret == WOLFCOSE_SUCCESS) {
                        byte tmpX[MAX_ECC_BYTES];
                        byte tmpY[MAX_ECC_BYTES];
                        byte tmpD[MAX_ECC_BYTES];

                        if (coordSz > sizeof(tmpX)) {
                            ret = WOLFCOSE_E_COSE_BAD_HDR;
                        }
                        /* Coordinates are fixed length (validated above). */
                        if (ret == WOLFCOSE_SUCCESS) {
                            (void)XMEMSET(tmpX, 0, sizeof(tmpX));
                            (void)XMEMSET(tmpY, 0, sizeof(tmpY));
                            (void)XMEMSET(tmpD, 0, sizeof(tmpD));
                            (void)XMEMCPY(tmpX, xData, coordSz);
                            (void)XMEMCPY(tmpY, yData, coordSz);
                            if (dData != NULL) {
                                (void)XMEMCPY(tmpD, dData, coordSz);
                                INJECT_FAILURE(WOLF_FAIL_ECC_IMPORT_X963, -1,
                                    ret = wc_ecc_import_unsigned(
                                        key->key.ecc,
                                        tmpX, tmpY, tmpD, wcCrv));
                                (void)wolfCose_ForceZero(tmpD, sizeof(tmpD));
#ifdef WOLFCOSE_FORCE_FAILURE
                                if (ret == 0) {
                                    INJECT_FAILURE(
                                        WOLF_FAIL_ECC_IMPORT_PRIVATE_POST, -1,
                                        ret = WOLFCOSE_SUCCESS);
                                }
#endif
                                if (ret == 0) {
                                    key->hasPrivate = 1;
                                }
                                else {
                                    wolfCose_EccPrivateImportRollback(
                                        key->key.ecc, &importState);
                                    key->hasPrivate = 0;
                                }
                            }
                            else {
                                INJECT_FAILURE(WOLF_FAIL_ECC_IMPORT_X963, -1,
                                    ret = wc_ecc_import_unsigned(
                                        key->key.ecc,
                                        tmpX, tmpY, NULL, wcCrv));
                            }
                        }
                        if ((ret != WOLFCOSE_SUCCESS) &&
                            (ret != WOLFCOSE_E_INVALID_ARG) &&
                            (ret != WOLFCOSE_E_UNSUPPORTED)) {
                            ret = WOLFCOSE_E_CRYPTO;
                        }
                    }
                }
            }
            else
#endif
#ifdef WOLFCOSE_HAVE_RSAPSS
            if ((key->kty == WOLFCOSE_KTY_RSA) &&
                (key->attachedType == WOLFCOSE_ATT_RSA)) {
                /* RFC 8230: -1 n, -2 e, -3 d, -4 p, -5 q, -8 qInv. */
                if ((nData == NULL) || (xData == NULL)) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
#ifdef WOLFCOSE_HAVE_RSA_PRIVATE_KEY
                else if ((yData != NULL) && (dData != NULL) &&
                         (qData != NULL) && (qiData != NULL)) {
                    /* dP/dQ (when present) are forwarded as-is; an imported
                     * private COSE_Key is trusted as much as its source, and
                     * wolfCrypt's sign-then-verify CRT fault check guards
                     * against a tampered CRT exponent producing a faulty sig. */
                    INJECT_FAILURE(WOLF_FAIL_RSA_PUBLIC_DECODE, -1,
                        ret = wc_RsaPrivateKeyDecodeRaw(nData, (word32)nLen,
                            xData, (word32)xLen, yData, (word32)yLen,
                            qiData, (word32)qiLen, dData, (word32)dLen,
                            qData, (word32)qLen,
                            dpData, (word32)dpLen, dqData, (word32)dqLen,
                            key->key.rsa));
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
                    else {
                        key->hasPrivate = 1u;
                    }
                }
#endif /* WOLFCOSE_HAVE_RSA_PRIVATE_KEY */
                else {
                    INJECT_FAILURE(WOLF_FAIL_RSA_PUBLIC_DECODE, -1,
                        ret = wc_RsaPublicKeyDecodeRaw(nData, (word32)nLen,
                            xData, (word32)xLen, key->key.rsa));
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
                    else {
                        key->hasPrivate = 0u;
                    }
                }
            }
            else
#endif
#ifdef WOLFCOSE_HAVE_MLDSA
            if ((key->kty == WOLFCOSE_KTY_AKP) &&
                (key->attachedType == WOLFCOSE_ATT_MLDSA)) {
                /* RFC 9964 AKP: pub(-1) bstr was stashed in nData, the priv(-2)
                 * 32-byte seed in xData. The ML-DSA level comes from alg. */
                const uint8_t* akpPub = nData;
                size_t akpPubLen = nLen;
#ifndef WOLFSSL_MLDSA_NO_MAKE_KEY
                const uint8_t* akpSeed = xData;
                size_t akpSeedLen = xLen;
#endif
                byte dlLevel;

                if (key->alg == WOLFCOSE_ALG_ML_DSA_44) {
                    dlLevel = 2;
                }
                else if (key->alg == WOLFCOSE_ALG_ML_DSA_65) {
                    dlLevel = 3;
                }
                else if (key->alg == WOLFCOSE_ALG_ML_DSA_87) {
                    dlLevel = 5;
                }
                else {
                    dlLevel = 0;
                }

                if (dlLevel == 0u) {
                    ret = WOLFCOSE_E_COSE_BAD_ALG;
                }
                else if (key->crv != 0) {
                    /* RFC 9964 AKP keys carry no crv. */
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
                else if (akpPub == NULL) {
                    /* RFC 9964: pub is REQUIRED for AKP keys, public or
                     * private. Reject a seed-only key with no public part. */
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
                else {
                    ret = wc_MlDsaKey_SetParams(key->key.mldsa, dlLevel);
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
                    if (ret == WOLFCOSE_SUCCESS) {
                        /* Apply the parameter-set-specific public key import
                         * checks before deriving a private key from its seed. */
                        INJECT_FAILURE(WOLF_FAIL_MLDSA_IMPORT_PUB, -1,
                            ret = wc_MlDsaKey_ImportPubRaw(
                                key->key.mldsa, akpPub,
                                (word32)akpPubLen));
                        if (ret != 0) {
                            ret = WOLFCOSE_E_CRYPTO;
                        }
                    }
#ifndef WOLFSSL_MLDSA_NO_MAKE_KEY
                    if ((ret == WOLFCOSE_SUCCESS) && (akpSeed != NULL)) {
                        if (akpSeedLen != WOLFCOSE_MLDSA_SEED_SZ) {
                            ret = WOLFCOSE_E_COSE_BAD_HDR;
                        }
                        else {
                            INJECT_FAILURE(WOLF_FAIL_MLDSA_IMPORT_PRIV, -1,
                                ret = wc_MlDsaKey_MakeKeyFromSeed(
                                    key->key.mldsa, akpSeed));
                            if ((ret == 0) &&
                                (XMEMCMP(key->key.mldsa->p, akpPub,
                                         akpPubLen) != 0)) {
                                wolfCose_MlDsaImportRollback(
                                    key->key.mldsa, dlLevel);
                                key->hasPrivate = 0u;
                                key->mldsaSeed = NULL;
                                key->mldsaSeedLen = 0u;
                                ret = WOLFCOSE_E_COSE_BAD_HDR;
                            }
                            else if (ret == 0) {
                                key->hasPrivate = 1;
                                /* Retain the seed (zero-copy into the input,
                                 * like kid) so a decode->encode round-trip can
                                 * re-emit the private key. */
                                key->mldsaSeed = akpSeed;
                                key->mldsaSeedLen = akpSeedLen;
                            }
                            else {
                                wolfCose_MlDsaImportRollback(
                                    key->key.mldsa, dlLevel);
                                key->hasPrivate = 0u;
                                key->mldsaSeed = NULL;
                                key->mldsaSeedLen = 0u;
                                ret = WOLFCOSE_E_CRYPTO;
                            }
                        }
                    }
#endif
                }
            }
            else
#endif /* WOLFCOSE_HAVE_MLDSA */
#ifdef WOLFCOSE_HAVE_LMS
            if ((key->kty == WOLFCOSE_KTY_HSS_LMS) &&
                (key->attachedType == WOLFCOSE_ATT_LMS)) {
                /* RFC 8778: pub(-1) bstr was stashed in nData. The RFC 8554
                 * levels/type codes inside it select the parameter set, so
                 * the import derives or cross-checks the key's parameters.
                 * There is no private-key wire form: the import is always
                 * public/verify-only. Reaching here means nData holds the pub
                 * bstr, so label -1 was not an int and crv is unset. */
                INJECT_FAILURE(WOLF_FAIL_LMS_IMPORT_PUB, -1,
                    ret = wc_LmsKey_ImportPubRaw(key->key.lms, nData,
                                                 (word32)nLen));
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else {
                    key->hasPrivate = 0u;
                }
            }
            else
#endif /* WOLFCOSE_HAVE_LMS */
#if defined(WOLFCOSE_HAVE_EDDSA) || defined(WOLFCOSE_HAVE_ED448)
            if (key->kty == WOLFCOSE_KTY_OKP) {
                /* RFC 9052: x is recommended, not required, for a private OKP
                 * key, so accept {kty, crv, d} and recompute the public key. */
                if ((xData == NULL) && (dData == NULL)) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
#ifdef WOLFCOSE_HAVE_EDDSA
                else if ((key->crv == WOLFCOSE_CRV_ED25519) &&
                         (key->attachedType == WOLFCOSE_ATT_ED25519)) {
                    if (dData != NULL) {
                        if (xData != NULL) {
                            INJECT_FAILURE(WOLF_FAIL_ED25519_IMPORT_PRIV, -1,
                                ret = wc_ed25519_import_private_key(dData,
                                    (word32)dLen, xData, (word32)xLen,
                                    key->key.ed25519));
                        }
                        else {
                            INJECT_FAILURE(WOLF_FAIL_ED25519_IMPORT_PRIV, -1,
                                ret = wc_ed25519_import_private_only(dData,
                                    (word32)dLen, key->key.ed25519));
                            if (ret == 0) {
                                INJECT_FAILURE(WOLF_FAIL_ED25519_MAKE_PUB, -1,
                                    ret = wc_ed25519_make_public(
                                        key->key.ed25519,
                                        key->key.ed25519->p,
                                        ED25519_PUB_KEY_SIZE));
                                if (ret != 0) {
                                    (void)wolfCose_ForceZero(
                                        key->key.ed25519->k,
                                        ED25519_KEY_SIZE);
                                    key->key.ed25519->privKeySet = 0;
                                }
                            }
                        }
                        if (ret == 0) { key->hasPrivate = 1; }
                        else { ret = WOLFCOSE_E_CRYPTO; }
                    }
                    else {
                        INJECT_FAILURE(WOLF_FAIL_ED25519_IMPORT_PUB, -1,
                            ret = wc_ed25519_import_public(xData, (word32)xLen,
                                                            key->key.ed25519));
                        if (ret != 0) { ret = WOLFCOSE_E_CRYPTO; }
                    }
                }
#endif
#ifdef WOLFCOSE_HAVE_ED448
                else if ((key->crv == WOLFCOSE_CRV_ED448) &&
                         (key->attachedType == WOLFCOSE_ATT_ED448)) {
                    if (dData != NULL) {
                        if (xData != NULL) {
                            INJECT_FAILURE(WOLF_FAIL_ED448_IMPORT_PRIV, -1,
                                ret = wc_ed448_import_private_key(dData,
                                    (word32)dLen, xData, (word32)xLen,
                                    key->key.ed448));
                        }
                        else {
                            INJECT_FAILURE(WOLF_FAIL_ED448_IMPORT_PRIV, -1,
                                ret = wc_ed448_import_private_only(dData,
                                    (word32)dLen, key->key.ed448));
                            if (ret == 0) {
                                INJECT_FAILURE(WOLF_FAIL_ED448_MAKE_PUB, -1,
                                    ret = wc_ed448_make_public(
                                        key->key.ed448,
                                        key->key.ed448->p,
                                        ED448_PUB_KEY_SIZE));
                                if (ret != 0) {
                                    (void)wolfCose_ForceZero(
                                        key->key.ed448->k, ED448_KEY_SIZE);
                                    key->key.ed448->privKeySet = 0;
                                }
                            }
                        }
                        if (ret == 0) { key->hasPrivate = 1; }
                        else { ret = WOLFCOSE_E_CRYPTO; }
                    }
                    else {
                        INJECT_FAILURE(WOLF_FAIL_ED448_IMPORT_PUB, -1,
                            ret = wc_ed448_import_public(xData, (word32)xLen,
                                                          key->key.ed448));
                        if (ret != 0) { ret = WOLFCOSE_E_CRYPTO; }
                    }
                }
#endif
                else {
                    ret = WOLFCOSE_E_COSE_BAD_ALG;
                }
            }
            else
#endif /* WOLFCOSE_HAVE_EDDSA || WOLFCOSE_HAVE_ED448 */
            if (key->kty == WOLFCOSE_KTY_SYMMETRIC) {
                /* nData holds the symmetric k value (parsed from label -1).
                 * Reject a missing or empty mandatory k parameter. */
                if ((nData == NULL) || (nLen == 0u)) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
                else {
                    key->key.symm.key = nData;
                    key->key.symm.keyLen = nLen;
                    key->hasPrivate = 1;
                }
            }
            else {
                /* Other key types (EC2/OKP/RSA) without a caller-attached
                 * wolfCrypt key reach this fall-through; the metadata
                 * (kty, crv, alg, kid) is still populated so the caller
                 * can inspect it. Nothing to do here. */
            }
        }
    }

    return ret;
}
#endif /* WOLFCOSE_KEY_DECODE */

/* ----- Internal: RSA-PSS hash-to-MGF mapping ----- */
#if defined(WOLFCOSE_HAVE_RSAPSS) && \
    (defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_SIGN1_VERIFY) || \
     defined(WOLFCOSE_SIGN_SIGN) || defined(WOLFCOSE_SIGN_VERIFY))
/* RFC 8230 Section 6.1 requires RSA-PSS keys of at least 2048 bits. */
static int wolfCose_RsaPssCheckKey(const WOLFCOSE_KEY* key,
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
static int wolfCose_HashToMgf(enum wc_HashType hashType, int* mgf)
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

/* -----
 * Unified Structure Builders (Phase 3 refactoring)
 *
 * These shared helpers reduce code size by unifying:
 * - Sig_structure (Sign1/Sign): [context, body_prot, [sign_prot,] ext_aad, payload]
 * - MAC_structure (Mac0/Mac): [context, body_prot, ext_aad, payload]
 * - Enc_structure (Encrypt0/Encrypt): [context, body_prot, ext_aad]
 * ----- */

/**
 * Build a ToBeSigned/ToBeMAced structure (RFC 9052 Section 4.4, 6.3).
 *
 * For Sign1/Mac0/Mac: [context, body_protected, external_aad, payload]
 * For Sign (multi-signer): [context, body_protected, sign_protected, external_aad, payload]
 */
int wolfCose_BuildToBeSignedMaced(
    const uint8_t* context, size_t contextLen,
    const uint8_t* bodyProtected, size_t bodyProtectedLen,
    const uint8_t* signProtected, size_t signProtectedLen,
    const uint8_t* extAad, size_t extAadLen,
    const uint8_t* payload, size_t payloadLen,
    uint8_t* scratch, size_t scratchSz,
    size_t* structLen)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;

    if ((context == NULL) || (scratch == NULL) || (structLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        size_t arrayLen;
        ctx.buf = scratch;
        ctx.bufSz = scratchSz;
        ctx.idx = 0;

        /* 4 elements normally, 5 if sign_protected is present (multi-signer) */
        arrayLen = (signProtected != NULL) ? (size_t)5 : (size_t)4;

        ret = wc_CBOR_EncodeArrayStart(&ctx, arrayLen);

        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeTstr(&ctx, context, contextLen);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, bodyProtected, bodyProtectedLen);
        }
        if ((ret == WOLFCOSE_SUCCESS) && (signProtected != NULL)) {
            ret = wc_CBOR_EncodeBstr(&ctx, signProtected, signProtectedLen);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, extAad, extAadLen);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, payload, payloadLen);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            *structLen = ctx.idx;
        }
    }
    return ret;
}

#if (defined(WOLFCOSE_ENCRYPT0) || defined(WOLFCOSE_ENCRYPT)) && \
    (defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM) || \
     defined(WOLFCOSE_HAVE_CHACHA20))
/**
 * Build an Enc_structure for AEAD operations (RFC 9052 Section 5.3).
 *
 * [context, body_protected, external_aad]
 */
static int wolfCose_BuildEncStructure(
    const uint8_t* context, size_t contextLen,
    const uint8_t* bodyProtected, size_t bodyProtectedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    size_t* structLen)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;

    if ((context == NULL) || (scratch == NULL) || (structLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ctx.buf = scratch;
        ctx.bufSz = scratchSz;
        ctx.idx = 0;

        ret = wc_CBOR_EncodeArrayStart(&ctx, 3);

        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeTstr(&ctx, context, contextLen);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, bodyProtected, bodyProtectedLen);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, extAad, extAadLen);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            *structLen = ctx.idx;
        }
    }
    return ret;
}
#endif /* (ENCRYPT0 || ENCRYPT) && AEAD */

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
static int wolfCose_KeyWrapKeySize(int32_t alg, size_t* keySz)
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
static int wolfCose_KeyWrap(int32_t alg, const WOLFCOSE_KEY* kek,
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
static int wolfCose_KeyUnwrap(int32_t alg, const WOLFCOSE_KEY* kek,
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
static int wolfCose_IsKeyWrapAlg(int32_t alg)
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
static int wolfCose_EcdhEsDirect(int32_t alg,
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
static int wolfCose_EcdhEsDirectRecv(int32_t alg,
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
static int wolfCose_IsEcdhEsDirectAlg(int32_t alg)
{
    return ((alg == WOLFCOSE_ALG_ECDH_ES_HKDF_256) ||
            (alg == WOLFCOSE_ALG_ECDH_ES_HKDF_512)) ? 1 : 0;
}

/**
 * Encode ephemeral public key as COSE_Key in recipient unprotected header.
 *
 * COSE_Key: {1: 2, -1: crv, -2: x, -3: y}
 */
static int wolfCose_EncodeEphemeralKey(WOLFCOSE_CBOR_CTX* ctx,
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
static int wolfCose_DecodeEphemeralKey(WOLFCOSE_CBOR_CTX* ctx,
                                        int* crv,
                                        uint8_t* x, size_t xSz, size_t* xLen,
                                        uint8_t* y, size_t ySz, size_t* yLen)
{
    int ret;
    size_t mapCount = 0;
    size_t i;
    int64_t label;
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
static int wolfCose_UpdateRecipientMode(int32_t alg, int* commonMode)
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
#define WOLFCOSE_CHECK_WORD32_LEN
/* Reject a size_t length that cannot be represented as word32, so a structure,
 * payload, or key length fails cleanly instead of truncating when cast for
 * wolfCrypt. */
static int wolfCose_LenFitsWord32(size_t n)
{
    int ret = 1;
    if (n > (size_t)0xFFFFFFFFUL) {
        ret = 0;
    }
    return ret;
}
#endif

/* ----- COSE_Sign1 API ----- */

/* Used by both COSE_Sign1 and COSE_Sign, so kept outside the
 * WOLFCOSE_SIGN1 region below, but narrowed to the signing and verifying
 * operations that actually call them. */
#if defined(WOLFCOSE_HAVE_MLDSA) && \
    (defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_SIGN1_VERIFY) || \
     defined(WOLFCOSE_SIGN_SIGN) || defined(WOLFCOSE_SIGN_VERIFY))
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
static int wolfCose_MlDsaCheckKey(const WOLFCOSE_KEY* key, int32_t alg)
{
    int ret;
    byte reqLevel = 0;

    if ((key == NULL) || (key->kty != WOLFCOSE_KTY_AKP) ||
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
     defined(WOLFCOSE_EXT_SIGN))
/* RFC 8778: validate that the key is HSS-LMS-typed and was attached through
 * wc_CoseKey_SetLms() so the union member is known to be an LmsKey. */
static int wolfCose_LmsCheckKey(const WOLFCOSE_KEY* key)
{
    int ret = WOLFCOSE_SUCCESS;

    if ((key == NULL) || (key->kty != WOLFCOSE_KTY_HSS_LMS) ||
        (key->attachedType != WOLFCOSE_ATT_LMS) || (key->key.lms == NULL)) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_LMS */

#if defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_EXT_SIGN)
/* Exact signature length for this key and algorithm. wolfCose_SigSize() alone
 * reports EdDSA's worst case rather than the key's curve, and has no RSA case.
 * Fails closed when the exact length cannot be determined. */
static int wolfCose_SignSigLen(const WOLFCOSE_KEY* key, int32_t alg,
                               size_t* expSigLen)
{
    int ret;

    (void)key;

    switch (alg) {
#if defined(WOLFCOSE_HAVE_EDDSA) || defined(WOLFCOSE_HAVE_ED448)
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
#if defined(WOLFCOSE_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY)
        case WOLFCOSE_ALG_HSS_LMS:
        {
            /* The exact length lives in the attached key's parameter set,
             * so an LMS key must be attached even for a delegated signer. */
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
#if defined(WOLFCOSE_HAVE_ECDSA)
            /* ES* lengths come from alg alone, so a declared curve would
             * otherwise be ignored here while the local path rejects it.
             * crv 0 means the caller declared none, which stays legal. */
            if (ret == WOLFCOSE_SUCCESS) {
                int32_t expectedCrv = 0;
                if (alg == WOLFCOSE_ALG_ES256) {
                    expectedCrv = WOLFCOSE_CRV_P256;
                }
                else if (alg == WOLFCOSE_ALG_ES384) {
                    expectedCrv = WOLFCOSE_CRV_P384;
                }
                else if (alg == WOLFCOSE_ALG_ES512) {
                    expectedCrv = WOLFCOSE_CRV_P521;
                }
                else {
                    /* No action required */
                }
                /* expectedCrv stays 0 for non-ECDSA, which this arm does not
                 * bind. A declared kty or crv is honoured for ES* the way the
                 * local path does; 0 means the caller declared none. */
                if ((key != NULL) && (expectedCrv != 0)) {
                    if ((key->kty != 0) && (key->kty != WOLFCOSE_KTY_EC2)) {
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
static int wolfCose_ExtSignAlg(int32_t alg, int* preHashes)
{
    int ret = WOLFCOSE_SUCCESS;

    switch (alg) {
#if defined(WOLFCOSE_HAVE_ES256)
        case WOLFCOSE_ALG_ES256:
            *preHashes = 1;
            break;
#endif
#if defined(WOLFCOSE_HAVE_ES384)
        case WOLFCOSE_ALG_ES384:
            *preHashes = 1;
            break;
#endif
#if defined(WOLFCOSE_HAVE_ES512)
        case WOLFCOSE_ALG_ES512:
            *preHashes = 1;
            break;
#endif
#if defined(WOLFCOSE_HAVE_PS256)
        case WOLFCOSE_ALG_PS256:
            *preHashes = 1;
            break;
#endif
#if defined(WOLFCOSE_HAVE_PS384)
        case WOLFCOSE_ALG_PS384:
            *preHashes = 1;
            break;
#endif
#if defined(WOLFCOSE_HAVE_PS512)
        case WOLFCOSE_ALG_PS512:
            *preHashes = 1;
            break;
#endif
#if defined(WOLFCOSE_HAVE_EDDSA) || defined(WOLFCOSE_HAVE_ED448)
        case WOLFCOSE_ALG_EDDSA:
            *preHashes = 0;
            break;
#endif
#if defined(WOLFCOSE_HAVE_MLDSA)
        case WOLFCOSE_ALG_ML_DSA_44:
        case WOLFCOSE_ALG_ML_DSA_65:
        case WOLFCOSE_ALG_ML_DSA_87:
            *preHashes = 0;
            break;
#endif
#if defined(WOLFCOSE_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY)
        case WOLFCOSE_ALG_HSS_LMS:
            *preHashes = 0;
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
    int preHashes = 0;

    if ((key == NULL) || (key->signCb == NULL) || (sigStruct == NULL) ||
        (sig == NULL) || (sigLen == NULL) || (sigSz == 0u)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    /* Reject algorithms this build does not support. */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_ExtSignAlg(alg, &preHashes);
    }

    if ((ret == WOLFCOSE_SUCCESS) && (preHashes != 0)) {
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

    /* Sign based on algorithm */
#if defined(WOLFCOSE_EXT_SIGN)
    if ((ret == WOLFCOSE_SUCCESS) && (key->signCb != NULL)) {
        size_t extSigLen = 0;
        size_t sigOff = 0;
        int extPreHash = 0;

        /* A pre-hashing algorithm has its digest copied out before the
         * callback runs, so the signature may reuse the whole scratch.
         * EdDSA and ML-DSA sign the Sig_structure in place, so there the
         * signature has to start past it. */
        ret = wolfCose_ExtSignAlg(alg, &extPreHash);
        if (ret == WOLFCOSE_SUCCESS) {
            sigOff = (extPreHash != 0) ? 0u : sigStructLen;
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
    if ((ret == WOLFCOSE_SUCCESS) && (alg == WOLFCOSE_ALG_EDDSA)) {
        word32 edSigLen = (word32)sizeof(sigBuf);
        if (key->kty != WOLFCOSE_KTY_OKP) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        /* EdDSA signs raw Sig_structure (no pre-hash) */
        if (ret == WOLFCOSE_SUCCESS) {
#ifdef WOLFCOSE_HAVE_EDDSA
            if (key->crv == WOLFCOSE_CRV_ED25519) {
                if (key->key.ed25519 == NULL) {
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
                if (key->key.ed448 == NULL) {
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
    if ((ret == WOLFCOSE_SUCCESS) && ((alg == WOLFCOSE_ALG_ES256) ||
        (alg == WOLFCOSE_ALG_ES384) || (alg == WOLFCOSE_ALG_ES512))) {
        enum wc_HashType hashType;
        int digestSz = 0;
        size_t coordSz = 0;

        if (key->kty != WOLFCOSE_KTY_EC2) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }

        /* Each ECDSA alg is bound to one curve. */
        if (ret == WOLFCOSE_SUCCESS) {
            int32_t expectedCrv;
            if (alg == WOLFCOSE_ALG_ES256) {
                expectedCrv = WOLFCOSE_CRV_P256;
            }
            else if (alg == WOLFCOSE_ALG_ES384) {
                expectedCrv = WOLFCOSE_CRV_P384;
            }
            else {
                expectedCrv = WOLFCOSE_CRV_P521;
            }
            if (key->crv != expectedCrv) {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }
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
        int mgf = 0;

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
         * write callback persists it. */
        ret = wolfCose_LmsCheckKey(key);

        if (ret == WOLFCOSE_SUCCESS) {
            word32 lmsSigLen = 0;
            if (wc_LmsKey_GetSigLen(key->key.lms, &lmsSigLen) != 0) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else {
                expectedSigSz = (size_t)lmsSigLen;
            }
        }

        /* Sig output goes after Sig_structure in scratch. LMS signs the
         * raw Sig_structure directly (no pre-hash). */
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((sigStructLen + expectedSigSz) > scratchSz)) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }

        if (ret == WOLFCOSE_SUCCESS) {
            word32 lmsSigLen = (word32)expectedSigSz;
            INJECT_FAILURE(WOLF_FAIL_LMS_SIGN, -1,
                ret = wc_LmsKey_Sign(key->key.lms,
                    &scratch[sigStructLen], &lmsSigLen,
                    scratch, (int)sigStructLen));
            if (ret != 0) {
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
int wc_CoseSign1_Verify(const WOLFCOSE_KEY* key,
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

        /* Optional Tag(18) */
        if ((ctx.idx < ctx.bufSz) &&
            (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TAG)) {
            ret = wc_CBOR_DecodeTag(&ctx, &tag);
            if ((ret == WOLFCOSE_SUCCESS) && (tag != WOLFCOSE_TAG_SIGN1)) {
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

    /* 4. Signature (bstr) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &sigData, &sigDataLen);
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
    if ((ret == WOLFCOSE_SUCCESS) && (alg == WOLFCOSE_ALG_EDDSA)) {
        int verified = 0;
        if (key->kty != WOLFCOSE_KTY_OKP) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
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
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_ES256) || (alg == WOLFCOSE_ALG_ES384) ||
         (alg == WOLFCOSE_ALG_ES512))) {
        ecc_key* eccKey = NULL;
        int verified = 0;
        size_t coordSz = 0;
        enum wc_HashType hashType = WC_HASH_TYPE_NONE;
        int digestSz = 0;

        if (key->kty != WOLFCOSE_KTY_EC2) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        /* Each ECDSA alg is bound to one curve. */
        if (ret == WOLFCOSE_SUCCESS) {
            int32_t expectedCrv;
            if (alg == WOLFCOSE_ALG_ES256) {
                expectedCrv = WOLFCOSE_CRV_P256;
            }
            else if (alg == WOLFCOSE_ALG_ES384) {
                expectedCrv = WOLFCOSE_CRV_P384;
            }
            else {
                expectedCrv = WOLFCOSE_CRV_P521;
            }
            if (key->crv != expectedCrv) {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }
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
        int mgf = 0;

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
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_LMS_VERIFY, SIG_VERIFY_E,
                ret = wc_LmsKey_Verify(key->key.lms,
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
#endif /* WOLFCOSE_SIGN1_VERIFY */

#endif /* WOLFCOSE_SIGN1 */

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
         * macro (ML-DSA). ML-DSA and HSS-LMS sign the Sig_structure
         * directly without a pre-hash so the hash type lookup is
         * skipped. */
        if ((ret == WOLFCOSE_SUCCESS) &&
#if defined(WOLFCOSE_EXT_SIGN)
            (signerKey->signCb == NULL) &&
#endif
            (signer->algId != WOLFCOSE_ALG_ML_DSA_44) &&
            (signer->algId != WOLFCOSE_ALG_ML_DSA_65) &&
            (signer->algId != WOLFCOSE_ALG_ML_DSA_87) &&
            (signer->algId != WOLFCOSE_ALG_HSS_LMS)) {
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

        /* Hash the Sig_structure for algorithms that pre-hash. EdDSA,
         * ML-DSA and HSS-LMS sign the structure directly, and a delegated
         * signer does its own hashing inside wolfCose_ExtSign. */
        if ((ret == WOLFCOSE_SUCCESS) &&
#if defined(WOLFCOSE_EXT_SIGN)
            (signerKey->signCb == NULL) &&
#endif
            (signer->algId != WOLFCOSE_ALG_EDDSA) &&
            (signer->algId != WOLFCOSE_ALG_ML_DSA_44) &&
            (signer->algId != WOLFCOSE_ALG_ML_DSA_65) &&
            (signer->algId != WOLFCOSE_ALG_ML_DSA_87) &&
            (signer->algId != WOLFCOSE_ALG_HSS_LMS)) {
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
#if defined(WOLFCOSE_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY)
        if ((ret == WOLFCOSE_SUCCESS) &&
            (signer->algId == WOLFCOSE_ALG_HSS_LMS)) {
            size_t expectedSigSz = 0;

            /* RFC 8778: HSS-LMS key attached via wc_CoseKey_SetLms();
             * signature length comes from the key's parameter set. */
            ret = wolfCose_LmsCheckKey(signerKey);
            if (ret == WOLFCOSE_SUCCESS) {
                word32 lmsSigLen = 0;
                if (wc_LmsKey_GetSigLen(signerKey->key.lms,
                                        &lmsSigLen) != 0) {
                    ret = WOLFCOSE_E_COSE_KEY_TYPE;
                }
                else {
                    expectedSigSz = (size_t)lmsSigLen;
                }
            }
            /* Sig output goes after Sig_structure in scratch. */
            if ((ret == WOLFCOSE_SUCCESS) &&
                ((sigStructLen + expectedSigSz) > scratchSz)) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            if (ret == WOLFCOSE_SUCCESS) {
                word32 lmsSigLen = (word32)expectedSigSz;
                INJECT_FAILURE(WOLF_FAIL_LMS_SIGN, -1,
                    ret = wc_LmsKey_Sign(signerKey->key.lms,
                        &scratch[sigStructLen], &lmsSigLen,
                        scratch, (int)sigStructLen));
                if (ret != 0) {
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

    /* Get hash type for algorithms that pre-hash. EdDSA, ML-DSA and
     * HSS-LMS verify against the raw Sig_structure so the hash type
     * lookup is skipped (also avoids WOLFCOSE_E_COSE_BAD_ALG since
     * these algorithms have no external hash). */
    if ((ret == WOLFCOSE_SUCCESS) && (alg != WOLFCOSE_ALG_EDDSA) &&
        (alg != WOLFCOSE_ALG_ML_DSA_44) &&
        (alg != WOLFCOSE_ALG_ML_DSA_65) &&
        (alg != WOLFCOSE_ALG_ML_DSA_87) &&
        (alg != WOLFCOSE_ALG_HSS_LMS)) {
        ret = wolfCose_AlgToHashType(alg, &hashType);
    }

    /* Hash the Sig_structure for algorithms that pre-hash. EdDSA,
     * ML-DSA and HSS-LMS verify the structure directly. */
    if ((ret == WOLFCOSE_SUCCESS) && (alg != WOLFCOSE_ALG_EDDSA) &&
        (alg != WOLFCOSE_ALG_ML_DSA_44) &&
        (alg != WOLFCOSE_ALG_ML_DSA_65) &&
        (alg != WOLFCOSE_ALG_ML_DSA_87) &&
        (alg != WOLFCOSE_ALG_HSS_LMS)) {
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
#ifdef WOLFCOSE_HAVE_LMS
    if ((ret == WOLFCOSE_SUCCESS) && (alg == WOLFCOSE_ALG_HSS_LMS)) {
        /* RFC 8778: HSS-LMS verifies the raw Sig_structure directly. Only a
         * genuine mismatch (SIG_VERIFY_E) is an auth failure. */
        ret = wolfCose_LmsCheckKey(verifyKey);
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_LMS_VERIFY, SIG_VERIFY_E,
                ret = wc_LmsKey_Verify(verifyKey->key.lms,
                    signature, (word32)signatureLen,
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
static int wolfCose_MacTagSize(int32_t alg, size_t* tagSz)
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
static int wolfCose_AesCbcMacKeySize(int32_t alg, size_t* keySz)
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
static int wolfCose_AesCbcMac(const uint8_t* key, size_t keyLen,
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
static int wolfCose_IsHmacAlg(int32_t alg)
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
static int wolfCose_IsAesCbcMacAlg(int32_t alg)
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

/* ----- COSE_Mac Multi-Recipient API (RFC 9052 Section 6.1) ----- */

#if defined(WOLFCOSE_MAC) && (defined(WOLFCOSE_HAVE_HMAC) || defined(WOLFCOSE_HAVE_AESMAC))

/**
 * Build the MAC_structure for COSE_Mac (context = "MAC"):
 *   ["MAC", body_protected, external_aad, payload]
 */
static int wolfCose_BuildMacStructureMulti(const uint8_t* protectedHdr,
                                            size_t protectedLen,
                                            const uint8_t* extAad,
                                            size_t extAadLen,
                                            const uint8_t* payload,
                                            size_t payloadLen,
                                            uint8_t* scratch, size_t scratchSz,
                                            size_t* structLen)
{
    return wolfCose_BuildToBeSignedMaced(WOLFCOSE_CTX_MAC,
                                          sizeof(WOLFCOSE_CTX_MAC),
                                          protectedHdr, protectedLen,
                                          NULL, 0,  /* no sign_protected */
                                          extAad, extAadLen,
                                          payload, payloadLen,
                                          scratch, scratchSz, structLen);
}

#if defined(WOLFCOSE_MAC_CREATE)
/**
 * wc_CoseMac_Create - Create a COSE_Mac message (RFC 9052 Section 6.1)
 *
 * Structure: [Headers, payload, tag, recipients: [+ COSE_recipient]]
 *
 * For direct key mode: the MAC key is pre-shared among all recipients.
 */
int wc_CoseMac_Create(const WOLFCOSE_RECIPIENT* recipients,
    size_t recipientCount,
    int32_t macAlgId,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_CBOR_CTX ctx;
    uint8_t protectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t protectedLen = 0;
    size_t macStructLen = 0;
    uint8_t macTag[WC_MAX_DIGEST_SIZE];
    size_t macTagLen = 0;
    const uint8_t* macPayload = NULL;
    size_t macPayloadLen = 0;
    size_t i;
#ifdef WOLFCOSE_HAVE_HMAC
    Hmac hmac;
    int hashType = 0;
    int hmacInited = 0;
#endif

    /* Parameter validation */
    if ((recipients == NULL) || (recipientCount == 0u) ||
        (out == NULL) || (outLen == NULL) || (scratch == NULL)) {
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

    /* Reject inconsistent (kid, kidLen) per recipient. */
    if (ret == WOLFCOSE_SUCCESS) {
        for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < recipientCount); i++) {
            if (((recipients[i].kid != NULL) && (recipients[i].kidLen == 0u)) ||
                ((recipients[i].kid == NULL) && (recipients[i].kidLen != 0u))) {
                ret = WOLFCOSE_E_INVALID_ARG;
            }
        }
    }

    /* Must have either payload or detached, and not both (the inline payload
     * would be silently ignored). */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (payload == NULL) && (detachedPayload == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (payload != NULL) && (detachedPayload != NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    /* Get the payload to MAC */
    if (ret == WOLFCOSE_SUCCESS) {
        if (detachedPayload != NULL) {
            macPayload = detachedPayload;
            macPayloadLen = detachedLen;
        }
        else {
            macPayload = payload;
            macPayloadLen = payloadLen;
        }
    }

    /* Validate first recipient has correct key. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((recipients[0].key == NULL) ||
        (recipients[0].key->kty != WOLFCOSE_KTY_SYMMETRIC))) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
    for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < recipientCount); i++) {
        if ((recipients[i].key != NULL) &&
            (recipients[i].key->alg != WOLFCOSE_ALG_UNSET) &&
            (recipients[i].key->alg != macAlgId)) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
    }

    /* COSE_Mac here is direct-keyed only: require an explicit
     * WOLFCOSE_ALG_DIRECT so a zero-initialized (WOLFCOSE_ALG_UNSET) or a
     * key-distribution algId cannot silently select the direct construction. */
    for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < recipientCount); i++) {
        if (recipients[i].algId != WOLFCOSE_ALG_DIRECT) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
    }

    /* Get tag size for algorithm */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_MacTagSize(macAlgId, &macTagLen);
    }

    /* Encode body protected header: {1: alg} */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EncodeProtectedHdr(macAlgId, protectedBuf,
                                           sizeof(protectedBuf), &protectedLen);
    }

    /* Build MAC_structure */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildMacStructureMulti(protectedBuf, protectedLen,
                                               extAad, extAadLen,
                                               macPayload, macPayloadLen,
                                               scratch, scratchSz, &macStructLen);
    }

    /* Compute MAC: dispatch by algorithm class. */
#ifdef WOLFCOSE_HAVE_HMAC
    if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_IsHmacAlg(macAlgId) != 0)) {
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_HmacType(macAlgId, &hashType);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            int hmacRet = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
            if (hmacRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                hmacInited = 1;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_HmacCheckKeyLen(macAlgId,
                recipients[0].key->key.symm.keyLen);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            int hmacRet = wc_HmacSetKey(&hmac, hashType,
                             recipients[0].key->key.symm.key,
                             (word32)recipients[0].key->key.symm.keyLen);
            if (hmacRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            int hmacRet = wc_HmacUpdate(&hmac, scratch, (word32)macStructLen);
            if (hmacRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            int hmacRet = wc_HmacFinal(&hmac, macTag);
            if (hmacRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
    }
    else
#endif /* WOLFCOSE_HAVE_HMAC */
#ifdef WOLFCOSE_HAVE_AESMAC
    if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_IsAesCbcMacAlg(macAlgId) != 0)) {
        size_t expectedKeyLen = 0;
        ret = wolfCose_AesCbcMacKeySize(macAlgId, &expectedKeyLen);
        if ((ret == WOLFCOSE_SUCCESS) &&
            (recipients[0].key->key.symm.keyLen != expectedKeyLen)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AesCbcMac(recipients[0].key->key.symm.key,
                                      recipients[0].key->key.symm.keyLen,
                                      scratch, macStructLen,
                                      macTag, macTagLen);
        }
    }
    else
#endif /* WOLFCOSE_HAVE_AESMAC */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        /* No action required */
    }

    /* Initialize CBOR encoder */
    if (ret == WOLFCOSE_SUCCESS) {
        ctx.buf = out;
        ctx.bufSz = outSz;
        ctx.idx = 0;

        /* Encode COSE_Mac tag (97) */
        ret = wc_CBOR_EncodeTag(&ctx, WOLFCOSE_TAG_MAC);
    }

    /* Start outer array [protected, unprotected, payload, tag, recipients] */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, 5u);
    }

    /* [0] protected header bstr */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, protectedBuf, protectedLen);
    }

    /* [1] unprotected header (empty map) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&ctx, 0u);
    }

    /* [2] payload (or null if detached) */
    if (ret == WOLFCOSE_SUCCESS) {
        if (detachedPayload != NULL) {
            ret = wc_CBOR_EncodeNull(&ctx);
        }
        else {
            ret = wc_CBOR_EncodeBstr(&ctx, payload, payloadLen);
        }
    }

    /* [3] tag */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, macTag, macTagLen);
    }

    /* [4] recipients array */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, (uint64_t)recipientCount);
    }

    /* Encode each recipient */
    for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < recipientCount); i++) {
        /* Start recipient array [protected, unprotected, ciphertext]. The loop
         * condition guarantees ret == WOLFCOSE_SUCCESS on entry. */
        ret = wc_CBOR_EncodeArrayStart(&ctx, 3u);

        /* [0] protected header bstr. Every recipient was validated to
         * WOLFCOSE_ALG_DIRECT above, which uses a zero-length protected
         * header (RFC 9053 Section 6.1). */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, NULL, 0);
        }

        /* [1] unprotected header map. The direct algorithm is mandatory and
         * belongs in the unprotected bucket (RFC 9053 Section 6.1). */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeMapStart(&ctx,
                ((recipients[i].kid != NULL) &&
                 (recipients[i].kidLen > 0u)) ? 2u : 1u);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx, WOLFCOSE_HDR_ALG);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx, WOLFCOSE_ALG_DIRECT);
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

        /* [2] wrapped key (empty for direct key) */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, NULL, 0);
        }
    }

    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = ctx.idx;
    }

#ifdef WOLFCOSE_HAVE_HMAC
    if (hmacInited != 0) {
        (void)wc_HmacFree(&hmac);
    }
#endif
    (void)wolfCose_ForceZero(macTag, sizeof(macTag));
    if (scratch != NULL) {
        (void)wolfCose_ForceZero(scratch, scratchSz);
    }
    if ((ret != WOLFCOSE_SUCCESS) && (out != NULL)) {
        (void)wolfCose_ForceZero(out, outSz);
    }
    return ret;
}
#endif /* WOLFCOSE_MAC_CREATE */

#if defined(WOLFCOSE_MAC_VERIFY)
/**
 * wc_CoseMac_Verify - Verify a COSE_Mac message
 */
int wc_CoseMac_Verify(const WOLFCOSE_RECIPIENT* recipient,
    size_t recipientIndex,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_CBOR_CTX ctx;
    WOLFCOSE_CBOR_ITEM item;
    uint64_t tag = 0;
    size_t arrayCount = 0;
    const uint8_t* protectedData = NULL;
    size_t protectedLen = 0;
    const uint8_t* payloadData = NULL;
    size_t payloadDataLen = 0;
    const uint8_t* macTag = NULL;
    size_t macTagLen = 0;
    size_t recipientsCount = 0;
    size_t i;
    int32_t alg = 0;
    int32_t recipientAlgId = WOLFCOSE_ALG_UNSET;
    int recipientMode = 0;
    size_t macStructLen = 0;
    size_t expectedTagLen = 0;
    uint8_t computedTag[WC_MAX_DIGEST_SIZE];
    WOLFCOSE_HDR_STATE hdrState;
    int bodyAlgProtected = 0;
#ifdef WOLFCOSE_HAVE_HMAC
    Hmac hmac;
    int hashType = 0;
    int hmacInited = 0;
#endif
    const uint8_t* verifyPayload = NULL;
    size_t verifyPayloadLen = 0;
    int payloadIsNull = 0;
    int recipientValueIsNull = 0;
    size_t recipientValueLen = 0;

    /* Parameter validation */
    if ((recipient == NULL) || (in == NULL) || (inSz == 0u) ||
        (hdr == NULL) || (payload == NULL) || (payloadLen == NULL) ||
        (scratch == NULL)) {
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
        /* Initialize header output */
        (void)XMEMSET(hdr, 0, sizeof(*hdr));

        /* Initialize CBOR decoder */
        ctx.cbuf = in;
        ctx.bufSz = inSz;
        ctx.idx = 0;

        /* Decode and verify tag (97 = COSE_Mac) if present */
        if ((ctx.idx < ctx.bufSz) &&
            (wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TAG)) {
            ret = wc_CBOR_DecodeTag(&ctx, &tag);
            if ((ret == WOLFCOSE_SUCCESS) && (tag != WOLFCOSE_TAG_MAC)) {
                ret = WOLFCOSE_E_COSE_BAD_TAG;
            }
        }
    }

    /* Decode outer array - must be 5 elements */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (arrayCount != 5u)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }

    /* [0] Decode protected header bstr */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &protectedData, &protectedLen);
    }

    /* Parse protected header to get algorithm */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeProtectedHdr(protectedData, protectedLen, hdr,
                                          &hdrState);
        if (ret == WOLFCOSE_SUCCESS) {
            bodyAlgProtected = wolfCose_HdrStateContains(&hdrState,
                WOLFCOSE_HDR_ALG);
        }
    }

    /* [1] Decode unprotected header */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr, &hdrState);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        alg = hdr->alg;
    }

    /* [2] Decode payload */
    if (ret == WOLFCOSE_SUCCESS) {
        payloadIsNull = 0;
        if ((ctx.idx < ctx.bufSz) &&
            (ctx.cbuf[ctx.idx] == WOLFCOSE_CBOR_NULL)) {
            payloadIsNull = 1;
        }
        ret = wolfCose_CBOR_DecodeHead(&ctx, &item);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        if (payloadIsNull != 0) {
            /* Null - detached payload */
            if (detachedPayload == NULL) {
                hdr->flags |= WOLFCOSE_HDR_FLAG_DETACHED;
                ret = WOLFCOSE_E_DETACHED_PAYLOAD;
            }
            else {
                payloadData = NULL;
                payloadDataLen = 0;
                verifyPayload = detachedPayload;
                verifyPayloadLen = detachedLen;
                hdr->flags |= WOLFCOSE_HDR_FLAG_DETACHED;
            }
        }
        else if (item.majorType == WOLFCOSE_CBOR_BSTR) {
            payloadData = item.data;
            payloadDataLen = item.dataLen;
            verifyPayload = payloadData;
            verifyPayloadLen = payloadDataLen;
        }
        else {
            ret = WOLFCOSE_E_CBOR_TYPE;
        }
    }

    /* [3] Decode tag */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &macTag, &macTagLen);
    }

    /* [4] Decode recipients array */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &recipientsCount);
    }

    /* Validate recipient index */
    if ((ret == WOLFCOSE_SUCCESS) && (recipientIndex >= recipientsCount)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    /* Skip to the requested recipient */
    for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < recipientIndex); i++) {
        int32_t skippedAlg = WOLFCOSE_ALG_UNSET;

        ret = wolfCose_DecodeSkippedRecipient(&ctx, &skippedAlg);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_UpdateRecipientMode(skippedAlg, &recipientMode);
        }
    }

    /* Parse the selected COSE_recipient: [protected, unprotected, ciphertext].
     * The caller-supplied key is used for the MAC, but the recipient structure
     * and header buckets must still be well formed (duplicate-label checks). */
    if (ret == WOLFCOSE_SUCCESS) {
        size_t recipArrCount = 0;
        ret = wc_CBOR_DecodeArrayStart(&ctx, &recipArrCount);
        if ((ret == WOLFCOSE_SUCCESS) && (recipArrCount != 3u)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        const uint8_t* recipProt = NULL;
        size_t recipProtLen = 0;
        WOLFCOSE_HDR recipHdr;
        WOLFCOSE_HDR_STATE recipState;

        ret = wc_CBOR_DecodeBstr(&ctx, &recipProt, &recipProtLen);
        if (ret == WOLFCOSE_SUCCESS) {
            (void)XMEMSET(&recipHdr, 0, sizeof(recipHdr));
            ret = wolfCose_DecodeProtectedHdr(recipProt, recipProtLen,
                                              &recipHdr, &recipState);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_DecodeUnprotectedHdr(&ctx, &recipHdr, &recipState);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            recipientAlgId = recipHdr.alg;
            ret = wolfCose_UpdateRecipientMode(recipientAlgId,
                                               &recipientMode);
        }
        /* Parse the recipient ciphertext before classifying its algorithm. */
        if (ret == WOLFCOSE_SUCCESS) {
            recipientValueIsNull = 0;
            if ((ctx.idx < ctx.bufSz) &&
                (ctx.cbuf[ctx.idx] == WOLFCOSE_CBOR_NULL)) {
                recipientValueIsNull = 1;
            }
            ret = wolfCose_CBOR_DecodeHead(&ctx, &item);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            if (recipientValueIsNull != 0) {
                /* Validate after recipient algorithm classification. */
            }
            else if (item.majorType == WOLFCOSE_CBOR_BSTR) {
                recipientValueLen = item.dataLen;
            }
            else {
                ret = WOLFCOSE_E_CBOR_TYPE;
            }
        }
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

    /* Validate key and enforce key->alg agreement with the message. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((recipient->key == NULL) ||
        (recipient->key->kty != WOLFCOSE_KTY_SYMMETRIC))) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
    /* An unprotected alg is safe only when constrained by key policy. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (recipient->key->alg == WOLFCOSE_ALG_UNSET) &&
        (bodyAlgProtected == 0)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (recipient->key->alg != WOLFCOSE_ALG_UNSET) && (recipient->key->alg != alg)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

    /* COSE_Mac is direct-keyed here and the recipient algorithm is mandatory. */
    if (ret == WOLFCOSE_SUCCESS) {
        if (recipientAlgId == WOLFCOSE_ALG_UNSET) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
        else if (recipientAlgId != WOLFCOSE_ALG_DIRECT) {
            ret = WOLFCOSE_E_UNSUPPORTED;
        }
        else {
            /* No action required */
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        if ((recipientValueIsNull == 0) && (recipientValueLen != 0u)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
        else {
            /* No action required */
        }
    }

    /* Enforce the caller's recipient->algId policy when set. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (recipient->algId != WOLFCOSE_ALG_UNSET)) {
        if (recipient->algId != recipientAlgId) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
    }

    /* Get expected tag size */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_MacTagSize(alg, &expectedTagLen);
    }

    if ((ret == WOLFCOSE_SUCCESS) && (macTagLen != expectedTagLen)) {
        ret = WOLFCOSE_E_MAC_FAIL;
    }

    /* Build MAC_structure */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildMacStructureMulti(protectedData, protectedLen,
                                               extAad, extAadLen,
                                               verifyPayload, verifyPayloadLen,
                                               scratch, scratchSz, &macStructLen);
    }

    /* Compute MAC: dispatch by algorithm class. */
#ifdef WOLFCOSE_HAVE_HMAC
    if ((ret == WOLFCOSE_SUCCESS) && (wolfCose_IsHmacAlg(alg) != 0)) {
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_HmacType(alg, &hashType);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            int hmacRet = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
            if (hmacRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                hmacInited = 1;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_HmacCheckKeyLen(alg,
                recipient->key->key.symm.keyLen);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            int hmacRet = wc_HmacSetKey(&hmac, hashType,
                             recipient->key->key.symm.key,
                             (word32)recipient->key->key.symm.keyLen);
            if (hmacRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            int hmacRet = wc_HmacUpdate(&hmac, scratch, (word32)macStructLen);
            if (hmacRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            int hmacRet = wc_HmacFinal(&hmac, computedTag);
            if (hmacRet != 0) {
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
        if ((ret == WOLFCOSE_SUCCESS) &&
            (recipient->key->key.symm.keyLen != expectedKeyLen)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AesCbcMac(recipient->key->key.symm.key,
                                      recipient->key->key.symm.keyLen,
                                      scratch, macStructLen,
                                      computedTag, expectedTagLen);
        }
    }
    else
#endif /* WOLFCOSE_HAVE_AESMAC */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        /* No action required */
    }

    /* Constant-time comparison */
    if (ret == WOLFCOSE_SUCCESS) {
        if (wolfCose_ConstantCompare(computedTag, macTag,
                                      (word32)expectedTagLen) != 0) {
            ret = WOLFCOSE_E_MAC_FAIL;
        }
    }

#ifdef WOLFCOSE_HAVE_HMAC
    if (hmacInited != 0) {
        (void)wc_HmacFree(&hmac);
    }
#endif
    (void)wolfCose_ForceZero(computedTag, sizeof(computedTag));
    if (scratch != NULL) {
        (void)wolfCose_ForceZero(scratch, scratchSz);
    }

    /* Return payload pointer. Clear on failure to avoid stale data. */
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

    return ret;
}
#endif /* WOLFCOSE_MAC_VERIFY */

#endif /* WOLFCOSE_MAC && (WOLFCOSE_HAVE_HMAC || WOLFCOSE_HAVE_AESMAC) */
