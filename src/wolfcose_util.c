/* wolfcose_util.c
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
 * Force-failure injection, secure zeroization, key-import rollback,
 * constant-time comparison, and RFC 9052 context strings.
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
void wolfCose_MlDsaImportRollback(wc_MlDsaKey* key, byte level)
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

int wolfCose_EccPrivateImportBegin(ecc_key* ecc,
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

void wolfCose_EccPrivateImportRollback(ecc_key* ecc,
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
void wolfCose_HdrClearOnFail(int ret, WOLFCOSE_HDR* hdr)
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
int wolfCose_ConstantCompare(const byte* a, const byte* b,
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
