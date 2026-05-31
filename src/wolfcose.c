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
 * dilithium.h, rsa.h, random.h.  Only list headers not pulled in. */
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>  /* XMEMCPY */
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#ifndef NO_HMAC
    #include <wolfssl/wolfcrypt/hmac.h>
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    #include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#endif
#include <string.h>

/* ----- Forced failure injection for testing error paths ----- */
#ifdef WOLFCOSE_FORCE_FAILURE
    #include "../tests/force_failure.h"
    /* Check if a forced failure is set; if so, consume it and set ret */
    #define INJECT_FAILURE(failure_type, error_code) \
        if (wolfForceFailure_Check(failure_type) != 0) { \
            ret = (error_code); \
        } else
#else
    /* No-op when not testing */
    #define INJECT_FAILURE(failure_type, error_code)
#endif

/* ----- Secure memory zero ----- */

/**
 * Portable secure-zero. Volatile pointer prevents the compiler optimising
 * the writes away when the buffer is dead at function exit. Used in place
 * of wc_ForceZero so wolfCOSE links against the full wolfSSL 5.x range
 * (wc_ForceZero only became a public WOLFSSL_API symbol in v5.8.4).
 */
WOLFCOSE_LOCAL void wolfCose_ForceZero(void* mem, size_t len)
{
    if ((mem != NULL) && (len > 0u)) {
        volatile unsigned char* p = (volatile unsigned char*)mem;
        size_t i;
        for (i = 0u; i < len; i++) {
            p[i] = 0u;
        }
    }
}

/* ----- Constant-time comparison (side-channel safe) ----- */

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
#ifdef HAVE_ECC
            case WOLFCOSE_ALG_ES256:
                *hashType = WC_HASH_TYPE_SHA256;
                break;
    #ifdef WOLFSSL_SHA384
            case WOLFCOSE_ALG_ES384:
                *hashType = WC_HASH_TYPE_SHA384;
                break;
    #endif
    #ifdef WOLFSSL_SHA512
            case WOLFCOSE_ALG_ES512:
                *hashType = WC_HASH_TYPE_SHA512;
                break;
    #endif
#endif /* HAVE_ECC */
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
            case WOLFCOSE_ALG_EDDSA:
                /* RFC 9053 Section 2.2: EdDSA hashes the message internally
                 * with SHA-512 (Ed25519) or SHAKE-256 (Ed448). The "external"
                 * hash type is unused; SHA-512 stands in for both. */
                *hashType = WC_HASH_TYPE_SHA512;
                break;
#endif
#ifdef WC_RSA_PSS
            case WOLFCOSE_ALG_PS256:
                *hashType = WC_HASH_TYPE_SHA256;
                break;
    #ifdef WOLFSSL_SHA384
            case WOLFCOSE_ALG_PS384:
                *hashType = WC_HASH_TYPE_SHA384;
                break;
    #endif
    #ifdef WOLFSSL_SHA512
            case WOLFCOSE_ALG_PS512:
                *hashType = WC_HASH_TYPE_SHA512;
                break;
    #endif
#endif /* WC_RSA_PSS */
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
#ifdef HAVE_ECC
            case WOLFCOSE_ALG_ES256:
                *sigSz = 64;  /* r(32) || s(32) */
                break;
    #ifdef WOLFSSL_SHA384
            case WOLFCOSE_ALG_ES384:
                *sigSz = 96;  /* r(48) || s(48) */
                break;
    #endif
    #ifdef WOLFSSL_SHA512
            case WOLFCOSE_ALG_ES512:
                *sigSz = 132; /* r(66) || s(66) */
                break;
    #endif
#endif
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
            case WOLFCOSE_ALG_EDDSA:
                /* Returns the worst-case signature size when both curves
                 * are available so caller buffers are always sufficient. */
    #ifdef HAVE_ED448
                *sigSz = 114;
    #else
                *sigSz = 64;
    #endif
                break;
#endif
#ifdef HAVE_DILITHIUM
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
#ifdef HAVE_AESGCM
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
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
            case WOLFCOSE_ALG_CHACHA20_POLY1305:
                *keyLen = WOLFCOSE_CHACHA_KEY_SZ;
                break;
#endif
#ifdef HAVE_AESCCM
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
#ifdef HAVE_AESGCM
            case WOLFCOSE_ALG_A128GCM:  /* fall through */
            case WOLFCOSE_ALG_A192GCM:  /* fall through */
            case WOLFCOSE_ALG_A256GCM:
                *nonceLen = WOLFCOSE_AES_GCM_NONCE_SZ;
                break;
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
            case WOLFCOSE_ALG_CHACHA20_POLY1305:
                *nonceLen = WOLFCOSE_CHACHA_NONCE_SZ;
                break;
#endif
#ifdef HAVE_AESCCM
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
#ifdef HAVE_AESGCM
            case WOLFCOSE_ALG_A128GCM:  /* fall through */
            case WOLFCOSE_ALG_A192GCM:  /* fall through */
            case WOLFCOSE_ALG_A256GCM:
                *tagLen = WOLFCOSE_AES_GCM_TAG_SZ;
                break;
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
            case WOLFCOSE_ALG_CHACHA20_POLY1305:
                *tagLen = WOLFCOSE_CHACHA_TAG_SZ;
                break;
#endif
#ifdef HAVE_AESCCM
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

/* ----- Internal: HMAC helpers ----- */

#if !defined(NO_HMAC)
int wolfCose_HmacType(int32_t alg, int* hmacType)
{
    int ret = WOLFCOSE_SUCCESS;

    if (hmacType == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
            case WOLFCOSE_ALG_HMAC_256_256:
                *hmacType = WC_SHA256;
                break;
#ifdef WOLFSSL_SHA384
            case WOLFCOSE_ALG_HMAC_384_384:
                *hmacType = WC_SHA384;
                break;
#endif
#ifdef WOLFSSL_SHA512
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
#endif /* !NO_HMAC */

/* ----- Internal: ECC DER <-> raw r||s conversion ----- */

#ifdef HAVE_ECC
int wolfCose_EccSignRaw(const uint8_t* hash, size_t hashLen,
                         uint8_t* sigBuf, size_t* sigLen,
                         size_t coordSz, WC_RNG* rng, ecc_key* eccKey)
{
    int ret;
    uint8_t derSig[ECC_MAX_SIG_SIZE];
    word32 derSigLen = (word32)sizeof(derSig);
    word32 rLen;
    word32 sLen;

    if ((hash == NULL) || (sigBuf == NULL) || (sigLen == NULL) ||
        (rng == NULL) || (eccKey == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (*sigLen < (coordSz * 2u)) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }
    else {
        /* Sign producing DER-encoded signature */
        INJECT_FAILURE(WOLF_FAIL_ECC_SIGN, -1)
        {
            ret = wc_ecc_sign_hash(hash, (word32)hashLen, derSig, &derSigLen,
                                    rng, eccKey);
        }
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            /* Extract raw r and s from DER */
            rLen = (word32)coordSz;
            sLen = (word32)coordSz;

            /* Zero the output buffer for left-padding */
            (void)XMEMSET(sigBuf, 0, coordSz * 2u);

            /* wc_ecc_sig_to_rs extracts r and s as raw bytes */
            INJECT_FAILURE(WOLF_FAIL_ECC_SIG_TO_RS, -1)
            {
                ret = wc_ecc_sig_to_rs(derSig, derSigLen,
                                        sigBuf, &rLen,
                                        &sigBuf[coordSz], &sLen);
            }
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
    }
    return ret;
}

int wolfCose_EccVerifyRaw(const uint8_t* sigBuf, size_t sigLen,
                           const uint8_t* hash, size_t hashLen,
                           size_t coordSz, ecc_key* eccKey, int* verified)
{
    int ret;
    uint8_t derSig[ECC_MAX_SIG_SIZE];
    word32 derSigLen = (word32)sizeof(derSig);

    if ((sigBuf == NULL) || (hash == NULL) || (eccKey == NULL) || (verified == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (sigLen != (coordSz * 2u)) {
        ret = WOLFCOSE_E_COSE_SIG_FAIL;
    }
    else {
        *verified = 0;

        /* Convert raw r||s to DER */
        INJECT_FAILURE(WOLF_FAIL_ECC_RS_TO_SIG, -1)
        {
            ret = wc_ecc_rs_raw_to_sig(sigBuf, (word32)coordSz,
                                         &sigBuf[coordSz], (word32)coordSz,
                                         derSig, &derSigLen);
        }
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            INJECT_FAILURE(WOLF_FAIL_ECC_VERIFY, -1)
            {
                ret = wc_ecc_verify_hash(derSig, derSigLen, hash,
                                          (word32)hashLen, verified, eccKey);
            }
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        (void)wolfCose_ForceZero(derSig, sizeof(derSig));
    }
    return ret;
}
#endif /* HAVE_ECC */

/* ----- Internal: Protected/Unprotected header encode/decode ----- */

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
                    ret = wc_CBOR_DecodeInt(&ctx, &intVal);
                    if (ret == WOLFCOSE_SUCCESS) {
                        hdr->contentType = (int32_t)intVal;
                    }
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
                    if (ret == WOLFCOSE_SUCCESS) {
                        hdr->alg = (int32_t)algVal;
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
    else {
        key->kty = WOLFCOSE_KTY_EC2;
        key->crv = crv;
        key->alg = WOLFCOSE_ALG_UNSET;
        key->key.ecc = eccKey;
        /* Check if private key is present */
        key->hasPrivate = ((wc_ecc_size(eccKey) > 0) &&
                           (eccKey->type == ECC_PRIVATEKEY)) ? 1u : 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif

#ifdef HAVE_ED25519
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
        key->hasPrivate = (edKey->privKeySet != 0u) ? 1u : 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif

#ifdef HAVE_ED448
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
        key->hasPrivate = (edKey->privKeySet != 0u) ? 1u : 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif /* HAVE_ED448 */

#ifdef HAVE_DILITHIUM
int wc_CoseKey_SetDilithium(WOLFCOSE_KEY* key, int32_t alg,
                              dilithium_key* dlKey)
{
    int ret;

    if ((key == NULL) || (dlKey == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((alg != WOLFCOSE_ALG_ML_DSA_44) &&
             (alg != WOLFCOSE_ALG_ML_DSA_65) &&
             (alg != WOLFCOSE_ALG_ML_DSA_87)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        key->kty = WOLFCOSE_KTY_OKP; /* PQC uses OKP kty per COSE WG */
        key->alg = alg;
        if (alg == WOLFCOSE_ALG_ML_DSA_44) {
            key->crv = WOLFCOSE_CRV_ML_DSA_44;
        }
        else if (alg == WOLFCOSE_ALG_ML_DSA_65) {
            key->crv = WOLFCOSE_CRV_ML_DSA_65;
        }
        else {
            key->crv = WOLFCOSE_CRV_ML_DSA_87;
        }
        key->key.dilithium = dlKey;
        key->hasPrivate = (dlKey->prvKeySet != 0u) ? 1u : 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif /* HAVE_DILITHIUM */

#ifdef WC_RSA_PSS
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
        key->hasPrivate = ((wc_RsaEncryptSize(rsaKey) > 0) &&
                           (rsaKey->type == RSA_PRIVATE)) ? 1u : 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif /* WC_RSA_PSS */

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
        key->hasPrivate = 1;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}

#if defined(WOLFCOSE_KEY_ENCODE)
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

int wc_CoseKey_Encode(WOLFCOSE_KEY* key, uint8_t* out, size_t outSz,
                       size_t* outLen)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_CBOR_CTX ctx;

    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ctx.buf = out;
        ctx.bufSz = outSz;
        ctx.idx = 0;

#ifdef HAVE_ECC
        if (key->kty == WOLFCOSE_KTY_EC2) {
            uint8_t xBuf[66]; /* Max P-521 coordinate */
            uint8_t yBuf[66];
            word32 xLen = (word32)sizeof(xBuf);
            word32 yLen = (word32)sizeof(yBuf);
            size_t coordSz;
            size_t mapEntries;

            if (key->key.ecc == NULL) {
                ret = WOLFCOSE_E_INVALID_ARG;
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_CrvKeySize(key->crv, &coordSz);
            }

            if (ret == WOLFCOSE_SUCCESS) {
                INJECT_FAILURE(WOLF_FAIL_ECC_EXPORT_X963, -1)
                {
                    ret = wc_ecc_export_public_raw(key->key.ecc, xBuf, &xLen,
                                                   yBuf, &yLen);
                }
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }

            /* Map: kty [, kid] [, alg], crv, x, y [, d]. Optional kid and
             * alg are emitted when set so the decode/encode roundtrip
             * preserves them. */
            mapEntries = (key->hasPrivate != 0u) ? (size_t)5 : (size_t)4;
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
            /* -2: x */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx, (int64_t)WOLFCOSE_KEY_LABEL_X);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeBstr(&ctx, xBuf, (size_t)xLen);
            }
            /* -3: y */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx, (int64_t)WOLFCOSE_KEY_LABEL_Y);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeBstr(&ctx, yBuf, (size_t)yLen);
            }
            /* -4: d (private key, optional) */
            if ((ret == WOLFCOSE_SUCCESS) && (key->hasPrivate != 0u)) {
                uint8_t dBuf[66];
                word32 dLen = (word32)sizeof(dBuf);
                INJECT_FAILURE(WOLF_FAIL_ECC_EXPORT_PRIVATE, -1)
                {
                    ret = wc_ecc_export_private_only(key->key.ecc, dBuf, &dLen);
                }
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else {
                    ret = wc_CBOR_EncodeInt(&ctx,
                                             (int64_t)WOLFCOSE_KEY_LABEL_D);
                    if (ret == WOLFCOSE_SUCCESS) {
                        ret = wc_CBOR_EncodeBstr(&ctx, dBuf, (size_t)dLen);
                    }
                }
                (void)wolfCose_ForceZero(dBuf, sizeof(dBuf));
            }

            if (ret == WOLFCOSE_SUCCESS) {
                *outLen = ctx.idx;
            }
            (void)wolfCose_ForceZero(xBuf, sizeof(xBuf));
            (void)wolfCose_ForceZero(yBuf, sizeof(yBuf));
        }
        else
#endif /* HAVE_ECC */
#ifdef WC_RSA_PSS
        if (key->kty == WOLFCOSE_KTY_RSA) {
            /* RFC 8230: {1:3, -1:n_bstr, -2:e_bstr [, -3:d_bstr]}
             * Export n and d directly into output buffer to avoid
             * large stack allocations (RSA-4096 modulus = 512 bytes). */
            uint8_t eBuf[8]; /* exponent, typically 3 bytes */
            word32 eLen = (word32)sizeof(eBuf);
            word32 nLen;
            size_t hdrPos;
            size_t mapEntries;

            /* Get n directly into output buffer, e into small stack buf */
            mapEntries = (key->hasPrivate != 0u) ? (size_t)4 : (size_t)3;
            mapEntries += wolfCose_KeyOptionalEntries(key);
            ret = wc_CBOR_EncodeMapStart(&ctx, mapEntries);

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
                    else if ((nLen < 256u) || (nLen > 65535u)) {
                        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                    }
                    else {
                        ctx.buf[hdrPos] = 0x59u;
                        ctx.buf[hdrPos + 1u] =
                            (uint8_t)((uint32_t)nLen >> 8u);
                        ctx.buf[hdrPos + 2u] =
                            (uint8_t)((uint32_t)nLen & 0xFFu);
                        ctx.idx += (size_t)nLen;
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
            if ((ret == WOLFCOSE_SUCCESS) && (key->hasPrivate != 0u)) {
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

                        INJECT_FAILURE(WOLF_FAIL_RSA_ENCRYPT_SIZE, rsaEncSz)
                        {
                            rsaEncSz = wc_RsaEncryptSize(key->key.rsa);
                        }
                        if (rsaEncSz <= 0) {
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
                                INJECT_FAILURE(WOLF_FAIL_RSA_EXPORT_KEY, -1)
                                {
                                    ret = wc_RsaExportKey(
                                        key->key.rsa,
                                        &ctx.buf[scrOff], &eSz2,
                                        &ctx.buf[scrOff + 8u], &nSz2,
                                        &ctx.buf[dOff], &dSz,
                                        &ctx.buf[scrOff + 8u + nSz2], &pSz,
                                        &ctx.buf[scrOff + 8u + nSz2 + pSz],
                                        &qSz);
                                }
                                if (ret != 0) {
                                    ret = WOLFCOSE_E_CRYPTO;
                                }
                                else if ((dSz < 256u) || (dSz > 65535u)) {
                                    ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                                }
                                else {
                                    ctx.buf[hdrPos] = 0x59u;
                                    ctx.buf[hdrPos + 1u] =
                                        (uint8_t)((uint32_t)dSz >> 8u);
                                    ctx.buf[hdrPos + 2u] =
                                        (uint8_t)((uint32_t)dSz & 0xFFu);
                                    ctx.idx = dOff + (size_t)dSz;
                                }
                                /* Zero scratch (e2/n2/p/q) */
                                (void)wolfCose_ForceZero(&ctx.buf[scrOff],
                                    needed - scrOff);
                            }
                        }
                    }
                }
            }

            if (ret == WOLFCOSE_SUCCESS) {
                *outLen = ctx.idx;
            }
            (void)wolfCose_ForceZero(eBuf, sizeof(eBuf));
        }
        else
#endif /* WC_RSA_PSS */
#ifdef HAVE_DILITHIUM
        if ((key->kty == WOLFCOSE_KTY_OKP) &&
            ((key->crv == WOLFCOSE_CRV_ML_DSA_44) ||
             (key->crv == WOLFCOSE_CRV_ML_DSA_65) ||
             (key->crv == WOLFCOSE_CRV_ML_DSA_87))) {
            /* ML-DSA (Dilithium) COSE_Key: OKP with PQC curve.
             * Keys are large (pub up to 2592B, priv up to 4896B),
             * so we export directly into the output buffer to
             * avoid large stack allocations. */
            size_t dlMapEntries;
            word32 dlKeyLen;
            size_t hdrPos;

            dlMapEntries = (key->hasPrivate != 0u) ? (size_t)4 : (size_t)3;
            dlMapEntries += wolfCose_KeyOptionalEntries(key);
            ret = wc_CBOR_EncodeMapStart(&ctx, dlMapEntries);

            /* 1: kty = OKP (1) */
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
            /* -1: crv (negative for ML-DSA) */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_CRV);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx, (int64_t)key->crv);
            }
            /* -2: x (public key bstr) - direct export into output */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_X);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                /* Reserve 3 bytes for CBOR bstr header (2-byte length).
                 * All Dilithium pub sizes (1312-2592) need this form. */
                hdrPos = ctx.idx;
                if ((ctx.idx + 3u) > ctx.bufSz) {
                    ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                }
                else {
                    ctx.idx += 3u;
                    dlKeyLen = (word32)(ctx.bufSz - ctx.idx);
                    INJECT_FAILURE(WOLF_FAIL_DILITHIUM_EXPORT_PUB, -1)
                    {
                        ret = wc_dilithium_export_public(key->key.dilithium,
                            &ctx.buf[ctx.idx], &dlKeyLen);
                    }
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
            /* -4: d (private key, optional) - direct export */
            if ((ret == WOLFCOSE_SUCCESS) && (key->hasPrivate != 0u)) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_D);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdrPos = ctx.idx;
                    if ((ctx.idx + 3u) > ctx.bufSz) {
                        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                    }
                    else {
                        ctx.idx += 3u;
                        dlKeyLen = (word32)(ctx.bufSz - ctx.idx);
                        INJECT_FAILURE(WOLF_FAIL_DILITHIUM_EXPORT_PRIV, -1)
                        {
                            ret = wc_dilithium_export_private(
                                key->key.dilithium,
                                &ctx.buf[ctx.idx], &dlKeyLen);
                        }
                        if (ret != 0) {
                            ret = WOLFCOSE_E_CRYPTO;
                        }
                        else if ((dlKeyLen < 256u) || (dlKeyLen > 65535u)) {
                            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                        }
                        else {
                            ctx.buf[hdrPos] = 0x59u;
                            ctx.buf[hdrPos + 1u] =
                                (uint8_t)((uint32_t)dlKeyLen >> 8u);
                            ctx.buf[hdrPos + 2u] =
                                (uint8_t)((uint32_t)dlKeyLen & 0xFFu);
                            ctx.idx += (size_t)dlKeyLen;
                        }
                    }
                }
            }

            if (ret == WOLFCOSE_SUCCESS) {
                *outLen = ctx.idx;
            }
        }
        else
#endif /* HAVE_DILITHIUM */
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
        if (key->kty == WOLFCOSE_KTY_OKP) {
            uint8_t pubBuf[57]; /* Ed448 pub = 57 bytes, Ed25519 = 32 */
            word32 pubLen = (word32)sizeof(pubBuf);
            size_t mapEntries;

#ifdef HAVE_ED25519
            if (key->crv == WOLFCOSE_CRV_ED25519) {
                INJECT_FAILURE(WOLF_FAIL_ED25519_EXPORT_PUB, -1)
                {
                    ret = wc_ed25519_export_public(key->key.ed25519,
                                                    pubBuf, &pubLen);
                }
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }
            else
#endif
#ifdef HAVE_ED448
            if (key->crv == WOLFCOSE_CRV_ED448) {
                INJECT_FAILURE(WOLF_FAIL_ED448_EXPORT_PUB, -1)
                {
                    ret = wc_ed448_export_public(key->key.ed448,
                                                  pubBuf, &pubLen);
                }
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }
            else
#endif
            {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }

            mapEntries = (key->hasPrivate != 0u) ? (size_t)4 : (size_t)3;
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
            if ((ret == WOLFCOSE_SUCCESS) && (key->hasPrivate != 0u)) {
                uint8_t privBuf[57]; /* Ed448 priv = 57 bytes */
                word32 privLen = (word32)sizeof(privBuf);
#ifdef HAVE_ED25519
                if (key->crv == WOLFCOSE_CRV_ED25519) {
                    INJECT_FAILURE(WOLF_FAIL_ED25519_EXPORT_PRIV, -1)
                    {
                        ret = wc_ed25519_export_private_only(key->key.ed25519,
                                                              privBuf, &privLen);
                    }
                }
                else
#endif
#ifdef HAVE_ED448
                if (key->crv == WOLFCOSE_CRV_ED448) {
                    INJECT_FAILURE(WOLF_FAIL_ED448_EXPORT_PRIV, -1)
                    {
                        ret = wc_ed448_export_private_only(key->key.ed448,
                                                            privBuf, &privLen);
                    }
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
#endif /* HAVE_ED25519 || HAVE_ED448 */
        if (key->kty == WOLFCOSE_KTY_SYMMETRIC) {
            /* {1: 4, -1: k_bytes} */
            size_t mapEntries = 2u + wolfCose_KeyOptionalEntries(key);

            ret = wc_CBOR_EncodeMapStart(&ctx, mapEntries);
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
    if ((ret != WOLFCOSE_SUCCESS) && (out != NULL)) {
        (void)wolfCose_ForceZero(out, outSz);
    }

    return ret;
}
#endif /* WOLFCOSE_KEY_ENCODE */

#if defined(WOLFCOSE_KEY_DECODE)
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
    const uint8_t* dData = NULL;  /* EC2/OKP: private key */
    size_t dLen = 0;
    const uint8_t* nData = NULL;  /* RSA: n (modulus) */
    size_t nLen = 0;
    WOLFCOSE_HDR_STATE keyLabelState;

    if ((key == NULL) || (in == NULL) || (inSz == 0u)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ctx.cbuf = in;
        ctx.bufSz = inSz;
        ctx.idx = 0;
        wolfCose_HdrStateInit(&keyLabelState);

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
                    if (ret == WOLFCOSE_SUCCESS) {
                        key->alg = (int32_t)algVal;
                    }
                }
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
            else {
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wc_CBOR_Skip(&ctx);
                }
            }
        }

        /* Import key data into wolfCrypt key structs */
        if (ret == WOLFCOSE_SUCCESS) {
#ifdef HAVE_ECC
            if ((key->kty == WOLFCOSE_KTY_EC2) && (key->key.ecc != NULL)) {
                if ((xData == NULL) || (yData == NULL)) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
                else {
                    int wcCrv;
                    size_t coordSz = 0;
                    ret = wolfCose_CrvToWcCurve(key->crv, &wcCrv);
                    if (ret == WOLFCOSE_SUCCESS) {
                        ret = wolfCose_CrvKeySize(key->crv, &coordSz);
                    }
                    if (ret == WOLFCOSE_SUCCESS) {
                        byte tmpX[MAX_ECC_BYTES];
                        byte tmpY[MAX_ECC_BYTES];
                        byte tmpD[MAX_ECC_BYTES];

                        /* Accept shorter coordinates and right-justify them
                         * into the fixed-size import buffers. */
                        if ((coordSz > sizeof(tmpX)) ||
                            (xLen > coordSz) || (yLen > coordSz) ||
                            ((dData != NULL) && (dLen > coordSz))) {
                            ret = WOLFCOSE_E_COSE_BAD_HDR;
                        }

                        if (ret == WOLFCOSE_SUCCESS) {
                            (void)XMEMSET(tmpX, 0, sizeof(tmpX));
                            (void)XMEMSET(tmpY, 0, sizeof(tmpY));
                            (void)XMEMSET(tmpD, 0, sizeof(tmpD));
                            (void)XMEMCPY(&tmpX[coordSz - xLen], xData, xLen);
                            (void)XMEMCPY(&tmpY[coordSz - yLen], yData, yLen);
                            if (dData != NULL) {
                                (void)XMEMCPY(&tmpD[coordSz - dLen], dData,
                                              dLen);
                                INJECT_FAILURE(WOLF_FAIL_ECC_IMPORT_X963, -1)
                                {
                                    ret = wc_ecc_import_unsigned(
                                        key->key.ecc,
                                        tmpX, tmpY, tmpD, wcCrv);
                                }
                                (void)wolfCose_ForceZero(tmpD, sizeof(tmpD));
                                if (ret == 0) {
                                    key->hasPrivate = 1;
                                }
                            }
                            else {
                                INJECT_FAILURE(WOLF_FAIL_ECC_IMPORT_X963, -1)
                                {
                                    ret = wc_ecc_import_unsigned(
                                        key->key.ecc,
                                        tmpX, tmpY, NULL, wcCrv);
                                }
                            }
                        }
                        if ((ret != WOLFCOSE_SUCCESS) &&
                            (ret != WOLFCOSE_E_INVALID_ARG)) {
                            ret = WOLFCOSE_E_CRYPTO;
                        }
                    }
                }
            }
            else
#endif
#ifdef WC_RSA_PSS
            if ((key->kty == WOLFCOSE_KTY_RSA) && (key->key.rsa != NULL)) {
                /* RFC 8230: -1=n(bstr), -2=e(bstr), -3=d(bstr) */
                if ((nData == NULL) || (xData == NULL)) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
                else {
                    INJECT_FAILURE(WOLF_FAIL_RSA_PUBLIC_DECODE, -1)
                    {
                        ret = wc_RsaPublicKeyDecodeRaw(nData, (word32)nLen,
                            xData, (word32)xLen, key->key.rsa);
                    }
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
                    else {
                        /* Public key only — full private import from raw
                         * n,e,d components is not currently supported */
                        key->hasPrivate = 0u;
                    }
                }
            }
            else
#endif
#ifdef HAVE_DILITHIUM
            if ((key->kty == WOLFCOSE_KTY_OKP) &&
                (key->key.dilithium != NULL) &&
                ((key->crv == WOLFCOSE_CRV_ML_DSA_44) ||
                 (key->crv == WOLFCOSE_CRV_ML_DSA_65) ||
                 (key->crv == WOLFCOSE_CRV_ML_DSA_87))) {
                byte dlLevel;
                if (key->crv == WOLFCOSE_CRV_ML_DSA_44) {
                    dlLevel = 2;
                }
                else if (key->crv == WOLFCOSE_CRV_ML_DSA_65) {
                    dlLevel = 3;
                }
                else {
                    dlLevel = 5;
                }

                if (xData == NULL) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
                else {
                    /* Set level before import */
                    ret = wc_dilithium_set_level(key->key.dilithium,
                                                  dlLevel);
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
                    else if (dData != NULL) {
                        INJECT_FAILURE(WOLF_FAIL_DILITHIUM_IMPORT_PRIV, -1)
                        {
                            ret = wc_dilithium_import_key(
                                dData, (word32)dLen,
                                xData, (word32)xLen, key->key.dilithium);
                        }
                        if (ret == 0) { key->hasPrivate = 1; }
                        else { ret = WOLFCOSE_E_CRYPTO; }
                    }
                    else {
                        INJECT_FAILURE(WOLF_FAIL_DILITHIUM_IMPORT_PUB, -1)
                        {
                            ret = wc_dilithium_import_public(
                                xData, (word32)xLen, key->key.dilithium);
                        }
                        if (ret != 0) { ret = WOLFCOSE_E_CRYPTO; }
                    }
                }
            }
            else
#endif /* HAVE_DILITHIUM */
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
            if (key->kty == WOLFCOSE_KTY_OKP) {
                if (xData == NULL) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
#ifdef HAVE_ED25519
                else if ((key->crv == WOLFCOSE_CRV_ED25519) &&
                         (key->key.ed25519 != NULL)) {
                    if (dData != NULL) {
                        INJECT_FAILURE(WOLF_FAIL_ED25519_IMPORT_PRIV, -1)
                        {
                            ret = wc_ed25519_import_private_key(dData, (word32)dLen,
                                xData, (word32)xLen, key->key.ed25519);
                        }
                        if (ret == 0) { key->hasPrivate = 1; }
                        else { ret = WOLFCOSE_E_CRYPTO; }
                    }
                    else {
                        INJECT_FAILURE(WOLF_FAIL_ED25519_IMPORT_PUB, -1)
                        {
                            ret = wc_ed25519_import_public(xData, (word32)xLen,
                                                            key->key.ed25519);
                        }
                        if (ret != 0) { ret = WOLFCOSE_E_CRYPTO; }
                    }
                }
#endif
#ifdef HAVE_ED448
                else if ((key->crv == WOLFCOSE_CRV_ED448) &&
                         (key->key.ed448 != NULL)) {
                    if (dData != NULL) {
                        INJECT_FAILURE(WOLF_FAIL_ED448_IMPORT_PRIV, -1)
                        {
                            ret = wc_ed448_import_private_key(dData, (word32)dLen,
                                xData, (word32)xLen, key->key.ed448);
                        }
                        if (ret == 0) { key->hasPrivate = 1; }
                        else { ret = WOLFCOSE_E_CRYPTO; }
                    }
                    else {
                        INJECT_FAILURE(WOLF_FAIL_ED448_IMPORT_PUB, -1)
                        {
                            ret = wc_ed448_import_public(xData, (word32)xLen,
                                                          key->key.ed448);
                        }
                        if (ret != 0) { ret = WOLFCOSE_E_CRYPTO; }
                    }
                }
#endif
                else {
                    ret = WOLFCOSE_E_COSE_BAD_ALG;
                }
            }
            else
#endif /* HAVE_ED25519 || HAVE_ED448 */
            if (key->kty == WOLFCOSE_KTY_SYMMETRIC) {
                /* nData holds the symmetric k value (parsed from label -1).
                 * Reject the message when the mandatory k parameter is
                 * absent so callers cannot end up with an empty key. */
                if (nData == NULL) {
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

        /* kty is mandatory. */
        if ((ret == WOLFCOSE_SUCCESS) && (key->kty == 0)) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }

        /* RFC 8949 Section 5.3.1: reject trailing data after the map. */
        if ((ret == WOLFCOSE_SUCCESS) && (ctx.idx != ctx.bufSz)) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }

    return ret;
}
#endif /* WOLFCOSE_KEY_DECODE */

/* ----- Internal: RSA-PSS hash-to-MGF mapping ----- */
#ifdef WC_RSA_PSS
static int wolfCose_HashToMgf(enum wc_HashType hashType, int* mgf)
{
    int ret = WOLFCOSE_SUCCESS;

    if (mgf == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (hashType == WC_HASH_TYPE_SHA256) {
        *mgf = WC_MGF1SHA256;
    }
#ifdef WOLFSSL_SHA384
    else if (hashType == WC_HASH_TYPE_SHA384) {
        *mgf = WC_MGF1SHA384;
    }
#endif
#ifdef WOLFSSL_SHA512
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
            ret = wc_CBOR_EncodeBstr(&ctx, extAad,
                                      (extAad != NULL) ? extAadLen : 0u);
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

/**
 * Build an Enc_structure for AEAD operations (RFC 9052 Section 5.3).
 *
 * [context, body_protected, external_aad]
 */
int wolfCose_BuildEncStructure(
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
            ret = wc_CBOR_EncodeBstr(&ctx, extAad,
                                      (extAad != NULL) ? extAadLen : 0u);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            *structLen = ctx.idx;
        }
    }
    return ret;
}

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
 * Simplified version: PartyUInfo and PartyVInfo are empty arrays.
 * SuppPubInfo contains only keyDataLength and empty protected header.
 *
 * \param contentAlgId      Content encryption algorithm for derived key
 * \param keyDataLengthBits Key length in bits
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
        INJECT_FAILURE(WOLF_FAIL_ECDH_SHARED_SECRET, eccRet)
        {
            eccRet = wc_ecc_shared_secret(&ephemKey, recipientPub->key.ecc,
                                           sharedSecret, &sharedSecretLen);
        }
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
                                      uint8_t* cekOut, size_t cekOutSz)
{
    int ret = WOLFCOSE_SUCCESS;
    ecc_key ephemPub;
    int ephemInited = 0;
    uint8_t sharedSecret[66];
    word32 sharedSecretLen = sizeof(sharedSecret);
    uint8_t kdfContext[64];
    size_t kdfContextLen = 0;
    int hashType = 0;
    int wcCurve = 0;
    WC_RNG rng;
    int rngInited = 0;
    int rngSetOnRecipient = 0;
    WC_RNG* priorRecipientRng = NULL;

    /* Parameter validation */
    if ((recipientKey == NULL) || (ephemPubX == NULL) || (ephemPubY == NULL) ||
        (cekOut == NULL)) {
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
                                         kdfContext, sizeof(kdfContext),
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

    /* Reject oversized coordinates; shorter peers are accepted. */
    if (ret == WOLFCOSE_SUCCESS) {
        size_t coordSz = 0;
        ret = wolfCose_CrvKeySize(*crv, &coordSz);
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((*xLen > coordSz) || (*yLen > coordSz))) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
    }

    return ret;
}

#endif /* WOLFCOSE_ECDH_ES_DIRECT && HAVE_ECC && HAVE_HKDF */

/* ----- COSE_Sign1 API ----- */

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
int wc_CoseSign1_Sign(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng)
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

    if ((key == NULL) || (sigPayload == NULL) || (scratch == NULL) ||
        (out == NULL) || (outLen == NULL) || (rng == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
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

    if ((ret == WOLFCOSE_SUCCESS) && (key->hasPrivate != 1u)) {
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
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    if ((ret == WOLFCOSE_SUCCESS) && (alg == WOLFCOSE_ALG_EDDSA)) {
        word32 edSigLen = (word32)sizeof(sigBuf);
        if (key->kty != WOLFCOSE_KTY_OKP) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        /* EdDSA signs raw Sig_structure (no pre-hash) */
        if (ret == WOLFCOSE_SUCCESS) {
#ifdef HAVE_ED25519
            if (key->crv == WOLFCOSE_CRV_ED25519) {
                if (key->key.ed25519 == NULL) {
                    ret = WOLFCOSE_E_COSE_KEY_TYPE;
                }
                else {
                    INJECT_FAILURE(WOLF_FAIL_ED25519_SIGN, -1)
                    {
                        ret = wc_ed25519_sign_msg(scratch,
                            (word32)sigStructLen,
                            sigBuf, &edSigLen, key->key.ed25519);
                    }
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
#ifdef HAVE_ED448
            if (key->crv == WOLFCOSE_CRV_ED448) {
                if (key->key.ed448 == NULL) {
                    ret = WOLFCOSE_E_COSE_KEY_TYPE;
                }
                else {
                    INJECT_FAILURE(WOLF_FAIL_ED448_SIGN, -1)
                    {
                        ret = wc_ed448_sign_msg(scratch,
                            (word32)sigStructLen,
                            sigBuf, &edSigLen, key->key.ed448, NULL, 0);
                    }
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
#endif /* HAVE_ED25519 || HAVE_ED448 */
#ifdef HAVE_ECC
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
            ret = wolfCose_AlgToHashType(alg, &hashType);
        }

        if (ret == WOLFCOSE_SUCCESS) {
            digestSz = wc_HashGetDigestSize(hashType);
            if (digestSz <= 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }

        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_HASH, -1)
            {
                ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                               hashBuf, (word32)digestSz);
            }
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
                                       rng, key->key.ecc);
            if (ret == WOLFCOSE_SUCCESS) {
                sigSz = rawSigLen;
            }
        }
    }
    else
#endif
#ifdef WC_RSA_PSS
    if ((ret == WOLFCOSE_SUCCESS) && ((alg == WOLFCOSE_ALG_PS256) ||
        (alg == WOLFCOSE_ALG_PS384) || (alg == WOLFCOSE_ALG_PS512))) {
        enum wc_HashType hashType;
        int digestSz = 0;
        int mgf = 0;

        if ((key->kty != WOLFCOSE_KTY_RSA) || (key->key.rsa == NULL)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
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

        /* Hash Sig_structure */
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_HASH, -1)
            {
                ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                               hashBuf, (word32)digestSz);
            }
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
            INJECT_FAILURE(WOLF_FAIL_RSA_SSL_SIGN, -1)
            {
                ret = wc_RsaPSS_Sign_ex(hashBuf, (word32)digestSz,
                                          scratch, rsaSigLen,
                                          hashType, mgf, digestSz,
                                          key->key.rsa, rng);
            }
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
#endif /* WC_RSA_PSS */
#ifdef HAVE_DILITHIUM
    if ((ret == WOLFCOSE_SUCCESS) && ((alg == WOLFCOSE_ALG_ML_DSA_44) ||
        (alg == WOLFCOSE_ALG_ML_DSA_65) || (alg == WOLFCOSE_ALG_ML_DSA_87))) {
        size_t expectedSigSz = 0;

        if ((key->kty != WOLFCOSE_KTY_OKP) || (key->key.dilithium == NULL)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
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
            INJECT_FAILURE(WOLF_FAIL_DILITHIUM_SIGN, -1)
            {
                /* wolfSSL gates the legacy non-context ML-DSA API on
                 * WOLFSSL_DILITHIUM_NO_CTX since the FIPS 204 final
                 * transition.  When undefined (modern default), only the
                 * context-aware API is available; pass an empty context
                 * since COSE has no application context string. */
#ifdef WOLFSSL_DILITHIUM_NO_CTX
                ret = wc_dilithium_sign_msg(
                    scratch, (word32)sigStructLen,
                    &scratch[sigStructLen], &dlSigLen,
                    key->key.dilithium, rng);
#else
                ret = wc_dilithium_sign_ctx_msg(
                    NULL, 0,
                    scratch, (word32)sigStructLen,
                    &scratch[sigStructLen], &dlSigLen,
                    key->key.dilithium, rng);
#endif
            }
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
#endif /* HAVE_DILITHIUM */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        /* No action required */
    }

    /* Encode COSE_Sign1 output:
     * Tag(18) [protected_bstr, unprotected_map, payload_bstr, signature_bstr]
     */
    outCtx.buf = out;
    outCtx.bufSz = outSz;
    outCtx.idx = 0;

    /* Encode COSE_Sign1 output */
    if (ret == WOLFCOSE_SUCCESS) {
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
    if ((ret != WOLFCOSE_SUCCESS) && (out != NULL)) {
        (void)wolfCose_ForceZero(out, outSz);
    }

    return ret;
}
#endif /* WOLFCOSE_SIGN1_SIGN */

#if defined(WOLFCOSE_SIGN1_VERIFY)
int wc_CoseSign1_Verify(WOLFCOSE_KEY* key,
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

    if ((key == NULL) || (in == NULL) || (scratch == NULL) || (hdr == NULL) ||
        (payload == NULL) || (payloadLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

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

    if (ret == WOLFCOSE_SUCCESS) {
        /* Rebuild Sig_structure in scratch using appropriate payload */
        ret = wolfCose_BuildSigStructure(protectedData, protectedLen,
                                          extAad, extAadLen,
                                          verifyPayload, verifyPayloadLen,
                                          scratch, scratchSz, &sigStructLen);
    }

    /* Verify based on algorithm */
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    if ((ret == WOLFCOSE_SUCCESS) && (alg == WOLFCOSE_ALG_EDDSA)) {
        int verified = 0;
        if (key->kty != WOLFCOSE_KTY_OKP) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
#ifdef HAVE_ED25519
        if ((ret == WOLFCOSE_SUCCESS) && (key->crv == WOLFCOSE_CRV_ED25519)) {
            if (key->key.ed25519 == NULL) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else {
                INJECT_FAILURE(WOLF_FAIL_ED25519_VERIFY, -1)
                {
                    ret = wc_ed25519_verify_msg(sigData, (word32)sigDataLen,
                                                 scratch, (word32)sigStructLen,
                                                 &verified, key->key.ed25519);
                }
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }
        }
        else
#endif
#ifdef HAVE_ED448
        if ((ret == WOLFCOSE_SUCCESS) && (key->crv == WOLFCOSE_CRV_ED448)) {
            if (key->key.ed448 == NULL) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else {
                INJECT_FAILURE(WOLF_FAIL_ED448_VERIFY, -1)
                {
                    ret = wc_ed448_verify_msg(sigData, (word32)sigDataLen,
                                               scratch, (word32)sigStructLen,
                                               &verified, key->key.ed448,
                                               NULL, 0);
                }
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
#endif
#ifdef HAVE_ECC
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_ES256) || (alg == WOLFCOSE_ALG_ES384) ||
         (alg == WOLFCOSE_ALG_ES512))) {
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
            ret = wolfCose_AlgToHashType(alg, &hashType);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            digestSz = wc_HashGetDigestSize(hashType);
            if (digestSz <= 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_HASH, -1)
            {
                ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                               hashBuf, (word32)digestSz);
            }
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
                                         coordSz, key->key.ecc, &verified);
        }
        if ((ret == WOLFCOSE_SUCCESS) && (verified != 1)) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
        }
    }
    else
#endif
#ifdef WC_RSA_PSS
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_PS256) || (alg == WOLFCOSE_ALG_PS384) ||
         (alg == WOLFCOSE_ALG_PS512))) {
        enum wc_HashType hashType = WC_HASH_TYPE_NONE;
        int digestSz = 0;
        int mgf = 0;

        if ((key->kty != WOLFCOSE_KTY_RSA) || (key->key.rsa == NULL)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
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
            INJECT_FAILURE(WOLF_FAIL_HASH, -1)
            {
                ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                               hashBuf, (word32)digestSz);
            }
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
            INJECT_FAILURE(WOLF_FAIL_RSA_SSL_VERIFY, -1)
            {
                ret = wc_RsaPSS_VerifyCheck(scratch, (word32)sigDataLen,
                                              scratch, (word32)scratchSz,
                                              hashBuf, (word32)digestSz,
                                              hashType, mgf, key->key.rsa);
            }
            if (ret < 0) {
                ret = WOLFCOSE_E_COSE_SIG_FAIL;
            }
            else {
                ret = WOLFCOSE_SUCCESS;
            }
        }
    }
    else
#endif /* WC_RSA_PSS */
#ifdef HAVE_DILITHIUM
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_ML_DSA_44) || (alg == WOLFCOSE_ALG_ML_DSA_65) ||
         (alg == WOLFCOSE_ALG_ML_DSA_87))) {
        int verified = 0;

        if ((key->kty != WOLFCOSE_KTY_OKP) || (key->key.dilithium == NULL)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_DILITHIUM_VERIFY, -1)
            {
#ifdef WOLFSSL_DILITHIUM_NO_CTX
                ret = wc_dilithium_verify_msg(
                    sigData, (word32)sigDataLen,
                    scratch, (word32)sigStructLen,
                    &verified, key->key.dilithium);
#else
                ret = wc_dilithium_verify_ctx_msg(
                    sigData, (word32)sigDataLen,
                    NULL, 0,
                    scratch, (word32)sigStructLen,
                    &verified, key->key.dilithium);
#endif
            }
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if ((ret == WOLFCOSE_SUCCESS) && (verified != 1)) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
        }
    }
    else
#endif /* HAVE_DILITHIUM */
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
        (scratch == NULL) || (out == NULL) || (outLen == NULL) || (rng == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    /* Reject ambiguous inline+detached input. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (payload != NULL) && (detachedPayload != NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    /* Fail-fast key/alg checks before any hashing. */
    for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < signerCount); i++) {
        if ((signers[i].key == NULL) || (signers[i].key->hasPrivate != 1u)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        else if (((signers[i].kid != NULL) && (signers[i].kidLen == 0u)) ||
                 ((signers[i].kid == NULL) && (signers[i].kidLen != 0u))) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
        else if ((signers[i].key->alg != WOLFCOSE_ALG_UNSET) &&
                 (signers[i].key->alg != signers[i].algId)) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
#ifdef HAVE_ECC
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
            if (signers[i].key->kty != WOLFCOSE_KTY_EC2) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else if (signers[i].key->crv != expectedCrv) {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }
            else {
                /* No action required */
            }
        }
#endif
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
        else if ((signers[i].algId == WOLFCOSE_ALG_EDDSA) &&
                 (signers[i].key->kty != WOLFCOSE_KTY_OKP)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
#endif
#ifdef WC_RSA_PSS
        else if (((signers[i].algId == WOLFCOSE_ALG_PS256) ||
                  (signers[i].algId == WOLFCOSE_ALG_PS384) ||
                  (signers[i].algId == WOLFCOSE_ALG_PS512)) &&
                 (signers[i].key->kty != WOLFCOSE_KTY_RSA)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
#endif
#ifdef HAVE_DILITHIUM
        else if (((signers[i].algId == WOLFCOSE_ALG_ML_DSA_44) ||
                  (signers[i].algId == WOLFCOSE_ALG_ML_DSA_65) ||
                  (signers[i].algId == WOLFCOSE_ALG_ML_DSA_87)) &&
                 (signers[i].key->kty != WOLFCOSE_KTY_OKP)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        /* ML-DSA level must match algId. */
        else if ((signers[i].algId == WOLFCOSE_ALG_ML_DSA_44) &&
                 (signers[i].key->crv != WOLFCOSE_CRV_ML_DSA_44)) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
        else if ((signers[i].algId == WOLFCOSE_ALG_ML_DSA_65) &&
                 (signers[i].key->crv != WOLFCOSE_CRV_ML_DSA_65)) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
        else if ((signers[i].algId == WOLFCOSE_ALG_ML_DSA_87) &&
                 (signers[i].key->crv != WOLFCOSE_CRV_ML_DSA_87)) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
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
         * and ML-DSA sign the structure directly. */
        if ((ret == WOLFCOSE_SUCCESS) &&
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
#ifdef HAVE_ECC
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((signer->algId == WOLFCOSE_ALG_ES256) ||
             (signer->algId == WOLFCOSE_ALG_ES384) ||
             (signer->algId == WOLFCOSE_ALG_ES512))) {
            size_t coordSz = 0;
            ret = wolfCose_CrvKeySize(signer->key->crv, &coordSz);
            if (ret == WOLFCOSE_SUCCESS) {
                sigSz = coordSz * 2u;
                ret = wolfCose_EccSignRaw(hashBuf, hashLen,
                                           sigBuf, &sigSz, coordSz,
                                           rng, signer->key->key.ecc);
            }
        }
        else
#endif
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
        if ((ret == WOLFCOSE_SUCCESS) &&
            (signer->algId == WOLFCOSE_ALG_EDDSA)) {
            word32 edSigSz = (word32)sizeof(sigBuf);
#ifdef HAVE_ED25519
            if (signer->key->crv == WOLFCOSE_CRV_ED25519) {
                if (signer->key->key.ed25519 == NULL) {
                    ret = WOLFCOSE_E_COSE_KEY_TYPE;
                }
                else {
                    ret = wc_ed25519_sign_msg(scratch, (word32)sigStructLen,
                                               sigBuf, &edSigSz,
                                               signer->key->key.ed25519);
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
#ifdef HAVE_ED448
            if (signer->key->crv == WOLFCOSE_CRV_ED448) {
                if (signer->key->key.ed448 == NULL) {
                    ret = WOLFCOSE_E_COSE_KEY_TYPE;
                }
                else {
                    ret = wc_ed448_sign_msg(scratch, (word32)sigStructLen,
                                             sigBuf, &edSigSz,
                                             signer->key->key.ed448, NULL, 0);
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
#endif /* HAVE_ED25519 || HAVE_ED448 */
#ifdef WC_RSA_PSS
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((signer->algId == WOLFCOSE_ALG_PS256) ||
             (signer->algId == WOLFCOSE_ALG_PS384) ||
             (signer->algId == WOLFCOSE_ALG_PS512))) {
            int mgf = 0;
            if (signer->key->key.rsa == NULL) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
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
                                          signer->key->key.rsa, rng);
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
#endif /* WC_RSA_PSS */
#ifdef HAVE_DILITHIUM
        if ((ret == WOLFCOSE_SUCCESS) &&
            ((signer->algId == WOLFCOSE_ALG_ML_DSA_44) ||
             (signer->algId == WOLFCOSE_ALG_ML_DSA_65) ||
             (signer->algId == WOLFCOSE_ALG_ML_DSA_87))) {
            size_t expectedSigSz = 0;
            if (signer->key->key.dilithium == NULL) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
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
#ifdef WOLFSSL_DILITHIUM_NO_CTX
                ret = wc_dilithium_sign_msg(
                    scratch, (word32)sigStructLen,
                    &scratch[sigStructLen], &dlSigLen,
                    signer->key->key.dilithium, rng);
#else
                ret = wc_dilithium_sign_ctx_msg(
                    NULL, 0,
                    scratch, (word32)sigStructLen,
                    &scratch[sigStructLen], &dlSigLen,
                    signer->key->key.dilithium, rng);
#endif
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
#endif /* HAVE_DILITHIUM */
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
    if ((ret != WOLFCOSE_SUCCESS) && (out != NULL)) {
        (void)wolfCose_ForceZero(out, outSz);
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

    if ((verifyKey == NULL) || (in == NULL) || (scratch == NULL) || (hdr == NULL) ||
        (payload == NULL) || (payloadLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

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
        ret = wc_CBOR_Skip(&ctx);
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
            alg = signerHdr.alg;
        }
    }

    /* Honour the verifyKey->alg pin. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (verifyKey->alg != WOLFCOSE_ALG_UNSET) &&
        (verifyKey->alg != alg)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

    /* Signer unprotected headers (skip for now) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_Skip(&ctx);
    }

    /* Signature */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &signature, &signatureLen);
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
#ifdef HAVE_ECC
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_ES256) || (alg == WOLFCOSE_ALG_ES384) ||
         (alg == WOLFCOSE_ALG_ES512))) {
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
            ret = wolfCose_CrvKeySize(verifyKey->crv, &coordSz);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_EccVerifyRaw(signature, signatureLen,
                                         hashBuf, hashLen, coordSz,
                                         verifyKey->key.ecc, &verified);
        }
        if ((ret == WOLFCOSE_SUCCESS) && (verified != 1)) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
        }
    }
    else
#endif
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    if ((ret == WOLFCOSE_SUCCESS) && (alg == WOLFCOSE_ALG_EDDSA)) {
        int verified = 0;
        if (verifyKey->kty != WOLFCOSE_KTY_OKP) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
#ifdef HAVE_ED25519
        if ((ret == WOLFCOSE_SUCCESS) &&
            (verifyKey->crv == WOLFCOSE_CRV_ED25519)) {
            if (verifyKey->key.ed25519 == NULL) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else {
                ret = wc_ed25519_verify_msg(signature, (word32)signatureLen,
                                             scratch, (word32)sigStructLen,
                                             &verified, verifyKey->key.ed25519);
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }
        }
        else
#endif
#ifdef HAVE_ED448
        if ((ret == WOLFCOSE_SUCCESS) &&
            (verifyKey->crv == WOLFCOSE_CRV_ED448)) {
            if (verifyKey->key.ed448 == NULL) {
                ret = WOLFCOSE_E_COSE_KEY_TYPE;
            }
            else {
                ret = wc_ed448_verify_msg(signature, (word32)signatureLen,
                                           scratch, (word32)sigStructLen,
                                           &verified, verifyKey->key.ed448,
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
#endif /* HAVE_ED25519 || HAVE_ED448 */
#ifdef WC_RSA_PSS
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_PS256) || (alg == WOLFCOSE_ALG_PS384) ||
         (alg == WOLFCOSE_ALG_PS512))) {
        int mgf = 0;
        if ((verifyKey->kty != WOLFCOSE_KTY_RSA) ||
            (verifyKey->key.rsa == NULL)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
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
                                          hashType, mgf, verifyKey->key.rsa);
            if (ret < 0) {
                ret = WOLFCOSE_E_COSE_SIG_FAIL;
            }
            else {
                ret = WOLFCOSE_SUCCESS;
            }
        }
    }
    else
#endif /* WC_RSA_PSS */
#ifdef HAVE_DILITHIUM
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_ML_DSA_44) || (alg == WOLFCOSE_ALG_ML_DSA_65) ||
         (alg == WOLFCOSE_ALG_ML_DSA_87))) {
        int verified = 0;
        if ((verifyKey->kty != WOLFCOSE_KTY_OKP) ||
            (verifyKey->key.dilithium == NULL)) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
#ifdef WOLFSSL_DILITHIUM_NO_CTX
            ret = wc_dilithium_verify_msg(
                signature, (word32)signatureLen,
                scratch, (word32)sigStructLen,
                &verified, verifyKey->key.dilithium);
#else
            ret = wc_dilithium_verify_ctx_msg(
                signature, (word32)signatureLen,
                NULL, 0,
                scratch, (word32)sigStructLen,
                &verified, verifyKey->key.dilithium);
#endif
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if ((ret == WOLFCOSE_SUCCESS) && (verified != 1)) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
        }
    }
    else
#endif /* HAVE_DILITHIUM */
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

#if defined(WOLFCOSE_ENCRYPT0) && (defined(HAVE_AESGCM) || defined(HAVE_AESCCM) || \
    (defined(HAVE_CHACHA) && defined(HAVE_POLY1305)))

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
int wc_CoseEncrypt0_Encrypt(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* iv, size_t ivLen,
    const uint8_t* payload, size_t payloadLen,
    uint8_t* detachedPayload, size_t detachedSz, size_t* detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen)
{
    int ret = WOLFCOSE_SUCCESS;
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
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
#ifdef HAVE_AESGCM
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_A128GCM) || (alg == WOLFCOSE_ALG_A192GCM) ||
         (alg == WOLFCOSE_ALG_A256GCM))) {
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            aesInited = 1;
            INJECT_FAILURE(WOLF_FAIL_AES_GCM_SET_KEY, -1)
            {
                ret = wc_AesGcmSetKey(&aes, key->key.symm.key, (word32)aeadKeyLen);
            }
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }

        if ((ret == WOLFCOSE_SUCCESS) && (isDetached != 0)) {
            /* Detached mode: ciphertext goes to detachedPayload buffer */
            INJECT_FAILURE(WOLF_FAIL_AES_GCM_ENCRYPT, -1)
            {
                ret = wc_AesGcmEncrypt(&aes,
                    detachedPayload,                      /* ciphertext output */
                    payload, (word32)payloadLen,          /* plaintext input */
                    iv, (word32)ivLen,                    /* nonce */
                    &detachedPayload[payloadLen],         /* auth tag (after ct) */
                    (word32)aeadTagLen,
                    scratch, (word32)encStructLen);       /* AAD = Enc_structure */
            }
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
                INJECT_FAILURE(WOLF_FAIL_AES_GCM_ENCRYPT, -1)
                {
                    ret = wc_AesGcmEncrypt(&aes,
                        &out[ciphertextOffset],              /* ciphertext output */
                        payload, (word32)payloadLen,          /* plaintext input */
                        iv, (word32)ivLen,                    /* nonce */
                        &out[ciphertextOffset + payloadLen],  /* auth tag */
                        (word32)aeadTagLen,
                        scratch, (word32)encStructLen);       /* AAD */
                }
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
#endif /* HAVE_AESGCM */
#ifdef HAVE_AESCCM
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
            INJECT_FAILURE(WOLF_FAIL_AES_CCM_SET_KEY, -1)
            {
                ret = wc_AesCcmSetKey(&aes, key->key.symm.key, (word32)aeadKeyLen);
            }
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }

        if ((ret == WOLFCOSE_SUCCESS) && (isDetached != 0)) {
            INJECT_FAILURE(WOLF_FAIL_AES_CCM_ENCRYPT, -1)
            {
                ret = wc_AesCcmEncrypt(&aes,
                    detachedPayload,
                    payload, (word32)payloadLen,
                    iv, (word32)ivLen,
                    &detachedPayload[payloadLen],
                    (word32)aeadTagLen,
                    scratch, (word32)encStructLen);
            }
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
                INJECT_FAILURE(WOLF_FAIL_AES_CCM_ENCRYPT, -1)
                {
                    ret = wc_AesCcmEncrypt(&aes,
                        &out[ciphertextOffset],
                        payload, (word32)payloadLen,
                        iv, (word32)ivLen,
                        &out[ciphertextOffset + payloadLen],
                        (word32)aeadTagLen,
                        scratch, (word32)encStructLen);
                }
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
#endif /* HAVE_AESCCM */
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
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
#endif /* HAVE_CHACHA && HAVE_POLY1305 */
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
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
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
int wc_CoseEncrypt0_Decrypt(WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedCt, size_t detachedCtLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    uint8_t* plaintext, size_t plaintextSz, size_t* plaintextLen)
{
    int ret = WOLFCOSE_SUCCESS;
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
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

    if ((key == NULL) || (in == NULL) || (scratch == NULL) || (hdr == NULL) ||
        (plaintext == NULL) || (plaintextLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

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

    if (ret == WOLFCOSE_SUCCESS) {
        alg = hdr->alg;
    }

    /* Honour the key->alg pin on the decrypt path. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (key->alg != WOLFCOSE_ALG_UNSET) && (key->alg != alg)) {
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
        if (payloadSz > plaintextSz) {
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
#ifdef HAVE_AESGCM
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((alg == WOLFCOSE_ALG_A128GCM) || (alg == WOLFCOSE_ALG_A192GCM) ||
         (alg == WOLFCOSE_ALG_A256GCM))) {
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            aesInited = 1;
            INJECT_FAILURE(WOLF_FAIL_AES_GCM_SET_KEY, -1)
            {
                ret = wc_AesGcmSetKey(&aes, key->key.symm.key, (word32)aeadKeyLen);
            }
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_AES_GCM_DECRYPT, -1)
            {
                ret = wc_AesGcmDecrypt(&aes,
                    plaintext,
                    ciphertext, (word32)payloadSz,
                    hdr->iv, (word32)hdr->ivLen,
                    &ciphertext[payloadSz], (word32)aeadTagLen,
                    scratch, (word32)encStructLen);
            }
            if (ret != 0) {
                ret = WOLFCOSE_E_COSE_DECRYPT_FAIL;
            }
        }
    }
    else
#endif /* HAVE_AESGCM */
#ifdef HAVE_AESCCM
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
            INJECT_FAILURE(WOLF_FAIL_AES_CCM_SET_KEY, -1)
            {
                ret = wc_AesCcmSetKey(&aes, key->key.symm.key, (word32)aeadKeyLen);
            }
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_AES_CCM_DECRYPT, -1)
            {
                ret = wc_AesCcmDecrypt(&aes,
                    plaintext,
                    ciphertext, (word32)payloadSz,
                    hdr->iv, (word32)hdr->ivLen,
                    &ciphertext[payloadSz], (word32)aeadTagLen,
                    scratch, (word32)encStructLen);
            }
            if (ret != 0) {
                ret = WOLFCOSE_E_COSE_DECRYPT_FAIL;
            }
        }
    }
    else
#endif /* HAVE_AESCCM */
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
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
#endif /* HAVE_CHACHA && HAVE_POLY1305 */
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

    /* Cleanup: always executed */
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
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

#endif /* WOLFCOSE_ENCRYPT0 && (HAVE_AESGCM || HAVE_AESCCM || (HAVE_CHACHA && HAVE_POLY1305)) */

/* -----
 * COSE_Mac0 API (RFC 9052 Section 6.2)
 * Supports HMAC (RFC 9053 Section 3.1) and AES-CBC-MAC (RFC 9053 Section 3.2)
 * ----- */

#if defined(WOLFCOSE_MAC0) && (!defined(NO_HMAC) || defined(HAVE_AES_CBC))

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
#ifndef NO_HMAC
            case WOLFCOSE_ALG_HMAC_256_256:
                *tagSz = 32; /* SHA-256 output */
                break;
#ifdef WOLFSSL_SHA384
            case WOLFCOSE_ALG_HMAC_384_384:
                *tagSz = 48; /* SHA-384 output */
                break;
#endif
#ifdef WOLFSSL_SHA512
            case WOLFCOSE_ALG_HMAC_512_512:
                *tagSz = 64; /* SHA-512 output */
                break;
#endif
#endif /* !NO_HMAC */
#ifdef HAVE_AES_CBC
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

#ifdef HAVE_AES_CBC
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
#endif /* HAVE_AES_CBC */

/**
 * Check if algorithm is HMAC-based.
 */
static int wolfCose_IsHmacAlg(int32_t alg)
{
    return ((alg == WOLFCOSE_ALG_HMAC_256_256)
#ifdef WOLFSSL_SHA384
         || (alg == WOLFCOSE_ALG_HMAC_384_384)
#endif
#ifdef WOLFSSL_SHA512
         || (alg == WOLFCOSE_ALG_HMAC_512_512)
#endif
    ) ? 1 : 0;
}

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
#ifndef NO_HMAC
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

    /* Determine which payload to use for MAC. A zero-length inline
     * payload (NULL, 0) is valid: it authenticates only the protected
     * headers and external AAD. */
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
    /* Reject ambiguous inline+detached input. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (payload != NULL) && (detachedPayload != NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (macPayload == NULL) && (macPayloadLen > 0u)) {
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
#ifndef NO_HMAC
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
            INJECT_FAILURE(WOLF_FAIL_HMAC_SET_KEY, -1)
            {
                ret = wc_HmacSetKey(&hmac, hmacType, key->key.symm.key,
                                     (word32)key->key.symm.keyLen);
            }
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_HMAC_UPDATE, -1)
            {
                ret = wc_HmacUpdate(&hmac, scratch, (word32)macStructLen);
            }
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            INJECT_FAILURE(WOLF_FAIL_HMAC_FINAL, -1)
            {
                ret = wc_HmacFinal(&hmac, tagBuf);
            }
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
    }
    else
#endif /* !NO_HMAC */
#ifdef HAVE_AES_CBC
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
#endif /* HAVE_AES_CBC */
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
#ifndef NO_HMAC
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
#ifndef NO_HMAC
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

    if ((key == NULL) || (in == NULL) || (scratch == NULL) || (hdr == NULL) ||
        (payload == NULL) || (payloadLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

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

    if (ret == WOLFCOSE_SUCCESS) {
        alg = hdr->alg;
        /* RFC 9052 §7: key->alg, when set, must match message alg. */
        if ((key->alg != WOLFCOSE_ALG_UNSET) && (key->alg != alg)) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
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
#ifndef NO_HMAC
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
#endif /* !NO_HMAC */
#ifdef HAVE_AES_CBC
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
#endif /* HAVE_AES_CBC */
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

    /* Cleanup: always executed */
#ifndef NO_HMAC
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

#endif /* WOLFCOSE_MAC0 && (!NO_HMAC || HAVE_AES_CBC) */

/* ----- COSE_Encrypt Multi-Recipient API (RFC 9052 Section 5.1) ----- */

#if defined(WOLFCOSE_ENCRYPT) && \
    (defined(HAVE_AESGCM) || defined(HAVE_AESCCM) || \
     (defined(HAVE_CHACHA) && defined(HAVE_POLY1305)))

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
 * Each COSE_recipient: [Headers, wrapped_cek]
 *
 * For simplicity, this implementation uses direct key (no key wrap):
 * - The content encryption key (CEK) is pre-shared or derived externally
 * - Recipients array contains header-only entries with no wrapped key
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
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
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
            recipientCrv = recipients[0].key->crv;

            /* Pre-encode recipient protected hdr for KDF context. */
            ret = wolfCose_EncodeProtectedHdr(recipients[0].algId,
                recipientProtectedBuf, sizeof(recipientProtectedBuf),
                &recipientProtectedLen);

            /* Derive CEK from ephemeral-static ECDH */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_EcdhEsDirect(
                    recipients[0].algId,
                    recipients[0].key,
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
            if ((recipients[i].algId != WOLFCOSE_ALG_UNSET) &&
                (recipients[i].algId != WOLFCOSE_ALG_DIRECT)) {
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

#ifdef HAVE_AESGCM
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
#ifdef HAVE_AESCCM
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
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
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

        /* Encode recipient protected header */
        if (recipients[i].algId != WOLFCOSE_ALG_UNSET) {
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
            if ((recipients[i].kid != NULL) && (recipients[i].kidLen > 0u)) {
                ret = wc_CBOR_EncodeMapStart(&ctx, 1u);
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wc_CBOR_EncodeInt(&ctx, WOLFCOSE_HDR_KID);
                }
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wc_CBOR_EncodeBstr(&ctx, recipients[i].kid,
                                              recipients[i].kidLen);
                }
            } else {
                /* Empty map */
                ret = wc_CBOR_EncodeMapStart(&ctx, 0u);
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
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
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
    size_t encStructLen = 0;
    size_t recipientsCount = 0;
    size_t i;
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
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
    WOLFCOSE_HDR_STATE hdrState;
    WOLFCOSE_HDR_STATE recipientHdrState;
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
    }
    if (ret == WOLFCOSE_SUCCESS) {
        alg = hdr->alg;
    }

    /* [1] unprotected header */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr, &hdrState);
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
        ret = wolfCose_CBOR_DecodeHead(&ctx, &item);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        if ((item.majorType == WOLFCOSE_CBOR_SIMPLE) && (item.val == 22u)) {
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
        ret = wc_CBOR_Skip(&ctx);
    }

    /* Parse recipient array */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (arrayCount != 3u)) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }

    /* [0] recipient protected header */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &recipientProtectedData, &recipientProtectedLen);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (recipientProtectedLen > 0u)) {
        WOLFCOSE_HDR recipientHdr;
        (void)XMEMSET(&recipientHdr, 0, sizeof(recipientHdr));
        ret = wolfCose_DecodeProtectedHdr(recipientProtectedData,
                                          recipientProtectedLen,
                                          &recipientHdr, &recipientHdrState);
        if (ret == WOLFCOSE_SUCCESS) {
            recipientAlgId = recipientHdr.alg;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_ValidateRecipientKeyAlg(recipient->key, recipientAlgId,
            alg);
    }

    /* [1] recipient unprotected header */
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    if ((ret == WOLFCOSE_SUCCESS) &&
        (wolfCose_IsEcdhEsDirectAlg(recipientAlgId) != 0)) {
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
        ret = wc_CBOR_Skip(&ctx);
    }
    else {
        /* No action required */
    }

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
        ret = wc_CBOR_Skip(&ctx);
    }
    else {
        /* No action required */
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
        if ((recipient->key == NULL) ||
            (recipient->key->kty != WOLFCOSE_KTY_EC2) ||
            (recipient->key->key.ecc == NULL) ||
            (recipient->key->hasPrivate != 1u)) {
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
                recipientAlgId, recipient->key,
                ephemPubX, ephemPubY, ephemPubXLen,
                alg, keyLen,
                recipientProtectedData, recipientProtectedLen,
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
        if (payloadLen > plaintextSz) {
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
#ifdef HAVE_AESGCM
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
#ifdef HAVE_AESCCM
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
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
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
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
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

    return ret;
}
#endif /* WOLFCOSE_ENCRYPT_DECRYPT */

#endif /* WOLFCOSE_ENCRYPT && any supported AEAD */

/* ----- COSE_Mac Multi-Recipient API (RFC 9052 Section 6.1) ----- */

#if defined(WOLFCOSE_MAC) && (!defined(NO_HMAC) || defined(HAVE_AES_CBC))

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
    uint8_t recipientProtectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t recipientProtectedLen = 0;
    size_t macStructLen = 0;
    uint8_t macTag[WC_MAX_DIGEST_SIZE];
    size_t macTagLen = 0;
    const uint8_t* macPayload = NULL;
    size_t macPayloadLen = 0;
    size_t i;
#ifndef NO_HMAC
    Hmac hmac;
    int hashType = 0;
    int hmacInited = 0;
#endif

    /* Parameter validation */
    if ((recipients == NULL) || (recipientCount == 0u) ||
        (out == NULL) || (outLen == NULL) || (scratch == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    /* Reject inconsistent (kid, kidLen) per recipient. */
    if (ret == WOLFCOSE_SUCCESS) {
        for (i = 0; (ret == WOLFCOSE_SUCCESS) && (i < recipientCount); i++) {
            if (((recipients[i].kid != NULL) && (recipients[i].kidLen == 0u)) ||
                ((recipients[i].kid == NULL) && (recipients[i].kidLen != 0u))) {
                ret = WOLFCOSE_E_INVALID_ARG;
            }
        }
    }

    /* Must have either payload or detached */
    if ((ret == WOLFCOSE_SUCCESS) &&
        (payload == NULL) && (detachedPayload == NULL)) {
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
#ifndef NO_HMAC
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
        if (hmacInited != 0) {
            (void)wc_HmacFree(&hmac);
            hmacInited = 0;
        }
    }
    else
#endif /* !NO_HMAC */
#ifdef HAVE_AES_CBC
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
#endif /* HAVE_AES_CBC */
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
        /* Encode recipient protected header */
        if (recipients[i].algId != WOLFCOSE_ALG_UNSET) {
            ret = wolfCose_EncodeProtectedHdr(recipients[i].algId,
                recipientProtectedBuf, sizeof(recipientProtectedBuf),
                &recipientProtectedLen);
        }
        else {
            recipientProtectedLen = 0;
        }

        /* Start recipient array [protected, unprotected, ciphertext] */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeArrayStart(&ctx, 3u);
        }

        /* [0] protected header bstr */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, recipientProtectedBuf,
                                      recipientProtectedLen);
        }

        /* [1] unprotected header map (with kid if present) */
        if (ret == WOLFCOSE_SUCCESS) {
            if ((recipients[i].kid != NULL) && (recipients[i].kidLen > 0u)) {
                ret = wc_CBOR_EncodeMapStart(&ctx, 1u);
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wc_CBOR_EncodeInt(&ctx, WOLFCOSE_HDR_KID);
                }
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wc_CBOR_EncodeBstr(&ctx, recipients[i].kid,
                                              recipients[i].kidLen);
                }
            }
            else {
                ret = wc_CBOR_EncodeMapStart(&ctx, 0u);
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

#ifndef NO_HMAC
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
    size_t macStructLen = 0;
    size_t expectedTagLen = 0;
    uint8_t computedTag[WC_MAX_DIGEST_SIZE];
    WOLFCOSE_HDR_STATE hdrState;
#ifndef NO_HMAC
    Hmac hmac;
    int hashType = 0;
    int hmacInited = 0;
#endif
    const uint8_t* verifyPayload = NULL;
    size_t verifyPayloadLen = 0;

    /* Parameter validation */
    if ((recipient == NULL) || (in == NULL) || (inSz == 0u) ||
        (hdr == NULL) || (payload == NULL) || (payloadLen == NULL) ||
        (scratch == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

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
    }
    if (ret == WOLFCOSE_SUCCESS) {
        alg = hdr->alg;
    }

    /* [1] Decode unprotected header */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr, &hdrState);
    }

    /* [2] Decode payload */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CBOR_DecodeHead(&ctx, &item);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        if ((item.majorType == WOLFCOSE_CBOR_SIMPLE) && (item.val == 22u)) {
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
        ret = wc_CBOR_Skip(&ctx);
    }

    /* Parse the recipient (skip it - we use the provided key) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_Skip(&ctx);
    }

    /* Validate key and enforce key->alg agreement with the message. */
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((recipient->key == NULL) ||
        (recipient->key->kty != WOLFCOSE_KTY_SYMMETRIC))) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (recipient->key->alg != WOLFCOSE_ALG_UNSET) && (recipient->key->alg != alg)) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
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
#ifndef NO_HMAC
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
        if (hmacInited != 0) {
            (void)wc_HmacFree(&hmac);
            hmacInited = 0;
        }
    }
    else
#endif /* !NO_HMAC */
#ifdef HAVE_AES_CBC
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
#endif /* HAVE_AES_CBC */
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

#ifndef NO_HMAC
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

    return ret;
}
#endif /* WOLFCOSE_MAC_VERIFY */

#endif /* WOLFCOSE_MAC && (!NO_HMAC || HAVE_AES_CBC) */
