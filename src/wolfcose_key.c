/* wolfcose_key.c
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
 * COSE_Key encode/decode and wolfCrypt key attachment. RFC 9052 Section 7.
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
int wolfCose_KeyCanSign(const WOLFCOSE_KEY* key)
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
int wolfCose_SizeAdd(size_t* total, size_t add)
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

int wolfCose_CborStringSize(size_t len, size_t* encodedLen)
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
    int64_t label = 0;

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
    int64_t label = 0;
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
