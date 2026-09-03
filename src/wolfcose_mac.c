/* wolfcose_mac.c
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
 * COSE_Mac multi-recipient MAC create and verify. RFC 9052 Section 6.1.
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
