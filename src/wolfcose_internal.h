/* wolfcose_internal.h
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

#ifndef WOLFCOSE_INTERNAL_H
#define WOLFCOSE_INTERNAL_H

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#if defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM)
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#if defined(WOLFCOSE_HAVE_HMAC)
    #include <wolfssl/wolfcrypt/hmac.h>
#endif
#if defined(WOLFCOSE_HAVE_CHACHA20)
    #include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#endif

/* ECC private-material import is unavailable when wolfCrypt uses an
 * incompatible math layout or cannot roll back accepted or provisioned key
 * material. */
#if defined(HAVE_ECC) && defined(WOLFCOSE_KEY_DECODE) && \
    (defined(WOLFSSL_CRYPTOCELL) || defined(WOLFSSL_QNX_CAAM) || \
     defined(WOLFSSL_IMXRT1170_CAAM) || \
     defined(WOLFSSL_SILABS_SE_ACCEL) || \
     defined(WOLFSSL_MAXQ10XX_CRYPTO) || \
     (defined(ALT_ECC_SIZE) && defined(USE_FAST_MATH) && \
      defined(HAVE_WOLF_BIGINT)) || \
     (defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_SETKEY) && \
      defined(WOLF_CRYPTO_CB_FIND)) || \
     (defined(WOLFCOSE_FORCE_FAILURE) && \
      defined(WOLFCOSE_TEST_NONTRANSACTIONAL_ECC_IMPORT)))
    #define WOLFCOSE_ECC_PRIVATE_IMPORT_ALWAYS_UNSUPPORTED
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ----- Secure memory zero -----
 * Portable secure-zero using a volatile pointer so the compiler cannot
 * optimise the writes away. Used in place of wc_ForceZero so wolfCOSE
 * links against the full 5.x range (wc_ForceZero only became a public
 * WOLFSSL_API symbol in v5.8.4). Definition lives in wolfcose.c. */
WOLFCOSE_LOCAL void wolfCose_ForceZero(void* mem, size_t len);

/* ----- Big-endian load/store helpers (bit-shift only, no platform dependencies) ----- */

static inline void wolfCose_StoreBE16(uint8_t* buf, uint64_t val)
{
    uint16_t beVal = (uint16_t)val;

    buf[0] = (uint8_t)(((uint32_t)beVal) >> 8u);
    buf[1] = (uint8_t)(((uint32_t)beVal) & 0xFFu);
}

static inline void wolfCose_StoreBE32(uint8_t* buf, uint64_t val)
{
    uint32_t beVal = (uint32_t)val;

    buf[0] = (uint8_t)(beVal >> 24u);
    buf[1] = (uint8_t)(beVal >> 16u);
    buf[2] = (uint8_t)(beVal >> 8u);
    buf[3] = (uint8_t)(beVal & 0xFFu);
}

static inline void wolfCose_StoreBE64(uint8_t* buf, uint64_t val)
{
    buf[0] = (uint8_t)(val >> 56u);
    buf[1] = (uint8_t)(val >> 48u);
    buf[2] = (uint8_t)(val >> 40u);
    buf[3] = (uint8_t)(val >> 32u);
    buf[4] = (uint8_t)(val >> 24u);
    buf[5] = (uint8_t)(val >> 16u);
    buf[6] = (uint8_t)(val >> 8u);
    buf[7] = (uint8_t)(val & 0xFFu);
}

static inline uint16_t wolfCose_LoadBE16(const uint8_t* buf)
{
    return (uint16_t)((((uint32_t)buf[0]) << 8u) |
                      ((uint32_t)buf[1]));
}

static inline uint32_t wolfCose_LoadBE32(const uint8_t* buf)
{
    return ((((uint32_t)buf[0]) << 24u) |
            (((uint32_t)buf[1]) << 16u) |
            (((uint32_t)buf[2]) << 8u)  |
            ((uint32_t)buf[3]));
}

static inline uint64_t wolfCose_LoadBE64(const uint8_t* buf)
{
    return ((((uint64_t)buf[0]) << 56u) |
            (((uint64_t)buf[1]) << 48u) |
            (((uint64_t)buf[2]) << 40u) |
            (((uint64_t)buf[3]) << 32u) |
            (((uint64_t)buf[4]) << 24u) |
            (((uint64_t)buf[5]) << 16u) |
            (((uint64_t)buf[6]) << 8u)  |
            ((uint64_t)buf[7]));
}

/* ----- Internal CBOR head encode/decode ----- */

/**
 * \brief Encode a CBOR initial byte + argument.
 * RFC 8949 Section 3.1: initial_byte = (majorType << 5) | additional_info
 */
WOLFCOSE_LOCAL int wolfCose_CBOR_EncodeHead(WOLFCOSE_CBOR_CTX* ctx,
                                             uint8_t majorType, uint64_t val);

/**
 * \brief Decode a CBOR initial byte + argument. Sets item fields.
 * For bstr/tstr: item->data points into ctx->buf, item->dataLen set.
 */
WOLFCOSE_LOCAL int wolfCose_CBOR_DecodeHead(WOLFCOSE_CBOR_CTX* ctx,
                                             WOLFCOSE_CBOR_ITEM* item);

/* ----- RFC 9052 context-string byte arrays (see wolfcose.c) ----- */
WOLFCOSE_LOCAL extern const uint8_t WOLFCOSE_CTX_SIGNATURE1[10];
WOLFCOSE_LOCAL extern const uint8_t WOLFCOSE_CTX_SIGNATURE[9];
WOLFCOSE_LOCAL extern const uint8_t WOLFCOSE_CTX_MAC0[4];
WOLFCOSE_LOCAL extern const uint8_t WOLFCOSE_CTX_MAC[3];
WOLFCOSE_LOCAL extern const uint8_t WOLFCOSE_CTX_ENCRYPT0[8];
WOLFCOSE_LOCAL extern const uint8_t WOLFCOSE_CTX_ENCRYPT[7];

#define WOLFCOSE_MAX_HEADER_LABELS WOLFCOSE_MAX_MAP_ITEMS

typedef struct WOLFCOSE_HDR_STATE {
    uint32_t       labelBits;
    int64_t        extraIntegerLabels[WOLFCOSE_MAX_HEADER_LABELS];
    const uint8_t* extraTextLabels[WOLFCOSE_MAX_HEADER_LABELS];
    size_t         extraIntegerCount;
    size_t         extraTextCount;
} WOLFCOSE_HDR_STATE;

/* ----- COSE internal helpers ----- */

/**
 * \brief Encode a protected header map: {1: alg} as a bstr.
 * \param alg     Algorithm identifier.
 * \param buf     Output buffer.
 * \param bufSz   Buffer size.
 * \param outLen  Output: bytes written.
 */
WOLFCOSE_LOCAL int wolfCose_EncodeProtectedHdr(int32_t alg, uint8_t* buf,
                                                size_t bufSz, size_t* outLen);

/**
 * \brief Decode a protected header bstr (containing a CBOR map).
 * \param data     Raw bstr content.
 * \param dataLen  Length of bstr.
 * \param hdr      Output: parsed header fields.
 */
WOLFCOSE_LOCAL int wolfCose_DecodeProtectedHdr(const uint8_t* data,
                                                size_t dataLen,
                                                WOLFCOSE_HDR* hdr,
                                                WOLFCOSE_HDR_STATE* hdrState);

/**
 * \brief Decode an unprotected header map from the decoder context.
 * \param ctx  Decoder context positioned at the map.
 * \param hdr  Output: parsed header fields (merged with protected).
 */
WOLFCOSE_LOCAL int wolfCose_DecodeUnprotectedHdr(WOLFCOSE_CBOR_CTX* ctx,
                                                  WOLFCOSE_HDR* hdr,
                                                  WOLFCOSE_HDR_STATE* hdrState);

/**
 * \brief Map COSE algorithm ID to wolfCrypt hash type.
 *        Central hash agility point -- extend here for PQC (SHA3, SHAKE).
 * \param alg      COSE algorithm ID.
 * \param hashType Output: wolfCrypt hash type.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_COSE_BAD_ALG.
 */
WOLFCOSE_LOCAL int wolfCose_AlgToHashType(int32_t alg,
                                           enum wc_HashType* hashType);

/**
 * \brief Get signature size for an algorithm.
 * \param alg    COSE algorithm ID.
 * \param sigSz  Output: signature size in bytes.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_COSE_BAD_ALG.
 */
WOLFCOSE_LOCAL int wolfCose_SigSize(int32_t alg, size_t* sigSz);

/**
 * \brief Get key size (coordinate size) for a COSE curve.
 * \param crv    COSE curve ID.
 * \param keySz  Output: coordinate size in bytes.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_COSE_BAD_ALG.
 */
WOLFCOSE_LOCAL int wolfCose_CrvKeySize(int32_t crv, size_t* keySz);

#ifdef HAVE_ECC
/**
 * \brief Map COSE curve ID to wolfCrypt ECC curve ID.
 * \param crv    COSE curve ID.
 * \param wcCrv  Output: wolfCrypt ECC_SECP* value.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_COSE_BAD_ALG.
 */
WOLFCOSE_LOCAL int wolfCose_CrvToWcCurve(int32_t crv, int* wcCrv);
#endif

/* -----
 * Unified structure builders (RFC 9052 Section 4.4, 5.3, 6.3)
 *
 * These shared helpers reduce code size by unifying:
 * - Sig_structure (Sign1/Sign): ["Signature1"|"Signature", body_prot, [sign_prot,] ext_aad, payload]
 * - MAC_structure (Mac0/Mac): ["MAC0"|"MAC", body_prot, ext_aad, payload]
 * - Enc_structure (Encrypt0/Encrypt): ["Encrypt0"|"Encrypt", body_prot, ext_aad]
 * ----- */

/**
 * \brief Build a ToBeSigned/ToBeMAced structure.
 *
 * This unified builder handles both Sig_structure and MAC_structure since they
 * share the same 4-element format: [context, body_protected, external_aad, payload]
 *
 * For multi-signer COSE_Sign, set signProtected non-NULL to create the 5-element
 * format: [context, body_protected, sign_protected, external_aad, payload]
 *
 * \param context         Context string ("Signature1", "Signature", "MAC0", "MAC")
 * \param contextLen      Length of context string
 * \param bodyProtected   Serialized protected headers (body-level)
 * \param bodyProtectedLen Length of body protected headers
 * \param signProtected   Signer-specific protected headers (NULL for Sign1/Mac0/Mac)
 * \param signProtectedLen Length of sign protected headers
 * \param extAad          External AAD (may be NULL)
 * \param extAadLen       Length of external AAD
 * \param payload         Payload bytes
 * \param payloadLen      Length of payload
 * \param scratch         Output buffer for structure
 * \param scratchSz       Size of output buffer
 * \param structLen       Output: bytes written
 * \return WOLFCOSE_SUCCESS or error code
 */
WOLFCOSE_LOCAL int wolfCose_BuildToBeSignedMaced(
    const uint8_t* context, size_t contextLen,
    const uint8_t* bodyProtected, size_t bodyProtectedLen,
    const uint8_t* signProtected, size_t signProtectedLen,
    const uint8_t* extAad, size_t extAadLen,
    const uint8_t* payload, size_t payloadLen,
    uint8_t* scratch, size_t scratchSz,
    size_t* structLen);


/**
 * \brief Get AEAD key length for any COSE AEAD algorithm.
 *        Dispatches across AES-GCM, ChaCha20-Poly1305, AES-CCM.
 * \param alg     COSE algorithm ID.
 * \param keyLen  Output: key length in bytes.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_COSE_BAD_ALG.
 */
WOLFCOSE_LOCAL int wolfCose_AeadKeyLen(int32_t alg, size_t* keyLen);

/**
 * \brief Get AEAD nonce length for any COSE AEAD algorithm.
 * \param alg       COSE algorithm ID.
 * \param nonceLen  Output: nonce length in bytes.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_COSE_BAD_ALG.
 */
WOLFCOSE_LOCAL int wolfCose_AeadNonceLen(int32_t alg, size_t* nonceLen);

/**
 * \brief Get AEAD tag length for any COSE AEAD algorithm.
 * \param alg     COSE algorithm ID.
 * \param tagLen  Output: tag length in bytes.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_COSE_BAD_ALG.
 */
WOLFCOSE_LOCAL int wolfCose_AeadTagLen(int32_t alg, size_t* tagLen);

#if defined(WOLFCOSE_HAVE_HMAC)
/**
 * \brief Map COSE HMAC algorithm ID to wolfCrypt HMAC type.
 * \param alg       COSE algorithm ID.
 * \param hmacType  Output: wolfCrypt hash type for HMAC.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_COSE_BAD_ALG.
 */
WOLFCOSE_LOCAL int wolfCose_HmacType(int32_t alg, int* hmacType);
#endif /* WOLFCOSE_HAVE_HMAC */

#ifdef WOLFCOSE_HAVE_ECDSA
/**
 * \brief Sign a hash with ECC, producing raw r||s output.
 *        Wraps wolfCrypt DER signature -> fixed-width r||s conversion.
 * \param hash     Hash to sign.
 * \param hashLen  Hash length.
 * \param sigBuf   Output: raw r||s signature.
 * \param sigLen   In/Out: buffer size / bytes written.
 * \param coordSz  Coordinate size for this curve (e.g., 32 for P-256).
 * \param hashType Hash type for optional deterministic k generation.
 * \param rng      Initialized WC_RNG.
 * \param eccKey   Caller-owned ECC key with private key.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
#if defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_SIGN_SIGN) || \
    defined(WOLFCOSE_COUNTERSIGN_SIGN)
WOLFCOSE_LOCAL int wolfCose_EccSignRaw(const uint8_t* hash, size_t hashLen,
                                        uint8_t* sigBuf, size_t* sigLen,
                                        size_t coordSz,
                                        enum wc_HashType hashType,
                                        WC_RNG* rng, ecc_key* eccKey);
#endif /* WOLFCOSE_SIGN1_SIGN || WOLFCOSE_SIGN_SIGN || COUNTERSIGN_SIGN */


/**
 * \brief Verify a raw r||s ECC signature.
 *        Converts raw r||s -> DER then calls wc_ecc_verify_hash.
 * \param sigBuf    Raw r||s signature.
 * \param sigLen    Signature length.
 * \param hash      Hash to verify against.
 * \param hashLen   Hash length.
 * \param coordSz   Coordinate size for this curve.
 * \param eccKey    Caller-owned ECC key with public key.
 * \param verified  Output: 1 if signature verified, 0 otherwise.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_LOCAL int wolfCose_EccVerifyRaw(const uint8_t* sigBuf, size_t sigLen,
                                          const uint8_t* hash, size_t hashLen,
                                          size_t coordSz,
                                          ecc_key* eccKey, int* verified);
#endif /* WOLFCOSE_HAVE_ECDSA */

#if defined(WOLFCOSE_EXT_SIGN)
/**
 * \brief Produce a signature via the key's external signer callback.
 *        Pre-hashes the Sig_structure for algorithms whose primitive takes a
 *        digest, then validates the length the callback reports.
 * \param key           Key with signCb set.
 * \param alg           WOLFCOSE_ALG_* being signed with.
 * \param sigStruct     Encoded Sig_structure.
 * \param sigStructLen  Sig_structure length.
 * \param sig           Output buffer for the signature.
 * \param sigSz         Capacity of sig.
 * \param sigLen        Output: bytes written to sig.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_LOCAL int wolfCose_ExtSign(const WOLFCOSE_KEY* key, int32_t alg,
                                     const uint8_t* sigStruct,
                                     size_t sigStructLen,
                                     uint8_t* sig, size_t sigSz,
                                     size_t* sigLen);
#endif /* WOLFCOSE_EXT_SIGN */

#ifdef __cplusplus
}
#endif

#endif /* WOLFCOSE_INTERNAL_H */
