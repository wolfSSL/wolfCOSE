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
#ifdef WOLFCOSE_FORCE_FAILURE
    #include "../tests/force_failure.h"
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
 * WOLFSSL_API symbol in v5.8.4). Definition lives in wolfcose_util.c. */
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

typedef struct WOLFCOSE_HDR_STATE {
    uint32_t labelBits;
    int64_t  extraLabels[WOLFCOSE_MAX_MAP_ITEMS];
    size_t   extraCount;
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
#if defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_SIGN_SIGN)
WOLFCOSE_LOCAL int wolfCose_EccSignRaw(const uint8_t* hash, size_t hashLen,
                                        uint8_t* sigBuf, size_t* sigLen,
                                        size_t coordSz,
                                        enum wc_HashType hashType,
                                        WC_RNG* rng, ecc_key* eccKey);
#endif /* WOLFCOSE_SIGN1_SIGN || WOLFCOSE_SIGN_SIGN */


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

/* ----- Forced failure injection for testing error paths ----- */
#ifdef WOLFCOSE_FORCE_FAILURE
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

/* ----- Internal helpers shared across the split source files ----- */

#ifdef WOLFCOSE_HAVE_RSAPSS
/* Widest RSA public exponent wolfCOSE emits and the RFC 8230 RSA-PSS
 * minimum modulus width. These are shared by COSE_Key encoding and message
 * operations, including builds that disable COSE_Key encoding. */
#define WOLFCOSE_RSA_E_MAX_SZ    8u
#define WOLFCOSE_RSA_PSS_MIN_SZ  256u
#endif


#ifdef HAVE_ECC
/* EccKeyCheckCurve -- defined in wolfcose_alg.c */
WOLFCOSE_LOCAL int wolfCose_EccKeyCheckCurve(int32_t crv, ecc_key* eccKey);
#endif

#if defined(WOLFCOSE_HAVE_AESCCM) && \
    (defined(WOLFCOSE_ENCRYPT0_ENCRYPT) || \
     defined(WOLFCOSE_ENCRYPT0_DECRYPT) || \
     defined(WOLFCOSE_ENCRYPT_ENCRYPT) || \
     defined(WOLFCOSE_ENCRYPT_DECRYPT))
/* AeadCheckPayloadLen -- defined in wolfcose_alg.c */
WOLFCOSE_LOCAL int wolfCose_AeadCheckPayloadLen(int32_t alg, size_t payloadLen);
#endif

#if defined(WOLFCOSE_HAVE_HMAC)
#if defined(WOLFCOSE_MAC0_CREATE) || defined(WOLFCOSE_MAC0_VERIFY) || \
    defined(WOLFCOSE_MAC_CREATE) || defined(WOLFCOSE_MAC_VERIFY)
/* HmacCheckKeyLen -- defined in wolfcose_alg.c */
WOLFCOSE_LOCAL int wolfCose_HmacCheckKeyLen(int32_t alg, size_t keyLen);
#endif
#endif

#if defined(WOLFCOSE_HAVE_RSAPSS) && \
    (defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_SIGN1_VERIFY) || \
     defined(WOLFCOSE_SIGN_SIGN) || defined(WOLFCOSE_SIGN_VERIFY))
/* RsaPssCheckKey -- defined in wolfcose_alg.c */
WOLFCOSE_LOCAL int wolfCose_RsaPssCheckKey(const WOLFCOSE_KEY* key,
                                   size_t* modulusLen);

/* HashToMgf -- defined in wolfcose_alg.c */
WOLFCOSE_LOCAL int wolfCose_HashToMgf(enum wc_HashType hashType, int* mgf);
#endif

/* InInt32Range -- defined in wolfcose_hdr.c */
WOLFCOSE_LOCAL int wolfCose_InInt32Range(int64_t val);

/* HdrStateInit -- defined in wolfcose_hdr.c */
WOLFCOSE_LOCAL void wolfCose_HdrStateInit(WOLFCOSE_HDR_STATE* state);

/* HdrStateContains -- defined in wolfcose_hdr.c */
WOLFCOSE_LOCAL int wolfCose_HdrStateContains(const WOLFCOSE_HDR_STATE* state,
    int64_t label);

/* HdrStateCheckAndAdd -- defined in wolfcose_hdr.c */
WOLFCOSE_LOCAL int wolfCose_HdrStateCheckAndAdd(WOLFCOSE_HDR_STATE* state,
    int64_t label);

/* SkipIfTstrLabel -- defined in wolfcose_hdr.c */
WOLFCOSE_LOCAL int wolfCose_SkipIfTstrLabel(const WOLFCOSE_CBOR_CTX* ctx, int* skipped);


#if defined(WOLFCOSE_SIGN_VERIFY) || defined(WOLFCOSE_ENCRYPT_DECRYPT) || \
    defined(WOLFCOSE_MAC_VERIFY)
#if defined(WOLFCOSE_SIGN_VERIFY)
/* DecodeSkippedSignature -- defined in wolfcose_hdr.c */
WOLFCOSE_LOCAL int wolfCose_DecodeSkippedSignature(WOLFCOSE_CBOR_CTX* ctx);
#endif
#endif

#if defined(WOLFCOSE_SIGN_VERIFY) || defined(WOLFCOSE_ENCRYPT_DECRYPT) || \
    defined(WOLFCOSE_MAC_VERIFY)
#if defined(WOLFCOSE_ENCRYPT_DECRYPT) || defined(WOLFCOSE_MAC_VERIFY)
/* DecodeSkippedRecipient -- defined in wolfcose_hdr.c */
WOLFCOSE_LOCAL int wolfCose_DecodeSkippedRecipient(WOLFCOSE_CBOR_CTX* ctx,
    int32_t* recipientAlg);
#endif
#endif

#if defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_SIGN_SIGN)
/* KeyCanSign -- defined in wolfcose_key.c */
WOLFCOSE_LOCAL int wolfCose_KeyCanSign(const WOLFCOSE_KEY* key);
#endif

#if defined(WOLFCOSE_KEY_ENCODE) || defined(WOLFCOSE_SIGN1_SIGN)
/* SizeAdd -- defined in wolfcose_key.c */
WOLFCOSE_LOCAL int wolfCose_SizeAdd(size_t* total, size_t add);

/* CborStringSize -- defined in wolfcose_key.c */
WOLFCOSE_LOCAL int wolfCose_CborStringSize(size_t len, size_t* encodedLen);
#endif

#if (defined(WOLFCOSE_KEY_DECODE) || defined(WOLFCOSE_SIGN1) || \
     defined(WOLFCOSE_SIGN) || \
     defined(WOLFCOSE_MAC0) || defined(WOLFCOSE_MAC) || \
     defined(WOLFCOSE_ENCRYPT0) || defined(WOLFCOSE_ENCRYPT)) && \
    defined(SIZE_MAX) && (SIZE_MAX > 0xFFFFFFFFUL)
#define WOLFCOSE_CHECK_WORD32_LEN
/* LenFitsWord32 -- defined in wolfcose_recipient.c */
WOLFCOSE_LOCAL int wolfCose_LenFitsWord32(size_t n);
#endif

#if (defined(WOLFCOSE_MAC0) || defined(WOLFCOSE_MAC)) && \
    (defined(WOLFCOSE_HAVE_HMAC) || defined(WOLFCOSE_HAVE_AESMAC))
/* MacTagSize -- defined in wolfcose_mac0.c */
WOLFCOSE_LOCAL int wolfCose_MacTagSize(int32_t alg, size_t* tagSz);
#endif

#if (defined(WOLFCOSE_MAC0) || defined(WOLFCOSE_MAC)) && \
    (defined(WOLFCOSE_HAVE_HMAC) || defined(WOLFCOSE_HAVE_AESMAC))
#ifdef WOLFCOSE_HAVE_AESMAC
/* AesCbcMacKeySize -- defined in wolfcose_mac0.c */
WOLFCOSE_LOCAL int wolfCose_AesCbcMacKeySize(int32_t alg, size_t* keySz);

/* AesCbcMac -- defined in wolfcose_mac0.c */
WOLFCOSE_LOCAL int wolfCose_AesCbcMac(const uint8_t* key, size_t keyLen,
                               const uint8_t* data, size_t dataLen,
                               uint8_t* tag, size_t tagLen);
#endif
#endif

#if (defined(WOLFCOSE_MAC0) || defined(WOLFCOSE_MAC)) && \
    (defined(WOLFCOSE_HAVE_HMAC) || defined(WOLFCOSE_HAVE_AESMAC))
#ifdef WOLFCOSE_HAVE_HMAC
/* IsHmacAlg -- defined in wolfcose_mac0.c */
WOLFCOSE_LOCAL int wolfCose_IsHmacAlg(int32_t alg);
#endif
#endif

#if (defined(WOLFCOSE_MAC0) || defined(WOLFCOSE_MAC)) && \
    (defined(WOLFCOSE_HAVE_HMAC) || defined(WOLFCOSE_HAVE_AESMAC))
#ifdef WOLFCOSE_HAVE_AESMAC
/* IsAesCbcMacAlg -- defined in wolfcose_mac0.c */
WOLFCOSE_LOCAL int wolfCose_IsAesCbcMacAlg(int32_t alg);
#endif
#endif

#if defined(WOLFCOSE_KEY_WRAP)
/* KeyWrapKeySize -- defined in wolfcose_recipient.c */
WOLFCOSE_LOCAL int wolfCose_KeyWrapKeySize(int32_t alg, size_t* keySz);

/* KeyWrap -- defined in wolfcose_recipient.c */
WOLFCOSE_LOCAL int wolfCose_KeyWrap(int32_t alg, const WOLFCOSE_KEY* kek,
                             const uint8_t* cek, size_t cekLen,
                             uint8_t* out, size_t outSz, size_t* outLen);

/* KeyUnwrap -- defined in wolfcose_recipient.c */
WOLFCOSE_LOCAL int wolfCose_KeyUnwrap(int32_t alg, const WOLFCOSE_KEY* kek,
                               const uint8_t* wrappedCek, size_t wrappedLen,
                               uint8_t* cekOut, size_t cekOutSz, size_t* cekLen);

/* IsKeyWrapAlg -- defined in wolfcose_recipient.c */
WOLFCOSE_LOCAL int wolfCose_IsKeyWrapAlg(int32_t alg);
#endif

#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
/* EcdhEsDirect -- defined in wolfcose_recipient.c */
WOLFCOSE_LOCAL int wolfCose_EcdhEsDirect(int32_t alg,
                                  WOLFCOSE_KEY* recipientPub,
                                  int32_t contentAlgId,
                                  size_t cekLenBytes,
                                  const uint8_t* recipientProtected,
                                  size_t recipientProtectedLen,
                                  uint8_t* ephemPubX, uint8_t* ephemPubY,
                                  size_t ephemPubSz, size_t* ephemPubLen,
                                  uint8_t* cekOut, size_t cekOutSz,
                                  WC_RNG* rng);

/* EcdhEsDirectRecv -- defined in wolfcose_recipient.c */
WOLFCOSE_LOCAL int wolfCose_EcdhEsDirectRecv(int32_t alg,
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
                                      uint8_t* cekOut, size_t cekOutSz);

/* IsEcdhEsDirectAlg -- defined in wolfcose_recipient.c */
WOLFCOSE_LOCAL int wolfCose_IsEcdhEsDirectAlg(int32_t alg);

/* EncodeEphemeralKey -- defined in wolfcose_recipient.c */
WOLFCOSE_LOCAL int wolfCose_EncodeEphemeralKey(WOLFCOSE_CBOR_CTX* ctx,
                                        int crv,
                                        const uint8_t* x, size_t xLen,
                                        const uint8_t* y, size_t yLen);

/* DecodeEphemeralKey -- defined in wolfcose_recipient.c */
WOLFCOSE_LOCAL int wolfCose_DecodeEphemeralKey(WOLFCOSE_CBOR_CTX* ctx,
                                        int* crv,
                                        uint8_t* x, size_t xSz, size_t* xLen,
                                        uint8_t* y, size_t ySz, size_t* yLen);
#endif

#if defined(WOLFCOSE_ENCRYPT_DECRYPT) || defined(WOLFCOSE_MAC_VERIFY)
/* UpdateRecipientMode -- defined in wolfcose_recipient.c */
WOLFCOSE_LOCAL int wolfCose_UpdateRecipientMode(int32_t alg, int* commonMode);
#endif

#if defined(WOLFCOSE_HAVE_MLDSA) && \
    (defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_SIGN1_VERIFY) || \
     defined(WOLFCOSE_SIGN_SIGN) || defined(WOLFCOSE_SIGN_VERIFY))
/* MlDsaCheckKey -- defined in wolfcose_sign1.c */
WOLFCOSE_LOCAL int wolfCose_MlDsaCheckKey(const WOLFCOSE_KEY* key, int32_t alg);
#endif

#if defined(WOLFCOSE_EXT_SIGN)
/* ExtSignAlg -- defined in wolfcose_sign1.c */
WOLFCOSE_LOCAL int wolfCose_ExtSignAlg(int32_t alg, int* preHashes);
#endif

#if (defined(WOLFCOSE_ENCRYPT0) || defined(WOLFCOSE_ENCRYPT)) && \
    (defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM) || \
     defined(WOLFCOSE_HAVE_CHACHA20))
/* BuildEncStructure -- defined in wolfcose_struct.c */
WOLFCOSE_LOCAL int wolfCose_BuildEncStructure(
    const uint8_t* context, size_t contextLen,
    const uint8_t* bodyProtected, size_t bodyProtectedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    size_t* structLen);
#endif

#if defined(WOLFCOSE_HAVE_MLDSA) && defined(WOLFCOSE_KEY_DECODE) && \
    !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MLDSA_ASSIGN_KEY)
/* MlDsaImportRollback -- defined in wolfcose_util.c */
WOLFCOSE_LOCAL void wolfCose_MlDsaImportRollback(wc_MlDsaKey* key, byte level);
#endif

#if defined(HAVE_ECC) && defined(WOLFCOSE_KEY_DECODE)
typedef struct WOLFCOSE_ECC_IMPORT_STATE {
    int type;
    int idx;
    int state;
    const ecc_set_type* dp;
} WOLFCOSE_ECC_IMPORT_STATE;

/* EccPrivateImportBegin -- defined in wolfcose_util.c */
WOLFCOSE_LOCAL int wolfCose_EccPrivateImportBegin(ecc_key* ecc,
    WOLFCOSE_ECC_IMPORT_STATE* saved);

/* EccPrivateImportRollback -- defined in wolfcose_util.c */
WOLFCOSE_LOCAL void wolfCose_EccPrivateImportRollback(ecc_key* ecc,
    const WOLFCOSE_ECC_IMPORT_STATE* saved);
#endif

#if defined(WOLFCOSE_SIGN1_VERIFY) || defined(WOLFCOSE_SIGN_VERIFY) || \
    defined(WOLFCOSE_ENCRYPT0_DECRYPT) || defined(WOLFCOSE_MAC0_VERIFY) || \
    defined(WOLFCOSE_ENCRYPT_DECRYPT) || defined(WOLFCOSE_MAC_VERIFY)
/* HdrClearOnFail -- defined in wolfcose_util.c */
WOLFCOSE_LOCAL void wolfCose_HdrClearOnFail(int ret, WOLFCOSE_HDR* hdr);
#endif

#if defined(WOLFCOSE_MAC0_VERIFY) || defined(WOLFCOSE_MAC_VERIFY)
/* ConstantCompare -- defined in wolfcose_util.c */
WOLFCOSE_LOCAL int wolfCose_ConstantCompare(const byte* a, const byte* b,
                                     word32 length);
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFCOSE_INTERNAL_H */
