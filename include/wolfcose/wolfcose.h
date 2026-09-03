/* wolfcose.h
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

#ifndef WOLFCOSE_H
#define WOLFCOSE_H

#include <wolfcose/visibility.h>
#include <wolfcose/version.h>

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#include <stdint.h>
#include <stddef.h>

#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef WC_RSA_PSS
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef HAVE_ED448
    #include <wolfssl/wolfcrypt/ed448.h>
#endif
#ifdef WOLFSSL_HAVE_MLDSA
    #include <wolfssl/wolfcrypt/wc_mldsa.h>
#endif
#include <wolfssl/wolfcrypt/random.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Compile-time configuration: NO_/ENABLE_ feature gates, per-algorithm
 * WOLFCOSE_HAVE_* flags, and tunable limits all resolve here. */
#include <wolfcose/settings.h>

/* A lean verify build must actually verify. Fail loudly if it was reduced to a
 * library that can do nothing. */
#if defined(WOLFCOSE_LEAN_VERIFY) && !defined(WOLFCOSE_SIGN1_VERIFY)
    #error "WOLFCOSE_LEAN_VERIFY requires Sign1 verify; do not also disable it"
#endif
#if defined(WOLFCOSE_LEAN_VERIFY_MLDSA) && !defined(WOLFCOSE_SIGN1_VERIFY)
    #error "WOLFCOSE_LEAN_VERIFY_MLDSA requires Sign1 verify; do not also disable it"
#endif

/* ----- Error codes (-9000 to -9099) ----- */
#define WOLFCOSE_SUCCESS             0
#define WOLFCOSE_E_INVALID_ARG      (-9000)
#define WOLFCOSE_E_BUFFER_TOO_SMALL (-9001)
#define WOLFCOSE_E_CBOR_MALFORMED   (-9002)
#define WOLFCOSE_E_CBOR_TYPE        (-9003)
#define WOLFCOSE_E_CBOR_OVERFLOW    (-9004)
#define WOLFCOSE_E_CBOR_DEPTH       (-9006)
#define WOLFCOSE_E_COSE_BAD_TAG     (-9010)
#define WOLFCOSE_E_COSE_BAD_ALG     (-9011)
#define WOLFCOSE_E_COSE_SIG_FAIL    (-9012)
#define WOLFCOSE_E_COSE_DECRYPT_FAIL (-9013)
#define WOLFCOSE_E_COSE_BAD_HDR     (-9014)
#define WOLFCOSE_E_COSE_KEY_TYPE    (-9015)
#define WOLFCOSE_E_COSE_MAC_FAIL    (-9016)
#define WOLFCOSE_E_CRYPTO           (-9020)
#define WOLFCOSE_E_UNSUPPORTED      (-9021)
#define WOLFCOSE_E_MAC_FAIL         (-9022)
#define WOLFCOSE_E_DETACHED_PAYLOAD (-9023)

/* ----- CBOR constants (RFC 8949) ----- */

/* Major types (top 3 bits of initial byte) */
#define WOLFCOSE_CBOR_UINT      0u
#define WOLFCOSE_CBOR_NEGINT    1u
#define WOLFCOSE_CBOR_BSTR      2u
#define WOLFCOSE_CBOR_TSTR      3u
#define WOLFCOSE_CBOR_ARRAY     4u
#define WOLFCOSE_CBOR_MAP       5u
#define WOLFCOSE_CBOR_TAG       6u
#define WOLFCOSE_CBOR_SIMPLE    7u

/* Additional information values */
#define WOLFCOSE_CBOR_AI_1BYTE  24u
#define WOLFCOSE_CBOR_AI_2BYTE  25u
#define WOLFCOSE_CBOR_AI_4BYTE  26u
#define WOLFCOSE_CBOR_AI_8BYTE  27u
#define WOLFCOSE_CBOR_AI_INDEF  31u

/* Simple values */
#define WOLFCOSE_CBOR_FALSE     0xF4u
#define WOLFCOSE_CBOR_TRUE      0xF5u
#define WOLFCOSE_CBOR_NULL      0xF6u
#define WOLFCOSE_CBOR_BREAK     0xFFu

/* Float half/single/double AI */
#define WOLFCOSE_CBOR_AI_FLOAT16 25u
#define WOLFCOSE_CBOR_AI_FLOAT32 26u
#define WOLFCOSE_CBOR_AI_FLOAT64 27u

/* ----- COSE constants (RFC 9052) ----- */

/* Output options for wc_CoseSign1_Sign_ex() and
 * wc_CoseSign1_SignSize_ex(). */
#define WOLFCOSE_SIGN1_UNTAGGED 0x0001u  /* Omit the tag 18 prefix */

/* Output options for wc_CoseKey_Encode_ex() and wc_CoseKey_EncodeSize_ex(). */
#define WOLFCOSE_KEY_PUBLIC_ONLY 0x0001u /* Never serialise private material */

/* Tags (RFC 9052) */
#define WOLFCOSE_TAG_SIGN1      18u
#define WOLFCOSE_TAG_ENCRYPT0   16u
#define WOLFCOSE_TAG_MAC0       17u
#define WOLFCOSE_TAG_COUNTERSIGNATURE 19u
#define WOLFCOSE_TAG_SIGN       98u  /* Multi-signer */
#define WOLFCOSE_TAG_ENCRYPT    96u  /* Multi-recipient encryption */
#define WOLFCOSE_TAG_MAC        97u  /* Multi-recipient MAC */

/* Header labels */
#define WOLFCOSE_HDR_ALG         1
#define WOLFCOSE_HDR_CRIT        2
#define WOLFCOSE_HDR_CONTENT_TYPE 3
#define WOLFCOSE_HDR_KID         4
#define WOLFCOSE_HDR_IV          5
#define WOLFCOSE_HDR_PARTIAL_IV  6
#define WOLFCOSE_HDR_COUNTERSIGNATURE_LEGACY  7
#define WOLFCOSE_HDR_COUNTERSIGNATURE0_LEGACY 9
#define WOLFCOSE_HDR_COUNTERSIGNATURE_V2  11
#define WOLFCOSE_HDR_COUNTERSIGNATURE0_V2 12
#define WOLFCOSE_HDR_EPHEMERAL_KEY (-1)  /* Ephemeral COSE_Key for ECDH */

/*
 * Security considerations for the algorithms below:
 *
 * - Nonce/IV uniqueness: the AEAD encrypt APIs take a caller-supplied IV and
 *   only validate its length. Reusing an (key, IV) pair with AES-GCM,
 *   AES-CCM, or ChaCha20-Poly1305 breaks confidentiality and/or integrity.
 *   Callers MUST supply a unique IV per encryption (e.g. from wc_RNG).
 * - 64-bit authentication tags: the AES-CCM *_64_* and AES-MAC *_64
 *   algorithms produce 8-byte tags with much lower forgery resistance than
 *   their 128-bit counterparts. They exist for constrained interop only;
 *   prefer the 128-bit-tag variants unless a peer requires otherwise.
 * - Algorithm pinning: verify/decrypt dispatch on the message algorithm.
 *   To avoid algorithm-confusion, set key->alg (or recipient->algId) so the
 *   library enforces the expected algorithm rather than trusting the message.
 * - HMAC key length: HMAC-256/384/512 require a key of at least 32/48/64
 *   bytes (RFC 9053 Section 3.1). Shorter keys are rejected with
 *   WOLFCOSE_E_COSE_KEY_TYPE unless WOLFCOSE_ALLOW_SHORT_HMAC_KEY is defined.
 * - Strict decode: decoders require preferred (shortest-form) CBOR
 *   (RFC 8949 Section 4.2.1) across all entry points, and verify/decrypt
 *   APIs require inSz to be exactly the encoded object length (trailing bytes
 *   are rejected). EC2 coordinates must be exactly the curve size.
 */

/* Algorithms */
#define WOLFCOSE_ALG_UNSET      ((int32_t)0)
#define WOLFCOSE_ALG_ES256      (-7)
#define WOLFCOSE_ALG_ES384      (-35)
#define WOLFCOSE_ALG_ES512      (-36)
#define WOLFCOSE_ALG_EDDSA      (-8)
#define WOLFCOSE_ALG_PS256      (-37)
#define WOLFCOSE_ALG_PS384      (-38)
#define WOLFCOSE_ALG_PS512      (-39)
#define WOLFCOSE_ALG_A128GCM     1
#define WOLFCOSE_ALG_A192GCM     2
#define WOLFCOSE_ALG_A256GCM     3
#define WOLFCOSE_ALG_HMAC_256_256  5   /* HMAC w/ SHA-256, 256-bit tag */
#define WOLFCOSE_ALG_HMAC_384_384  6   /* HMAC w/ SHA-384, 384-bit tag */
#define WOLFCOSE_ALG_HMAC_512_512  7   /* HMAC w/ SHA-512, 512-bit tag */
/* Shorter aliases for convenience */
#define WOLFCOSE_ALG_HMAC256       WOLFCOSE_ALG_HMAC_256_256
#define WOLFCOSE_ALG_HMAC384       WOLFCOSE_ALG_HMAC_384_384
#define WOLFCOSE_ALG_HMAC512       WOLFCOSE_ALG_HMAC_512_512
#define WOLFCOSE_ALG_CHACHA20_POLY1305 24
/* AES-CCM (RFC 9053 Section 4.2) */
#define WOLFCOSE_ALG_AES_CCM_16_64_128   10
#define WOLFCOSE_ALG_AES_CCM_16_64_256   11
#define WOLFCOSE_ALG_AES_CCM_64_64_128   12
#define WOLFCOSE_ALG_AES_CCM_64_64_256   13
#define WOLFCOSE_ALG_AES_CCM_16_128_128  30
#define WOLFCOSE_ALG_AES_CCM_16_128_256  31
#define WOLFCOSE_ALG_AES_CCM_64_128_128  32
#define WOLFCOSE_ALG_AES_CCM_64_128_256  33

/* AES-CBC-MAC algorithms (RFC 9053 Section 3.2) */
#define WOLFCOSE_ALG_AES_MAC_128_64   14  /* AES-128 key, 64-bit tag */
#define WOLFCOSE_ALG_AES_MAC_256_64   15  /* AES-256 key, 64-bit tag */
#define WOLFCOSE_ALG_AES_MAC_128_128  25  /* AES-128 key, 128-bit tag */
#define WOLFCOSE_ALG_AES_MAC_256_128  26  /* AES-256 key, 128-bit tag */

/* Key Distribution Algorithms (RFC 9053 Section 6) */
#define WOLFCOSE_ALG_A128KW       (-3)   /* AES-128 Key Wrap */
#define WOLFCOSE_ALG_A192KW       (-4)   /* AES-192 Key Wrap */
#define WOLFCOSE_ALG_A256KW       (-5)   /* AES-256 Key Wrap */
#define WOLFCOSE_ALG_DIRECT       (-6)   /* Direct use of CEK */
#define WOLFCOSE_ALG_DIRECT_HKDF_SHA_256 (-10) /* Direct + HKDF-SHA-256 */
#define WOLFCOSE_ALG_DIRECT_HKDF_SHA_512 (-11) /* Direct + HKDF-SHA-512 */
#define WOLFCOSE_ALG_DIRECT_HKDF_AES_128 (-12) /* Direct + HKDF-AES-128 */
#define WOLFCOSE_ALG_DIRECT_HKDF_AES_256 (-13) /* Direct + HKDF-AES-256 */
#define WOLFCOSE_ALG_ECDH_ES_HKDF_256  (-25)  /* ECDH-ES + HKDF-256 */
#define WOLFCOSE_ALG_ECDH_ES_HKDF_512  (-26)  /* ECDH-ES + HKDF-512 */
#define WOLFCOSE_ALG_ECDH_SS_HKDF_256  (-27)  /* ECDH-SS + HKDF-256 */
#define WOLFCOSE_ALG_ECDH_SS_HKDF_512  (-28)  /* ECDH-SS + HKDF-512 */
#define WOLFCOSE_ALG_ECDH_ES_A128KW    (-29)  /* ECDH-ES + A128KW */
#define WOLFCOSE_ALG_ECDH_ES_A192KW    (-30)  /* ECDH-ES + A192KW */
#define WOLFCOSE_ALG_ECDH_ES_A256KW    (-31)  /* ECDH-ES + A256KW */

#define WOLFCOSE_ALG_ML_DSA_44   (-48)   /* ML-DSA Level 2 */
#define WOLFCOSE_ALG_ML_DSA_65   (-49)   /* ML-DSA Level 3 */
#define WOLFCOSE_ALG_ML_DSA_87   (-50)   /* ML-DSA Level 5 */

/* RFC 9964: an ML-DSA private key is the 32-byte seed (FIPS 204). */
#define WOLFCOSE_MLDSA_SEED_SZ   32u

/* Key types */
#define WOLFCOSE_KTY_OKP         1
#define WOLFCOSE_KTY_EC2         2
#define WOLFCOSE_KTY_RSA         3
#define WOLFCOSE_KTY_SYMMETRIC   4
#define WOLFCOSE_KTY_AKP         7   /* RFC 9964: Algorithm Key Pair (ML-DSA) */

/* key.* union is untagged: every member aliases one pointer, so a non-NULL
 * member is not a type check. Importers match on attachedType instead. */
#define WOLFCOSE_ATT_NONE        0u
#define WOLFCOSE_ATT_ECC         1u
#define WOLFCOSE_ATT_ED25519     2u
#define WOLFCOSE_ATT_ED448       3u
#define WOLFCOSE_ATT_RSA         4u
#define WOLFCOSE_ATT_MLDSA       5u
#define WOLFCOSE_ATT_SYMMETRIC   6u

/* Curves */
#define WOLFCOSE_CRV_P256        1
#define WOLFCOSE_CRV_P384        2
#define WOLFCOSE_CRV_P521        3
#define WOLFCOSE_CRV_ED25519     6
#define WOLFCOSE_CRV_ED448       7
/* Internal ML-DSA level<->alg mapping only; RFC 9964 AKP keys carry the level
 * in alg, not crv. These are never emitted in a COSE_Key. */
#define WOLFCOSE_CRV_ML_DSA_44   (-48)
#define WOLFCOSE_CRV_ML_DSA_65   (-49)
#define WOLFCOSE_CRV_ML_DSA_87   (-50)

/* COSE_Key map labels */
#define WOLFCOSE_KEY_LABEL_KTY    1
#define WOLFCOSE_KEY_LABEL_KID    2
#define WOLFCOSE_KEY_LABEL_ALG    3
#define WOLFCOSE_KEY_LABEL_KEY_OPS 4
#define WOLFCOSE_KEY_LABEL_CRV   (-1)
#define WOLFCOSE_KEY_LABEL_X     (-2)
#define WOLFCOSE_KEY_LABEL_Y     (-3)
#define WOLFCOSE_KEY_LABEL_D     (-4)
#define WOLFCOSE_KEY_LABEL_K     (-1)  /* Symmetric key value */
#define WOLFCOSE_KEY_LABEL_PUB   (-1)  /* RFC 9964: AKP public key */
#define WOLFCOSE_KEY_LABEL_PRIV  (-2)  /* RFC 9964: AKP private key (seed) */
#define WOLFCOSE_KEY_LABEL_RSA_P    (-4)  /* RFC 8230: first prime */
#define WOLFCOSE_KEY_LABEL_RSA_Q    (-5)  /* RFC 8230: second prime */
#define WOLFCOSE_KEY_LABEL_RSA_DP   (-6)  /* RFC 8230: d mod (p-1) */
#define WOLFCOSE_KEY_LABEL_RSA_DQ   (-7)  /* RFC 8230: d mod (q-1) */
#define WOLFCOSE_KEY_LABEL_RSA_QINV (-8)  /* RFC 8230: CRT coefficient */

/* AES-GCM constants */
#define WOLFCOSE_AES_GCM_TAG_SZ  16
#define WOLFCOSE_AES_GCM_NONCE_SZ 12

/* ChaCha20-Poly1305 constants */
#define WOLFCOSE_CHACHA_KEY_SZ    32
#define WOLFCOSE_CHACHA_NONCE_SZ  12
#define WOLFCOSE_CHACHA_TAG_SZ    16

/* ----- Structs ----- */

/**
 * \brief CBOR encoder/decoder context. Zero-copy cursor over a buffer.
 */
typedef struct WOLFCOSE_CBOR_CTX {
    uint8_t*       buf;   /**< Mutable buffer pointer (encode output) */
    const uint8_t* cbuf;  /**< Const buffer pointer (decode input, read-only) */
    size_t         bufSz; /**< Total buffer size */
    size_t         idx;   /**< Current read/write position */
} WOLFCOSE_CBOR_CTX;

/**
 * \brief Decoded CBOR item. For bstr/tstr, data points into the input buffer.
 */
typedef struct WOLFCOSE_CBOR_ITEM {
    uint8_t        majorType;  /**< Major type (0-7) */
    uint64_t       val;        /**< Numeric value or length of bstr/tstr/array/map */
    const uint8_t* data;       /**< Pointer into input buffer (bstr/tstr only) */
    size_t         dataLen;    /**< Length of data (bstr/tstr only) */
} WOLFCOSE_CBOR_ITEM;

/**
 * \brief Parsed COSE headers. Zero-copy pointers into the encoded message.
 */
typedef struct WOLFCOSE_HDR {
    int32_t        alg;           /**< Algorithm (from protected or unprotected) */
    const uint8_t* kid;           /**< Key ID pointer */
    size_t         kidLen;        /**< Key ID length */
    const uint8_t* iv;            /**< IV pointer */
    size_t         ivLen;         /**< IV length */
    const uint8_t* partialIv;     /**< Partial IV pointer */
    size_t         partialIvLen;  /**< Partial IV length */
    int32_t        contentType;   /**< Content type from either header bucket */
    uint8_t        flags;         /**< Header flags (see WOLFCOSE_HDR_FLAG_*) */
} WOLFCOSE_HDR;

/** \brief Flag indicating payload is detached (RFC 9052 Section 2) */
#define WOLFCOSE_HDR_FLAG_DETACHED 0x01u
/** \brief Flag indicating an unprotected content-type label was present */
#define WOLFCOSE_HDR_FLAG_CONTENT_TYPE_UNPROTECTED 0x02u

/**
 * \brief Caller-supplied signature callback (RFC 9052 Section 4.4).
 *
 * Return the signature exactly as it appears in the message; for ECDSA that is
 * fixed-width r||s (RFC 9053 Section 2.1), not DER. wolfCOSE converts nothing
 * but does check the length. See docs/Macros.md.
 *
 * \param cbCtx  Opaque caller context, passed through untouched.
 * \param alg    WOLFCOSE_ALG_* being signed with.
 * \param tbs    To-be-signed bytes (digest, or Sig_structure for EdDSA).
 * \param tbsSz  Length of tbs.
 * \param sig    Output buffer for the signature.
 * \param sigSz  Capacity of sig.
 * \param sigLen Output: bytes written to sig.
 * \return 0 on success, non-zero to fail the operation.
 */
typedef int (*WOLFCOSE_SIGN_CB)(void* cbCtx, int32_t alg,
                                const uint8_t* tbs, size_t tbsSz,
                                uint8_t* sig, size_t sigSz, size_t* sigLen);

/**
 * \brief COSE key structure. Pointers to caller-owned wolfCrypt key structs.
 *
 * Caller allocates and initializes wolfCrypt keys (wc_ecc_init, etc).
 * wolfCOSE never owns key lifecycle -- wc_CoseKey_Free does NOT free the
 * underlying wolfCrypt key. Callers must not share the same underlying
 * ECC key concurrently with ECDH-ES COSE operations in other threads.
 */
typedef struct WOLFCOSE_KEY {
    int32_t        kty;       /**< WOLFCOSE_KTY_* */
    int32_t        alg;       /**< WOLFCOSE_ALG_*, 0 if unset */
    int32_t        crv;       /**< WOLFCOSE_CRV_*, 0 if N/A */
    const uint8_t* kid;       /**< Key ID, zero-copy pointer */
    size_t         kidLen;    /**< Key ID length */
    union {
#ifdef HAVE_ECC
        ecc_key*       ecc;       /**< Caller-owned, init'd via wolfCrypt */
#endif
#ifdef HAVE_ED25519
        ed25519_key*   ed25519;   /**< Caller-owned */
#endif
#ifdef HAVE_ED448
        ed448_key*     ed448;     /**< Caller-owned */
#endif
#ifdef WC_RSA_PSS
        RsaKey*        rsa;       /**< Caller-owned RSA key */
#endif
#ifdef WOLFSSL_HAVE_MLDSA
        wc_MlDsaKey*   mldsa;     /**< ML-DSA (FIPS 204), caller-owned */
#endif
        void*          pqc;       /**< Generic PQC handle for future algos */
        struct {
            const uint8_t* key;    /**< Pointer to caller-owned key material */
            size_t         keyLen; /**< Key material length */
        } symm;
    } key;
#ifdef WOLFSSL_HAVE_MLDSA
    const uint8_t* mldsaSeed;    /**< RFC 9964 ML-DSA private seed (32B), caller-owned */
    size_t         mldsaSeedLen; /**< ML-DSA private seed length */
#endif
    uint8_t hasPrivate;  /**< 1 if wolfCOSE holds private key material.
                          *   Independent of signCb: a delegated key may also
                          *   carry a local key, which wc_CoseKey_Encode then
                          *   declines to serialise. */
    uint8_t attachedType; /**< WOLFCOSE_ATT_*, set by wc_CoseKey_Set*() */
    /* Appended last and present regardless of WOLFCOSE_ENABLE_EXT_SIGN, so
     * that macro alone cannot make a library and an application disagree
     * about sizeof(WOLFCOSE_KEY). Fields above still sit behind wolfSSL
     * feature macros, which must match between the two. */
    WOLFCOSE_SIGN_CB signCb;   /**< NULL: sign locally with wolfCrypt.
                                *   wc_CoseKey_Init() is mandatory: this is
                                *   called if non-NULL, so an uninitialised
                                *   key is an indirect call through stack
                                *   garbage. */
    void*            signCtx;  /**< Opaque, passed to signCb untouched */
} WOLFCOSE_KEY;

/**
 * \brief COSE_recipient structure for multi-recipient messages (RFC 9052 Section 5.1, 6.1).
 *
 * Represents a single recipient in COSE_Encrypt or COSE_Mac messages.
 * Used for key distribution (wrap, ECDH, direct).
 */
typedef struct WOLFCOSE_RECIPIENT {
    int32_t        algId;       /**< Key distribution algorithm; direct mode requires explicit WOLFCOSE_ALG_DIRECT (-6) on both encrypt and MAC create (-3..-31, -6) */
    WOLFCOSE_KEY*  key;         /**< Caller-owned key (KEK for wrap, recipient pubkey for ECDH) */
    const uint8_t* kid;         /**< Key ID for recipient lookup */
    size_t         kidLen;      /**< Key ID length */
} WOLFCOSE_RECIPIENT;

/**
 * \brief COSE_Signature structure for multi-signer messages (RFC 9052 Section 4.1).
 *
 * Represents a single signer in a COSE_Sign message.
 */
typedef struct WOLFCOSE_SIGNATURE {
    int32_t        algId;       /**< Signature algorithm (ES256, EdDSA, etc.) */
    WOLFCOSE_KEY*  key;         /**< Caller-owned signing key */
    const uint8_t* kid;         /**< Key ID for signer identification */
    size_t         kidLen;      /**< Key ID length */
} WOLFCOSE_SIGNATURE;

/** \brief Full RFC 9338 countersigner configuration. */
typedef struct WOLFCOSE_COUNTERSIGNATURE {
    int32_t        algId;  /**< Signature algorithm (ES256, EdDSA, etc.) */
    WOLFCOSE_KEY*  key;    /**< Caller-owned countersigning key */
    const uint8_t* kid;    /**< Optional countersigner key identifier */
    size_t         kidLen; /**< Key identifier length */
} WOLFCOSE_COUNTERSIGNATURE;

/** \brief Abbreviated RFC 9338 countersigner configuration. */
typedef struct WOLFCOSE_COUNTERSIGNATURE0 {
    int32_t       algId; /**< Signature algorithm supplied out of band */
    WOLFCOSE_KEY* key;   /**< Caller-owned countersigning key */
} WOLFCOSE_COUNTERSIGNATURE0;

/* -----
 * CBOR Encode API (RFC 8949)
 *
 * All functions return WOLFCOSE_SUCCESS or a negative error code.
 * Guarded by WOLFCOSE_CBOR_ENCODE — can be excluded for decode-only builds.
 * ----- */

#if defined(WOLFCOSE_CBOR_ENCODE)

/**
 * \brief Initialize a context for encoding into \p buf.
 *
 * WOLFCOSE_CBOR_CTX carries both an encode pointer (buf) and a decode pointer
 * (cbuf); this sets the encode one, clears the decode one, and rewinds idx, so
 * a context can never be half-initialized from the wrong direction.
 *
 * \param ctx    Context to initialize.
 * \param buf    Output buffer.
 * \param bufSz  Output buffer size.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_INVALID_ARG.
 */
static inline int wc_CBOR_EncoderInit(WOLFCOSE_CBOR_CTX* ctx, uint8_t* buf,
                                       size_t bufSz)
{
    int ret = WOLFCOSE_E_INVALID_ARG;

    if ((ctx != NULL) && (buf != NULL)) {
        ctx->buf = buf;
        ctx->cbuf = NULL;
        ctx->bufSz = bufSz;
        ctx->idx = 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}

/**
 * \brief Encode an unsigned integer.
 * \param ctx  Encoder context with output buffer.
 * \param val  Value to encode.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_EncodeUint(WOLFCOSE_CBOR_CTX* ctx, uint64_t val);

/**
 * \brief Encode a signed integer. Dispatches to EncodeUint internally.
 * \param ctx  Encoder context.
 * \param val  Signed value.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_EncodeInt(WOLFCOSE_CBOR_CTX* ctx, int64_t val);

/**
 * \brief Encode a byte string (major type 2).
 * \param ctx   Encoder context.
 * \param data  Byte string data (may be NULL if len is 0).
 * \param len   Length of data.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_EncodeBstr(WOLFCOSE_CBOR_CTX* ctx,
                                     const uint8_t* data, size_t len);

/**
 * \brief Encode a text string (major type 3).
 * \param ctx   Encoder context.
 * \param str   UTF-8 text (not null-terminated requirement).
 * \param len   Length in bytes.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_EncodeTstr(WOLFCOSE_CBOR_CTX* ctx,
                                     const uint8_t* str, size_t len);

/**
 * \brief Encode a definite-length array header.
 * \param ctx    Encoder context.
 * \param count  Number of items that follow.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_EncodeArrayStart(WOLFCOSE_CBOR_CTX* ctx,
                                           size_t count);

/**
 * \brief Encode a definite-length map header.
 * \param ctx    Encoder context.
 * \param count  Number of key-value pairs that follow.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_EncodeMapStart(WOLFCOSE_CBOR_CTX* ctx, size_t count);

/**
 * \brief Encode a CBOR tag (major type 6).
 * \param ctx  Encoder context.
 * \param tag  Tag number.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_EncodeTag(WOLFCOSE_CBOR_CTX* ctx, uint64_t tag);

/** \brief Encode CBOR true (0xF5). */
WOLFCOSE_API int wc_CBOR_EncodeTrue(WOLFCOSE_CBOR_CTX* ctx);

/** \brief Encode CBOR false (0xF4). */
WOLFCOSE_API int wc_CBOR_EncodeFalse(WOLFCOSE_CBOR_CTX* ctx);

/** \brief Encode CBOR null (0xF6). */
WOLFCOSE_API int wc_CBOR_EncodeNull(WOLFCOSE_CBOR_CTX* ctx);

#ifdef WOLFCOSE_FLOAT
/** \brief Encode an IEEE 754 single-precision float. */
WOLFCOSE_API int wc_CBOR_EncodeFloat(WOLFCOSE_CBOR_CTX* ctx, float val);

/** \brief Encode an IEEE 754 double-precision float. */
WOLFCOSE_API int wc_CBOR_EncodeDouble(WOLFCOSE_CBOR_CTX* ctx, double val);
#endif

#endif /* WOLFCOSE_CBOR_ENCODE */

/* -----
 * CBOR Decode API (zero-copy, single-pass)
 *
 * Guarded by WOLFCOSE_CBOR_DECODE — always needed for verify/decrypt builds.
 *
 * Strictness note (RFC 8949 Section 4.2.1): every decode entry point requires
 * preferred, shortest-form argument encoding and rejects indefinite-length
 * items. This is what COSE deterministic encoding and CTAP2 canonical CBOR
 * require, but it is stricter than a general-purpose CBOR parser: input that
 * other decoders accept — 0x1817 for 23, an indefinite-length bstr — is
 * rejected here with WOLFCOSE_E_CBOR_MALFORMED or WOLFCOSE_E_UNSUPPORTED.
 * See docs/Getting-Started.md, "Strict decoding".
 * ----- */

#if defined(WOLFCOSE_CBOR_DECODE)

/**
 * \brief Initialize a context for decoding from \p buf.
 *
 * Sets the const decode pointer, clears the mutable encode pointer, and
 * rewinds idx. The buffer is never written through this context.
 *
 * \param ctx    Context to initialize.
 * \param buf    Input buffer.
 * \param bufSz  Input buffer size.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_INVALID_ARG.
 */
static inline int wc_CBOR_DecoderInit(WOLFCOSE_CBOR_CTX* ctx,
                                       const uint8_t* buf, size_t bufSz)
{
    int ret = WOLFCOSE_E_INVALID_ARG;

    if ((ctx != NULL) && (buf != NULL)) {
        ctx->buf = NULL;
        ctx->cbuf = buf;
        ctx->bufSz = bufSz;
        ctx->idx = 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}

/**
 * \brief Decode a CBOR data item head. Core decoder function.
 *        For bstr/tstr, sets item->data to point into the input buffer.
 *
 * Enforces RFC 8949 Section 4.2.1 preferred serialization: an argument that
 * could have been encoded in fewer bytes is WOLFCOSE_E_CBOR_MALFORMED, and an
 * indefinite-length item (additional information 31) is
 * WOLFCOSE_E_UNSUPPORTED. Deliberately stricter than a general-purpose CBOR
 * parser; see the section note above.
 *
 * \param ctx   Decoder context (advances idx past the decoded item head + data).
 * \param item  Output: decoded item.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeHead(WOLFCOSE_CBOR_CTX* ctx,
                                     WOLFCOSE_CBOR_ITEM* item);

/**
 * \brief Decode an unsigned integer. Type-checks for major type 0.
 * \param ctx  Decoder context.
 * \param val  Output: decoded value.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeUint(WOLFCOSE_CBOR_CTX* ctx, uint64_t* val);

/**
 * \brief Decode a signed integer (major type 0 or 1).
 * \param ctx  Decoder context.
 * \param val  Output: decoded signed value.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeInt(WOLFCOSE_CBOR_CTX* ctx, int64_t* val);

/**
 * \brief Decode a byte string. Zero-copy: *data points into ctx->buf.
 * \param ctx      Decoder context.
 * \param data     Output: pointer into input buffer.
 * \param dataLen  Output: byte string length.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeBstr(WOLFCOSE_CBOR_CTX* ctx,
                                     const uint8_t** data, size_t* dataLen);

/**
 * \brief Decode a text string. Zero-copy: *str points into ctx->buf.
 * \param ctx     Decoder context.
 * \param str     Output: pointer into input buffer.
 * \param strLen  Output: text string length in bytes.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeTstr(WOLFCOSE_CBOR_CTX* ctx,
                                     const uint8_t** str, size_t* strLen);

/**
 * \brief Decode an array header (major type 4).
 * \param ctx    Decoder context.
 * \param count  Output: number of items in the array.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeArrayStart(WOLFCOSE_CBOR_CTX* ctx,
                                           size_t* count);

/**
 * \brief Decode a map header (major type 5).
 * \param ctx    Decoder context.
 * \param count  Output: number of key-value pairs.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeMapStart(WOLFCOSE_CBOR_CTX* ctx,
                                         size_t* count);

/**
 * \brief Decode a tag (major type 6).
 * \param ctx  Decoder context.
 * \param tag  Output: tag value.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeTag(WOLFCOSE_CBOR_CTX* ctx, uint64_t* tag);

/**
 * \brief Skip over a complete CBOR item (including nested arrays/maps).
 *        Uses iterative traversal with bounded stack depth.
 * \param ctx  Decoder context (idx advances past the skipped item).
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_Skip(WOLFCOSE_CBOR_CTX* ctx);

/**
 * \brief Skip a complete CBOR item and capture its raw encoded bytes.
 *
 * As wc_CBOR_Skip(), but also reports where the skipped item started and how
 * long it was, zero-copy into the decoder input. That is what a caller needs
 * to defer or nest a parse: a CTAP2 allowList entry, a COSE_Key embedded in
 * an extension map, the keyAgreement value in authenticatorClientPIN. Feed
 * \p data / \p dataLen to wc_CBOR_DecoderInit() or wc_CoseKey_Decode() later.
 *
 * \param ctx      Decoder context (idx advances past the skipped item).
 * \param data     Output: pointer to the first byte of the skipped item.
 * \param dataLen  Output: encoded length of the skipped item.
 * \return WOLFCOSE_SUCCESS or negative error code. On failure the outputs are
 *         untouched and ctx->idx may have advanced, as with wc_CBOR_Skip().
 */
WOLFCOSE_API int wc_CBOR_SkipItem(WOLFCOSE_CBOR_CTX* ctx,
                                   const uint8_t** data, size_t* dataLen);

/**
 * \brief Decoded CBOR map label: either an integer or a text string.
 *
 * RFC 9052 allows `label = int / tstr`, and real COSE and CTAP2 maps use both
 * spellings for the same field (`3` vs `"alg"`, `1` vs `"type"`, `2` vs
 * `"id"`). Populated by wc_CBOR_DecodeLabel(); compare with
 * wc_CBOR_LabelIsInt() / wc_CBOR_LabelIsText().
 */
typedef struct WOLFCOSE_CBOR_LABEL {
    int64_t        val;      /**< Integer label, valid when isText == 0 */
    const uint8_t* text;     /**< Text label, points into the input buffer */
    size_t         textLen;  /**< Text label length in bytes */
    uint8_t        isText;   /**< 1 if the label was a text string, else 0 */
} WOLFCOSE_CBOR_LABEL;

/**
 * \brief Decode a map label that may be an integer or a text string.
 *
 * Consumes exactly one item. Major types 0 and 1 populate label->val with
 * isText 0; major type 3 populates label->text / label->textLen with isText 1
 * and no copy. Invalid UTF-8 returns WOLFCOSE_E_CBOR_MALFORMED. Anything else
 * is WOLFCOSE_E_CBOR_TYPE with the item consumed.
 *
 * \param ctx    Decoder context.
 * \param label  Output: decoded label.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeLabel(WOLFCOSE_CBOR_CTX* ctx,
                                      WOLFCOSE_CBOR_LABEL* label);

/**
 * \brief Test a decoded label against an integer value.
 * \param label  Label from wc_CBOR_DecodeLabel().
 * \param val    Integer to compare against.
 * \return 1 if the label is that integer, 0 otherwise (including NULL).
 */
WOLFCOSE_API int wc_CBOR_LabelIsInt(const WOLFCOSE_CBOR_LABEL* label,
                                     int64_t val);

/**
 * \brief Test a decoded label against a text value.
 *
 * Compares bytes, not Unicode: no normalization or case folding, matching how
 * CTAP2 and COSE compare text labels.
 *
 * \param label    Label from wc_CBOR_DecodeLabel().
 * \param text     Text to compare against (not NUL-terminated by contract).
 * \param textLen  Length of text in bytes.
 * \return 1 if the label is that text, 0 otherwise (including NULL).
 */
WOLFCOSE_API int wc_CBOR_LabelIsText(const WOLFCOSE_CBOR_LABEL* label,
                                      const uint8_t* text, size_t textLen);

/**
 * \brief Peek at the major type of the next item without consuming it.
 * \param ctx  Decoder context.
 * \return Major type (0-7), or 0xFF if ctx is NULL or the buffer is exhausted.
 */
static inline uint8_t wc_CBOR_PeekType(const WOLFCOSE_CBOR_CTX* ctx)
{
    uint8_t majorType = 0xFFu;
    if ((ctx != NULL) && (ctx->cbuf != NULL) && (ctx->idx < ctx->bufSz)) {
        majorType = (uint8_t)(((uint32_t)ctx->cbuf[ctx->idx]) >> 5u);
    }
    return majorType;
}

#endif /* WOLFCOSE_CBOR_DECODE */

/* ----- COSE Key API ----- */

/**
 * \brief Initialize a WOLFCOSE_KEY structure (zero all fields).
 * \param key  Key structure to initialize.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_INVALID_ARG.
 */
WOLFCOSE_API int wc_CoseKey_Init(WOLFCOSE_KEY* key);

/**
 * \brief Free a WOLFCOSE_KEY. Does NOT free the underlying wolfCrypt key
 *        (caller owns key lifecycle). Zeros the structure.
 * \param key  Key to free.
 */
WOLFCOSE_API void wc_CoseKey_Free(WOLFCOSE_KEY* key);

#ifdef HAVE_ECC
/**
 * \brief Attach an ECC key to a COSE key structure.
 * \param key     COSE key (must be initialized).
 * \param crv     WOLFCOSE_CRV_P256/P384/P521.
 * \param eccKey  Caller-owned, initialized ecc_key.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseKey_SetEcc(WOLFCOSE_KEY* key, int32_t crv,
                                    ecc_key* eccKey);
#endif

#ifdef WOLFCOSE_HAVE_EDDSA
/**
 * \brief Attach an Ed25519 key to a COSE key structure.
 * \param key    COSE key (must be initialized).
 * \param edKey  Caller-owned, initialized ed25519_key.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseKey_SetEd25519(WOLFCOSE_KEY* key,
                                        ed25519_key* edKey);
#endif

#ifdef WOLFCOSE_HAVE_ED448
WOLFCOSE_API int wc_CoseKey_SetEd448(WOLFCOSE_KEY* key, ed448_key* edKey);
#endif

#ifdef WOLFCOSE_HAVE_MLDSA
WOLFCOSE_API int wc_CoseKey_SetMlDsa(WOLFCOSE_KEY* key, int32_t alg,
                                       wc_MlDsaKey* mlDsaKey);
/* RFC 9964 private-key export needs the 32-byte seed, which wolfCrypt does not
 * retain; the caller supplies it here (seed may be NULL for public/sign use). */
WOLFCOSE_API int wc_CoseKey_SetMlDsa_ex(WOLFCOSE_KEY* key, int32_t alg,
                                       wc_MlDsaKey* mlDsaKey,
                                       const uint8_t* seed, size_t seedLen);
#endif

#ifdef WOLFCOSE_HAVE_RSAPSS
WOLFCOSE_API int wc_CoseKey_SetRsa(WOLFCOSE_KEY* key, RsaKey* rsaKey);
#endif

/**
 * \brief Attach a symmetric key to a COSE key structure.
 * \param key      COSE key (must be initialized).
 * \param data     Pointer to caller-owned key material.
 * \param dataLen  Key material length in bytes.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseKey_SetSymmetric(WOLFCOSE_KEY* key,
                                          const uint8_t* data, size_t dataLen);

#if defined(WOLFCOSE_EXT_SIGN)
/**
 * \brief Delegate signing to a caller-supplied callback.
 *
 * Call after any wc_CoseKey_Set*(), which detach the signer. Leaves kty/crv,
 * the key union and hasPrivate alone, but wc_CoseKey_Encode() will not
 * serialise a private key while a signer is attached. Permits a NULL rng.
 *
 * Which kty/crv each algorithm still needs: see docs/Macros.md.
 *
 * \param key    COSE key (must be initialized).
 * \param cb     Signature callback, or NULL to detach.
 * \param cbCtx  Opaque context passed to cb (may be NULL).
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseKey_SetExtSigner(WOLFCOSE_KEY* key,
                                          WOLFCOSE_SIGN_CB cb, void* cbCtx);
#endif

#if defined(WOLFCOSE_KEY_ENCODE)
/**
 * \brief Encode a WOLFCOSE_KEY to CBOR COSE_Key map format.
 *
 * \warning This serialises the PRIVATE key when the key carries one, and says
 *          so nowhere in the output beyond one extra map entry: an ECC key
 *          attached with wc_CoseKey_SetEcc() has key->hasPrivate set whenever
 *          the ecc_key is a keypair, so publishing "the public key" of a live
 *          keypair with this function discloses the private scalar (P-256
 *          ES256: 112 bytes / map(6) instead of 77 bytes / map(5)). The same
 *          holds for RSA, Ed25519/Ed448, ML-DSA (seed) and symmetric keys.
 *          Anything that publishes a public key - WebAuthn/CTAP2 attestation
 *          authData, ECDH key agreement, JWK-style publication - must call
 *          wc_CoseKey_Encode_ex() with WOLFCOSE_KEY_PUBLIC_ONLY instead.
 *
 * Equivalent to wc_CoseKey_Encode_ex() with \p flags of 0.
 *
 * \param key     Key to encode.
 * \param out     Output buffer.
 * \param outSz   Output buffer size.
 * \param outLen  Output: number of bytes written.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseKey_Encode(WOLFCOSE_KEY* key, uint8_t* out,
                                    size_t outSz, size_t* outLen);

/**
 * \brief Encode a WOLFCOSE_KEY to CBOR COSE_Key map format, with options.
 *
 * Identical to wc_CoseKey_Encode() with the addition of \p flags, which is a
 * bitmask of WOLFCOSE_KEY_* values. Passing 0 is equivalent to calling
 * wc_CoseKey_Encode().
 *
 * | Flag | Effect |
 * |------|--------|
 * | WOLFCOSE_KEY_PUBLIC_ONLY | Emit the public half only: no `-4: d` for EC2
 *   or OKP, no `-3: d` / CRT factors for RSA, no `-2: priv` seed for an
 *   RFC 9964 AKP key. A symmetric key has no public half, so the whole key
 *   would be private material and WOLFCOSE_E_COSE_KEY_TYPE is returned. |
 *
 * \param key     Key to encode.
 * \param out     Output buffer.
 * \param outSz   Output buffer size.
 * \param outLen  Output: number of bytes written.
 * \param flags   Bitmask of WOLFCOSE_KEY_* output options.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseKey_Encode_ex(WOLFCOSE_KEY* key, uint8_t* out,
                                       size_t outSz, size_t* outLen,
                                       uint32_t flags);

#ifdef HAVE_ECC
/**
 * \brief Encode an EC2 COSE_Key from raw affine coordinates.
 *
 * For callers that hold only the coordinates (a stored credential record, a
 * peer key received on the wire) and want to re-emit them. No ecc_key is
 * needed, so none of the point import, on-curve check, or key-object stack
 * footprint of wc_ecc_import_unsigned() is paid just to serialise.
 *
 * Nothing here validates that (x, y) is on the curve; the bytes are copied
 * into the map as given. Encoding an unvalidated point is safe, using one is
 * not: import it through wolfCrypt before any ECDH or verify operation.
 *
 * \param crv       WOLFCOSE_CRV_P256/P384/P521.
 * \param x         X coordinate, exactly \p coordLen bytes, big-endian,
 *                  zero-padded (RFC 9053 Section 7.1.1).
 * \param y         Y coordinate, exactly \p coordLen bytes.
 * \param d         Private scalar, exactly \p coordLen bytes, or NULL for a
 *                  public-only key.
 * \param coordLen  Coordinate size; must equal the curve size (32/48/66).
 * \param kid       Key ID for the `2: kid` entry, or NULL to omit it.
 * \param kidLen    Key ID length.
 * \param alg       WOLFCOSE_ALG_* for the `3: alg` entry, or
 *                  WOLFCOSE_ALG_UNSET to omit it.
 * \param out       Output buffer.
 * \param outSz     Output buffer size.
 * \param outLen    Output: number of bytes written.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseKey_EncodeEccRaw(int32_t crv,
                                          const uint8_t* x, const uint8_t* y,
                                          const uint8_t* d, size_t coordLen,
                                          const uint8_t* kid, size_t kidLen,
                                          int32_t alg,
                                          uint8_t* out, size_t outSz,
                                          size_t* outLen);
#endif /* HAVE_ECC */

/**
 * \brief Compute the exact encoded size wc_CoseKey_Encode() would produce.
 *
 * Equivalent to wc_CoseKey_EncodeSize_ex() with \p flags of 0. Note that this
 * therefore sizes a buffer large enough to hold the PRIVATE key; see the
 * warning on wc_CoseKey_Encode().
 *
 * \param key     Key to size.
 * \param outLen  Output: exact encoded size in bytes.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseKey_EncodeSize(const WOLFCOSE_KEY* key,
                                        size_t* outLen);

/**
 * \brief Compute the exact encoded size wc_CoseKey_Encode_ex() would produce.
 *
 * Nothing is written and no key material is exported; only the component
 * lengths of the attached key are read. The result is exact, not an upper
 * bound, so it can be used to size a buffer or to reject an oversized key
 * before committing storage.
 *
 * One configuration limit: in a build with neither HAVE_ECC nor
 * WOLFSSL_EXPORT_INT, reading the RSA public exponent needs a scratch copy of
 * the modulus, so an RSA key whose modulus exceeds WOLFCOSE_MAX_SCRATCH_SZ
 * returns WOLFCOSE_E_CRYPTO here even though wc_CoseKey_Encode_ex() encodes
 * it. Any build with ECC or WOLFSSL_EXPORT_INT enabled is unaffected.
 *
 * \param key     Key to size.
 * \param outLen  Output: exact encoded size in bytes.
 * \param flags   Bitmask of WOLFCOSE_KEY_* output options.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseKey_EncodeSize_ex(const WOLFCOSE_KEY* key,
                                           size_t* outLen, uint32_t flags);
#endif /* WOLFCOSE_KEY_ENCODE */

#if defined(WOLFCOSE_KEY_DECODE)
/**
 * \brief Key metadata read out of a COSE_Key without importing anything.
 *
 * Filled by wc_CoseKey_PeekInfo(). kid points into the caller's input buffer.
 */
typedef struct WOLFCOSE_KEY_INFO {
    int32_t        kty;     /**< WOLFCOSE_KTY_*, always set on success */
    int32_t        alg;     /**< WOLFCOSE_ALG_*, WOLFCOSE_ALG_UNSET if absent */
    int32_t        crv;     /**< WOLFCOSE_CRV_*, 0 if absent or N/A */
    const uint8_t* kid;     /**< Key ID, zero-copy pointer, NULL if absent */
    size_t         kidLen;  /**< Key ID length, 0 if absent */
} WOLFCOSE_KEY_INFO;

/**
 * \brief Read kty/alg/crv/kid from a COSE_Key buffer without importing it.
 *
 * wc_CoseKey_Decode() needs a wolfCrypt key of the matching type attached up
 * front and returns WOLFCOSE_E_COSE_KEY_TYPE otherwise, so a parser that
 * accepts more than one key type would have to guess and retry. This reads
 * the metadata first so the caller can attach the right key object once.
 *
 * Nothing is imported, no key object is needed, and \p in is not modified.
 * The same structural checks wc_CoseKey_Decode() applies are applied here
 * (integer labels only, no duplicate labels, kty required, no trailing
 * bytes), so a buffer that peeks successfully will not be rejected by the
 * decoder for those reasons.
 * Keys containing key_ops are rejected with WOLFCOSE_E_UNSUPPORTED because
 * the fixed-size key wrapper cannot retain arbitrary operation identifiers.
 *
 * \param in    Input CBOR COSE_Key buffer.
 * \param inSz  Input buffer size; must be exactly the encoded length.
 * \param info  Output: decoded metadata.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseKey_PeekInfo(const uint8_t* in, size_t inSz,
                                      WOLFCOSE_KEY_INFO* info);

/**
 * \brief Decode a CBOR COSE_Key map into a WOLFCOSE_KEY structure.
 *        For symmetric keys, pointers reference the input buffer.
 *        For ECC/Ed25519, caller must attach a key struct via
 *        wc_CoseKey_SetEcc()/SetEd25519()/SetEd448()/SetRsa()/SetMlDsa();
 *        assigning key.* directly records no type and imports nothing.
 *        A decoded kty/crv that does not match the attached type returns
 *        WOLFCOSE_E_COSE_KEY_TYPE before any import runs.
 *        Keys containing key_ops return WOLFCOSE_E_UNSUPPORTED before any
 *        key material is imported.
 *        An attached ECC object receiving private EC2 material must be
 *        freshly initialized, with no existing curve or key material.
 *        When wolfCrypt's private importer uses an unsupported math layout
 *        or a non-transactional callback or hardware backend, private EC2
 *        decode returns WOLFCOSE_E_UNSUPPORTED before importing key
 *        material.
 * \param key   Key structure (should be initialized, with wolfCrypt key
 *              attached for asymmetric types).
 * \param in    Input CBOR buffer.
 * \param inSz  Input buffer size.
 * \return WOLFCOSE_SUCCESS or negative error code.
 * \see wc_CoseKey_PeekInfo() to learn the key type before attaching one.
 */
WOLFCOSE_API int wc_CoseKey_Decode(WOLFCOSE_KEY* key, const uint8_t* in,
                                    size_t inSz);
#endif /* WOLFCOSE_KEY_DECODE */

/* ----- COSE_Sign1 API (RFC 9052 Section 4.3) ----- */

/* All message APIs require extAadLen to be zero when extAad is NULL. */

#if defined(WOLFCOSE_SIGN1_SIGN)
/**
 * \brief Sign a payload producing a COSE_Sign1 message (RFC 9052 Section 4.3).
 *
 * \param key             WOLFCOSE_KEY with hasPrivate=1, or an external
 *                        signing callback when enabled. Caller retains
 *                        ownership.
 * \param alg             Algorithm identifier (WOLFCOSE_ALG_ES256, etc).
 * \param kid             Key ID to include in unprotected headers (NULL if none).
 * \param kidLen          Key ID length.
 * \param payload         Payload to sign (NULL if detached).
 * \param payloadLen      Payload length (0 if detached).
 * \param detachedPayload Detached payload for signing (NULL if attached).
 *                        If non-NULL, payload is encoded as CBOR null.
 * \param detachedLen     Detached payload length.
 * \param extAad          External additional authenticated data (NULL if none).
 * \param extAadLen       External AAD length.
 * \param scratch         Working buffer for Sig_structure.
 * \param scratchSz       Scratch buffer size.
 * \param out             Output buffer.
 * \param outSz           Output buffer size.
 * \param outLen          Output: bytes written to out.
 * \param rng             Initialized WC_RNG for local signing; may be NULL
 *                        when an external signing callback is configured.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseSign1_Sign(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng);

/**
 * \brief Sign a payload producing a COSE_Sign1 message, with output options.
 *
 * Identical to wc_CoseSign1_Sign() with the addition of \p flags, which is a
 * bitmask of WOLFCOSE_SIGN1_* values. Passing 0 is equivalent to calling
 * wc_CoseSign1_Sign().
 *
 * \param flags  Bitmask of WOLFCOSE_SIGN1_* output options.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseSign1_Sign_ex(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng, uint32_t flags);

/**
 * \brief Compute the exact encoded size wc_CoseSign1_Sign_ex() would produce.
 *
 * This function does not sign, use an RNG, or invoke an external signer.
 * Only the lengths of the key identifier and payload affect framing.
 *
 * \param key         Key whose type determines the signature length. May be
 *                    NULL when \p alg determines the exact length. Required
 *                    for RSA-PSS and when both Ed25519 and Ed448 are enabled.
 * \param alg         Algorithm identifier (WOLFCOSE_ALG_ES256, etc).
 * \param kidLen      Key ID length (0 if none).
 * \param payloadLen  Attached payload length (0 if detached).
 * \param detachedLen Detached payload length (0 if attached).
 * \param flags       WOLFCOSE_SIGN1_* output options.
 * \param outLen      Output: exact encoded size in bytes.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseSign1_SignSize_ex(const WOLFCOSE_KEY* key,
    int32_t alg, size_t kidLen, size_t payloadLen, size_t detachedLen,
    uint32_t flags, size_t* outLen);
#endif /* WOLFCOSE_SIGN1_SIGN */

#if defined(WOLFCOSE_SIGN1_VERIFY)
/**
 * \brief Verify a COSE_Sign1 message and extract the payload.
 *
 * \param key             WOLFCOSE_KEY with public key. Caller retains ownership.
 * \param in              Input COSE_Sign1 message.
 * \param inSz            Input message size.
 * \param detachedPayload Detached payload for verification (NULL if attached).
 *                        Required if message has nil payload.
 * \param detachedLen     Detached payload length.
 * \param extAad          External additional authenticated data (NULL if none).
 * \param extAadLen       External AAD length.
 * \param scratch         Working buffer for Sig_structure reconstruction.
 * \param scratchSz       Scratch buffer size.
 * \param hdr             Output: parsed COSE headers. flags field indicates detached.
 * \param payload         Output: zero-copy pointer to payload (NULL if detached).
 * \param payloadLen      Output: payload length (0 if detached).
 * \return WOLFCOSE_SUCCESS or negative error code.
 *         WOLFCOSE_E_DETACHED_PAYLOAD if payload is nil and detachedPayload is NULL.
 */
WOLFCOSE_API int wc_CoseSign1_Verify(const WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen);
#endif /* WOLFCOSE_SIGN1_VERIFY */

/* ----- COSE Countersignature API (RFC 9338) ----- */

#if defined(WOLFCOSE_COUNTERSIGN_SIGN)
/**
 * \brief Add a full V2 countersignature to a tagged COSE message.
 *
 * Existing full countersignatures are retained and the new value is appended.
 * \p out may equal \p in for exact in-place growth. Other overlap is rejected.
 * \p scratch must not overlap the input, output, detached payload, external
 * AAD, or key identifier buffers.
 * A detached target payload must be supplied through
 * \p detachedPayload. The counter signature is stored in unprotected header
 * parameter 11 as specified by RFC 9338.
 */
WOLFCOSE_API int wc_Cose_AddCounterSignature(
    const WOLFCOSE_COUNTERSIGNATURE* counterSigner,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng);

/**
 * \brief Add an abbreviated V2 countersignature to a tagged COSE message.
 *
 * The signature is stored in unprotected header parameter 12. The algorithm
 * and key identifier remain application context and are not carried in the
 * message. Only one abbreviated countersignature may be attached to a target.
 * \p scratch must not overlap the input, output, detached payload, or external
 * AAD buffers.
 */
WOLFCOSE_API int wc_Cose_AddCounterSignature0(
    const WOLFCOSE_COUNTERSIGNATURE0* counterSigner,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng);
#endif /* WOLFCOSE_COUNTERSIGN_SIGN */

#if defined(WOLFCOSE_COUNTERSIGN_VERIFY)
/**
 * \brief Verify one full countersignature on a tagged COSE message.
 *
 * \p counterIndex selects a value from V2 header parameter 11 or legacy
 * header parameter 7. Zero selects the sole value when the compact
 * single-value representation is used. Parsed countersigner headers are
 * returned through \p counterHdr. V2 is preferred when both labels exist. An
 * algorithm in the unprotected bucket is accepted only when \p key has the
 * same non-UNSET alg value, providing the external authentication required by
 * RFC 9052. \p scratch must not overlap any input buffer or \p counterHdr.
 */
WOLFCOSE_API int wc_Cose_VerifyCounterSignature(
    const WOLFCOSE_KEY* key, size_t counterIndex,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* counterHdr);

/**
 * \brief Verify an abbreviated countersignature on a tagged COSE message.
 *
 * The verification algorithm is supplied through \p counterSigner because a
 * COSE_Countersignature0 carries only the signature bytes. V2 header
 * parameter 12 and legacy header parameter 9 are accepted, with V2 preferred.
 * \p scratch must not overlap any input buffer.
 */
WOLFCOSE_API int wc_Cose_VerifyCounterSignature0(
    const WOLFCOSE_COUNTERSIGNATURE0* counterSigner,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz);
#endif /* WOLFCOSE_COUNTERSIGN_VERIFY */

/* ----- COSE_Encrypt0 API (RFC 9052 Section 5.3) ----- */

#if defined(WOLFCOSE_ENCRYPT0_ENCRYPT)
/**
 * \brief Encrypt a payload producing a COSE_Encrypt0 message.
 *
 * \param key             WOLFCOSE_KEY with symmetric key material.
 * \param alg             Algorithm (WOLFCOSE_ALG_A128GCM/A192GCM/A256GCM).
 * \param iv              Initialization vector (12 bytes for AES-GCM).
 * \param ivLen           IV length.
 * \param payload         Plaintext payload (NULL if detached).
 * \param payloadLen      Payload length (0 if detached).
 * \param detachedPayload Detached ciphertext destination (NULL if attached).
 *                        If non-NULL, ciphertext is stored here, message has nil.
 * \param detachedSz      Detached buffer size.
 * \param detachedLen     Output: detached ciphertext length.
 * \param extAad          External additional authenticated data (NULL if none).
 * \param extAadLen       External AAD length.
 * \param scratch         Working buffer for Enc_structure.
 * \param scratchSz       Scratch buffer size.
 * \param out             Output buffer.
 * \param outSz           Output buffer size.
 * \param outLen          Output: bytes written to out.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseEncrypt0_Encrypt(const WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* iv, size_t ivLen,
    const uint8_t* payload, size_t payloadLen,
    uint8_t* detachedPayload, size_t detachedSz, size_t* detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen);
#endif /* WOLFCOSE_ENCRYPT0_ENCRYPT */

#if defined(WOLFCOSE_ENCRYPT0_DECRYPT)
/**
 * \brief Decrypt a COSE_Encrypt0 message.
 *
 * \param key             WOLFCOSE_KEY with symmetric key material.
 * \param in              Input COSE_Encrypt0 message.
 * \param inSz            Input size.
 * \param detachedCt      Detached ciphertext (NULL if attached).
 *                        Required if message has nil ciphertext.
 * \param detachedCtLen   Detached ciphertext length.
 * \param extAad          External additional authenticated data (NULL if none).
 * \param extAadLen       External AAD length.
 * \param scratch         Working buffer for Enc_structure reconstruction.
 * \param scratchSz       Scratch buffer size.
 * \param hdr             Output: parsed COSE headers.
 * \param plaintext       Output buffer for decrypted payload.
 * \param plaintextSz     Plaintext buffer size.
 * \param plaintextLen    Output: decrypted payload length.
 * \return WOLFCOSE_SUCCESS or negative error code.
 *         WOLFCOSE_E_DETACHED_PAYLOAD if ciphertext is nil and detachedCt is NULL.
 */
WOLFCOSE_API int wc_CoseEncrypt0_Decrypt(const WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedCt, size_t detachedCtLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    uint8_t* plaintext, size_t plaintextSz, size_t* plaintextLen);
#endif /* WOLFCOSE_ENCRYPT0_DECRYPT */

/* ----- COSE_Mac0 API (RFC 9052 Section 6.2) ----- */

#if defined(WOLFCOSE_MAC0_CREATE) && (defined(WOLFCOSE_HAVE_HMAC) || defined(WOLFCOSE_HAVE_AESMAC))
/**
 * \brief Create a COSE_Mac0 message (RFC 9052 Section 6.2).
 *
 * \param key             WOLFCOSE_KEY with symmetric key for HMAC.
 * \param alg             Algorithm (WOLFCOSE_ALG_HMAC_256_256).
 * \param kid             Key identifier for unprotected header (NULL if none).
 * \param kidLen          Key identifier length.
 * \param payload         Inline payload to authenticate (NULL only when a
 *                        detached payload is supplied). An omitted payload
 *                        (payload and detachedPayload both NULL) is rejected;
 *                        authenticate an empty payload with a non-NULL
 *                        zero-length buffer.
 * \param payloadLen      Payload length (0 for an empty inline payload).
 * \param detachedPayload Detached payload for MAC (NULL if attached). Must be
 *                        NULL when payload is non-NULL. If non-NULL, payload
 *                        is encoded as CBOR null.
 * \param detachedLen     Detached payload length.
 * \param extAad          External additional authenticated data (NULL if none).
 * \param extAadLen       External AAD length.
 * \param scratch         Working buffer for MAC_structure.
 * \param scratchSz       Scratch buffer size.
 * \param out             Output buffer.
 * \param outSz           Output buffer size.
 * \param outLen          Output: bytes written to out.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseMac0_Create(const WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen);
#endif /* WOLFCOSE_MAC0_CREATE && (WOLFCOSE_HAVE_HMAC || WOLFCOSE_HAVE_AESMAC) */

#if defined(WOLFCOSE_MAC0_VERIFY) && (defined(WOLFCOSE_HAVE_HMAC) || defined(WOLFCOSE_HAVE_AESMAC))
/**
 * \brief Verify a COSE_Mac0 message and extract the payload.
 *
 * \param key             WOLFCOSE_KEY with symmetric key for HMAC.
 * \param in              Input COSE_Mac0 message.
 * \param inSz            Input message size.
 * \param detachedPayload Detached payload for verification (NULL if attached).
 *                        Required if message has nil payload.
 * \param detachedLen     Detached payload length.
 * \param extAad          External additional authenticated data (NULL if none).
 * \param extAadLen       External AAD length.
 * \param scratch         Working buffer for MAC_structure reconstruction.
 * \param scratchSz       Scratch buffer size.
 * \param hdr             Output: parsed COSE headers. flags field indicates detached.
 * \param payload         Output: zero-copy pointer to payload (NULL if detached).
 * \param payloadLen      Output: payload length (0 if detached).
 * \return WOLFCOSE_SUCCESS or negative error code.
 *         WOLFCOSE_E_DETACHED_PAYLOAD if payload is nil and detachedPayload is NULL.
 */
WOLFCOSE_API int wc_CoseMac0_Verify(const WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen);
#endif /* WOLFCOSE_MAC0_VERIFY && WOLFCOSE_HAVE_HMAC */

/* ----- COSE_Sign Multi-Signer API (RFC 9052 Section 4.1) ----- */

#if defined(WOLFCOSE_SIGN_SIGN)
/**
 * \brief Create a COSE_Sign message with multiple signers (RFC 9052 Section 4.1).
 *
 * Creates a COSE_Sign structure:
 *   COSE_Sign = [Headers, payload, signatures : [+ COSE_Signature]]
 *
 * Each COSE_Signature contains signer-specific protected headers (alg)
 * and the signature computed over:
 *   Sig_structure = ["Signature", body_protected, sign_protected, ext_aad, payload]
 *
 * \param signers         Array of WOLFCOSE_SIGNATURE with keys and algorithms.
 * \param signerCount     Number of signers (must be >= 1).
 * \param payload         Payload to sign (NULL if detached).
 * \param payloadLen      Payload length (0 if detached).
 * \param detachedPayload Detached payload for signing (NULL if attached).
 *                        If non-NULL, payload is encoded as CBOR null.
 * \param detachedLen     Detached payload length.
 * \param extAad          External additional authenticated data (NULL if none).
 * \param extAadLen       External AAD length.
 * \param scratch         Working buffer for Sig_structure.
 * \param scratchSz       Scratch buffer size.
 * \param out             Output buffer.
 * \param outSz           Output buffer size.
 * \param outLen          Output: bytes written to out.
 * \param rng             Initialized WC_RNG.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseSign_Sign(const WOLFCOSE_SIGNATURE* signers,
    size_t signerCount,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng);
#endif /* WOLFCOSE_SIGN_SIGN */

#if defined(WOLFCOSE_SIGN_VERIFY)
/**
 * \brief Verify one signature in a COSE_Sign message.
 *
 * Verifies the signature at signerIndex against the provided verifyKey.
 * The caller must match the key to the signer (via kid or out-of-band).
 *
 * \param verifyKey       WOLFCOSE_KEY with public key. Caller retains ownership.
 * \param signerIndex     0-based index of signer to verify.
 * \param in              Input COSE_Sign message.
 * \param inSz            Input message size.
 * \param detachedPayload Detached payload for verification (NULL if attached).
 *                        Required if message has nil payload.
 * \param detachedLen     Detached payload length.
 * \param extAad          External additional authenticated data (NULL if none).
 * \param extAadLen       External AAD length.
 * \param scratch         Working buffer for Sig_structure reconstruction.
 * \param scratchSz       Scratch buffer size.
 * \param hdr             Output: parsed COSE headers (body level).
 * \param payload         Output: zero-copy pointer to payload (NULL if detached).
 * \param payloadLen      Output: payload length (0 if detached).
 * \return WOLFCOSE_SUCCESS or negative error code.
 *         WOLFCOSE_E_DETACHED_PAYLOAD if payload is nil and detachedPayload is NULL.
 */
WOLFCOSE_API int wc_CoseSign_Verify(const WOLFCOSE_KEY* verifyKey,
    size_t signerIndex,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen);
#endif /* WOLFCOSE_SIGN_VERIFY */

/* ----- COSE_Encrypt Multi-Recipient API (RFC 9052 Section 5.1) ----- */

#if defined(WOLFCOSE_ENCRYPT_ENCRYPT)
/**
 * \brief Create a COSE_Encrypt message with recipients (RFC 9052 Section 5.1).
 *
 * Creates a COSE_Encrypt structure:
 *   COSE_Encrypt = [Headers, ciphertext, recipients : [+ COSE_recipient]]
 *
 * Depending on build configuration, recipient key management supports direct,
 * AES Key Wrap, and ECDH-ES direct key agreement. Direct mode uses a
 * pre-shared content encryption key (CEK). AES Key Wrap generates one CEK and
 * wraps it separately for each recipient. ECDH-ES derives the CEK for one
 * recipient and puts the ephemeral public key in the unprotected header.
 *
 * \param recipients       Array of WOLFCOSE_RECIPIENT with keys.
 * \param recipientCount   Number of recipients (must be >= 1).
 * \param contentAlgId     Content encryption algorithm (A128GCM, etc).
 * \param iv               Initialization vector.
 * \param ivLen            IV length.
 * \param payload          Payload to encrypt (inline).
 * \param payloadLen       Payload length.
 * \param detachedPayload  Not supported for multi-recipient COSE_Encrypt;
 *                         must be NULL. A non-NULL value returns
 *                         WOLFCOSE_E_UNSUPPORTED. See wolfSSL/wolfCOSE
 *                         issue tracker for detached-create support.
 * \param detachedLen      Must be 0.
 * \param extAad           External additional authenticated data (NULL if none).
 * \param extAadLen        External AAD length.
 * \param scratch          Working buffer for Enc_structure.
 * \param scratchSz        Scratch buffer size.
 * \param out              Output buffer.
 * \param outSz            Output buffer size.
 * \param outLen           Output: bytes written to out.
 * \param rng              Initialized WC_RNG for AES Key Wrap or ECDH-ES;
 *                         may be NULL for direct mode.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseEncrypt_Encrypt(const WOLFCOSE_RECIPIENT* recipients,
    size_t recipientCount,
    int32_t contentAlgId,
    const uint8_t* iv, size_t ivLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng);
#endif /* WOLFCOSE_ENCRYPT_ENCRYPT */

#if defined(WOLFCOSE_ENCRYPT_DECRYPT)
/**
 * \brief Decrypt a COSE_Encrypt message.
 *
 * Decrypts using the key from the specified recipient entry.
 * Every on-wire recipient must declare its key-management algorithm, all
 * top-level sibling recipients must use an RFC-compatible key-distribution
 * mode, and a direct recipient's ciphertext item must be an empty bstr or
 * null. Selecting a recipient that contains nested recipients is unsupported.
 * An unprotected body algorithm is accepted only when recipient->key->alg
 * pins the same value.
 *
 * \param recipient        WOLFCOSE_RECIPIENT with decryption key.
 * \param recipientIndex   0-based index of recipient to use.
 * \param in               Input COSE_Encrypt message.
 * \param inSz             Input message size.
 * \param detachedCt       Detached ciphertext (NULL if attached).
 * \param detachedCtLen    Detached ciphertext length.
 * \param extAad           External additional authenticated data (NULL if none).
 * \param extAadLen        External AAD length.
 * \param scratch          Working buffer for Enc_structure reconstruction.
 * \param scratchSz        Scratch buffer size.
 * \param hdr              Output: parsed COSE headers.
 * \param plaintext        Output buffer for decrypted payload.
 * \param plaintextSz      Plaintext buffer size.
 * \param plaintextLen     Output: decrypted payload length.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseEncrypt_Decrypt(const WOLFCOSE_RECIPIENT* recipient,
    size_t recipientIndex,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedCt, size_t detachedCtLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    uint8_t* plaintext, size_t plaintextSz, size_t* plaintextLen);
#endif /* WOLFCOSE_ENCRYPT_DECRYPT */

/* ----- COSE_Mac Multi-Recipient API (RFC 9052 Section 6.1) ----- */

#if defined(WOLFCOSE_MAC_CREATE)
/**
 * \brief Create a COSE_Mac message with recipients (RFC 9052 Section 6.1).
 *
 * Creates a COSE_Mac structure:
 *   COSE_Mac = [Headers, payload, tag, recipients : [+ COSE_recipient]]
 *
 * For direct key mode: the MAC key is pre-shared among all recipients.
 *
 * \param recipients       Array of WOLFCOSE_RECIPIENT with keys.
 * \param recipientCount   Number of recipients (must be >= 1).
 * \param macAlgId         MAC algorithm (HMAC-256/256, etc).
 * \param payload          Inline payload (NULL only when detachedPayload is
 *                         supplied; payload and detachedPayload must not both
 *                         be NULL, nor both be non-NULL).
 * \param payloadLen       Payload length (0 for an empty inline payload).
 * \param detachedPayload  Detached payload for MAC (NULL if attached). Must be
 *                         NULL when payload is non-NULL.
 * \param detachedLen      Detached payload length.
 * \param extAad           External additional authenticated data (NULL if none).
 * \param extAadLen        External AAD length.
 * \param scratch          Working buffer for MAC_structure.
 * \param scratchSz        Scratch buffer size.
 * \param out              Output buffer.
 * \param outSz            Output buffer size.
 * \param outLen           Output: bytes written to out.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseMac_Create(const WOLFCOSE_RECIPIENT* recipients,
    size_t recipientCount,
    int32_t macAlgId,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen);
#endif /* WOLFCOSE_MAC_CREATE */

#if defined(WOLFCOSE_MAC_VERIFY)
/**
 * \brief Verify a COSE_Mac message.
 *
 * Verifies using the key from the specified recipient entry.
 * Every on-wire recipient must declare a direct key-distribution algorithm,
 * all top-level sibling recipients must use direct mode, and the recipient
 * ciphertext item must be an empty bstr or null. Selecting a recipient that
 * contains nested recipients is unsupported. An unprotected body algorithm is
 * accepted only when recipient->key->alg pins the same value.
 *
 * \param recipient        WOLFCOSE_RECIPIENT with MAC key.
 * \param recipientIndex   0-based index of recipient to use.
 * \param in               Input COSE_Mac message.
 * \param inSz             Input message size.
 * \param detachedPayload  Detached payload for verification (NULL if attached).
 * \param detachedLen      Detached payload length.
 * \param extAad           External additional authenticated data (NULL if none).
 * \param extAadLen        External AAD length.
 * \param scratch          Working buffer for MAC_structure reconstruction.
 * \param scratchSz        Scratch buffer size.
 * \param hdr              Output: parsed COSE headers.
 * \param payload          Output: zero-copy pointer to payload (NULL if detached).
 * \param payloadLen       Output: payload length (0 if detached).
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseMac_Verify(const WOLFCOSE_RECIPIENT* recipient,
    size_t recipientIndex,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen);
#endif /* WOLFCOSE_MAC_VERIFY */

#ifdef __cplusplus
}
#endif

#endif /* WOLFCOSE_H */
