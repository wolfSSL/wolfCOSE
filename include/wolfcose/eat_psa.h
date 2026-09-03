/* eat_psa.h
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

#ifndef WOLFCOSE_EAT_PSA_H
#define WOLFCOSE_EAT_PSA_H

#include <wolfcose/wolfcose.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WOLFCOSE_EAT_PSA

#define WOLFCOSE_EAT_PSA_PROFILE_TFM \
    "tag:psacertified.org,2023:psa\x23" "tfm"
#define WOLFCOSE_EAT_PSA_PROFILE_LEGACY "PSA_IOT_PROFILE_1"

/* PSA/EAT-specific errors are intentionally absent from the base API when
 * this optional feature is not enabled. */
#define WOLFCOSE_E_EAT_PSA_CLAIM    (-9030)
#define WOLFCOSE_E_EAT_PSA_PROFILE  (-9031)
#define WOLFCOSE_E_EAT_PSA_NONCE    (-9032)
#define WOLFCOSE_E_EAT_PSA_KEY      (-9033)

/* settings.h derives WOLFCOSE_EAT_PSA_TFM_FULL only when the complete RFC
 * 9783 Section 5.2 #tfm receiver algorithm and envelope set is enabled. It
 * is a receiver-conformance gate; an attester may issue #tfm using one enabled
 * RFC 9783 Sign1 or Mac0 protection algorithm. */

typedef enum WOLFCOSE_EAT_PSA_PROFILE {
    WOLFCOSE_EAT_PSA_PROFILE_NONE = 0, /**< No authenticated profile. */
    WOLFCOSE_EAT_PSA_PROFILE_CURRENT = 1, /**< RFC 9783 TF-M profile. */
    WOLFCOSE_EAT_PSA_PROFILE_OLD = 2 /**< PSA_IOT_PROFILE_1 compatibility. */
} WOLFCOSE_EAT_PSA_PROFILE;

typedef enum WOLFCOSE_EAT_PSA_PROTECTION {
    WOLFCOSE_EAT_PSA_PROTECTION_NONE = 0, /**< No authenticated envelope. */
    WOLFCOSE_EAT_PSA_PROTECTION_SIGN1 = 1, /**< COSE_Sign1 envelope. */
    WOLFCOSE_EAT_PSA_PROTECTION_MAC0 = 2 /**< COSE_Mac0 envelope. */
} WOLFCOSE_EAT_PSA_PROTECTION;

typedef struct WOLFCOSE_EAT_PSA_SPAN {
    const uint8_t* data; /**< Borrowed byte or text-string data. */
    size_t         len;  /**< Data length in bytes. */
} WOLFCOSE_EAT_PSA_SPAN;

typedef struct WOLFCOSE_EAT_PSA_COMPONENT {
    WOLFCOSE_EAT_PSA_SPAN measurementType; /**< Optional text type. */
    WOLFCOSE_EAT_PSA_SPAN measurementValue; /**< Required 32, 48, or 64-byte hash. */
    WOLFCOSE_EAT_PSA_SPAN version; /**< Optional text version. */
    WOLFCOSE_EAT_PSA_SPAN signerId; /**< Required 32, 48, or 64-byte hash. */
    WOLFCOSE_EAT_PSA_SPAN measurementDesc; /**< Optional text description. */
} WOLFCOSE_EAT_PSA_COMPONENT;

typedef struct WOLFCOSE_EAT_PSA_CLAIMS {
    WOLFCOSE_EAT_PSA_SPAN nonce; /**< Required 32, 48, or 64-byte challenge. */
    WOLFCOSE_EAT_PSA_SPAN ueid; /**< Required 33-byte UEID starting with 0x01. */
    WOLFCOSE_EAT_PSA_SPAN implementationId; /**< Required 32-byte implementation ID. */
    WOLFCOSE_EAT_PSA_SPAN bootSeed; /**< Optional current-profile 8 to 32-byte seed. */
    /** Optional 13-digit EAN-13, dash, and five-digit version. */
    WOLFCOSE_EAT_PSA_SPAN certificationReference;
    WOLFCOSE_EAT_PSA_SPAN verificationServiceIndicator; /**< Optional text VSI. */
    int32_t clientId; /**< Required nonzero signed PSA client ID. */
    uint16_t lifecycle; /**< Required lifecycle; 0x00xx is structurally valid unknown state. */
    const WOLFCOSE_EAT_PSA_COMPONENT* components; /**< Required component array. */
    size_t componentCount; /**< Component count from 1 through configured maximum. */
} WOLFCOSE_EAT_PSA_CLAIMS;

typedef struct WOLFCOSE_EAT_PSA_TOKEN {
    WOLFCOSE_EAT_PSA_PROFILE profile; /**< Authenticated current or legacy profile. */
    WOLFCOSE_EAT_PSA_PROTECTION protection; /**< Authenticated Sign1 or Mac0 type. */
    WOLFCOSE_EAT_PSA_SPAN nonce; /**< Authenticated challenge. */
    WOLFCOSE_EAT_PSA_SPAN ueid; /**< Authenticated UEID. */
    WOLFCOSE_EAT_PSA_SPAN implementationId; /**< Authenticated implementation ID. */
    WOLFCOSE_EAT_PSA_SPAN bootSeed; /**< Optional authenticated boot seed. */
    /** Optional EAN-13 and five-digit certification reference. */
    WOLFCOSE_EAT_PSA_SPAN certificationReference;
    WOLFCOSE_EAT_PSA_SPAN verificationServiceIndicator; /**< Optional VSI. */
    int32_t clientId; /**< Authenticated nonzero PSA client ID. */
    uint16_t lifecycle; /**< Authenticated lifecycle; appraise 0x00xx by policy. */
    WOLFCOSE_EAT_PSA_SPAN components; /**< Borrowed encoded authenticated CBOR component array. */
    size_t componentCount; /**< Authenticated component count. */
    uint8_t noSoftwareMeasurements; /**< Legacy no-measurements assertion. */
} WOLFCOSE_EAT_PSA_TOKEN;

#if defined(WOLFCOSE_EAT_PSA_UEID_RESOLVER)
/**
 * \brief Resolve a candidate key from untrusted routing claims before verification.
 *
 * The callback must not grant authorization from these untrusted values. It
 * initializes or populates \p key for a candidate IAK; wolfCOSE authenticates
 * the original token only after this callback returns success.
 *
 * \param ctx Opaque application context supplied to VerifyByUeid().
 * \param profile Untrusted selected current or legacy profile indication.
 * \param ueid Untrusted UEID bytes borrowed from the input token.
 * \param ueidLen Length of \p ueid.
 * \param alg Untrusted protected COSE algorithm indication.
 * \param key Output caller-owned key description to use for verification.
 * \return WOLFCOSE_SUCCESS to continue, or an application error returned
 *         unchanged by VerifyByUeid().
 */
typedef int (*WOLFCOSE_EAT_PSA_KEY_RESOLVER)(void* ctx,
    WOLFCOSE_EAT_PSA_PROFILE profile,
    const uint8_t* ueid, size_t ueidLen, int32_t alg,
    WOLFCOSE_KEY* key);
#endif

#if defined(WOLFCOSE_EAT_PSA_COMPONENT_ITERATOR)
/**
 * \brief Consume one decoded component from an authenticated token.
 *
 * \param ctx Opaque application context supplied to ForEachComponent().
 * \param component Decoded component structure valid only during this
 *                  callback. Its span data borrows from the authenticated
 *                  input token and remains valid while that token is retained
 *                  unchanged.
 * \return WOLFCOSE_SUCCESS to continue. A nonzero application error stops
 *         traversal and is returned unchanged by the iterator.
 */
typedef int (*WOLFCOSE_EAT_PSA_COMPONENT_CB)(void* ctx,
    const WOLFCOSE_EAT_PSA_COMPONENT* component);
#endif

/**
 * \brief Encode current RFC 9783 PSA claims as a CBOR map.
 *
 * All input spans borrow caller-owned storage for the duration of this call.
 * Optional spans are absent when data is NULL and len is zero. This API emits
 * only the current RFC 9783 profile and never emits legacy claims.
 * The output range must not overlap the claims structure, component array, or
 * any nonempty claim/component span. Exact or partial overlap returns
 * WOLFCOSE_E_INVALID_ARG before CBOR encoding starts.
 *
 * \param claims Current-profile claims to validate and encode.
 * \param out Caller-owned CBOR output buffer.
 * \param outSz Capacity of \p out in bytes.
 * \param outLen Output encoded length. It is zero on every failure.
 * An attester needs one enabled RFC 9783 Sign1 or Mac0 creation path to make
 * a protected token. WOLFCOSE_EAT_PSA_TFM_FULL applies only to verification
 * of the complete standardized receiver profile.
 *
 * \return WOLFCOSE_SUCCESS, WOLFCOSE_E_EAT_PSA_CLAIM,
 *         WOLFCOSE_E_CBOR_MALFORMED for invalid UTF-8,
 *         WOLFCOSE_E_BUFFER_TOO_SMALL, or WOLFCOSE_E_INVALID_ARG.
 */
#if defined(WOLFCOSE_EAT_PSA_ISSUE)
WOLFCOSE_API int wc_CoseEatPsaToken_EncodeClaims(
    const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    uint8_t* out, size_t outSz, size_t* outLen);
#endif

#if defined(WOLFCOSE_EAT_PSA_SIGN1_ISSUE)
/**
 * \brief Encode current claims and create an attached COSE_Sign1 PSA token.
 *
 * The \p claimsBuf, \p scratch, and \p out buffer ranges must be pairwise
 * disjoint. The claims structure, component array, and all nonempty input spans
 * must also be disjoint from \p claimsBuf. Exact or partial overlap returns
 * WOLFCOSE_E_INVALID_ARG before claims are encoded.
 *
 * \param key Signing key or an external signing callback key.
 * \param alg Enabled RFC 9783 ES256, ES384, or ES512 algorithm.
 * \param claims Current-profile claims to validate and encode.
 * \param claimsBuf Temporary caller-owned claims buffer.
 * \param claimsBufSz Capacity of \p claimsBuf in bytes.
 * \param scratch Caller-owned COSE signing workspace.
 * \param scratchSz Capacity of \p scratch in bytes.
 * \param out Caller-owned token output buffer.
 * \param outSz Capacity of \p out in bytes.
 * \param outLen Output token length, zeroed on every failure.
 * \param rng RNG for a local private key. It may be NULL for an external
 *            signer that owns its randomness.
 * \return WOLFCOSE_SUCCESS or a validation, COSE, cryptographic, buffer,
 *         argument, or unsupported-algorithm error. \p out is cleared and
 *         \p outLen is zero on failure.
 */
WOLFCOSE_API int wc_CoseEatPsaToken_CreateSign1(WOLFCOSE_KEY* key, int32_t alg,
    const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    uint8_t* claimsBuf, size_t claimsBufSz,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng);
#endif

#if defined(WOLFCOSE_EAT_PSA_MAC0_ISSUE)
/**
 * \brief Encode current claims and create an attached COSE_Mac0 PSA token.
 *
 * The \p claimsBuf, \p scratch, and \p out buffer ranges must be pairwise
 * disjoint. The claims structure, component array, and all nonempty input spans
 * must also be disjoint from \p claimsBuf. Exact or partial overlap returns
 * WOLFCOSE_E_INVALID_ARG before claims are encoded.
 *
 * \param key Symmetric MAC key.
 * \param alg Enabled RFC 9783 HMAC 256, 384, or 512 algorithm.
 * \param claims Current-profile claims to validate and encode.
 * \param claimsBuf Temporary caller-owned claims buffer.
 * \param claimsBufSz Capacity of \p claimsBuf in bytes.
 * \param scratch Caller-owned COSE MAC workspace.
 * \param scratchSz Capacity of \p scratch in bytes.
 * \param out Caller-owned token output buffer.
 * \param outSz Capacity of \p out in bytes.
 * \param outLen Output token length, zeroed on every failure.
 * \return WOLFCOSE_SUCCESS or a validation, COSE, buffer, argument, or
 *         unsupported-algorithm error. \p out is cleared and \p outLen is
 *         zero on failure.
 */
WOLFCOSE_API int wc_CoseEatPsaToken_CreateMac0(const WOLFCOSE_KEY* key,
    int32_t alg, const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    uint8_t* claimsBuf, size_t claimsBufSz,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen);
#endif

/**
 * \brief Verify a current or legacy PSA token with a caller-owned key.
 *
 * The expected nonce is mandatory. The output borrows from the verified token
 * buffer and remains valid while that buffer remains unchanged. The standard
 * RFC 9783 #tfm profile is accepted only when settings.h derives
 * WOLFCOSE_EAT_PSA_TFM_FULL; otherwise it returns WOLFCOSE_E_EAT_PSA_PROFILE.
 * Legacy profile support is consume-only. The result is a verified token, not
 * an authorization or appraisal decision.
 *
 * \param key Caller-owned verification or MAC key.
 * \param in Tagged, attached COSE_Sign1 or COSE_Mac0 token bytes.
 * \param inSz Length of \p in in bytes.
 * \param expectedNonce Required challenge of 32, 48, or 64 bytes.
 * \param expectedNonceLen Length of \p expectedNonce.
 * \param scratch Caller-owned COSE verification workspace.
 * \param scratchSz Capacity of \p scratch in bytes.
 * \param token Output token. It is fully zeroed on every failure.
 * \return WOLFCOSE_SUCCESS, a COSE verification error,
 *         WOLFCOSE_E_EAT_PSA_CLAIM, WOLFCOSE_E_EAT_PSA_PROFILE,
 *         WOLFCOSE_E_EAT_PSA_NONCE, or WOLFCOSE_E_INVALID_ARG.
 */
#if defined(WOLFCOSE_EAT_PSA_VERIFY)
WOLFCOSE_API int wc_CoseEatPsaToken_Verify(const WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* expectedNonce, size_t expectedNonceLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_EAT_PSA_TOKEN* token);
#endif

/**
 * \brief Verify a PSA token after resolving its key using the untrusted UEID.
 *
 * The resolver receives routing data before cryptographic verification. It
 * must select a candidate key only; policy and authorization decisions belong
 * after this function succeeds.
 *
 * \param resolver Callback that supplies a caller-owned key description.
 * \param resolverCtx Opaque callback context, which may be NULL.
 * \param in Tagged, attached COSE_Sign1 or COSE_Mac0 token bytes.
 * \param inSz Length of \p in in bytes.
 * \param expectedNonce Required challenge of 32, 48, or 64 bytes.
 * \param expectedNonceLen Length of \p expectedNonce.
 * \param scratch Caller-owned COSE verification workspace.
 * \param scratchSz Capacity of \p scratch in bytes.
 * \param token Output token. It is fully zeroed on every failure.
 * \return WOLFCOSE_SUCCESS or the resolver, COSE, claim, profile, nonce, or
 *         argument error. Resolver errors are returned unchanged.
 */
#if defined(WOLFCOSE_EAT_PSA_UEID_RESOLVER)
WOLFCOSE_API int wc_CoseEatPsaToken_VerifyByUeid(
    WOLFCOSE_EAT_PSA_KEY_RESOLVER resolver, void* resolverCtx,
    const uint8_t* in, size_t inSz,
    const uint8_t* expectedNonce, size_t expectedNonceLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_EAT_PSA_TOKEN* token);
#endif

/**
 * \brief Traverse software components in a verified PSA token.
 *
 * \param token Successfully verified token whose backing input remains valid.
 * \param cb Component callback. A nonzero return stops iteration.
 * \param cbCtx Opaque callback context, which may be NULL.
 * \return WOLFCOSE_SUCCESS, WOLFCOSE_E_EAT_PSA_CLAIM,
 *         WOLFCOSE_E_INVALID_ARG, or the callback's nonzero return value.
 */
#if defined(WOLFCOSE_EAT_PSA_COMPONENT_ITERATOR)
WOLFCOSE_API int wc_CoseEatPsaToken_ForEachComponent(
    const WOLFCOSE_EAT_PSA_TOKEN* token,
    WOLFCOSE_EAT_PSA_COMPONENT_CB cb, void* cbCtx);
#endif

/* Source aliases retain compatibility with the pre-release PSA/EAT branch.
 * The wc_CoseEatPsaToken_* names are the exported public API. */
#if defined(WOLFCOSE_EAT_PSA_ISSUE)
    #define wc_EatPsaToken_EncodeClaims wc_CoseEatPsaToken_EncodeClaims
#endif
#if defined(WOLFCOSE_EAT_PSA_SIGN1_ISSUE)
    #define wc_EatPsaToken_CreateSign1 wc_CoseEatPsaToken_CreateSign1
#endif
#if defined(WOLFCOSE_EAT_PSA_MAC0_ISSUE)
    #define wc_EatPsaToken_CreateMac0 wc_CoseEatPsaToken_CreateMac0
#endif
#if defined(WOLFCOSE_EAT_PSA_VERIFY)
    #define wc_EatPsaToken_Verify wc_CoseEatPsaToken_Verify
#endif
#if defined(WOLFCOSE_EAT_PSA_UEID_RESOLVER)
    #define wc_EatPsaToken_VerifyByUeid wc_CoseEatPsaToken_VerifyByUeid
#endif
#if defined(WOLFCOSE_EAT_PSA_COMPONENT_ITERATOR)
    #define wc_EatPsaToken_ForEachComponent wc_CoseEatPsaToken_ForEachComponent
#endif

#endif /* WOLFCOSE_EAT_PSA */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WOLFCOSE_EAT_PSA_H */
