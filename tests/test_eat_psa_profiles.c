/* test_eat_psa_profiles.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfCOSE.
 */

/* Runtime coverage for deliberately small PSA/EAT builds. The normal
 * conformance suite enables every feature; this companion verifies that an
 * application can retain just one envelope/profile and that a disabled
 * envelope is refused before any cryptographic operation. */

#include <stdio.h>
#include <string.h>

#include <wolfcose/eat_psa.h>
#include <wolfssl/wolfcrypt/random.h>
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

#include "test_suite.h"

#if defined(WOLFCOSE_TEST_EAT_PSA_PROFILES) && defined(WOLFCOSE_EAT_PSA)

static int g_profile_failures = 0;

#define PROFILE_ASSERT(cond, name) do {                        \
    if (!(cond)) {                                              \
        (void)printf("  FAIL: %s (line %d)\n", name, __LINE__); \
        g_profile_failures++;                                   \
    }                                                           \
} while (0)

static const uint8_t kProfileNonce[32] = { 0x11u };
static const uint8_t kProfileUeid[33] = { 0x01u, 0x22u };
static const uint8_t kProfileImplementationId[32] = { 0x33u };
static const uint8_t kProfileMeasurement[32] = { 0x55u };
static const uint8_t kProfileSignerId[32] = { 0x66u };
static const uint8_t kProfileBootSeed[32] = { 0x44u };

static int test_eat_psa_profile_token_is_zero(
    const WOLFCOSE_EAT_PSA_TOKEN* token)
{
    WOLFCOSE_EAT_PSA_TOKEN zero;

    (void)memset(&zero, 0, sizeof(zero));
    return ((token != NULL) &&
            (memcmp(token, &zero, sizeof(zero)) == 0)) ? 1 : 0;
}

static void test_eat_psa_profile_expect_error(
    const WOLFCOSE_KEY* key, const uint8_t* message, size_t messageLen,
    uint8_t* scratch, size_t scratchSz, int expected, const char* name)
{
    WOLFCOSE_EAT_PSA_TOKEN token;
    int ret;

    (void)memset(&token, 0xA5, sizeof(token));
    ret = wc_CoseEatPsaToken_Verify(key, message, messageLen, kProfileNonce,
        sizeof(kProfileNonce), scratch, scratchSz, &token);
    PROFILE_ASSERT(ret == expected &&
                   test_eat_psa_profile_token_is_zero(&token) != 0,
        name);
}

#if defined(WOLFCOSE_EAT_PSA_CURRENT) && \
    defined(WOLFCOSE_EAT_PSA_ISSUE)
static void test_eat_psa_profile_current_claims(
    WOLFCOSE_EAT_PSA_CLAIMS* claims, WOLFCOSE_EAT_PSA_COMPONENT* component)
{
    (void)memset(claims, 0, sizeof(*claims));
    (void)memset(component, 0, sizeof(*component));
    component->measurementValue.data = kProfileMeasurement;
    component->measurementValue.len = sizeof(kProfileMeasurement);
    component->signerId.data = kProfileSignerId;
    component->signerId.len = sizeof(kProfileSignerId);
    claims->nonce.data = kProfileNonce;
    claims->nonce.len = sizeof(kProfileNonce);
    claims->ueid.data = kProfileUeid;
    claims->ueid.len = sizeof(kProfileUeid);
    claims->implementationId.data = kProfileImplementationId;
    claims->implementationId.len = sizeof(kProfileImplementationId);
    claims->clientId = -1;
    claims->lifecycle = 0x3000u;
    claims->components = component;
    claims->componentCount = 1u;
}
#endif

/* Build authenticated payloads with the public CBOR encoder so the legacy-only
 * profile test can distinguish a disabled current profile from a bad
 * signature. */
#if defined(WOLFCOSE_EAT_PSA_LEGACY) && defined(WOLFCOSE_CBOR_ENCODE) && \
    ((defined(WOLFCOSE_EAT_PSA_SIGN1) && \
      defined(WOLFCOSE_SIGN1_SIGN)) || \
     (defined(WOLFCOSE_EAT_PSA_MAC0) && defined(WOLFCOSE_MAC0_CREATE)))
static int test_eat_psa_encode_current_tfm(uint8_t* out, size_t outSz,
    size_t* outLen)
{
    static const uint8_t profile[] = WOLFCOSE_EAT_PSA_PROFILE_TFM;
    WOLFCOSE_CBOR_CTX ctx;
    int ret;

    if (outLen != NULL) {
        *outLen = 0u;
    }
    if ((out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wc_CBOR_EncoderInit(&ctx, out, outSz);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&ctx, 7u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, 10u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, kProfileNonce, sizeof(kProfileNonce));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, 256u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, kProfileUeid, sizeof(kProfileUeid));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, 265u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeTstr(&ctx, profile, sizeof(profile) - 1u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, 2394u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -1);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, 2395u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, 0x3000u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, 2396u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, kProfileImplementationId,
            sizeof(kProfileImplementationId));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, 2399u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, 1u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&ctx, 2u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, 2u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, kProfileMeasurement,
            sizeof(kProfileMeasurement));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, 5u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, kProfileSignerId,
            sizeof(kProfileSignerId));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = ctx.idx;
    }

    return ret;
}
#endif

static int test_eat_psa_encode_legacy_profile(uint8_t* out, size_t outSz,
    size_t* outLen)
{
    WOLFCOSE_CBOR_CTX ctx;
    int ret;

    if (outLen != NULL) {
        *outLen = 0u;
    }
    if ((out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wc_CBOR_EncoderInit(&ctx, out, outSz);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&ctx, 7u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75008);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, kProfileNonce, sizeof(kProfileNonce));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75009);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, kProfileUeid, sizeof(kProfileUeid));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75001);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -1);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75002);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, 0x3000u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75003);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, kProfileImplementationId,
            sizeof(kProfileImplementationId));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75004);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, kProfileBootSeed,
            sizeof(kProfileBootSeed));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75006);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, 1u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&ctx, 2u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, 2u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, kProfileMeasurement,
            sizeof(kProfileMeasurement));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, 5u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, kProfileSignerId,
            sizeof(kProfileSignerId));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = ctx.idx;
    }

    return ret;
}

#if defined(WOLFCOSE_EAT_PSA_CURRENT) && \
    defined(WOLFCOSE_EAT_PSA_SIGN1_ISSUE) && \
    defined(WOLFCOSE_SIGN1_VERIFY) && defined(WOLFCOSE_HAVE_ES256)
static void test_eat_psa_current_sign1_only(void)
{
    static const uint8_t disabledMac0[] = {
        0xD1u, 0x84u, 0x43u, 0xA1u, 0x01u, 0x05u,
        0xA0u, 0x40u, 0x40u
    };
    WOLFCOSE_EAT_PSA_CLAIMS claims;
    WOLFCOSE_EAT_PSA_COMPONENT component;
    WOLFCOSE_KEY key;
    WOLFCOSE_HDR hdr = { 0 };
    ecc_key ecc;
    WC_RNG rng;
    uint8_t claimsBuf[512];
    uint8_t payload[512];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[1024];
    const uint8_t* genericPayload = NULL;
    size_t genericPayloadLen = 0u;
    size_t payloadLen = 0u;
    size_t messageLen = 0u;
    int ret;
    int testRet;
    int rngInited = 0;
    int eccInited = 0;
    int keyInited = 0;
    int setupOk = 0;

    (void)printf("  [current Sign1-only runtime profile]\n");
    test_eat_psa_profile_current_claims(&claims, &component);
    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInited = 1;
        ret = wc_ecc_init(&ecc);
    }
    if (ret == 0) {
        eccInited = 1;
        ret = wc_ecc_make_key_ex(&rng, 32, &ecc, ECC_SECP256R1);
    }
    if (ret == 0) {
        ret = wc_CoseKey_Init(&key);
        if (ret == WOLFCOSE_SUCCESS) {
            keyInited = 1;
            ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &ecc);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        setupOk = 1;
    }
    PROFILE_ASSERT(setupOk != 0, "initialize Sign1 profile key");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseEatPsaToken_EncodeClaims(&claims, payload,
            sizeof(payload), &payloadLen);
    }
    PROFILE_ASSERT(ret == WOLFCOSE_SUCCESS && payloadLen > 0u,
        "encode #tfm claims in Sign1-only sender build");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseEatPsaToken_CreateSign1(&key, WOLFCOSE_ALG_ES256,
            &claims, claimsBuf, sizeof(claimsBuf), scratch, sizeof(scratch),
            message, sizeof(message), &messageLen, &rng);
    }
    PROFILE_ASSERT(ret == WOLFCOSE_SUCCESS && messageLen > 0u,
        "issue #tfm Sign1 in Sign1-only sender build");
    if ((messageLen > 0u) && (setupOk != 0)) {
        testRet = wc_CoseSign1_Verify(&key, message, messageLen, NULL, 0u,
            NULL, 0u, scratch, sizeof(scratch), &hdr, &genericPayload,
            &genericPayloadLen);
        PROFILE_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                       genericPayloadLen == payloadLen &&
                       memcmp(genericPayload, payload, payloadLen) == 0,
            "verify Sign1-only sender token with generic COSE");
        test_eat_psa_profile_expect_error(&key, message, messageLen,
            scratch, sizeof(scratch), WOLFCOSE_E_EAT_PSA_PROFILE,
            "reject #tfm without every RFC 9783 envelope and algorithm");
    }

    ret = test_eat_psa_encode_legacy_profile(payload, sizeof(payload),
        &payloadLen);
    if ((ret == WOLFCOSE_SUCCESS) && (setupOk != 0)) {
        ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0u, payload,
            payloadLen, NULL, 0u, NULL, 0u, scratch, sizeof(scratch),
            message, sizeof(message), &messageLen, &rng);
    }
    PROFILE_ASSERT(ret == WOLFCOSE_SUCCESS && messageLen > 0u,
        "construct authenticated legacy Sign1 for disabled-profile rejection");
    if ((ret == WOLFCOSE_SUCCESS) && (messageLen > 0u) && (setupOk != 0)) {
        test_eat_psa_profile_expect_error(&key, message, messageLen,
            scratch, sizeof(scratch), WOLFCOSE_E_EAT_PSA_PROFILE,
            "reject recognized legacy labels when legacy support is disabled");
    }
    if (setupOk != 0) {
        test_eat_psa_profile_expect_error(&key, disabledMac0,
            sizeof(disabledMac0), scratch, sizeof(scratch),
            WOLFCOSE_E_UNSUPPORTED,
            "reject Mac0 when compiled out of Sign1-only build");
    }
    if (keyInited != 0) {
        wc_CoseKey_Free(&key);
    }
    if (eccInited != 0) {
        (void)wc_ecc_free(&ecc);
    }
    if (rngInited != 0) {
        (void)wc_FreeRng(&rng);
    }
}
#endif

#if defined(WOLFCOSE_EAT_PSA_CURRENT) && \
    defined(WOLFCOSE_EAT_PSA_MAC0_ISSUE) && \
    defined(WOLFCOSE_MAC0_VERIFY) && defined(WOLFCOSE_HAVE_HMAC256)
static void test_eat_psa_current_mac0_only(void)
{
    static const uint8_t disabledSign1[] = {
        0xD2u, 0x84u, 0x43u, 0xA1u, 0x01u, 0x26u,
        0xA0u, 0x40u, 0x40u
    };
    WOLFCOSE_EAT_PSA_CLAIMS claims;
    WOLFCOSE_EAT_PSA_COMPONENT component;
    WOLFCOSE_KEY key;
    WOLFCOSE_HDR hdr = { 0 };
    uint8_t hmacKey[32] = { 0 };
    uint8_t claimsBuf[512];
    uint8_t payload[512];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[1024];
    const uint8_t* genericPayload = NULL;
    size_t genericPayloadLen = 0u;
    size_t payloadLen = 0u;
    size_t messageLen = 0u;
    int ret;
    int testRet;
    int keyInited = 0;
    int setupOk = 0;

    (void)printf("  [current Mac0-only runtime profile]\n");
    test_eat_psa_profile_current_claims(&claims, &component);
    ret = wc_CoseKey_Init(&key);
    if (ret == WOLFCOSE_SUCCESS) {
        keyInited = 1;
        ret = wc_CoseKey_SetSymmetric(&key, hmacKey, sizeof(hmacKey));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        setupOk = 1;
    }
    PROFILE_ASSERT(setupOk != 0, "initialize Mac0 profile key");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseEatPsaToken_EncodeClaims(&claims, payload,
            sizeof(payload), &payloadLen);
    }
    PROFILE_ASSERT(ret == WOLFCOSE_SUCCESS && payloadLen > 0u,
        "encode #tfm claims in Mac0-only sender build");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseEatPsaToken_CreateMac0(&key,
            WOLFCOSE_ALG_HMAC_256_256, &claims, claimsBuf,
            sizeof(claimsBuf), scratch, sizeof(scratch), message,
            sizeof(message), &messageLen);
    }
    PROFILE_ASSERT(ret == WOLFCOSE_SUCCESS && messageLen > 0u,
        "issue #tfm Mac0 in Mac0-only sender build");
    if ((messageLen > 0u) && (setupOk != 0)) {
        testRet = wc_CoseMac0_Verify(&key, message, messageLen, NULL, 0u,
            NULL, 0u, scratch, sizeof(scratch), &hdr, &genericPayload,
            &genericPayloadLen);
        PROFILE_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                       genericPayloadLen == payloadLen &&
                       memcmp(genericPayload, payload, payloadLen) == 0,
            "verify Mac0-only sender token with generic COSE");
        test_eat_psa_profile_expect_error(&key, message, messageLen,
            scratch, sizeof(scratch), WOLFCOSE_E_EAT_PSA_PROFILE,
            "reject #tfm without every RFC 9783 envelope and algorithm");
    }

    ret = test_eat_psa_encode_legacy_profile(payload, sizeof(payload),
        &payloadLen);
    if ((ret == WOLFCOSE_SUCCESS) && (setupOk != 0)) {
        ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256, NULL, 0u,
            payload, payloadLen, NULL, 0u, NULL, 0u, scratch,
            sizeof(scratch), message, sizeof(message), &messageLen);
    }
    PROFILE_ASSERT(ret == WOLFCOSE_SUCCESS && messageLen > 0u,
        "construct authenticated legacy Mac0 for disabled-profile rejection");
    if ((ret == WOLFCOSE_SUCCESS) && (messageLen > 0u) && (setupOk != 0)) {
        test_eat_psa_profile_expect_error(&key, message, messageLen,
            scratch, sizeof(scratch), WOLFCOSE_E_EAT_PSA_PROFILE,
            "reject recognized legacy labels when legacy support is disabled");
    }
    if (setupOk != 0) {
        test_eat_psa_profile_expect_error(&key, disabledSign1,
            sizeof(disabledSign1), scratch, sizeof(scratch),
            WOLFCOSE_E_UNSUPPORTED,
            "reject Sign1 when compiled out of Mac0-only build");
    }
    if (keyInited != 0) {
        wc_CoseKey_Free(&key);
    }
}
#endif

#if defined(WOLFCOSE_EAT_PSA_LEGACY) && \
    defined(WOLFCOSE_EAT_PSA_SIGN1) && \
    defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_SIGN1_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES256)
static void test_eat_psa_legacy_sign1_only(void)
{
    WOLFCOSE_EAT_PSA_TOKEN token;
    WOLFCOSE_KEY key;
    ecc_key ecc;
    WC_RNG rng;
    uint8_t payload[512];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[1024];
    size_t payloadLen = 0u;
    size_t messageLen = 0u;
    int ret;
    int rngInited = 0;
    int eccInited = 0;
    int keyInited = 0;
    int setupOk = 0;

    (void)printf("  [legacy Sign1-only runtime profile]\n");
    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInited = 1;
        ret = wc_ecc_init(&ecc);
    }
    if (ret == 0) {
        eccInited = 1;
        ret = wc_ecc_make_key_ex(&rng, 32, &ecc, ECC_SECP256R1);
    }
    if (ret == 0) {
        ret = wc_CoseKey_Init(&key);
        if (ret == WOLFCOSE_SUCCESS) {
            keyInited = 1;
            ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &ecc);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        setupOk = 1;
    }
    PROFILE_ASSERT(setupOk != 0, "initialize legacy Sign1 profile key");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = test_eat_psa_encode_legacy_profile(payload, sizeof(payload),
            &payloadLen);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (setupOk != 0)) {
        ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0u, payload,
            payloadLen, NULL, 0u, NULL, 0u, scratch, sizeof(scratch),
            message, sizeof(message), &messageLen, &rng);
    }
    PROFILE_ASSERT(ret == WOLFCOSE_SUCCESS && messageLen > 0u,
        "construct legacy Sign1 in legacy-only build");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseEatPsaToken_Verify(&key, message, messageLen,
            kProfileNonce, sizeof(kProfileNonce), scratch, sizeof(scratch),
            &token);
        PROFILE_ASSERT(ret == WOLFCOSE_SUCCESS &&
                       token.profile == WOLFCOSE_EAT_PSA_PROFILE_OLD &&
                       token.protection == WOLFCOSE_EAT_PSA_PROTECTION_SIGN1,
            "verify legacy Sign1 in legacy-only build");
    }

    ret = test_eat_psa_encode_current_tfm(payload, sizeof(payload),
        &payloadLen);
    if ((ret == WOLFCOSE_SUCCESS) && (setupOk != 0)) {
        ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0u, payload,
            payloadLen, NULL, 0u, NULL, 0u, scratch, sizeof(scratch),
            message, sizeof(message), &messageLen, &rng);
    }
    PROFILE_ASSERT(ret == WOLFCOSE_SUCCESS && messageLen > 0u,
        "construct authenticated #tfm Sign1 for disabled-profile rejection");
    if ((ret == WOLFCOSE_SUCCESS) && (messageLen > 0u) && (setupOk != 0)) {
        test_eat_psa_profile_expect_error(&key, message, messageLen,
            scratch, sizeof(scratch), WOLFCOSE_E_EAT_PSA_PROFILE,
            "reject recognized current labels when current support is disabled");
    }
    if (keyInited != 0) {
        wc_CoseKey_Free(&key);
    }
    if (eccInited != 0) {
        (void)wc_ecc_free(&ecc);
    }
    if (rngInited != 0) {
        (void)wc_FreeRng(&rng);
    }
}
#endif

#if defined(WOLFCOSE_EAT_PSA_LEGACY) && \
    defined(WOLFCOSE_EAT_PSA_MAC0) && \
    defined(WOLFCOSE_MAC0_CREATE) && defined(WOLFCOSE_MAC0_VERIFY) && \
    defined(WOLFCOSE_HAVE_HMAC256)
static void test_eat_psa_legacy_mac0_only(void)
{
    static const uint8_t disabledSign1[] = {
        0xD2u, 0x84u, 0x43u, 0xA1u, 0x01u, 0x26u,
        0xA0u, 0x40u, 0x40u
    };
    WOLFCOSE_EAT_PSA_TOKEN token;
    WOLFCOSE_KEY key;
    uint8_t hmacKey[32] = { 0 };
    uint8_t payload[512];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[1024];
    size_t payloadLen = 0u;
    size_t messageLen = 0u;
    int ret;
    int keyInited = 0;
    int setupOk = 0;

    (void)printf("  [legacy Mac0-only runtime profile]\n");
    ret = wc_CoseKey_Init(&key);
    if (ret == WOLFCOSE_SUCCESS) {
        keyInited = 1;
        ret = wc_CoseKey_SetSymmetric(&key, hmacKey, sizeof(hmacKey));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        setupOk = 1;
    }
    PROFILE_ASSERT(setupOk != 0, "initialize legacy Mac0 profile key");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = test_eat_psa_encode_legacy_profile(payload, sizeof(payload),
            &payloadLen);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (setupOk != 0)) {
        ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256, NULL, 0u,
            payload, payloadLen, NULL, 0u, NULL, 0u, scratch,
            sizeof(scratch), message, sizeof(message), &messageLen);
    }
    PROFILE_ASSERT(ret == WOLFCOSE_SUCCESS && messageLen > 0u,
        "construct legacy Mac0 in legacy-only build");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseEatPsaToken_Verify(&key, message, messageLen,
            kProfileNonce, sizeof(kProfileNonce), scratch, sizeof(scratch),
            &token);
        PROFILE_ASSERT(ret == WOLFCOSE_SUCCESS &&
                       token.profile == WOLFCOSE_EAT_PSA_PROFILE_OLD &&
                       token.protection == WOLFCOSE_EAT_PSA_PROTECTION_MAC0,
            "verify legacy Mac0 in legacy-only build");
    }

    ret = test_eat_psa_encode_current_tfm(payload, sizeof(payload),
        &payloadLen);
    if ((ret == WOLFCOSE_SUCCESS) && (setupOk != 0)) {
        ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256, NULL, 0u,
            payload, payloadLen, NULL, 0u, NULL, 0u, scratch,
            sizeof(scratch), message, sizeof(message), &messageLen);
    }
    PROFILE_ASSERT(ret == WOLFCOSE_SUCCESS && messageLen > 0u,
        "construct authenticated #tfm Mac0 for disabled-profile rejection");
    if ((ret == WOLFCOSE_SUCCESS) && (messageLen > 0u) && (setupOk != 0)) {
        test_eat_psa_profile_expect_error(&key, message, messageLen,
            scratch, sizeof(scratch), WOLFCOSE_E_EAT_PSA_PROFILE,
            "reject recognized current labels when current support is disabled");
    }
    if (setupOk != 0) {
        test_eat_psa_profile_expect_error(&key, disabledSign1,
            sizeof(disabledSign1), scratch, sizeof(scratch),
            WOLFCOSE_E_UNSUPPORTED,
            "reject Sign1 when compiled out of legacy Mac0-only build");
    }
    if (keyInited != 0) {
        wc_CoseKey_Free(&key);
    }
}
#endif

#endif /* WOLFCOSE_TEST_EAT_PSA_PROFILES && WOLFCOSE_EAT_PSA */

int test_eat_psa_profiles(void)
{
#if defined(WOLFCOSE_TEST_EAT_PSA_PROFILES) && defined(WOLFCOSE_EAT_PSA)
    g_profile_failures = 0;
    (void)printf("  [PSA/EAT independent feature-profile tests]\n");

    #if defined(WOLFCOSE_EAT_PSA_CURRENT) && \
        defined(WOLFCOSE_EAT_PSA_SIGN1_ISSUE) && \
        defined(WOLFCOSE_SIGN1_VERIFY) && defined(WOLFCOSE_HAVE_ES256)
    test_eat_psa_current_sign1_only();
    #endif
    #if defined(WOLFCOSE_EAT_PSA_CURRENT) && \
        defined(WOLFCOSE_EAT_PSA_MAC0_ISSUE) && \
        defined(WOLFCOSE_MAC0_VERIFY) && defined(WOLFCOSE_HAVE_HMAC256)
    test_eat_psa_current_mac0_only();
    #endif
    #if defined(WOLFCOSE_EAT_PSA_LEGACY) && \
        defined(WOLFCOSE_EAT_PSA_SIGN1) && \
        defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_SIGN1_VERIFY) && \
        defined(WOLFCOSE_HAVE_ES256)
    test_eat_psa_legacy_sign1_only();
    #endif
    #if defined(WOLFCOSE_EAT_PSA_LEGACY) && \
        defined(WOLFCOSE_EAT_PSA_MAC0) && \
        defined(WOLFCOSE_MAC0_CREATE) && defined(WOLFCOSE_MAC0_VERIFY) && \
        defined(WOLFCOSE_HAVE_HMAC256)
    test_eat_psa_legacy_mac0_only();
    #endif

    return g_profile_failures;
#else
    return 0;
#endif
}
