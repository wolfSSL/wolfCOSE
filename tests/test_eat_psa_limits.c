/* test_eat_psa_limits.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfCOSE.
 */

/* Exercise the claim-map ceilings with deliberately small, independently
 * compiled limits. The normal RFC 9783 suite uses production defaults, while
 * this test proves that each boundary check is reached before parser work can
 * grow beyond the configured bound. */

#include <stdio.h>
#include <string.h>

#include <wolfcose/eat_psa.h>

#if defined(WOLFCOSE_TEST_EAT_PSA_LIMITS) && defined(WOLFCOSE_EAT_PSA)

#if !defined(WOLFCOSE_EAT_PSA_TFM_FULL)
    #error "claim-limit test requires the full RFC 9783 #tfm receiver profile"
#endif

#define EAT_LIMITS_OUTER_REQUIRED 7u
#define EAT_LIMITS_COMPONENT_REQUIRED 2u

enum test_eat_psa_limit_case {
    TEST_EAT_PSA_LIMIT_EXACT = 0,
    TEST_EAT_PSA_LIMIT_TOP_PLUS_ONE = 1,
    TEST_EAT_PSA_LIMIT_COMPONENT_PLUS_ONE = 2
};

static const uint8_t kLimitsNonce[32] = { 0x11u };
static const uint8_t kLimitsUeid[33] = { 0x01u, 0x22u };
static const uint8_t kLimitsImplementationId[32] = { 0x33u };
static const uint8_t kLimitsMeasurement[32] = { 0x55u };
static const uint8_t kLimitsSignerId[32] = { 0x66u };
static const uint8_t kLimitsProfile[] = WOLFCOSE_EAT_PSA_PROFILE_TFM;
static int g_limit_failures = 0;

#define LIMIT_ASSERT(cond, name) do {                          \
    if (!(cond)) {                                              \
        (void)printf("  FAIL: %s (line %d)\n", name, __LINE__); \
        g_limit_failures++;                                     \
    }                                                           \
} while (0)

static int test_eat_psa_limits_token_is_zero(
    const WOLFCOSE_EAT_PSA_TOKEN* token)
{
    WOLFCOSE_EAT_PSA_TOKEN zero;

    (void)memset(&zero, 0, sizeof(zero));
    return ((token != NULL) &&
            (memcmp(token, &zero, sizeof(zero)) == 0)) ? 1 : 0;
}

static int test_eat_psa_limits_encode_component(WOLFCOSE_CBOR_CTX* ctx,
    int overLimit)
{
    int ret;
    size_t i;
    size_t count = overLimit != 0 ?
        WOLFCOSE_EAT_PSA_MAX_COMPONENT_CLAIMS + 1u :
        WOLFCOSE_EAT_PSA_MAX_COMPONENT_CLAIMS;

    ret = wc_CBOR_EncodeMapStart(ctx, count);
    if (overLimit != 0) {
        /* The generic CBOR container check needs one remaining byte per
         * declared pair. The EAT component ceiling is tested before parsing
         * any pair, so these values intentionally need not form valid pairs. */
        for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < count); i++) {
            ret = wc_CBOR_EncodeUint(ctx, 0u);
        }
    }
    else {
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeUint(ctx, 2u);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(ctx, kLimitsMeasurement,
                sizeof(kLimitsMeasurement));
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeUint(ctx, 5u);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(ctx, kLimitsSignerId,
                sizeof(kLimitsSignerId));
        }
        for (i = EAT_LIMITS_COMPONENT_REQUIRED;
             (ret == WOLFCOSE_SUCCESS) && (i < count); i++) {
            ret = wc_CBOR_EncodeUint(ctx, 70000u + (uint64_t)i);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(ctx, (uint64_t)i);
            }
        }
    }

    return ret;
}

static int test_eat_psa_limits_encode_current(WOLFCOSE_CBOR_CTX* ctx,
    int componentOverLimit)
{
    int ret;
    size_t i;

    ret = wc_CBOR_EncodeUint(ctx, 10u);
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(ctx, kLimitsNonce, sizeof(kLimitsNonce));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(ctx, 256u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(ctx, kLimitsUeid, sizeof(kLimitsUeid));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(ctx, 265u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeTstr(ctx, kLimitsProfile,
            sizeof(kLimitsProfile) - 1u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(ctx, 2394u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(ctx, -1);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(ctx, 2395u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(ctx, 0x3000u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(ctx, 2396u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(ctx, kLimitsImplementationId,
            sizeof(kLimitsImplementationId));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(ctx, 2399u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(ctx, 1u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = test_eat_psa_limits_encode_component(ctx, componentOverLimit);
    }
    for (i = EAT_LIMITS_OUTER_REQUIRED;
         (ret == WOLFCOSE_SUCCESS) &&
         (i < WOLFCOSE_EAT_PSA_MAX_CLAIMS); i++) {
        ret = wc_CBOR_EncodeUint(ctx, 80000u + (uint64_t)i);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeUint(ctx, (uint64_t)i);
        }
    }

    return ret;
}

static int test_eat_psa_limits_encode_payload(
    enum test_eat_psa_limit_case which, uint8_t* out, size_t outSz,
    size_t* outLen)
{
    WOLFCOSE_CBOR_CTX ctx;
    int ret;
    size_t i;

    if (outLen != NULL) {
        *outLen = 0u;
    }
    if ((out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = wc_CBOR_EncoderInit(&ctx, out, outSz);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (which == TEST_EAT_PSA_LIMIT_TOP_PLUS_ONE)) {
        ret = wc_CBOR_EncodeMapStart(&ctx,
            WOLFCOSE_EAT_PSA_MAX_CLAIMS + 1u);
        for (i = 0u; (ret == WOLFCOSE_SUCCESS) &&
             (i < (WOLFCOSE_EAT_PSA_MAX_CLAIMS + 1u)); i++) {
            ret = wc_CBOR_EncodeUint(&ctx, 0u);
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (which != TEST_EAT_PSA_LIMIT_TOP_PLUS_ONE)) {
        ret = wc_CBOR_EncodeMapStart(&ctx, WOLFCOSE_EAT_PSA_MAX_CLAIMS);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (which != TEST_EAT_PSA_LIMIT_TOP_PLUS_ONE)) {
        ret = test_eat_psa_limits_encode_current(&ctx,
            which == TEST_EAT_PSA_LIMIT_COMPONENT_PLUS_ONE ? 1 : 0);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = ctx.idx;
    }

    return ret;
}

static void test_eat_psa_limits_run_case(const WOLFCOSE_KEY* key,
    enum test_eat_psa_limit_case which, int expected, const char* name)
{
    WOLFCOSE_EAT_PSA_TOKEN token;
    uint8_t payload[1024];
    uint8_t message[1536];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    size_t payloadLen = 0u;
    size_t messageLen = 0u;
    int ret;

    ret = test_eat_psa_limits_encode_payload(which, payload, sizeof(payload),
        &payloadLen);
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseMac0_Create(key, WOLFCOSE_ALG_HMAC_256_256, NULL, 0u,
            payload, payloadLen, NULL, 0u, NULL, 0u, scratch, sizeof(scratch),
            message, sizeof(message), &messageLen);
    }
    LIMIT_ASSERT(ret == WOLFCOSE_SUCCESS && messageLen > 0u, name);
    if (ret == WOLFCOSE_SUCCESS) {
        (void)memset(&token, 0xA5, sizeof(token));
        ret = wc_CoseEatPsaToken_Verify(key, message, messageLen,
            kLimitsNonce, sizeof(kLimitsNonce), scratch, sizeof(scratch),
            &token);
        LIMIT_ASSERT(ret == expected, name);
        if (expected == WOLFCOSE_SUCCESS) {
            LIMIT_ASSERT(token.componentCount == 1u, name);
        }
        else {
            LIMIT_ASSERT(test_eat_psa_limits_token_is_zero(&token) != 0,
                name);
        }
    }
}

int main(void)
{
    WOLFCOSE_KEY key;
    uint8_t hmacKey[32] = { 0xA5u };
    int ret;
    int keyInited = 0;

    (void)printf("=== wolfCOSE PSA/EAT Claim-Limit Tests ===\n\n");
    ret = wc_CoseKey_Init(&key);
    if (ret == WOLFCOSE_SUCCESS) {
        keyInited = 1;
        ret = wc_CoseKey_SetSymmetric(&key, hmacKey, sizeof(hmacKey));
    }
    LIMIT_ASSERT(ret == WOLFCOSE_SUCCESS, "initialize HMAC key");
    if (ret == WOLFCOSE_SUCCESS) {
        test_eat_psa_limits_run_case(&key, TEST_EAT_PSA_LIMIT_EXACT,
            WOLFCOSE_SUCCESS, "accept exact claim and component limits");
        test_eat_psa_limits_run_case(&key, TEST_EAT_PSA_LIMIT_TOP_PLUS_ONE,
            WOLFCOSE_E_EAT_PSA_CLAIM, "reject claim-map limit plus one");
        test_eat_psa_limits_run_case(&key,
            TEST_EAT_PSA_LIMIT_COMPONENT_PLUS_ONE, WOLFCOSE_E_EAT_PSA_CLAIM,
            "reject component-map limit plus one");
    }
    if (keyInited != 0) {
        wc_CoseKey_Free(&key);
    }

    (void)printf("\n=== Results: %s ===\n",
        g_limit_failures == 0 ? "ALL PASSED" : "FAILURES");
    return g_limit_failures == 0 ? 0 : 1;
}

#else

int main(void)
{
    return 0;
}

#endif /* WOLFCOSE_TEST_EAT_PSA_LIMITS && WOLFCOSE_EAT_PSA */
