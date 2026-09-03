/* test_eat_psa.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfCOSE.
 */

#include <stdio.h>
#include <string.h>

#include <wolfcose/eat_psa.h>
#include <wolfssl/wolfcrypt/random.h>
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

#include "../src/wolfcose_internal.h"  /* Test delegated-signing seam. */
#include "test_suite.h"

static int g_failures = 0;

#define TEST_ASSERT(cond, name) do {                           \
    if (!(cond)) {                                              \
        (void)printf("  FAIL: %s (line %d)\n", name, __LINE__); \
        g_failures++;                                           \
    }                                                           \
} while (0)

#if defined(WOLFCOSE_EAT_PSA) && \
    defined(WOLFCOSE_EAT_PSA_CURRENT) && \
    defined(WOLFCOSE_EAT_PSA_SIGN1) && \
    defined(WOLFCOSE_EAT_PSA_MAC0) && \
    defined(WOLFCOSE_EAT_PSA_ISSUE) && \
    defined(WOLFCOSE_EAT_PSA_LEGACY) && \
    defined(WOLFCOSE_EAT_PSA_UEID_RESOLVER) && \
    defined(WOLFCOSE_EAT_PSA_COMPONENT_ITERATOR) && \
    defined(WOLFCOSE_EAT_PSA_TFM_FULL)
    #define WOLFCOSE_TEST_EAT_PSA_FULL
#endif

#if defined(WOLFCOSE_TEST_EAT_PSA_FULL) && \
    (defined(WOLFCOSE_HAVE_ES256) || defined(WOLFCOSE_HAVE_HMAC256))

static const uint8_t kNonce[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

static const uint8_t kUeid[33] = {
    0x01,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
};

static const uint8_t kImplementationId[32] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
};

static const uint8_t kMeasurement[32] = {
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F
};

static const uint8_t kSignerId[32] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F
};

static const uint8_t kBootSeed[32] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
};

#if defined(WOLFCOSE_MAC0_VERIFY) && defined(WOLFCOSE_HAVE_HMAC256)
static const uint8_t kMac0TestKey[32] = { 0 };
#endif

static const uint8_t kOversizedBootSeed[33] = { 0xC0u };

static const uint8_t kInvalidCurrentCertRef[] = "1234567890123_12345";

#if defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_SIGN1_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES256)
static const uint8_t kLegacyBootSeed[32] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
};
#endif

/* RFC 9783 Appendix A uses this nonce in both external-producer vectors. */
static const uint8_t kRfc9783Nonce[32] = {
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
};

#if defined(WOLFCOSE_SIGN1_VERIFY) && defined(WOLFCOSE_HAVE_ES256)
static const uint8_t kRfc9783Sign1KeyX[32] = {
    0x4E, 0x5E, 0x22, 0x09, 0x9E, 0x3B, 0xCE, 0xB4,
    0x5B, 0x44, 0x6D, 0x13, 0x55, 0xFD, 0x1D, 0xC3,
    0xB5, 0x45, 0x94, 0x7B, 0x6F, 0xD7, 0xC1, 0xC8,
    0x9D, 0x88, 0x67, 0x98, 0xC3, 0x72, 0x6E, 0x8F
};

static const uint8_t kRfc9783Sign1KeyY[32] = {
    0x80, 0xD7, 0x0B, 0x84, 0x0B, 0x25, 0x6A, 0xAC,
    0x34, 0xA6, 0x2E, 0xDE, 0x10, 0x43, 0x36, 0x4F,
    0x04, 0x40, 0x95, 0xF0, 0x03, 0x47, 0x4B, 0x91,
    0xE0, 0x18, 0x20, 0x92, 0xAF, 0xB1, 0x3F, 0x2E
};

static const char kRfc9783Sign1Hex[] =
    "d28443a10126a0590100a819010058210102020202020202020202020202"
    "0202020202020202020202020202020202020219095c5820000000000000"
    "00000000000000000000000000000000000000000000000000000a582001"
    "010101010101010101010101010101010101010101010101010101010101"
    "0119095a1a7fffffff19095b19300019010978217461673a707361636572"
    "7469666965642e6f72672c323032333a7073612374666d19010c48000000"
    "000000000019095f81a30558200404040404040404040404040404040404"
    "040404040404040404040404040404025820030303030303030303030303"
    "0303030303030303030303030303030303030303016450526f545840786e"
    "937a4c42667af3847399319ca95c7e7dbabdc9b50fdb8de3f6bff4ab82ff"
    "80c42140e2a488000219e3e10663193da69c75f52b798ea10b2f7041a90e"
    "8e5a";
#endif /* WOLFCOSE_SIGN1_VERIFY && WOLFCOSE_HAVE_ES256 */

#if defined(WOLFCOSE_MAC0_VERIFY) && defined(WOLFCOSE_HAVE_HMAC256)
static const uint8_t kRfc9783Mac0Key[64] = {
    0xDE, 0x03, 0x8B, 0x34, 0xAC, 0xA1, 0x25, 0x76,
    0x8C, 0x5E, 0x33, 0x57, 0xAB, 0x8D, 0x06, 0xB3,
    0x67, 0xB9, 0xAB, 0x0D, 0x7E, 0x8B, 0xE1, 0x24,
    0xED, 0xCA, 0x47, 0xFE, 0x03, 0x3A, 0x5B, 0xB7,
    0xA9, 0x3D, 0x30, 0x7F, 0xF2, 0x29, 0xAA, 0x36,
    0xFF, 0x24, 0x6C, 0x12, 0x95, 0x96, 0x4F, 0xAC,
    0xF7, 0x1A, 0xB7, 0xAA, 0x6E, 0xC4, 0xFD, 0x61,
    0x02, 0xB7, 0xB3, 0x98, 0x32, 0x55, 0xAD, 0x92
};

static const char kRfc9783Mac0Hex[] =
    "d18443a10105a0590100a8190100582101c557bd4fadc83f756fca2cd5ea"
    "2dcc8b82159bb4e7453d6a744d4eecd6d0ac6019095c5820000000000000"
    "00000000000000000000000000000000000000000000000000000a582001"
    "010101010101010101010101010101010101010101010101010101010101"
    "0119095a1a7fffffff19095b19300019010978217461673a707361636572"
    "7469666965642e6f72672c323032333a7073612374666d19010c48000000"
    "000000000019095f81a30558200404040404040404040404040404040404"
    "040404040404040404040404040404025820030303030303030303030303"
    "0303030303030303030303030303030303030303016450526f545820cf88"
    "d330e7a5366a95cf744a4dbf0d50304d405edd8b2530e243eddbd3177820";
#endif /* WOLFCOSE_MAC0_VERIFY && WOLFCOSE_HAVE_HMAC256 */

#if (defined(WOLFCOSE_SIGN1_VERIFY) && defined(WOLFCOSE_HAVE_ES256)) || \
    (defined(WOLFCOSE_MAC0_VERIFY) && defined(WOLFCOSE_HAVE_HMAC256))
static int test_eat_psa_hex_nibble(uint8_t c, uint8_t* value)
{
    int ret = WOLFCOSE_SUCCESS;

    if (value == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((c >= (uint8_t)'0') && (c <= (uint8_t)'9')) {
        *value = (uint8_t)(c - (uint8_t)'0');
    }
    else if ((c >= (uint8_t)'a') && (c <= (uint8_t)'f')) {
        *value = (uint8_t)(c - (uint8_t)'a' + 10u);
    }
    else if ((c >= (uint8_t)'A') && (c <= (uint8_t)'F')) {
        *value = (uint8_t)(c - (uint8_t)'A' + 10u);
    }
    else {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    return ret;
}

static int test_eat_psa_hex_decode(const char* hex, uint8_t* out,
    size_t outSz, size_t* outLen)
{
    int ret = WOLFCOSE_SUCCESS;
    size_t hexLen;
    size_t i;

    if (outLen != NULL) {
        *outLen = 0u;
    }
    if ((hex == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        hexLen = strlen(hex);
        if (((hexLen & 1u) != 0u) || ((hexLen / 2u) > outSz)) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }
        for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < (hexLen / 2u)); i++) {
            uint8_t high;
            uint8_t low;

            ret = test_eat_psa_hex_nibble((uint8_t)hex[2u * i], &high);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = test_eat_psa_hex_nibble((uint8_t)hex[(2u * i) + 1u],
                    &low);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                out[i] = (uint8_t)((high << 4) | low);
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            *outLen = hexLen / 2u;
        }
    }

    return ret;
}
#endif

#if defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_SIGN1_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES256)
#define TEST_EAT_PSA_OMIT_NONCE          0x01u
#define TEST_EAT_PSA_OMIT_UEID           0x02u
#define TEST_EAT_PSA_OMIT_PROFILE        0x04u
#define TEST_EAT_PSA_OMIT_CLIENT_ID      0x08u
#define TEST_EAT_PSA_OMIT_LIFECYCLE      0x10u
#define TEST_EAT_PSA_OMIT_IMPLEMENTATION 0x20u
#define TEST_EAT_PSA_OMIT_COMPONENTS     0x40u
#define TEST_EAT_PSA_UNKNOWN_TEXT         0x80u
#define TEST_EAT_PSA_DUP_UNKNOWN_CLAIM    0x100u
#define TEST_EAT_PSA_DUP_UNKNOWN_TEXT     0x200u

#define TEST_EAT_PSA_COMPONENT_OMIT_VALUE  0x01u
#define TEST_EAT_PSA_COMPONENT_OMIT_SIGNER 0x02u
#define TEST_EAT_PSA_COMPONENT_DUP_VALUE   0x04u
#define TEST_EAT_PSA_COMPONENT_UNKNOWN_TEXT 0x08u
#define TEST_EAT_PSA_COMPONENT_DUP_UNKNOWN_TEXT 0x10u
#define TEST_EAT_PSA_COMPONENT_DUP_UNKNOWN_CLAIM 0x20u

static int test_eat_psa_encode_raw_component_ex(WOLFCOSE_CBOR_CTX* ctx,
    const WOLFCOSE_EAT_PSA_COMPONENT* component, uint32_t flags)
{
    static const uint8_t unknownLabel[] = "vendor-component";
    static const uint8_t duplicateLabel[] = "vendor-duplicate";
    int ret;
    size_t count = 2u;

    count -= ((flags & TEST_EAT_PSA_COMPONENT_OMIT_VALUE) != 0u) ? 1u : 0u;
    count -= ((flags & TEST_EAT_PSA_COMPONENT_OMIT_SIGNER) != 0u) ? 1u : 0u;
    count += ((flags & TEST_EAT_PSA_COMPONENT_DUP_VALUE) != 0u) ? 1u : 0u;
    count += ((flags & TEST_EAT_PSA_COMPONENT_UNKNOWN_TEXT) != 0u) ? 1u : 0u;
    count += ((flags & TEST_EAT_PSA_COMPONENT_DUP_UNKNOWN_TEXT) != 0u) ?
             2u : 0u;
    count += ((flags & TEST_EAT_PSA_COMPONENT_DUP_UNKNOWN_CLAIM) != 0u) ?
             2u : 0u;
    ret = wc_CBOR_EncodeMapStart(ctx, count);
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & TEST_EAT_PSA_COMPONENT_OMIT_VALUE) == 0u)) {
        ret = wc_CBOR_EncodeUint(ctx, 2u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & TEST_EAT_PSA_COMPONENT_OMIT_VALUE) == 0u)) {
        ret = wc_CBOR_EncodeBstr(ctx, component->measurementValue.data,
            component->measurementValue.len);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & TEST_EAT_PSA_COMPONENT_DUP_VALUE) != 0u)) {
        ret = wc_CBOR_EncodeUint(ctx, 2u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & TEST_EAT_PSA_COMPONENT_DUP_VALUE) != 0u)) {
        ret = wc_CBOR_EncodeBstr(ctx, component->measurementValue.data,
            component->measurementValue.len);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & TEST_EAT_PSA_COMPONENT_OMIT_SIGNER) == 0u)) {
        ret = wc_CBOR_EncodeUint(ctx, 5u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & TEST_EAT_PSA_COMPONENT_OMIT_SIGNER) == 0u)) {
        ret = wc_CBOR_EncodeBstr(ctx, component->signerId.data,
            component->signerId.len);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & TEST_EAT_PSA_COMPONENT_UNKNOWN_TEXT) != 0u)) {
        ret = wc_CBOR_EncodeTstr(ctx, unknownLabel, sizeof(unknownLabel) - 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & TEST_EAT_PSA_COMPONENT_UNKNOWN_TEXT) != 0u)) {
        ret = wc_CBOR_EncodeUint(ctx, 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & TEST_EAT_PSA_COMPONENT_DUP_UNKNOWN_TEXT) != 0u)) {
        ret = wc_CBOR_EncodeTstr(ctx, duplicateLabel,
            sizeof(duplicateLabel) - 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & TEST_EAT_PSA_COMPONENT_DUP_UNKNOWN_TEXT) != 0u)) {
        ret = wc_CBOR_EncodeUint(ctx, 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & TEST_EAT_PSA_COMPONENT_DUP_UNKNOWN_TEXT) != 0u)) {
        ret = wc_CBOR_EncodeTstr(ctx, duplicateLabel,
            sizeof(duplicateLabel) - 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & TEST_EAT_PSA_COMPONENT_DUP_UNKNOWN_TEXT) != 0u)) {
        ret = wc_CBOR_EncodeUint(ctx, 2u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & TEST_EAT_PSA_COMPONENT_DUP_UNKNOWN_CLAIM) != 0u)) {
        ret = wc_CBOR_EncodeUint(ctx, 99u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & TEST_EAT_PSA_COMPONENT_DUP_UNKNOWN_CLAIM) != 0u)) {
        ret = wc_CBOR_EncodeUint(ctx, 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & TEST_EAT_PSA_COMPONENT_DUP_UNKNOWN_CLAIM) != 0u)) {
        ret = wc_CBOR_EncodeUint(ctx, 99u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((flags & TEST_EAT_PSA_COMPONENT_DUP_UNKNOWN_CLAIM) != 0u)) {
        ret = wc_CBOR_EncodeUint(ctx, 2u);
    }

    return ret;
}

/* Encode a signed-input fixture without issuer validation. This lets the
 * verifier tests exercise malformed but authenticated peer tokens. */
static int test_eat_psa_encode_current_raw_ex(
    const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    const uint8_t* profile, size_t profileLen, uint32_t omit,
    size_t unknownClaimCount, int addLegacyNoMeasurements,
    uint32_t componentFlags, size_t componentCount,
    uint8_t* out, size_t outSz, size_t* outLen)
{
    static const uint8_t unknownLabel[] = "vendor-claim";
    static const uint8_t duplicateLabel[] = "vendor-duplicate";
    WOLFCOSE_CBOR_CTX ctx;
    size_t count = 7u;
    size_t i;
    int ret;

    if (outLen != NULL) {
        *outLen = 0u;
    }
    if ((claims == NULL) || (profile == NULL) || (out == NULL) ||
        (outLen == NULL) || (claims->components == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        count -= ((omit & TEST_EAT_PSA_OMIT_NONCE) != 0u) ? 1u : 0u;
        count -= ((omit & TEST_EAT_PSA_OMIT_UEID) != 0u) ? 1u : 0u;
        count -= ((omit & TEST_EAT_PSA_OMIT_PROFILE) != 0u) ? 1u : 0u;
        count -= ((omit & TEST_EAT_PSA_OMIT_CLIENT_ID) != 0u) ? 1u : 0u;
        count -= ((omit & TEST_EAT_PSA_OMIT_LIFECYCLE) != 0u) ? 1u : 0u;
        count -= ((omit & TEST_EAT_PSA_OMIT_IMPLEMENTATION) != 0u) ? 1u : 0u;
        count -= ((omit & TEST_EAT_PSA_OMIT_COMPONENTS) != 0u) ? 1u : 0u;
        count += unknownClaimCount;
        count += (addLegacyNoMeasurements != 0) ? 1u : 0u;
        count += (claims->bootSeed.data != NULL) ? 1u : 0u;
        count += (claims->certificationReference.data != NULL) ? 1u : 0u;
        count += (claims->verificationServiceIndicator.data != NULL) ? 1u : 0u;
        count += ((omit & TEST_EAT_PSA_UNKNOWN_TEXT) != 0u) ? 1u : 0u;
        count += ((omit & TEST_EAT_PSA_DUP_UNKNOWN_TEXT) != 0u) ? 2u : 0u;
        ret = wc_CBOR_EncoderInit(&ctx, out, outSz);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&ctx, count);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((omit & TEST_EAT_PSA_OMIT_NONCE) == 0u)) {
        ret = wc_CBOR_EncodeUint(&ctx, 10u);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, claims->nonce.data, claims->nonce.len);
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((omit & TEST_EAT_PSA_OMIT_UEID) == 0u)) {
        ret = wc_CBOR_EncodeUint(&ctx, 256u);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, claims->ueid.data, claims->ueid.len);
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((omit & TEST_EAT_PSA_OMIT_PROFILE) == 0u)) {
        ret = wc_CBOR_EncodeUint(&ctx, 265u);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeTstr(&ctx, profile, profileLen);
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) && (claims->bootSeed.data != NULL)) {
        ret = wc_CBOR_EncodeUint(&ctx, 268u);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, claims->bootSeed.data,
                claims->bootSeed.len);
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((omit & TEST_EAT_PSA_OMIT_CLIENT_ID) == 0u)) {
        ret = wc_CBOR_EncodeUint(&ctx, 2394u);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeInt(&ctx, claims->clientId);
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((omit & TEST_EAT_PSA_OMIT_LIFECYCLE) == 0u)) {
        ret = wc_CBOR_EncodeUint(&ctx, 2395u);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeUint(&ctx, claims->lifecycle);
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((omit & TEST_EAT_PSA_OMIT_IMPLEMENTATION) == 0u)) {
        ret = wc_CBOR_EncodeUint(&ctx, 2396u);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, claims->implementationId.data,
                claims->implementationId.len);
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (claims->certificationReference.data != NULL)) {
        ret = wc_CBOR_EncodeUint(&ctx, 2398u);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeTstr(&ctx, claims->certificationReference.data,
                claims->certificationReference.len);
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((omit & TEST_EAT_PSA_OMIT_COMPONENTS) == 0u)) {
        ret = wc_CBOR_EncodeUint(&ctx, 2399u);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeArrayStart(&ctx, componentCount);
        }
        for (i = 0u; (ret == WOLFCOSE_SUCCESS) &&
             (i < componentCount); i++) {
            ret = test_eat_psa_encode_raw_component_ex(&ctx,
                &claims->components[i], componentFlags);
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (claims->verificationServiceIndicator.data != NULL)) {
        ret = wc_CBOR_EncodeUint(&ctx, 2400u);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeTstr(&ctx,
                claims->verificationServiceIndicator.data,
                claims->verificationServiceIndicator.len);
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) && (addLegacyNoMeasurements != 0)) {
        ret = wc_CBOR_EncodeInt(&ctx, -75007);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeUint(&ctx, 1u);
        }
    }
    for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < unknownClaimCount); i++) {
        ret = wc_CBOR_EncodeUint(&ctx, 5000u +
            (((omit & TEST_EAT_PSA_DUP_UNKNOWN_CLAIM) != 0u) && (i > 0u) ?
             0u : i));
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeUint(&ctx, 1u);
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((omit & TEST_EAT_PSA_UNKNOWN_TEXT) != 0u)) {
        ret = wc_CBOR_EncodeTstr(&ctx, unknownLabel, sizeof(unknownLabel) - 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((omit & TEST_EAT_PSA_UNKNOWN_TEXT) != 0u)) {
        ret = wc_CBOR_EncodeUint(&ctx, 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((omit & TEST_EAT_PSA_DUP_UNKNOWN_TEXT) != 0u)) {
        ret = wc_CBOR_EncodeTstr(&ctx, duplicateLabel,
            sizeof(duplicateLabel) - 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((omit & TEST_EAT_PSA_DUP_UNKNOWN_TEXT) != 0u)) {
        ret = wc_CBOR_EncodeUint(&ctx, 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((omit & TEST_EAT_PSA_DUP_UNKNOWN_TEXT) != 0u)) {
        ret = wc_CBOR_EncodeTstr(&ctx, duplicateLabel,
            sizeof(duplicateLabel) - 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((omit & TEST_EAT_PSA_DUP_UNKNOWN_TEXT) != 0u)) {
        ret = wc_CBOR_EncodeUint(&ctx, 2u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = ctx.idx;
    }

    return ret;
}

static int test_eat_psa_sign1_payload(WOLFCOSE_KEY* key, WC_RNG* rng,
    const uint8_t* payload, size_t payloadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen)
{
    return wc_CoseSign1_Sign(key, WOLFCOSE_ALG_ES256, NULL, 0u,
        payload, payloadLen, NULL, 0u, NULL, 0u, scratch, scratchSz,
        out, outSz, outLen, rng);
}

static int test_eat_psa_verify_raw_current_ex(WOLFCOSE_KEY* key, WC_RNG* rng,
    const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    const uint8_t* profile, size_t profileLen, uint32_t omit,
    size_t unknownClaimCount, int addLegacyNoMeasurements,
    uint32_t componentFlags, size_t componentCount,
    uint8_t* scratch, size_t scratchSz, WOLFCOSE_EAT_PSA_TOKEN* token)
{
    WOLFCOSE_EAT_PSA_TOKEN localToken;
    static uint8_t payload[4096];
    static uint8_t signedToken[4608];
    size_t payloadLen = 0u;
    size_t signedTokenLen = 0u;
    int ret;

    ret = test_eat_psa_encode_current_raw_ex(claims, profile, profileLen,
        omit, unknownClaimCount, addLegacyNoMeasurements, componentFlags,
        componentCount, payload, sizeof(payload), &payloadLen);
    if (ret == WOLFCOSE_SUCCESS) {
        ret = test_eat_psa_sign1_payload(key, rng, payload, payloadLen,
            scratch, scratchSz, signedToken, sizeof(signedToken),
            &signedTokenLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        if (token == NULL) {
            token = &localToken;
        }
        (void)memset(token, 0xA5, sizeof(*token));
        ret = wc_CoseEatPsaToken_Verify(key, signedToken, signedTokenLen,
            kNonce, sizeof(kNonce), scratch, scratchSz, token);
    }

    return ret;
}

static int test_eat_psa_verify_raw_current(WOLFCOSE_KEY* key, WC_RNG* rng,
    const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    const uint8_t* profile, size_t profileLen, uint32_t omit,
    size_t unknownClaimCount, int addLegacyNoMeasurements,
    uint8_t* scratch, size_t scratchSz)
{
    return test_eat_psa_verify_raw_current_ex(key, rng, claims, profile,
        profileLen, omit, unknownClaimCount, addLegacyNoMeasurements, 0u,
        (claims != NULL) ? claims->componentCount : 0u, scratch, scratchSz,
        NULL);
}
#endif

#if defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_SIGN1_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES256)
/* The issuer encodes lifecycle as uint16. Retaining that width makes zero a
 * non-preferred but valid CBOR representation, which tests claim validation. */
static int test_eat_psa_set_lifecycle(uint8_t* payload, size_t payloadLen,
    uint16_t lifecycle)
{
    int ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    size_t i;

    if (payload == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        for (i = 0u; (i + 5u) < payloadLen; i++) {
            if ((payload[i] == 0x19u) && (payload[i + 1u] == 0x09u) &&
                (payload[i + 2u] == 0x5Bu) && (payload[i + 3u] == 0x19u)) {
                payload[i + 4u] = (uint8_t)(lifecycle >> 8);
                payload[i + 5u] = (uint8_t)lifecycle;
                ret = WOLFCOSE_SUCCESS;
                break;
            }
        }
    }

    return ret;
}
#endif

#if defined(WOLFCOSE_EAT_PSA_UEID_RESOLVER) && \
    ((defined(WOLFCOSE_SIGN1_VERIFY) && defined(WOLFCOSE_HAVE_ES256)) || \
     (defined(WOLFCOSE_MAC0_VERIFY) && defined(WOLFCOSE_HAVE_HMAC256)))
typedef struct EAT_PSA_RESOLVER_CTX {
    const WOLFCOSE_KEY* key;
    int called;
    int fail;
    WOLFCOSE_EAT_PSA_PROFILE receivedProfile;
    int32_t receivedAlg;
} EAT_PSA_RESOLVER_CTX;
#endif

#if defined(WOLFCOSE_SIGN1_VERIFY) && defined(WOLFCOSE_HAVE_ES256)
typedef struct EAT_PSA_COMPONENT_CTX {
    int count;
    int valid;
    int fail;
    size_t expectedHashLen;
    const uint8_t* expectedVersion;
    size_t expectedVersionLen;
} EAT_PSA_COMPONENT_CTX;
#endif

#if (defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_SIGN1_VERIFY) && \
     defined(WOLFCOSE_HAVE_ES256)) || \
    (defined(WOLFCOSE_MAC0_CREATE) && defined(WOLFCOSE_MAC0_VERIFY) && \
     defined(WOLFCOSE_HAVE_HMAC256))
static void test_eat_psa_claims(WOLFCOSE_EAT_PSA_CLAIMS* claims,
    WOLFCOSE_EAT_PSA_COMPONENT* component)
{
    static const uint8_t type[] = "PRoT";
    static const uint8_t version[] = "1.2.3";
    static const uint8_t desc[] = "sha-256";
    static const uint8_t certRef[] = "1234567890123-12345";
    static const uint8_t vsi[] = "https://verifier.example/psa";

    (void)memset(claims, 0, sizeof(*claims));
    (void)memset(component, 0, sizeof(*component));
    component->measurementType.data = type;
    component->measurementType.len = sizeof(type) - 1u;
    component->measurementValue.data = kMeasurement;
    component->measurementValue.len = sizeof(kMeasurement);
    component->version.data = version;
    component->version.len = sizeof(version) - 1u;
    component->signerId.data = kSignerId;
    component->signerId.len = sizeof(kSignerId);
    component->measurementDesc.data = desc;
    component->measurementDesc.len = sizeof(desc) - 1u;
    claims->nonce.data = kNonce;
    claims->nonce.len = sizeof(kNonce);
    claims->ueid.data = kUeid;
    claims->ueid.len = sizeof(kUeid);
    claims->implementationId.data = kImplementationId;
    claims->implementationId.len = sizeof(kImplementationId);
    claims->bootSeed.data = kBootSeed;
    claims->bootSeed.len = sizeof(kBootSeed);
    claims->certificationReference.data = certRef;
    claims->certificationReference.len = sizeof(certRef) - 1u;
    claims->verificationServiceIndicator.data = vsi;
    claims->verificationServiceIndicator.len = sizeof(vsi) - 1u;
    claims->clientId = -1;
    claims->lifecycle = 0x3000u;
    claims->components = component;
    claims->componentCount = 1u;
}
#endif

#if defined(WOLFCOSE_EAT_PSA_UEID_RESOLVER) && \
    ((defined(WOLFCOSE_SIGN1_VERIFY) && defined(WOLFCOSE_HAVE_ES256)) || \
     (defined(WOLFCOSE_MAC0_VERIFY) && defined(WOLFCOSE_HAVE_HMAC256)))
static int test_eat_psa_resolve(void* ctx,
    WOLFCOSE_EAT_PSA_PROFILE profile,
    const uint8_t* ueid, size_t ueidLen, int32_t alg,
    WOLFCOSE_KEY* key)
{
    EAT_PSA_RESOLVER_CTX* resolver = (EAT_PSA_RESOLVER_CTX*)ctx;

    if ((resolver == NULL) || (key == NULL) ||
        (profile == WOLFCOSE_EAT_PSA_PROFILE_NONE) ||
        (ueid == NULL) || (ueidLen != sizeof(kUeid)) ||
        (memcmp(ueid, kUeid, sizeof(kUeid)) != 0) ||
        ((alg != WOLFCOSE_ALG_ES256) &&
         (alg != WOLFCOSE_ALG_HMAC_256_256))) {
        return WOLFCOSE_E_EAT_PSA_KEY;
    }
    resolver->receivedProfile = profile;
    resolver->receivedAlg = alg;
    resolver->called++;
    if (resolver->fail != 0) {
        return WOLFCOSE_E_EAT_PSA_KEY;
    }
    *key = *resolver->key;
    return WOLFCOSE_SUCCESS;
}
#endif

#if defined(WOLFCOSE_EAT_PSA_UEID_RESOLVER) && \
    defined(WOLFCOSE_MAC0_VERIFY) && defined(WOLFCOSE_HAVE_HMAC256)
static int test_eat_psa_resolve_without_ctx(void* ctx,
    WOLFCOSE_EAT_PSA_PROFILE profile,
    const uint8_t* ueid, size_t ueidLen, int32_t alg,
    WOLFCOSE_KEY* key)
{
    if ((ctx != NULL) || (key == NULL) ||
        (profile != WOLFCOSE_EAT_PSA_PROFILE_CURRENT) ||
        (ueid == NULL) || (ueidLen != sizeof(kUeid)) ||
        (memcmp(ueid, kUeid, sizeof(kUeid)) != 0) ||
        (alg != WOLFCOSE_ALG_HMAC_256_256)) {
        return WOLFCOSE_E_EAT_PSA_KEY;
    }

    return wc_CoseKey_SetSymmetric(key, kMac0TestKey,
        sizeof(kMac0TestKey));
}
#endif

#if defined(WOLFCOSE_SIGN1_VERIFY) && defined(WOLFCOSE_HAVE_ES256)
static int test_eat_psa_component(void* ctx,
    const WOLFCOSE_EAT_PSA_COMPONENT* component)
{
    EAT_PSA_COMPONENT_CTX* componentCtx = (EAT_PSA_COMPONENT_CTX*)ctx;

    if ((componentCtx == NULL) || (component == NULL) ||
        ((component->measurementValue.len != 32u) &&
         (component->measurementValue.len != 48u) &&
         (component->measurementValue.len != 64u)) ||
        ((component->signerId.len != 32u) &&
         (component->signerId.len != 48u) &&
         (component->signerId.len != 64u)) ||
        ((componentCtx->expectedHashLen != 0u) &&
         ((component->measurementValue.len != componentCtx->expectedHashLen) ||
          (component->signerId.len != componentCtx->expectedHashLen))) ||
        ((componentCtx->expectedVersion != NULL) &&
         ((component->version.len != componentCtx->expectedVersionLen) ||
          (component->version.data == NULL) ||
          (memcmp(component->version.data, componentCtx->expectedVersion,
              componentCtx->expectedVersionLen) != 0)))) {
        return WOLFCOSE_E_EAT_PSA_CLAIM;
    }
    componentCtx->count++;
    componentCtx->valid = 1;
    return (componentCtx->fail != 0) ? WOLFCOSE_E_EAT_PSA_CLAIM :
                                       WOLFCOSE_SUCCESS;
}

static int test_eat_psa_component_without_ctx(void* ctx,
    const WOLFCOSE_EAT_PSA_COMPONENT* component)
{
    if ((ctx != NULL) || (component == NULL) ||
        (component->measurementValue.data == NULL) ||
        (component->measurementValue.len != sizeof(kMeasurement)) ||
        (memcmp(component->measurementValue.data, kMeasurement,
            sizeof(kMeasurement)) != 0)) {
        return WOLFCOSE_E_EAT_PSA_CLAIM;
    }

    return WOLFCOSE_SUCCESS;
}
#endif

static int test_eat_psa_token_is_zero(
    const WOLFCOSE_EAT_PSA_TOKEN* token);

#if defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_SIGN1_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES256)
static void test_eat_psa_nonce_and_hash_lengths(WOLFCOSE_KEY* key, WC_RNG* rng)
{
    static const size_t lengths[] = { 32u, 48u, 64u };
    static uint8_t nonce[64];
    static uint8_t hash[64];
    static uint8_t wrongNonce[64];
    WOLFCOSE_EAT_PSA_CLAIMS claims;
    WOLFCOSE_EAT_PSA_COMPONENT component;
    WOLFCOSE_EAT_PSA_TOKEN token;
    EAT_PSA_COMPONENT_CTX componentCtx;
    uint8_t claimsBuf[1024];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t tokenBuf[1536];
    size_t i;
    size_t j;
    size_t tokenLen;
    int ret;

    (void)printf("  [RFC 9783 nonce and component hash lengths]\n");
    for (i = 0u; i < (sizeof(lengths) / sizeof(lengths[0])); i++) {
        for (j = 0u; j < lengths[i]; j++) {
            nonce[j] = (uint8_t)(0x20u + j);
            hash[j] = (uint8_t)(0x80u + j);
        }
        test_eat_psa_claims(&claims, &component);
        claims.nonce.data = nonce;
        claims.nonce.len = lengths[i];
        component.measurementValue.data = hash;
        component.measurementValue.len = lengths[i];
        component.signerId.data = hash;
        component.signerId.len = lengths[i];
        tokenLen = 0u;
        ret = wc_CoseEatPsaToken_CreateSign1(key, WOLFCOSE_ALG_ES256,
            &claims, claimsBuf, sizeof(claimsBuf), scratch, sizeof(scratch),
            tokenBuf, sizeof(tokenBuf), &tokenLen, rng);
        TEST_ASSERT(ret == WOLFCOSE_SUCCESS && tokenLen > 0u,
            "issue PSA token with supported nonce and component hash length");
        if (ret == WOLFCOSE_SUCCESS) {
            (void)memset(&token, 0, sizeof(token));
            ret = wc_CoseEatPsaToken_Verify(key, tokenBuf, tokenLen, nonce,
                lengths[i], scratch, sizeof(scratch), &token);
            TEST_ASSERT(ret == WOLFCOSE_SUCCESS && token.nonce.len == lengths[i],
                "verify PSA token with supported nonce length");
        }
        if (ret == WOLFCOSE_SUCCESS) {
            (void)memset(&componentCtx, 0, sizeof(componentCtx));
            componentCtx.expectedHashLen = lengths[i];
            componentCtx.expectedVersion = component.version.data;
            componentCtx.expectedVersionLen = component.version.len;
            ret = wc_CoseEatPsaToken_ForEachComponent(&token,
                test_eat_psa_component, &componentCtx);
            TEST_ASSERT(ret == WOLFCOSE_SUCCESS && componentCtx.count == 1 &&
                        componentCtx.valid != 0,
                "iterate complete supported component hash length and version");
        }
        if (tokenLen > 0u) {
            (void)memcpy(wrongNonce, nonce, lengths[i]);
            wrongNonce[0] ^= 0xFFu;
            ret = wc_CoseEatPsaToken_Verify(key, tokenBuf, tokenLen,
                wrongNonce, lengths[i], scratch, sizeof(scratch), &token);
            TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_NONCE,
                "reject same-length mismatched PSA nonce");
        }
        if ((tokenLen > 0u) && (lengths[i] == 32u)) {
            for (j = 0u; j < 48u; j++) {
                wrongNonce[j] = (uint8_t)(0x40u + j);
            }
            (void)memset(&token, 0xA5, sizeof(token));
            ret = wc_CoseEatPsaToken_Verify(key, tokenBuf, tokenLen,
                wrongNonce, 48u, scratch, sizeof(scratch), &token);
            TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_NONCE &&
                        test_eat_psa_token_is_zero(&token) != 0,
                "reject valid but different expected nonce length");
        }
    }
}
#endif

static int test_eat_psa_token_is_zero(const WOLFCOSE_EAT_PSA_TOKEN* token)
{
    WOLFCOSE_EAT_PSA_TOKEN zeroToken;

    (void)memset(&zeroToken, 0, sizeof(zeroToken));
    return ((token != NULL) &&
            (memcmp(token, &zeroToken, sizeof(zeroToken)) == 0)) ? 1 : 0;
}

#if defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_SIGN1_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES256)
static int test_eat_psa_replace_once(const uint8_t* in, size_t inLen,
    const uint8_t* find, size_t findLen,
    const uint8_t* replacement, size_t replacementLen,
    uint8_t* out, size_t outSz, size_t* outLen)
{
    size_t i;
    int ret = WOLFCOSE_E_INVALID_ARG;

    if (outLen != NULL) {
        *outLen = 0u;
    }
    if ((in == NULL) || (find == NULL) || (replacement == NULL) ||
        (out == NULL) || (outLen == NULL) || (findLen == 0u) ||
        (findLen > inLen) || (replacementLen == 0u)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((outSz < inLen) ||
             ((replacementLen > findLen) &&
              ((replacementLen - findLen) > (outSz - inLen)))) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }
    else {
        for (i = 0u; i <= (inLen - findLen); i++) {
            if (memcmp(&in[i], find, findLen) == 0) {
                (void)memcpy(out, in, i);
                (void)memcpy(&out[i], replacement, replacementLen);
                (void)memcpy(&out[i + replacementLen], &in[i + findLen],
                    inLen - i - findLen);
                *outLen = inLen - findLen + replacementLen;
                ret = WOLFCOSE_SUCCESS;
                break;
            }
        }
    }

    return ret;
}

static void test_eat_psa_nonpreferred_claim_form(WOLFCOSE_KEY* key,
    WC_RNG* rng, const uint8_t* payload, size_t payloadLen,
    const uint8_t* find, size_t findLen,
    const uint8_t* replacement, size_t replacementLen,
    const char* strictName, const char* acceptName)
{
    WOLFCOSE_CBOR_CTX ctx;
    WOLFCOSE_EAT_PSA_TOKEN token;
    uint8_t variant[1024];
    uint8_t signedToken[1536];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    size_t variantLen = 0u;
    size_t signedTokenLen = 0u;
    int ret;

    ret = test_eat_psa_replace_once(payload, payloadLen, find, findLen,
        replacement, replacementLen, variant, sizeof(variant), &variantLen);
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS,
        "construct non-preferred authenticated claim form");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecoderInit(&ctx, variant, variantLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_Skip(&ctx);
    }
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED, strictName);

    ret = test_eat_psa_sign1_payload(key, rng, variant, variantLen, scratch,
        sizeof(scratch), signedToken, sizeof(signedToken), &signedTokenLen);
    if (ret == WOLFCOSE_SUCCESS) {
        (void)memset(&token, 0xA5, sizeof(token));
        ret = wc_CoseEatPsaToken_Verify(key, signedToken, signedTokenLen,
            kNonce, sizeof(kNonce), scratch, sizeof(scratch), &token);
    }
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS &&
                token.profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT &&
                token.clientId == -1 && token.lifecycle == 0x3000u,
        acceptName);
}

static void test_eat_psa_nonpreferred_claim_forms(WOLFCOSE_KEY* key,
    WC_RNG* rng, const uint8_t* payload, size_t payloadLen)
{
    static const uint8_t findMap[] = { 0xAAu };
    static const uint8_t replaceMap[] = { 0xB8u, 0x0Au };
    static const uint8_t findNonce[] = { 0x0Au, 0x58u, 0x20u };
    static const uint8_t replaceNonce[] = {
        0x0Au, 0x59u, 0x00u, 0x20u
    };
    static const uint8_t findComponents[] = {
        0x19u, 0x09u, 0x5Fu, 0x81u
    };
    static const uint8_t replaceComponents[] = {
        0x19u, 0x09u, 0x5Fu, 0x98u, 0x01u
    };
    static const uint8_t findLifecycle[] = {
        0x19u, 0x09u, 0x5Bu, 0x19u, 0x30u, 0x00u
    };
    static const uint8_t replaceLifecycle[] = {
        0x19u, 0x09u, 0x5Bu, 0x1Au, 0x00u, 0x00u, 0x30u, 0x00u
    };
    static const uint8_t findClientId[] = {
        0x19u, 0x09u, 0x5Au, 0x20u
    };
    static const uint8_t replaceClientId[] = {
        0x19u, 0x09u, 0x5Au, 0x38u, 0x00u
    };

    (void)printf("  [RFC 9783 non-preferred authenticated claims]\n");
    test_eat_psa_nonpreferred_claim_form(key, rng, payload, payloadLen,
        findMap, sizeof(findMap), replaceMap, sizeof(replaceMap),
        "strict decoder rejects non-preferred claim map length",
        "PSA verifier accepts non-preferred claim map length");
    test_eat_psa_nonpreferred_claim_form(key, rng, payload, payloadLen,
        findNonce, sizeof(findNonce), replaceNonce, sizeof(replaceNonce),
        "strict decoder rejects non-preferred nonce bstr length",
        "PSA verifier accepts non-preferred nonce bstr length");
    test_eat_psa_nonpreferred_claim_form(key, rng, payload, payloadLen,
        findComponents, sizeof(findComponents), replaceComponents,
        sizeof(replaceComponents),
        "strict decoder rejects non-preferred component array length",
        "PSA verifier accepts non-preferred component array length");
    test_eat_psa_nonpreferred_claim_form(key, rng, payload, payloadLen,
        findLifecycle, sizeof(findLifecycle), replaceLifecycle,
        sizeof(replaceLifecycle),
        "strict decoder rejects non-preferred lifecycle value",
        "PSA verifier accepts non-preferred lifecycle value");
    test_eat_psa_nonpreferred_claim_form(key, rng, payload, payloadLen,
        findClientId, sizeof(findClientId), replaceClientId,
        sizeof(replaceClientId),
        "strict decoder rejects non-preferred signed client ID",
        "PSA verifier accepts non-preferred signed client ID");
}
#endif

static int test_eat_psa_bytes_are_zero(const uint8_t* buf, size_t len)
{
    size_t i;
    int ret = 1;

    if (buf == NULL) {
        ret = 0;
    }
    for (i = 0u; (i < len) && (ret != 0); i++) {
        if (buf[i] != 0u) {
            ret = 0;
        }
    }

    return ret;
}

#if defined(WOLFCOSE_SIGN1_VERIFY) && defined(WOLFCOSE_HAVE_ES256)
/* Exercise the PSA/EAT envelope pre-parser directly through its public
 * verifier entry point. Every failure must leave application-facing claims
 * cleared because these inputs are unauthenticated. */
static void test_eat_psa_expect_envelope_failure(const WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz, uint8_t* scratch, size_t scratchSz,
    int expected, const char* name)
{
    WOLFCOSE_EAT_PSA_TOKEN token;
    int ret;

    (void)memset(&token, 0xA5, sizeof(token));
    ret = wc_CoseEatPsaToken_Verify(key, in, inSz, kNonce, sizeof(kNonce),
        scratch, scratchSz, &token);
    TEST_ASSERT(ret == expected && test_eat_psa_token_is_zero(&token) != 0,
        name);
}
#endif

#if defined(WOLFCOSE_SIGN1_VERIFY) && defined(WOLFCOSE_HAVE_ES256)
static void test_eat_psa_verify_argument_guards(const WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz, uint8_t* scratch, size_t scratchSz)
{
    WOLFCOSE_EAT_PSA_TOKEN token;
    int ret;

    (void)printf("  [RFC 9783 verifier argument contracts]\n");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = wc_CoseEatPsaToken_Verify(NULL, in, inSz, kNonce, sizeof(kNonce),
        scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject NULL PSA verification key and clear token output");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = wc_CoseEatPsaToken_Verify(key, NULL, inSz, kNonce, sizeof(kNonce),
        scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject NULL PSA token input and clear token output");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = wc_CoseEatPsaToken_Verify(key, in, inSz, NULL, sizeof(kNonce),
        scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject NULL expected PSA nonce and clear token output");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = wc_CoseEatPsaToken_Verify(key, in, inSz, kNonce, sizeof(kNonce),
        NULL, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject NULL PSA verification scratch and clear token output");

    ret = wc_CoseEatPsaToken_Verify(key, in, inSz, kNonce, sizeof(kNonce),
        scratch, scratchSz, NULL);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG,
        "reject NULL PSA token output");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = wc_CoseEatPsaToken_Verify(key, in, inSz, kNonce, 31u, scratch,
        scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject unsupported expected PSA nonce length and clear token output");

#if defined(WOLFCOSE_EAT_PSA_UEID_RESOLVER)
    (void)memset(&token, 0xA5, sizeof(token));
    ret = wc_CoseEatPsaToken_VerifyByUeid(NULL, NULL, in, inSz, kNonce,
        sizeof(kNonce), scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject NULL PSA UEID resolver and clear token output");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = wc_CoseEatPsaToken_VerifyByUeid(test_eat_psa_resolve, NULL, NULL,
        inSz, kNonce, sizeof(kNonce), scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject NULL UEID-resolver token input and clear token output");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = wc_CoseEatPsaToken_VerifyByUeid(test_eat_psa_resolve, NULL, in,
        inSz, NULL, sizeof(kNonce), scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject NULL UEID-resolver nonce and clear token output");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = wc_CoseEatPsaToken_VerifyByUeid(test_eat_psa_resolve, NULL, in,
        inSz, kNonce, sizeof(kNonce), NULL, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject NULL UEID-resolver scratch and clear token output");

    ret = wc_CoseEatPsaToken_VerifyByUeid(test_eat_psa_resolve, NULL, in,
        inSz, kNonce, sizeof(kNonce), scratch, scratchSz, NULL);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG,
        "reject NULL UEID-resolver token output");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = wc_CoseEatPsaToken_VerifyByUeid(test_eat_psa_resolve, NULL, in,
        inSz, kNonce, 31u, scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject unsupported UEID-resolver nonce length and clear token output");
#endif
}
#endif

#if defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_SIGN1_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES256)
/* Construct a valid Sign1 whose inner protected-header map uses a
 * non-preferred definite-length encoding. This distinguishes propagation of
 * the decode option into the inner header parser from accepting only a
 * non-preferred outer tag. */
static void test_eat_psa_nonpreferred_protected_sign1(WOLFCOSE_KEY* key,
    WC_RNG* rng)
{
    static const uint8_t protectedHdr[] = {
        0xB8u, 0x01u, 0x01u, 0x26u
    };
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t digest[32];
    uint8_t signature[64];
    uint8_t message[256];
    WOLFCOSE_CBOR_CTX ctx;
    WOLFCOSE_HDR hdr;
    const uint8_t* verifiedPayload = NULL;
    size_t verifiedPayloadLen = 0u;
    size_t structureLen = 0u;
    size_t signatureLen = sizeof(signature);
    size_t messageLen = 0u;
    int ret;
    int testRet;

    ret = wolfCose_BuildToBeSignedMaced(WOLFCOSE_CTX_SIGNATURE1,
        sizeof(WOLFCOSE_CTX_SIGNATURE1), protectedHdr, sizeof(protectedHdr),
        NULL, 0u, NULL, 0u, kNonce, sizeof(kNonce), scratch,
        sizeof(scratch), &structureLen);
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_Hash(WC_SHA256, scratch, (word32)structureLen, digest,
            (word32)sizeof(digest));
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EccSignRaw(digest, sizeof(digest), signature,
            &signatureLen, 32u, WC_HASH_TYPE_SHA256, rng, key->key.ecc);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncoderInit(&ctx, message, sizeof(message));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeTag(&ctx, WOLFCOSE_TAG_SIGN1);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, 4u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, protectedHdr, sizeof(protectedHdr));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&ctx, 0u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, kNonce, sizeof(kNonce));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, signature, signatureLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        messageLen = ctx.idx;
    }
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS,
        "construct Sign1 with non-preferred protected header");
    if (ret == WOLFCOSE_SUCCESS) {
        testRet = wc_CoseSign1_Verify(key, message, messageLen, NULL, 0u,
            NULL, 0u, scratch, sizeof(scratch), &hdr, &verifiedPayload,
            &verifiedPayloadLen);
        TEST_ASSERT(testRet != WOLFCOSE_SUCCESS,
            "strict Sign1 rejects non-preferred protected header");
        testRet = wolfCose_Sign1_Verify_ex(key, message, messageLen, NULL, 0u,
            NULL, 0u, scratch, sizeof(scratch), &hdr, &verifiedPayload,
            &verifiedPayloadLen, WOLFCOSE_COSE_DECODE_ALLOW_NONPREFERRED);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                    verifiedPayloadLen == sizeof(kNonce),
            "Sign1 decode-option API accepts non-preferred protected header");
    }
    (void)wolfCose_ForceZero(digest, sizeof(digest));
    (void)wolfCose_ForceZero(signature, sizeof(signature));
}
#endif

#if defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_SIGN1_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES256)
/* The unprotected map is outside Sig_structure. Replacing its preferred empty
 * map header keeps the signature valid while testing decode-flag propagation
 * through the unprotected-header parser. */
static void test_eat_psa_nonpreferred_unprotected_sign1(WOLFCOSE_KEY* key,
    WC_RNG* rng)
{
    static const uint8_t expectedPrefix[] = {
        0xD2u, 0x84u, 0x43u, 0xA1u, 0x01u, 0x26u, 0xA0u
    };
    static const uint8_t textUnprotected[] = {
        0xA1u, 0x66u, 'v', 'e', 'n', 'd', 'o', 'r', 0x00u
    };
    static const uint8_t nonPreferredTextUnprotected[] = {
        0xA1u, 0x78u, 0x06u, 'v', 'e', 'n', 'd', 'o', 'r', 0x00u
    };
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[256];
    uint8_t nonPreferred[266];
    WOLFCOSE_HDR hdr;
    const uint8_t* verifiedPayload = NULL;
    size_t verifiedPayloadLen = 0u;
    size_t messageLen = 0u;
    size_t nonPreferredLen = 0u;
    int ret;
    int testRet;

    ret = wc_CoseSign1_Sign(key, WOLFCOSE_ALG_ES256, NULL, 0u, kNonce,
        sizeof(kNonce), NULL, 0u, NULL, 0u, scratch, sizeof(scratch), message,
        sizeof(message), &messageLen, rng);
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS,
        "construct Sign1 with preferred empty unprotected header");
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((messageLen < sizeof(expectedPrefix)) ||
         (memcmp(message, expectedPrefix, sizeof(expectedPrefix)) != 0))) {
        TEST_ASSERT(0, "expected deterministic Sign1 header layout");
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        (void)memcpy(nonPreferred, message, sizeof(expectedPrefix) - 1u);
        nonPreferred[sizeof(expectedPrefix) - 1u] = 0xB8u;
        nonPreferred[sizeof(expectedPrefix)] = 0x00u;
        (void)memcpy(&nonPreferred[sizeof(expectedPrefix) + 1u],
            &message[sizeof(expectedPrefix)],
            messageLen - sizeof(expectedPrefix));
        nonPreferredLen = messageLen + 1u;

        testRet = wc_CoseSign1_Verify(key, nonPreferred, nonPreferredLen,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr,
            &verifiedPayload, &verifiedPayloadLen);
        TEST_ASSERT(testRet != WOLFCOSE_SUCCESS,
            "strict Sign1 rejects non-preferred unprotected header");

        testRet = wolfCose_Sign1_Verify_ex(key, nonPreferred, nonPreferredLen,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr,
            &verifiedPayload, &verifiedPayloadLen,
            WOLFCOSE_COSE_DECODE_ALLOW_NONPREFERRED);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                    hdr.alg == WOLFCOSE_ALG_ES256 &&
                    verifiedPayloadLen == sizeof(kNonce) &&
                    memcmp(verifiedPayload, kNonce, sizeof(kNonce)) == 0,
            "Sign1 decode-option API accepts non-preferred unprotected header");

        (void)memcpy(nonPreferred, message, sizeof(expectedPrefix) - 1u);
        (void)memcpy(&nonPreferred[sizeof(expectedPrefix) - 1u],
            textUnprotected, sizeof(textUnprotected));
        (void)memcpy(&nonPreferred[sizeof(expectedPrefix) - 1u +
            sizeof(textUnprotected)], &message[sizeof(expectedPrefix)],
            messageLen - sizeof(expectedPrefix));
        nonPreferredLen = messageLen - 1u + sizeof(textUnprotected);
        testRet = wc_CoseSign1_Verify(key, nonPreferred, nonPreferredLen,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr,
            &verifiedPayload, &verifiedPayloadLen);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                    verifiedPayloadLen == sizeof(kNonce),
            "Sign1 accepts authenticated preferred tstr header extension");

        (void)memcpy(nonPreferred, message, sizeof(expectedPrefix) - 1u);
        (void)memcpy(&nonPreferred[sizeof(expectedPrefix) - 1u],
            nonPreferredTextUnprotected, sizeof(nonPreferredTextUnprotected));
        (void)memcpy(&nonPreferred[sizeof(expectedPrefix) - 1u +
            sizeof(nonPreferredTextUnprotected)], &message[sizeof(expectedPrefix)],
            messageLen - sizeof(expectedPrefix));
        nonPreferredLen = messageLen - 1u + sizeof(nonPreferredTextUnprotected);
        testRet = wc_CoseSign1_Verify(key, nonPreferred, nonPreferredLen,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr,
            &verifiedPayload, &verifiedPayloadLen);
        TEST_ASSERT(testRet != WOLFCOSE_SUCCESS,
            "strict Sign1 rejects non-preferred tstr header extension");
        testRet = wolfCose_Sign1_Verify_ex(key, nonPreferred, nonPreferredLen,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr,
            &verifiedPayload, &verifiedPayloadLen,
            WOLFCOSE_COSE_DECODE_ALLOW_NONPREFERRED);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                    verifiedPayloadLen == sizeof(kNonce),
            "Sign1 decode-option API accepts non-preferred tstr header extension");
    }
}
#endif

#if defined(WOLFCOSE_MAC0_VERIFY) && defined(WOLFCOSE_HAVE_HMAC256)
/* Same inner-header propagation test for Mac0. The construction is manually
 * MACed so its protected bytes stay intentionally non-preferred. */
static void test_eat_psa_nonpreferred_protected_mac0(const WOLFCOSE_KEY* key)
{
    static const uint8_t protectedHdr[] = {
        0xB8u, 0x01u, 0x01u, 0x05u
    };
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t tag[32];
    uint8_t message[256];
    WOLFCOSE_CBOR_CTX ctx;
    WOLFCOSE_HDR hdr;
    const uint8_t* verifiedPayload = NULL;
    size_t verifiedPayloadLen = 0u;
    size_t structureLen = 0u;
    size_t messageLen = 0u;
    Hmac hmac;
    int hmacInited = 0;
    int ret;
    int testRet;

    ret = wolfCose_BuildToBeSignedMaced(WOLFCOSE_CTX_MAC0,
        sizeof(WOLFCOSE_CTX_MAC0), protectedHdr, sizeof(protectedHdr), NULL,
        0u, NULL, 0u, kNonce, sizeof(kNonce), scratch, sizeof(scratch),
        &structureLen);
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
        ret = wc_HmacSetKey(&hmac, WC_SHA256, key->key.symm.key,
            (word32)key->key.symm.keyLen);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_HmacUpdate(&hmac, scratch, (word32)structureLen);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_HmacFinal(&hmac, tag);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncoderInit(&ctx, message, sizeof(message));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeTag(&ctx, WOLFCOSE_TAG_MAC0);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, 4u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, protectedHdr, sizeof(protectedHdr));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&ctx, 0u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, kNonce, sizeof(kNonce));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, tag, sizeof(tag));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        messageLen = ctx.idx;
    }
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS,
        "construct Mac0 with non-preferred protected header");
    if (ret == WOLFCOSE_SUCCESS) {
        testRet = wc_CoseMac0_Verify(key, message, messageLen, NULL, 0u,
            NULL, 0u, scratch, sizeof(scratch), &hdr, &verifiedPayload,
            &verifiedPayloadLen);
        TEST_ASSERT(testRet != WOLFCOSE_SUCCESS,
            "strict Mac0 rejects non-preferred protected header");
        testRet = wolfCose_Mac0_Verify_ex(key, message, messageLen, NULL, 0u,
            NULL, 0u, scratch, sizeof(scratch), &hdr, &verifiedPayload,
            &verifiedPayloadLen, WOLFCOSE_COSE_DECODE_ALLOW_NONPREFERRED);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                    verifiedPayloadLen == sizeof(kNonce),
            "Mac0 decode-option API accepts non-preferred protected header");
    }
    if (hmacInited != 0) {
        (void)wc_HmacFree(&hmac);
    }
    (void)wolfCose_ForceZero(tag, sizeof(tag));
}
#endif

#if defined(WOLFCOSE_MAC0_CREATE) && defined(WOLFCOSE_MAC0_VERIFY) && \
    defined(WOLFCOSE_HAVE_HMAC256)
/* This mirrors the Sign1 fixture above for the Mac0 unprotected-header path. */
static void test_eat_psa_nonpreferred_unprotected_mac0(const WOLFCOSE_KEY* key)
{
    static const uint8_t expectedPrefix[] = {
        0xD1u, 0x84u, 0x43u, 0xA1u, 0x01u, 0x05u, 0xA0u
    };
    static const uint8_t textUnprotected[] = {
        0xA1u, 0x66u, 'v', 'e', 'n', 'd', 'o', 'r', 0x00u
    };
    static const uint8_t nonPreferredTextUnprotected[] = {
        0xA1u, 0x78u, 0x06u, 'v', 'e', 'n', 'd', 'o', 'r', 0x00u
    };
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[256];
    uint8_t nonPreferred[266];
    WOLFCOSE_HDR hdr;
    const uint8_t* verifiedPayload = NULL;
    size_t verifiedPayloadLen = 0u;
    size_t messageLen = 0u;
    size_t nonPreferredLen = 0u;
    int ret;
    int testRet;

    ret = wc_CoseMac0_Create(key, WOLFCOSE_ALG_HMAC_256_256, NULL, 0u,
        kNonce, sizeof(kNonce), NULL, 0u, NULL, 0u, scratch, sizeof(scratch),
        message, sizeof(message), &messageLen);
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS,
        "construct Mac0 with preferred empty unprotected header");
    if ((ret == WOLFCOSE_SUCCESS) &&
        ((messageLen < sizeof(expectedPrefix)) ||
         (memcmp(message, expectedPrefix, sizeof(expectedPrefix)) != 0))) {
        TEST_ASSERT(0, "expected deterministic Mac0 header layout");
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        (void)memcpy(nonPreferred, message, sizeof(expectedPrefix) - 1u);
        nonPreferred[sizeof(expectedPrefix) - 1u] = 0xB8u;
        nonPreferred[sizeof(expectedPrefix)] = 0x00u;
        (void)memcpy(&nonPreferred[sizeof(expectedPrefix) + 1u],
            &message[sizeof(expectedPrefix)],
            messageLen - sizeof(expectedPrefix));
        nonPreferredLen = messageLen + 1u;

        testRet = wc_CoseMac0_Verify(key, nonPreferred, nonPreferredLen,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr,
            &verifiedPayload, &verifiedPayloadLen);
        TEST_ASSERT(testRet != WOLFCOSE_SUCCESS,
            "strict Mac0 rejects non-preferred unprotected header");

        testRet = wolfCose_Mac0_Verify_ex(key, nonPreferred, nonPreferredLen,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr,
            &verifiedPayload, &verifiedPayloadLen,
            WOLFCOSE_COSE_DECODE_ALLOW_NONPREFERRED);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                    hdr.alg == WOLFCOSE_ALG_HMAC_256_256 &&
                    verifiedPayloadLen == sizeof(kNonce) &&
                    memcmp(verifiedPayload, kNonce, sizeof(kNonce)) == 0,
            "Mac0 decode-option API accepts non-preferred unprotected header");

        (void)memcpy(nonPreferred, message, sizeof(expectedPrefix) - 1u);
        (void)memcpy(&nonPreferred[sizeof(expectedPrefix) - 1u],
            textUnprotected, sizeof(textUnprotected));
        (void)memcpy(&nonPreferred[sizeof(expectedPrefix) - 1u +
            sizeof(textUnprotected)], &message[sizeof(expectedPrefix)],
            messageLen - sizeof(expectedPrefix));
        nonPreferredLen = messageLen - 1u + sizeof(textUnprotected);
        testRet = wc_CoseMac0_Verify(key, nonPreferred, nonPreferredLen,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr,
            &verifiedPayload, &verifiedPayloadLen);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                    verifiedPayloadLen == sizeof(kNonce),
            "Mac0 accepts authenticated preferred tstr header extension");

        (void)memcpy(nonPreferred, message, sizeof(expectedPrefix) - 1u);
        (void)memcpy(&nonPreferred[sizeof(expectedPrefix) - 1u],
            nonPreferredTextUnprotected, sizeof(nonPreferredTextUnprotected));
        (void)memcpy(&nonPreferred[sizeof(expectedPrefix) - 1u +
            sizeof(nonPreferredTextUnprotected)], &message[sizeof(expectedPrefix)],
            messageLen - sizeof(expectedPrefix));
        nonPreferredLen = messageLen - 1u + sizeof(nonPreferredTextUnprotected);
        testRet = wc_CoseMac0_Verify(key, nonPreferred, nonPreferredLen,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr,
            &verifiedPayload, &verifiedPayloadLen);
        TEST_ASSERT(testRet != WOLFCOSE_SUCCESS,
            "strict Mac0 rejects non-preferred tstr header extension");
        testRet = wolfCose_Mac0_Verify_ex(key, nonPreferred, nonPreferredLen,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr,
            &verifiedPayload, &verifiedPayloadLen,
            WOLFCOSE_COSE_DECODE_ALLOW_NONPREFERRED);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                    verifiedPayloadLen == sizeof(kNonce),
            "Mac0 decode-option API accepts non-preferred tstr header extension");
    }
}
#endif

#if defined(WOLFCOSE_EXT_SIGN) && defined(WOLFCOSE_SIGN1_SIGN) && \
    defined(WOLFCOSE_SIGN1_VERIFY) && defined(WOLFCOSE_HAVE_ES256)
typedef struct EAT_PSA_EXT_SIGN_CTX {
    WC_RNG* rng;
    ecc_key* key;
    int called;
    int fail;
} EAT_PSA_EXT_SIGN_CTX;

static int test_eat_psa_ext_sign_cb(void* cbCtx, int32_t alg,
    const uint8_t* tbs, size_t tbsSz, uint8_t* sig, size_t sigSz,
    size_t* sigLen)
{
    EAT_PSA_EXT_SIGN_CTX* ctx = (EAT_PSA_EXT_SIGN_CTX*)cbCtx;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    int ret;

    if ((ctx == NULL) || (sigLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ctx->called++;
        if (ctx->fail != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            *sigLen = sigSz;
            ret = wolfCose_AlgToHashType(alg, &hashType);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wolfCose_EccSignRaw(tbs, tbsSz, sig, sigLen, 32u,
                    hashType, ctx->rng, ctx->key);
            }
        }
    }

    return ret;
}
#endif

#if (defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_SIGN1_VERIFY) && \
     defined(WOLFCOSE_HAVE_ES256)) || \
    (defined(WOLFCOSE_MAC0_CREATE) && defined(WOLFCOSE_MAC0_VERIFY) && \
     defined(WOLFCOSE_HAVE_HMAC256))
static int test_eat_psa_encode_legacy(const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    uint8_t* out, size_t outSz, size_t* outLen, int omitProfile,
    int noMeasurements, int incompatibleProfile)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    static const uint8_t profile[] = WOLFCOSE_EAT_PSA_PROFILE_LEGACY;
    static const uint8_t wrongProfile[] = "not-a-legacy-profile";
    const uint8_t* profileText = (incompatibleProfile != 0) ? wrongProfile :
                                                              profile;
    size_t profileLen = (incompatibleProfile != 0) ?
        (sizeof(wrongProfile) - 1u) : (sizeof(profile) - 1u);
    size_t count = (omitProfile != 0) ? 7u : 8u;

    if (claims->verificationServiceIndicator.data != NULL) {
        count++;
    }

    ret = wc_CBOR_EncoderInit(&ctx, out, outSz);
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&ctx, count);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75008);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, claims->nonce.data, claims->nonce.len);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75009);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, claims->ueid.data, claims->ueid.len);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (omitProfile == 0)) {
        ret = wc_CBOR_EncodeInt(&ctx, -75000);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (omitProfile == 0)) {
        ret = wc_CBOR_EncodeTstr(&ctx, profileText, profileLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75001);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, claims->clientId);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75002);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, claims->lifecycle);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75003);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, claims->implementationId.data,
                                 claims->implementationId.len);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75004);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, claims->bootSeed.data,
                                 claims->bootSeed.len);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (claims->verificationServiceIndicator.data != NULL)) {
        ret = wc_CBOR_EncodeInt(&ctx, -75010);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (claims->verificationServiceIndicator.data != NULL)) {
        ret = wc_CBOR_EncodeTstr(&ctx,
            claims->verificationServiceIndicator.data,
            claims->verificationServiceIndicator.len);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (noMeasurements != 0)) {
        ret = wc_CBOR_EncodeInt(&ctx, -75007);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (noMeasurements != 0)) {
        ret = wc_CBOR_EncodeUint(&ctx, 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (noMeasurements == 0)) {
        ret = wc_CBOR_EncodeInt(&ctx, -75006);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (noMeasurements == 0)) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (noMeasurements == 0)) {
        ret = wc_CBOR_EncodeMapStart(&ctx, 3u);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (noMeasurements == 0)) {
        ret = wc_CBOR_EncodeUint(&ctx, 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (noMeasurements == 0)) {
        ret = wc_CBOR_EncodeTstr(&ctx, claims->components[0].measurementType.data,
                                 claims->components[0].measurementType.len);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (noMeasurements == 0)) {
        ret = wc_CBOR_EncodeUint(&ctx, 2u);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (noMeasurements == 0)) {
        ret = wc_CBOR_EncodeBstr(&ctx, claims->components[0].measurementValue.data,
                                 claims->components[0].measurementValue.len);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (noMeasurements == 0)) {
        ret = wc_CBOR_EncodeUint(&ctx, 5u);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (noMeasurements == 0)) {
        ret = wc_CBOR_EncodeBstr(&ctx, claims->components[0].signerId.data,
                                 claims->components[0].signerId.len);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = ctx.idx;
    }

    return ret;
}
#endif

#if defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_SIGN1_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES256)
/* Legacy-only malformed fixtures: all structures are signed before the public
 * verifier sees them, so these exercise the receiver rather than issuer-side
 * validation. */
static int test_eat_psa_encode_legacy_raw(
    const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    int includeProfile, int includeComponents, int includeNoMeasurements,
    uint64_t noMeasurementsValue, const WOLFCOSE_EAT_PSA_SPAN* certification,
    uint8_t* out, size_t outSz, size_t* outLen)
{
    static const uint8_t profile[] = WOLFCOSE_EAT_PSA_PROFILE_LEGACY;
    WOLFCOSE_CBOR_CTX ctx;
    size_t count = 6u;
    int ret;

    if (outLen != NULL) {
        *outLen = 0u;
    }
    if ((claims == NULL) || (out == NULL) || (outLen == NULL) ||
        (claims->components == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        count += (includeProfile != 0) ? 1u : 0u;
        count += (includeComponents != 0) ? 1u : 0u;
        count += (includeNoMeasurements != 0) ? 1u : 0u;
        count += ((certification != NULL) &&
                  (certification->data != NULL)) ? 1u : 0u;
        ret = wc_CBOR_EncoderInit(&ctx, out, outSz);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&ctx, count);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75008);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, claims->nonce.data, claims->nonce.len);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75009);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, claims->ueid.data, claims->ueid.len);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (includeProfile != 0)) {
        ret = wc_CBOR_EncodeInt(&ctx, -75000);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (includeProfile != 0)) {
        ret = wc_CBOR_EncodeTstr(&ctx, profile, sizeof(profile) - 1u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75001);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, claims->clientId);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75002);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, claims->lifecycle);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75003);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, claims->implementationId.data,
            claims->implementationId.len);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, -75004);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, claims->bootSeed.data,
            claims->bootSeed.len);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (certification != NULL) &&
        (certification->data != NULL)) {
        ret = wc_CBOR_EncodeInt(&ctx, -75005);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (certification != NULL) &&
        (certification->data != NULL)) {
        ret = wc_CBOR_EncodeTstr(&ctx, certification->data,
            certification->len);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (includeComponents != 0)) {
        ret = wc_CBOR_EncodeInt(&ctx, -75006);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (includeComponents != 0)) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, 1u);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (includeComponents != 0)) {
        ret = test_eat_psa_encode_raw_component_ex(&ctx, claims->components,
            0u);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (includeNoMeasurements != 0)) {
        ret = wc_CBOR_EncodeInt(&ctx, -75007);
    }
    if ((ret == WOLFCOSE_SUCCESS) && (includeNoMeasurements != 0)) {
        ret = wc_CBOR_EncodeUint(&ctx, noMeasurementsValue);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = ctx.idx;
    }

    return ret;
}

static int test_eat_psa_verify_legacy_raw(WOLFCOSE_KEY* key, WC_RNG* rng,
    const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    int includeProfile, int includeComponents, int includeNoMeasurements,
    uint64_t noMeasurementsValue, const WOLFCOSE_EAT_PSA_SPAN* certification,
    uint8_t* scratch, size_t scratchSz, WOLFCOSE_EAT_PSA_TOKEN* token)
{
    static uint8_t payload[1024];
    static uint8_t signedToken[1536];
    size_t payloadLen = 0u;
    size_t signedTokenLen = 0u;
    int ret;

    if (token == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ret = test_eat_psa_encode_legacy_raw(claims, includeProfile,
            includeComponents, includeNoMeasurements, noMeasurementsValue,
            certification, payload, sizeof(payload), &payloadLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = test_eat_psa_sign1_payload(key, rng, payload, payloadLen,
            scratch, scratchSz, signedToken, sizeof(signedToken),
            &signedTokenLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        (void)memset(token, 0xA5, sizeof(*token));
        ret = wc_CoseEatPsaToken_Verify(key, signedToken, signedTokenLen,
            kNonce, sizeof(kNonce), scratch, scratchSz, token);
    }

    return ret;
}
#endif

#if defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_SIGN1_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES256)
static void test_eat_psa_claim_rejections(WOLFCOSE_KEY* key, WC_RNG* rng,
    const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    uint8_t* scratch, size_t scratchSz)
{
    static const uint8_t currentProfile[] = WOLFCOSE_EAT_PSA_PROFILE_TFM;
    static const uint8_t wrongProfile[] = "not-a-psa-profile";
    static WOLFCOSE_EAT_PSA_COMPONENT overComponents[
        WOLFCOSE_EAT_PSA_MAX_COMPONENTS + 1u];
    static uint8_t oversizedScratch[4096];
    WOLFCOSE_EAT_PSA_CLAIMS caseClaims;
    WOLFCOSE_EAT_PSA_COMPONENT caseComponent;
    WOLFCOSE_EAT_PSA_TOKEN token;
    EAT_PSA_COMPONENT_CTX componentCtx;
    uint8_t badUeid[sizeof(kUeid)];
    uint8_t invalidUtf8Payload[1024];
    uint8_t invalidUtf8Token[1536];
    size_t invalidUtf8PayloadLen = 0u;
    size_t invalidUtf8TokenLen = 0u;
    size_t i;
    int found;
    int ret;
    int testRet;

    (void)printf("  [RFC 9783 authenticated claim rejection matrix]\n");

    ret = test_eat_psa_verify_raw_current(key, rng, claims, currentProfile,
        sizeof(currentProfile) - 1u, TEST_EAT_PSA_OMIT_COMPONENTS, 0u, 0,
        scratch, scratchSz);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM,
        "reject signed token missing required current claim");

    caseClaims = *claims;
    caseClaims.clientId = 0;
    ret = test_eat_psa_verify_raw_current(key, rng, &caseClaims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0, scratch,
        scratchSz);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM,
        "reject signed zero current client ID");

    caseClaims = *claims;
    caseClaims.nonce.len = 31u;
    ret = test_eat_psa_verify_raw_current(key, rng, &caseClaims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0, scratch,
        scratchSz);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM,
        "reject signed invalid current nonce length");

    (void)memcpy(badUeid, kUeid, sizeof(badUeid));
    badUeid[0] = 0x02u;
    caseClaims = *claims;
    caseClaims.ueid.data = badUeid;
    ret = test_eat_psa_verify_raw_current(key, rng, &caseClaims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0, scratch,
        scratchSz);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM,
        "reject signed malformed UEID");

    caseClaims = *claims;
    caseClaims.implementationId.len = 31u;
    ret = test_eat_psa_verify_raw_current(key, rng, &caseClaims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0, scratch,
        scratchSz);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM,
        "reject signed malformed implementation ID");

    caseClaims = *claims;
    caseClaims.bootSeed.len = 7u;
    ret = test_eat_psa_verify_raw_current(key, rng, &caseClaims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0, scratch,
        scratchSz);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM,
        "reject signed current boot seed below profile minimum");

    caseClaims = *claims;
    caseClaims.bootSeed.data = kOversizedBootSeed;
    caseClaims.bootSeed.len = sizeof(kOversizedBootSeed);
    (void)memset(&token, 0xA5, sizeof(token));
    ret = test_eat_psa_verify_raw_current_ex(key, rng, &caseClaims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0, 0u,
        caseClaims.componentCount, scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject signed current boot seed above profile maximum and clear output");

    caseClaims = *claims;
    caseClaims.certificationReference.len--;
    ret = test_eat_psa_verify_raw_current(key, rng, &caseClaims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0, scratch,
        scratchSz);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM,
        "reject signed malformed current certification reference");

    caseClaims = *claims;
    caseClaims.certificationReference.data = kInvalidCurrentCertRef;
    caseClaims.certificationReference.len =
        sizeof(kInvalidCurrentCertRef) - 1u;
    (void)memset(&token, 0xA5, sizeof(token));
    ret = test_eat_psa_verify_raw_current_ex(key, rng, &caseClaims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0, 0u,
        caseClaims.componentCount, scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject signed current certification reference separator");

    ret = test_eat_psa_verify_raw_current(key, rng, claims, wrongProfile,
        sizeof(wrongProfile) - 1u, 0u, 0u, 0, scratch, scratchSz);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_PROFILE,
        "reject signed mismatched current profile");

    ret = test_eat_psa_verify_raw_current(key, rng, claims, currentProfile,
        sizeof(currentProfile) - 1u, 0u, 0u, 1, scratch, scratchSz);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_PROFILE,
        "reject signed mixed current and legacy labels");

    ret = test_eat_psa_verify_raw_current(key, rng, claims, currentProfile,
        sizeof(currentProfile) - 1u, 0u, 17u, 0, scratch, scratchSz);
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS,
        "accept signed unknown current claims beyond COSE map limit");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = test_eat_psa_verify_raw_current_ex(key, rng, claims,
        currentProfile, sizeof(currentProfile) - 1u,
        TEST_EAT_PSA_UNKNOWN_TEXT, 0u, 0,
        TEST_EAT_PSA_COMPONENT_UNKNOWN_TEXT, claims->componentCount, scratch,
        scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS && token.componentCount == 1u,
        "accept unknown text labels in PSA claims and components");
    if (ret == WOLFCOSE_SUCCESS) {
        (void)memset(&componentCtx, 0, sizeof(componentCtx));
        ret = wc_CoseEatPsaToken_ForEachComponent(&token,
            test_eat_psa_component, &componentCtx);
        TEST_ASSERT(ret == WOLFCOSE_SUCCESS && componentCtx.count == 1 &&
                    componentCtx.valid != 0,
            "iterate known component after unknown text labels");
    }

    /* Build a valid authenticated claim map, then corrupt a text-string byte
     * after CBOR encoding. The sender helper correctly refuses this text;
     * the receiver must also reject a malicious peer token. */
    testRet = test_eat_psa_encode_current_raw_ex(claims, currentProfile,
        sizeof(currentProfile) - 1u, 0u, 0u, 0, 0u,
        claims->componentCount, invalidUtf8Payload,
        sizeof(invalidUtf8Payload), &invalidUtf8PayloadLen);
    if (testRet == WOLFCOSE_SUCCESS) {
        found = 0;
        for (i = 0u; (i + (sizeof(currentProfile) - 1u)) <=
             invalidUtf8PayloadLen; i++) {
            if (memcmp(&invalidUtf8Payload[i], currentProfile,
                sizeof(currentProfile) - 1u) == 0) {
                invalidUtf8Payload[i] = 0xFFu;
                found = 1;
                break;
            }
        }
        if (found == 0) {
            testRet = WOLFCOSE_E_INVALID_ARG;
        }
    }
    if (testRet == WOLFCOSE_SUCCESS) {
        testRet = test_eat_psa_sign1_payload(key, rng, invalidUtf8Payload,
            invalidUtf8PayloadLen, scratch, scratchSz, invalidUtf8Token,
            sizeof(invalidUtf8Token), &invalidUtf8TokenLen);
    }
    if (testRet == WOLFCOSE_SUCCESS) {
        (void)memset(&token, 0xA5, sizeof(token));
        testRet = wc_CoseEatPsaToken_Verify(key, invalidUtf8Token,
            invalidUtf8TokenLen, kNonce, sizeof(kNonce), scratch, scratchSz,
            &token);
    }
    TEST_ASSERT(testRet == WOLFCOSE_E_CBOR_MALFORMED &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject signed invalid UTF-8 claim and clear output");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = test_eat_psa_verify_raw_current_ex(key, rng, claims,
        currentProfile, sizeof(currentProfile) - 1u,
        TEST_EAT_PSA_DUP_UNKNOWN_CLAIM, 2u, 0, 0u,
        claims->componentCount, scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject duplicate unknown numeric PSA claim and clear output");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = test_eat_psa_verify_raw_current_ex(key, rng, claims,
        currentProfile, sizeof(currentProfile) - 1u,
        TEST_EAT_PSA_DUP_UNKNOWN_TEXT, 0u, 0, 0u,
        claims->componentCount, scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject duplicate unknown text PSA claim and clear output");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = test_eat_psa_verify_raw_current_ex(key, rng, claims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0,
        TEST_EAT_PSA_COMPONENT_DUP_UNKNOWN_TEXT, claims->componentCount,
        scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject duplicate unknown component text label and clear output");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = test_eat_psa_verify_raw_current_ex(key, rng, claims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0,
        TEST_EAT_PSA_COMPONENT_DUP_UNKNOWN_CLAIM, claims->componentCount,
        scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject duplicate unknown numeric component claim and clear output");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = test_eat_psa_verify_raw_current_ex(key, rng, claims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0,
        TEST_EAT_PSA_COMPONENT_DUP_VALUE, 1u, scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject duplicate authenticated component field and clear output");

    caseClaims = *claims;
    caseComponent = claims->components[0];
    caseClaims.components = &caseComponent;
    caseComponent.measurementValue.len = 31u;
    (void)memset(&token, 0xA5, sizeof(token));
    ret = test_eat_psa_verify_raw_current_ex(key, rng, &caseClaims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0, 0u, 1u,
        scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject authenticated component measurement hash length");

    caseComponent = claims->components[0];
    caseComponent.signerId.len = 31u;
    (void)memset(&token, 0xA5, sizeof(token));
    ret = test_eat_psa_verify_raw_current_ex(key, rng, &caseClaims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0, 0u, 1u,
        scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject authenticated component signer hash length");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = test_eat_psa_verify_raw_current_ex(key, rng, claims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0,
        TEST_EAT_PSA_COMPONENT_OMIT_VALUE, 1u, scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject component missing measurement value and clear output");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = test_eat_psa_verify_raw_current_ex(key, rng, claims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0,
        TEST_EAT_PSA_COMPONENT_OMIT_SIGNER, 1u, scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject component missing signer ID and clear output");

    (void)memset(&token, 0xA5, sizeof(token));
    ret = test_eat_psa_verify_raw_current_ex(key, rng, claims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0, 0u, 0u,
        scratch, scratchSz, &token);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject empty authenticated component array and clear output");

    caseClaims = *claims;
    for (i = 0u; i < (WOLFCOSE_EAT_PSA_MAX_COMPONENTS + 1u); i++) {
        overComponents[i] = claims->components[0];
    }
    caseClaims.components = overComponents;
    (void)memset(&token, 0xA5, sizeof(token));
    ret = test_eat_psa_verify_raw_current_ex(key, rng, &caseClaims,
        currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0, 0u,
        WOLFCOSE_EAT_PSA_MAX_COMPONENTS + 1u, oversizedScratch,
        sizeof(oversizedScratch), &token);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM &&
                test_eat_psa_token_is_zero(&token) != 0,
        "reject component array beyond configured maximum and clear output");
}
#endif

#if defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_SIGN1_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES256)
static void test_eat_psa_expect_issue_claim_failure(
    const WOLFCOSE_EAT_PSA_CLAIMS* claims, uint8_t* out, size_t outSz,
    const char* name)
{
    size_t outLen = 17u;
    int ret;

    ret = wc_CoseEatPsaToken_EncodeClaims(claims, out, outSz, &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM && outLen == 0u, name);
}

#define TEST_EAT_PSA_INPUT_SPAN_COUNT 11u

static WOLFCOSE_EAT_PSA_SPAN* test_eat_psa_input_span(
    WOLFCOSE_EAT_PSA_CLAIMS* claims,
    WOLFCOSE_EAT_PSA_COMPONENT* component, size_t index)
{
    WOLFCOSE_EAT_PSA_SPAN* span = NULL;

    switch (index) {
        case 0u:
            span = &claims->nonce;
            break;
        case 1u:
            span = &claims->ueid;
            break;
        case 2u:
            span = &claims->implementationId;
            break;
        case 3u:
            span = &claims->bootSeed;
            break;
        case 4u:
            span = &claims->certificationReference;
            break;
        case 5u:
            span = &claims->verificationServiceIndicator;
            break;
        case 6u:
            span = &component->measurementType;
            break;
        case 7u:
            span = &component->measurementValue;
            break;
        case 8u:
            span = &component->version;
            break;
        case 9u:
            span = &component->signerId;
            break;
        case 10u:
            span = &component->measurementDesc;
            break;
        default:
            break;
    }

    return span;
}

static int test_eat_psa_alias_input_span(WOLFCOSE_EAT_PSA_CLAIMS* claims,
    WOLFCOSE_EAT_PSA_COMPONENT* component, size_t index,
    uint8_t* storage, size_t storageSz)
{
    WOLFCOSE_EAT_PSA_SPAN* span;
    int ret = 0;

    test_eat_psa_claims(claims, component);
    span = test_eat_psa_input_span(claims, component, index);
    if ((span != NULL) && (span->data != NULL) && (span->len > 1u) &&
        (span->len <= storageSz)) {
        (void)memcpy(storage, span->data, span->len);
        span->data = storage;
        ret = 1;
    }

    return ret;
}

static int test_eat_psa_encode_overlap_rejected(
    const WOLFCOSE_EAT_PSA_CLAIMS* claims, uint8_t* out, size_t outSz)
{
    size_t outLen = 17u;
    int ret;

    ret = wc_CoseEatPsaToken_EncodeClaims(claims, out, outSz, &outLen);
    return ((ret == WOLFCOSE_E_INVALID_ARG) && (outLen == 0u)) ? 1 : 0;
}

static int test_eat_psa_sign1_overlap_rejected(WOLFCOSE_KEY* key,
    WC_RNG* rng, const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    uint8_t* claimsBuf, size_t claimsBufSz,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz)
{
    size_t outLen = 17u;
    int ret;

    (void)memset(out, 0xA5, outSz);
    ret = wc_CoseEatPsaToken_CreateSign1(key, WOLFCOSE_ALG_ES256, claims,
        claimsBuf, claimsBufSz, scratch, scratchSz, out, outSz, &outLen, rng);
    return ((ret == WOLFCOSE_E_INVALID_ARG) && (outLen == 0u) &&
            (test_eat_psa_bytes_are_zero(out, outSz) != 0)) ? 1 : 0;
}

static void test_eat_psa_expect_sign1_overlap(WOLFCOSE_KEY* key,
    WC_RNG* rng, const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    uint8_t* claimsBuf, size_t claimsBufSz,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, const char* name)
{
    TEST_ASSERT(test_eat_psa_sign1_overlap_rejected(key, rng, claims,
                    claimsBuf, claimsBufSz, scratch, scratchSz, out,
                    outSz) != 0,
        name);
}

static void test_eat_psa_issue_boundaries(WOLFCOSE_KEY* key, WC_RNG* rng)
{
    static const uint8_t invalidUtf8[] = { 0xFFu };
    static const char* componentClaimTests[] = {
        "issue and verify component with version only",
        "issue and verify component with description only",
        "issue and verify component with required claims only"
    };
    WOLFCOSE_EAT_PSA_CLAIMS claims;
    WOLFCOSE_EAT_PSA_COMPONENT component;
    WOLFCOSE_EAT_PSA_COMPONENT components[WOLFCOSE_EAT_PSA_MAX_COMPONENTS + 1u];
    WOLFCOSE_EAT_PSA_TOKEN token;
    union {
        WOLFCOSE_EAT_PSA_CLAIMS claims;
        WOLFCOSE_EAT_PSA_COMPONENT component;
        uint8_t bytes[2048];
    } inputStorage;
    uint8_t badUeid[sizeof(kUeid)];
    uint8_t claimsBuf[8192];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[1024];
    uint8_t overlap[2048];
    size_t outLen = 17u;
    size_t tokenLen;
    size_t i;
    int ret;
    int spanChecks;

    (void)printf("  [RFC 9783 issuer boundary contracts]\n");
    test_eat_psa_claims(&claims, &component);

    ret = wc_CoseEatPsaToken_EncodeClaims(NULL, claimsBuf,
        sizeof(claimsBuf), &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM && outLen == 0u,
        "reject NULL claims and clear encoded length");

    outLen = 17u;
    ret = wc_CoseEatPsaToken_EncodeClaims(&claims, NULL, 0u, &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG && outLen == 0u,
        "reject NULL claims output and clear encoded length");

    ret = wc_CoseEatPsaToken_EncodeClaims(&claims, claimsBuf,
        sizeof(claimsBuf), NULL);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG,
        "reject NULL encoded-length output");

    outLen = 17u;
    ret = wc_CoseEatPsaToken_EncodeClaims(&claims, claimsBuf, 1u, &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_BUFFER_TOO_SMALL && outLen == 0u,
        "reject one-byte-short claims output");

    test_eat_psa_claims(&claims, &component);
    inputStorage.claims = claims;
    TEST_ASSERT(test_eat_psa_encode_overlap_rejected(&inputStorage.claims,
                    inputStorage.bytes, sizeof(inputStorage.bytes)) != 0,
        "direct encoder rejects exact claims-structure overlap");
    test_eat_psa_claims(&claims, &component);
    inputStorage.claims = claims;
    TEST_ASSERT(test_eat_psa_encode_overlap_rejected(&inputStorage.claims,
                    &inputStorage.bytes[sizeof(inputStorage.claims) / 2u],
                    sizeof(inputStorage.bytes) -
                        (sizeof(inputStorage.claims) / 2u)) != 0,
        "direct encoder rejects partial claims-structure overlap");
    test_eat_psa_claims(&claims, &component);
    inputStorage.claims = claims;
    TEST_ASSERT(test_eat_psa_sign1_overlap_rejected(key, rng,
                    &inputStorage.claims, inputStorage.bytes,
                    sizeof(inputStorage.bytes), scratch, sizeof(scratch), out,
                    sizeof(out)) != 0,
        "Sign1 issuer rejects exact claims-structure overlap");
    test_eat_psa_claims(&claims, &component);
    inputStorage.claims = claims;
    TEST_ASSERT(test_eat_psa_sign1_overlap_rejected(key, rng,
                    &inputStorage.claims,
                    &inputStorage.bytes[sizeof(inputStorage.claims) / 2u],
                    sizeof(inputStorage.bytes) -
                        (sizeof(inputStorage.claims) / 2u),
                    scratch, sizeof(scratch), out, sizeof(out)) != 0,
        "Sign1 issuer rejects partial claims-structure overlap");

    test_eat_psa_claims(&claims, &component);
    inputStorage.component = component;
    claims.components = &inputStorage.component;
    TEST_ASSERT(test_eat_psa_encode_overlap_rejected(&claims,
                    inputStorage.bytes, sizeof(inputStorage.bytes)) != 0,
        "direct encoder rejects exact component-array overlap");
    test_eat_psa_claims(&claims, &component);
    inputStorage.component = component;
    claims.components = &inputStorage.component;
    TEST_ASSERT(test_eat_psa_encode_overlap_rejected(&claims,
                    &inputStorage.bytes[sizeof(inputStorage.component) / 2u],
                    sizeof(inputStorage.bytes) -
                        (sizeof(inputStorage.component) / 2u)) != 0,
        "direct encoder rejects partial component-array overlap");
    test_eat_psa_claims(&claims, &component);
    inputStorage.component = component;
    claims.components = &inputStorage.component;
    TEST_ASSERT(test_eat_psa_sign1_overlap_rejected(key, rng, &claims,
                    inputStorage.bytes, sizeof(inputStorage.bytes), scratch,
                    sizeof(scratch), out, sizeof(out)) != 0,
        "Sign1 issuer rejects exact component-array overlap");
    test_eat_psa_claims(&claims, &component);
    inputStorage.component = component;
    claims.components = &inputStorage.component;
    TEST_ASSERT(test_eat_psa_sign1_overlap_rejected(key, rng, &claims,
                    &inputStorage.bytes[sizeof(inputStorage.component) / 2u],
                    sizeof(inputStorage.bytes) -
                        (sizeof(inputStorage.component) / 2u),
                    scratch, sizeof(scratch), out, sizeof(out)) != 0,
        "Sign1 issuer rejects partial component-array overlap");

    spanChecks = 1;
    for (i = 0u; i < TEST_EAT_PSA_INPUT_SPAN_COUNT; i++) {
        if ((test_eat_psa_alias_input_span(&claims, &component, i,
                 inputStorage.bytes, sizeof(inputStorage.bytes)) == 0) ||
            (test_eat_psa_encode_overlap_rejected(&claims,
                 inputStorage.bytes, sizeof(inputStorage.bytes)) == 0)) {
            spanChecks = 0;
        }
        if ((test_eat_psa_alias_input_span(&claims, &component, i,
                 inputStorage.bytes, sizeof(inputStorage.bytes)) == 0) ||
            (test_eat_psa_encode_overlap_rejected(&claims,
                 &inputStorage.bytes[1], sizeof(inputStorage.bytes) - 1u) ==
             0)) {
            spanChecks = 0;
        }
        if ((test_eat_psa_alias_input_span(&claims, &component, i,
                 inputStorage.bytes, sizeof(inputStorage.bytes)) == 0) ||
            (test_eat_psa_sign1_overlap_rejected(key, rng, &claims,
                 inputStorage.bytes, sizeof(inputStorage.bytes), scratch,
                 sizeof(scratch), out, sizeof(out)) == 0)) {
            spanChecks = 0;
        }
        if ((test_eat_psa_alias_input_span(&claims, &component, i,
                 inputStorage.bytes, sizeof(inputStorage.bytes)) == 0) ||
            (test_eat_psa_sign1_overlap_rejected(key, rng, &claims,
                 &inputStorage.bytes[1], sizeof(inputStorage.bytes) - 1u,
                 scratch, sizeof(scratch), out, sizeof(out)) == 0)) {
            spanChecks = 0;
        }
    }
    TEST_ASSERT(spanChecks != 0,
        "direct encoder and Sign1 reject exact/partial overlap for every input span");

    test_eat_psa_claims(&claims, &component);
    claims.nonce.data = NULL;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer nonce with NULL data");

    test_eat_psa_claims(&claims, &component);
    claims.nonce.len = 31u;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer nonce with unsupported length");

    test_eat_psa_claims(&claims, &component);
    claims.ueid.data = NULL;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer UEID with NULL data");

    test_eat_psa_claims(&claims, &component);
    claims.ueid.len--;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer UEID with wrong length");

    (void)memcpy(badUeid, kUeid, sizeof(badUeid));
    badUeid[0] = 0x02u;
    test_eat_psa_claims(&claims, &component);
    claims.ueid.data = badUeid;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer UEID with wrong type byte");

    test_eat_psa_claims(&claims, &component);
    claims.implementationId.data = NULL;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer implementation ID with NULL data");

    test_eat_psa_claims(&claims, &component);
    claims.implementationId.len--;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer implementation ID with wrong length");

    test_eat_psa_claims(&claims, &component);
    claims.clientId = 0;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject zero issuer client ID");

    test_eat_psa_claims(&claims, &component);
    claims.lifecycle = 0x0100u;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer lifecycle outside PSA state ranges");

    test_eat_psa_claims(&claims, &component);
    claims.components = NULL;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer NULL component array");

    test_eat_psa_claims(&claims, &component);
    claims.bootSeed.data = NULL;
    claims.bootSeed.len = 8u;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer optional boot seed with NULL data");

    test_eat_psa_claims(&claims, &component);
    claims.bootSeed.len = 7u;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer boot seed below profile minimum");

    test_eat_psa_claims(&claims, &component);
    claims.bootSeed.data = kOversizedBootSeed;
    claims.bootSeed.len = sizeof(kOversizedBootSeed);
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer boot seed above profile maximum");

    test_eat_psa_claims(&claims, &component);
    claims.certificationReference.data = NULL;
    claims.certificationReference.len = 1u;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf),
        "reject issuer certification reference with NULL data");

    test_eat_psa_claims(&claims, &component);
    claims.certificationReference.len--;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject malformed issuer certification reference");

    test_eat_psa_claims(&claims, &component);
    claims.certificationReference.data = kInvalidCurrentCertRef;
    claims.certificationReference.len = sizeof(kInvalidCurrentCertRef) - 1u;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf),
        "reject issuer certification reference with invalid separator");

    test_eat_psa_claims(&claims, &component);
    claims.verificationServiceIndicator.data = NULL;
    claims.verificationServiceIndicator.len = 1u;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer VSI with NULL data");

    test_eat_psa_claims(&claims, &component);
    component.measurementValue.data = NULL;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer component hash with NULL data");

    test_eat_psa_claims(&claims, &component);
    component.measurementValue.len = 31u;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer component hash with wrong length");

    test_eat_psa_claims(&claims, &component);
    component.signerId.data = NULL;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer signer ID with NULL data");

    test_eat_psa_claims(&claims, &component);
    component.signerId.len = 31u;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf), "reject issuer signer ID with wrong length");

    test_eat_psa_claims(&claims, &component);
    component.measurementType.data = NULL;
    component.measurementType.len = 1u;
    test_eat_psa_expect_issue_claim_failure(&claims, claimsBuf,
        sizeof(claimsBuf),
        "reject issuer optional component text with NULL data");

    for (i = 0u; i < (sizeof(componentClaimTests) /
         sizeof(componentClaimTests[0])); i++) {
        test_eat_psa_claims(&claims, &component);
        component.measurementType.data = NULL;
        component.measurementType.len = 0u;
        if (i != 0u) {
            component.version.data = NULL;
            component.version.len = 0u;
        }
        if (i != 1u) {
            component.measurementDesc.data = NULL;
            component.measurementDesc.len = 0u;
        }
        tokenLen = 0u;
        ret = wc_CoseEatPsaToken_CreateSign1(key, WOLFCOSE_ALG_ES256,
            &claims, claimsBuf, sizeof(claimsBuf), scratch, sizeof(scratch),
            out, sizeof(out), &tokenLen, rng);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CoseEatPsaToken_Verify(key, out, tokenLen, kNonce,
                sizeof(kNonce), scratch, sizeof(scratch), &token);
        }
        TEST_ASSERT(ret == WOLFCOSE_SUCCESS && token.componentCount == 1u,
            componentClaimTests[i]);
    }

    test_eat_psa_claims(&claims, &component);
    claims.componentCount = 0u;
    outLen = 17u;
    ret = wc_CoseEatPsaToken_EncodeClaims(&claims, claimsBuf,
        sizeof(claimsBuf), &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM && outLen == 0u,
        "reject zero software components");

    test_eat_psa_claims(&claims, &component);
    for (i = 0u; i < (WOLFCOSE_EAT_PSA_MAX_COMPONENTS + 1u); i++) {
        components[i] = component;
    }
    claims.components = components;
    claims.componentCount = WOLFCOSE_EAT_PSA_MAX_COMPONENTS;
    ret = wc_CoseEatPsaToken_EncodeClaims(&claims, claimsBuf,
        sizeof(claimsBuf), &outLen);
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS && outLen > 0u,
        "encode exactly the configured component maximum");

    claims.componentCount = WOLFCOSE_EAT_PSA_MAX_COMPONENTS + 1u;
    outLen = 17u;
    ret = wc_CoseEatPsaToken_EncodeClaims(&claims, claimsBuf,
        sizeof(claimsBuf), &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM && outLen == 0u,
        "reject one component beyond configured maximum");

    test_eat_psa_claims(&claims, &component);
    component.version.data = invalidUtf8;
    component.version.len = sizeof(invalidUtf8);
    outLen = 17u;
    ret = wc_CoseEatPsaToken_EncodeClaims(&claims, claimsBuf,
        sizeof(claimsBuf), &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED && outLen == 0u,
        "reject invalid UTF-8 issuer text claim");

    test_eat_psa_claims(&claims, &component);
    (void)memset(out, 0xA5, sizeof(out));
    outLen = 17u;
    ret = wc_CoseEatPsaToken_CreateSign1(NULL, WOLFCOSE_ALG_ES256, &claims,
        claimsBuf, sizeof(claimsBuf), scratch, sizeof(scratch), out,
        sizeof(out), &outLen, rng);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG && outLen == 0u &&
                test_eat_psa_bytes_are_zero(out, sizeof(out)) != 0,
        "clear Sign1 output after invalid arguments");

    for (i = 0u; i < 5u; i++) {
        const WOLFCOSE_EAT_PSA_CLAIMS* argClaims =
            (i == 0u) ? NULL : &claims;
        uint8_t* argClaimsBuf = (i == 1u) ? NULL : claimsBuf;
        uint8_t* argScratch = (i == 2u) ? NULL : scratch;
        uint8_t* argOut = (i == 3u) ? NULL : out;
        size_t* argOutLen = (i == 4u) ? NULL : &outLen;
        int expected = (i == 0u) ? WOLFCOSE_E_EAT_PSA_CLAIM :
                                   WOLFCOSE_E_INVALID_ARG;

        (void)memset(out, 0xA5, sizeof(out));
        outLen = 17u;
        ret = wc_CoseEatPsaToken_CreateSign1(key, WOLFCOSE_ALG_ES256,
            argClaims, argClaimsBuf, sizeof(claimsBuf), argScratch,
            sizeof(scratch), argOut, sizeof(out), argOutLen, rng);
        TEST_ASSERT(ret == expected &&
                    ((argOutLen == NULL) || (outLen == 0u)) &&
                    ((argOut == NULL) ||
                     (test_eat_psa_bytes_are_zero(out, sizeof(out)) != 0)),
            "Sign1 wrapper rejects each missing required pointer");
    }

    test_eat_psa_expect_sign1_overlap(key, rng, &claims,
        overlap, 512u, scratch, sizeof(scratch), overlap, 1024u,
        "Sign1 rejects exact claims/output overlap");
    test_eat_psa_expect_sign1_overlap(key, rng, &claims,
        &overlap[256], 512u, scratch, sizeof(scratch), overlap, 1024u,
        "Sign1 rejects partial claims/output overlap");
    test_eat_psa_expect_sign1_overlap(key, rng, &claims,
        overlap, 512u, overlap, 1024u, out, sizeof(out),
        "Sign1 rejects exact claims/scratch overlap");
    test_eat_psa_expect_sign1_overlap(key, rng, &claims,
        overlap, 512u, &overlap[256], 1024u, out, sizeof(out),
        "Sign1 rejects partial claims/scratch overlap");
    test_eat_psa_expect_sign1_overlap(key, rng, &claims,
        claimsBuf, sizeof(claimsBuf), overlap, 1024u, overlap, 1024u,
        "Sign1 rejects exact scratch/output overlap");
    test_eat_psa_expect_sign1_overlap(key, rng, &claims,
        claimsBuf, sizeof(claimsBuf), overlap, 1024u, &overlap[256], 1024u,
        "Sign1 rejects partial scratch/output overlap");

    (void)memset(out, 0xA5, sizeof(out));
    outLen = 17u;
    ret = wc_CoseEatPsaToken_CreateSign1(key, WOLFCOSE_ALG_EDDSA, &claims,
        claimsBuf, sizeof(claimsBuf), scratch, sizeof(scratch), out,
        sizeof(out), &outLen, rng);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_BAD_ALG && outLen == 0u &&
                test_eat_psa_bytes_are_zero(out, sizeof(out)) != 0,
        "clear Sign1 output after unsupported PSA algorithm");

    (void)memset(out, 0xA5, sizeof(out));
    outLen = 17u;
    ret = wc_CoseEatPsaToken_CreateSign1(key, WOLFCOSE_ALG_ES256, &claims,
        claimsBuf, 1u, scratch, sizeof(scratch), out, sizeof(out), &outLen,
        rng);
    TEST_ASSERT(ret != WOLFCOSE_SUCCESS && outLen == 0u &&
                test_eat_psa_bytes_are_zero(out, sizeof(out)) != 0,
        "clear Sign1 output after claims-buffer failure");

    (void)memset(out, 0xA5, sizeof(out));
    outLen = 17u;
    ret = wc_CoseEatPsaToken_CreateSign1(key, WOLFCOSE_ALG_ES256, &claims,
        claimsBuf, sizeof(claimsBuf), scratch, 1u, out, sizeof(out), &outLen,
        rng);
    TEST_ASSERT(ret != WOLFCOSE_SUCCESS && outLen == 0u &&
                test_eat_psa_bytes_are_zero(out, sizeof(out)) != 0,
        "clear Sign1 output after scratch-buffer failure");

    (void)memset(out, 0xA5, sizeof(out));
    outLen = 17u;
    ret = wc_CoseEatPsaToken_CreateSign1(key, WOLFCOSE_ALG_ES256, &claims,
        claimsBuf, sizeof(claimsBuf), scratch, sizeof(scratch), out, 1u,
        &outLen, rng);
    TEST_ASSERT(ret == WOLFCOSE_E_BUFFER_TOO_SMALL && outLen == 0u &&
                test_eat_psa_bytes_are_zero(out, 1u) != 0,
        "clear Sign1 output after token-buffer failure");
}
#endif

#if defined(WOLFCOSE_SIGN1_VERIFY) && defined(WOLFCOSE_HAVE_ES256)
static void test_eat_psa_rfc9783_sign1(void)
{
    static const uint8_t protectedX5chain[] = {
        0xA2u, 0x01u, 0x26u, 0x18u, 0x21u, 0x40u
    };
    WOLFCOSE_EAT_PSA_TOKEN token;
    EAT_PSA_COMPONENT_CTX componentCtx;
    WOLFCOSE_KEY key;
    WOLFCOSE_HDR hdr;
    WOLFCOSE_HDR_STATE hdrState;
    ecc_key ecc;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t tokenBuf[512];
    uint8_t nonPreferred[513];
    uint8_t cwtTagged[514];
    const uint8_t* genericPayload = NULL;
    size_t genericPayloadLen = 0u;
    size_t tokenLen = 0u;
    int ret;
    int testRet;
    int eccInited = 0;
    int keyInited = 0;

    (void)printf("  [RFC 9783 Appendix A Sign1]\n");
    (void)memset(&hdr, 0, sizeof(hdr));
    ret = wolfCose_DecodeProtectedHdr(protectedX5chain,
        sizeof(protectedX5chain), &hdr, &hdrState);
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS &&
                ((hdr.flags & WOLFCOSE_HDR_FLAG_X5CHAIN) != 0u),
        "detect x5chain in protected COSE headers");
    ret = test_eat_psa_hex_decode(kRfc9783Sign1Hex, tokenBuf,
        sizeof(tokenBuf), &tokenLen);
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS && tokenLen > 0u,
        "decode RFC 9783 Sign1 vector");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_ecc_init(&ecc);
        if (ret == 0) {
            eccInited = 1;
            ret = wc_ecc_import_unsigned(&ecc, kRfc9783Sign1KeyX,
                kRfc9783Sign1KeyY, NULL, ECC_SECP256R1);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseKey_Init(&key);
        if (ret == WOLFCOSE_SUCCESS) {
            keyInited = 1;
            ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &ecc);
            key.hasPrivate = 0u;
        }
    }
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS, "import RFC 9783 Sign1 key");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_EatPsaToken_Verify(&key, tokenBuf, tokenLen,
            kRfc9783Nonce, sizeof(kRfc9783Nonce), scratch, sizeof(scratch),
            &token);
        TEST_ASSERT(ret == WOLFCOSE_SUCCESS,
            "verify iat-verifier RFC 9783 Sign1 vector");
    }
    if (ret == WOLFCOSE_SUCCESS) {
        TEST_ASSERT(token.profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT &&
                    token.protection == WOLFCOSE_EAT_PSA_PROTECTION_SIGN1 &&
                    token.componentCount == 1u && token.bootSeed.len == 8u,
                    "parse RFC 9783 Sign1 claims");
        (void)memset(&componentCtx, 0, sizeof(componentCtx));
        ret = wc_EatPsaToken_ForEachComponent(&token,
            test_eat_psa_component, &componentCtx);
        TEST_ASSERT(ret == WOLFCOSE_SUCCESS && componentCtx.count == 1 &&
                    componentCtx.valid != 0,
                    "parse RFC 9783 Sign1 component");
    }
    /* RFC 9783 requires PSA receivers to accept non-preferred CBOR, while
     * normal COSE verification retains its strict-by-default behavior. */
    if (ret == WOLFCOSE_SUCCESS) {
        nonPreferred[0] = 0xD8u;
        nonPreferred[1] = 0x12u;
        (void)memcpy(&nonPreferred[2], &tokenBuf[1], tokenLen - 1u);
        ret = wc_CoseSign1_Verify(&key, nonPreferred, tokenLen + 1u, NULL,
            0u, NULL, 0u, scratch, sizeof(scratch), &hdr, &genericPayload,
            &genericPayloadLen);
        TEST_ASSERT(ret != WOLFCOSE_SUCCESS,
            "generic COSE remains strict for non-preferred tag");
        testRet = wolfCose_Sign1_Verify_ex(&key, nonPreferred, tokenLen + 1u,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr,
            &genericPayload, &genericPayloadLen,
            WOLFCOSE_COSE_DECODE_ALLOW_NONPREFERRED);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS,
            "Sign1 decode-option API accepts non-preferred tag");
        testRet = wolfCose_Sign1_Verify_ex(&key, tokenBuf, tokenLen, NULL, 0u,
            NULL, 0u, scratch, sizeof(scratch), &hdr, &genericPayload,
            &genericPayloadLen, 0x80000000u);
        TEST_ASSERT(testRet == WOLFCOSE_E_INVALID_ARG,
            "Sign1 decode-option API rejects unknown flag");
        ret = wc_EatPsaToken_Verify(&key, nonPreferred, tokenLen + 1u,
            kRfc9783Nonce, sizeof(kRfc9783Nonce), scratch, sizeof(scratch),
            &token);
        TEST_ASSERT(ret == WOLFCOSE_SUCCESS,
            "PSA verifier accepts non-preferred tag");
    }
    if (ret == WOLFCOSE_SUCCESS) {
        cwtTagged[0] = 0xD8u;
        cwtTagged[1] = 0x3Du;
        (void)memcpy(&cwtTagged[2], tokenBuf, tokenLen);
        ret = wc_EatPsaToken_Verify(&key, cwtTagged, tokenLen + 2u,
            kRfc9783Nonce, sizeof(kRfc9783Nonce), scratch, sizeof(scratch),
            &token);
        TEST_ASSERT(ret == WOLFCOSE_E_COSE_BAD_TAG,
            "reject CWT tag around PSA token");
    }

    if (keyInited != 0) {
        wc_CoseKey_Free(&key);
    }
    if (eccInited != 0) {
        (void)wc_ecc_free(&ecc);
    }
}
#endif /* WOLFCOSE_SIGN1_VERIFY && WOLFCOSE_HAVE_ES256 */

#if defined(WOLFCOSE_MAC0_VERIFY) && defined(WOLFCOSE_HAVE_HMAC256)
static void test_eat_psa_rfc9783_mac0(void)
{
    WOLFCOSE_EAT_PSA_TOKEN token;
    WOLFCOSE_KEY key;
    WOLFCOSE_HDR hdr;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t tokenBuf[512];
    uint8_t nonPreferred[513];
    const uint8_t* genericPayload = NULL;
    size_t genericPayloadLen = 0u;
    size_t tokenLen = 0u;
    int ret;
    int testRet;
    int keyInited = 0;

    (void)printf("  [RFC 9783 Appendix A Mac0]\n");
    ret = test_eat_psa_hex_decode(kRfc9783Mac0Hex, tokenBuf,
        sizeof(tokenBuf), &tokenLen);
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS && tokenLen > 0u,
        "decode RFC 9783 Mac0 vector");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseKey_Init(&key);
        if (ret == WOLFCOSE_SUCCESS) {
            keyInited = 1;
            ret = wc_CoseKey_SetSymmetric(&key, kRfc9783Mac0Key,
                sizeof(kRfc9783Mac0Key));
        }
    }
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS, "import RFC 9783 Mac0 key");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_EatPsaToken_Verify(&key, tokenBuf, tokenLen,
            kRfc9783Nonce, sizeof(kRfc9783Nonce), scratch, sizeof(scratch),
            &token);
        TEST_ASSERT(ret == WOLFCOSE_SUCCESS,
            "verify iat-verifier RFC 9783 Mac0 vector");
    }
    if (ret == WOLFCOSE_SUCCESS) {
        TEST_ASSERT(token.profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT &&
                    token.protection == WOLFCOSE_EAT_PSA_PROTECTION_MAC0 &&
                    token.componentCount == 1u,
                    "parse RFC 9783 Mac0 claims");
    }
    if (ret == WOLFCOSE_SUCCESS) {
        nonPreferred[0] = 0xD8u;
        nonPreferred[1] = 0x11u;
        (void)memcpy(&nonPreferred[2], &tokenBuf[1], tokenLen - 1u);
        testRet = wc_CoseMac0_Verify(&key, nonPreferred, tokenLen + 1u,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr,
            &genericPayload, &genericPayloadLen);
        TEST_ASSERT(testRet != WOLFCOSE_SUCCESS,
            "generic Mac0 remains strict for non-preferred tag");
        testRet = wolfCose_Mac0_Verify_ex(&key, nonPreferred, tokenLen + 1u,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr,
            &genericPayload, &genericPayloadLen,
            WOLFCOSE_COSE_DECODE_ALLOW_NONPREFERRED);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS,
            "Mac0 decode-option API accepts non-preferred tag");
        testRet = wolfCose_Mac0_Verify_ex(&key, tokenBuf, tokenLen, NULL, 0u,
            NULL, 0u, scratch, sizeof(scratch), &hdr, &genericPayload,
            &genericPayloadLen, 0x80000000u);
        TEST_ASSERT(testRet == WOLFCOSE_E_INVALID_ARG,
            "Mac0 decode-option API rejects unknown flag");
    }

    if (keyInited != 0) {
        wc_CoseKey_Free(&key);
    }
}
#endif /* WOLFCOSE_MAC0_VERIFY && WOLFCOSE_HAVE_HMAC256 */

#if defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_SIGN1_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES256)
static void test_eat_psa_sign1(void)
{
    static const uint8_t currentProfile[] = WOLFCOSE_EAT_PSA_PROFILE_TFM;
    static const uint16_t lifecycleClasses[] = {
        0x1000u, 0x4000u, 0x5000u, 0x6000u
    };
    static const uint16_t provisioningLifecycles[] = {
        0x2000u, 0x20FFu
    };
    WOLFCOSE_EAT_PSA_CLAIMS claims;
    WOLFCOSE_EAT_PSA_CLAIMS malformedClaims;
    WOLFCOSE_EAT_PSA_CLAIMS multiClaims;
    WOLFCOSE_EAT_PSA_COMPONENT component;
    WOLFCOSE_EAT_PSA_COMPONENT multiComponents[2];
    WOLFCOSE_EAT_PSA_TOKEN token;
    WOLFCOSE_EAT_PSA_TOKEN iteratorToken;
    WOLFCOSE_KEY key;
    EAT_PSA_RESOLVER_CTX resolver;
    EAT_PSA_COMPONENT_CTX componentCtx;
    ecc_key ecc;
    WC_RNG rng;
    uint8_t claimsBuf[512];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t tokenBuf[1024];
    uint8_t unprotectedAlgToken[1024];
    uint8_t malformedUeid[sizeof(kUeid)];
    uint8_t malformedPayload[512];
    uint8_t malformedToken[1024];
    uint8_t payload[512];
    uint8_t lifecyclePayload[512];
    uint8_t variantPayload[513];
    uint8_t duplicatePayload[600];
    uint8_t legacyToken[1024];
    size_t tokenLen = 0u;
    size_t payloadLen = 0u;
    size_t variantLen = 0u;
    size_t duplicateLen = 0u;
    size_t legacyLen = 0u;
    size_t auxTokenLen = 0u;
    size_t malformedPayloadLen = 0u;
    size_t malformedTokenLen = 0u;
    size_t i;
    int ret;
    int testRet;
    int rngInited = 0;
    int eccInited = 0;
    int keyInited = 0;

    (void)printf("  [RFC 9783 Sign1]\n");
    test_eat_psa_claims(&claims, &component);
    claims.certificationReference.len--;
    ret = wc_EatPsaToken_EncodeClaims(&claims, claimsBuf, sizeof(claimsBuf),
        &payloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM,
        "reject malformed current certification reference");
    claims.certificationReference.len++;
    claims.lifecycle = 0x0000u;
    ret = wc_EatPsaToken_EncodeClaims(&claims, claimsBuf, sizeof(claimsBuf),
        &payloadLen);
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS,
        "accept structurally valid unknown PSA lifecycle lower boundary");
    claims.lifecycle = 0x00FFu;
    ret = wc_EatPsaToken_EncodeClaims(&claims, claimsBuf, sizeof(claimsBuf),
        &payloadLen);
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS,
        "accept structurally valid unknown PSA lifecycle upper boundary");
    claims.lifecycle = 0x2000u;
    ret = wc_EatPsaToken_EncodeClaims(&claims, claimsBuf, sizeof(claimsBuf),
        &payloadLen);
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS,
        "accept PSA RoT provisioning lifecycle lower boundary");
    claims.lifecycle = 0x20FFu;
    ret = wc_EatPsaToken_EncodeClaims(&claims, claimsBuf, sizeof(claimsBuf),
        &payloadLen);
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS,
        "accept PSA RoT provisioning lifecycle upper boundary");
    claims.lifecycle = 0x0100u;
    ret = wc_EatPsaToken_EncodeClaims(&claims, claimsBuf, sizeof(claimsBuf),
        &payloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM,
        "reject PSA lifecycle outside RFC 9783 state ranges");
    claims.lifecycle = 0x3000u;
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
        }
    }
    if (ret == 0) {
        ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &ecc);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        test_eat_psa_issue_boundaries(&key, &rng);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        for (i = 0u; i < (sizeof(lifecycleClasses) /
             sizeof(lifecycleClasses[0])); i++) {
            claims.lifecycle = lifecycleClasses[i];
            auxTokenLen = 0u;
            testRet = wc_CoseEatPsaToken_CreateSign1(&key,
                WOLFCOSE_ALG_ES256, &claims, claimsBuf, sizeof(claimsBuf),
                scratch, sizeof(scratch), legacyToken, sizeof(legacyToken),
                &auxTokenLen, &rng);
            if (testRet == WOLFCOSE_SUCCESS) {
                testRet = wc_CoseEatPsaToken_Verify(&key, legacyToken,
                    auxTokenLen, kNonce, sizeof(kNonce), scratch,
                    sizeof(scratch), &token);
            }
            TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                        token.lifecycle == lifecycleClasses[i],
                "issue and verify accepted PSA lifecycle class");
        }
        claims.lifecycle = 0x3000u;
    }
    if (ret == 0) {
        ret = wc_EatPsaToken_CreateSign1(&key, WOLFCOSE_ALG_ES256, &claims,
            claimsBuf, sizeof(claimsBuf), scratch, sizeof(scratch), tokenBuf,
            sizeof(tokenBuf), &tokenLen, &rng);
    }
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS && tokenLen > 0u,
                "create current Sign1 token");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_EatPsaToken_Verify(&key, tokenBuf, tokenLen, kNonce,
            sizeof(kNonce), scratch, sizeof(scratch), &token);
        TEST_ASSERT(ret == WOLFCOSE_SUCCESS, "verify current Sign1 token");
        TEST_ASSERT(token.profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT,
                    "current profile");
        TEST_ASSERT(token.clientId == -1 && token.lifecycle == 0x3000u,
                    "current scalar claims");
        TEST_ASSERT(token.certificationReference.len ==
                    claims.certificationReference.len &&
                    token.verificationServiceIndicator.len ==
                    claims.verificationServiceIndicator.len,
                    "current optional claims");
        (void)memset(&componentCtx, 0, sizeof(componentCtx));
        ret = wc_EatPsaToken_ForEachComponent(&token, test_eat_psa_component,
            &componentCtx);
        TEST_ASSERT(ret == WOLFCOSE_SUCCESS && componentCtx.count == 1 &&
                    componentCtx.valid != 0, "component iteration");
        testRet = wc_CoseEatPsaToken_ForEachComponent(&token,
            test_eat_psa_component_without_ctx, NULL);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS,
            "component iterator permits NULL callback context");
        testRet = wc_CoseEatPsaToken_ForEachComponent(NULL,
            test_eat_psa_component, &componentCtx);
        TEST_ASSERT(testRet == WOLFCOSE_E_INVALID_ARG,
            "component iterator rejects NULL token");
        testRet = wc_CoseEatPsaToken_ForEachComponent(&token, NULL,
            &componentCtx);
        TEST_ASSERT(testRet == WOLFCOSE_E_INVALID_ARG,
            "component iterator rejects NULL callback");
        iteratorToken = token;
        iteratorToken.components.data = NULL;
        testRet = wc_CoseEatPsaToken_ForEachComponent(&iteratorToken,
            test_eat_psa_component, &componentCtx);
        TEST_ASSERT(testRet == WOLFCOSE_E_INVALID_ARG,
            "component iterator rejects absent component data");
        test_eat_psa_verify_argument_guards(&key, tokenBuf, tokenLen, scratch,
            sizeof(scratch));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        testRet = wc_CoseEatPsaToken_EncodeClaims(&claims, payload,
            sizeof(payload), &payloadLen);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS,
            "encode canonical claims for variation-tolerance tests");
        if (testRet == WOLFCOSE_SUCCESS) {
            test_eat_psa_nonpreferred_claim_forms(&key, &rng, payload,
                payloadLen);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        test_eat_psa_nonpreferred_protected_sign1(&key, &rng);
        test_eat_psa_nonpreferred_unprotected_sign1(&key, &rng);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        static const uint8_t textUnprotected[] = {
            0xA1u, 0x66u, 'v', 'e', 'n', 'd', 'o', 'r', 0x00u
        };
        static const uint8_t contentTypeUnprotected[] = {
            0xA1u, 0x03u, 0x00u
        };
        static const uint8_t nonPreferredTextUnprotected[] = {
            0xA1u, 0x78u, 0x06u, 'v', 'e', 'n', 'd', 'o', 'r', 0x00u
        };
        static const uint8_t duplicateTextUnprotected[] = {
            0xA2u,
            0x66u, 'v', 'e', 'n', 'd', 'o', 'r', 0x00u,
            0x66u, 'v', 'e', 'n', 'd', 'o', 'r', 0x01u
        };

        if ((tokenLen > 7u) && (tokenBuf[0] == 0xD2u) &&
            (tokenBuf[1] == 0x84u) && (tokenBuf[2] == 0x43u) &&
            (tokenBuf[3] == 0xA1u) && (tokenBuf[4] == 0x01u) &&
            (tokenBuf[5] == 0x26u) && (tokenBuf[6] == 0xA0u) &&
            (tokenLen + sizeof(duplicateTextUnprotected) - 1u <=
             sizeof(unprotectedAlgToken))) {
            (void)memcpy(unprotectedAlgToken, tokenBuf, 6u);
            (void)memcpy(&unprotectedAlgToken[6], textUnprotected,
                sizeof(textUnprotected));
            (void)memcpy(&unprotectedAlgToken[6u + sizeof(textUnprotected)],
                &tokenBuf[7], tokenLen - 7u);
            auxTokenLen = tokenLen + sizeof(textUnprotected) - 1u;
            testRet = wc_EatPsaToken_Verify(&key, unprotectedAlgToken,
                auxTokenLen, kNonce, sizeof(kNonce), scratch, sizeof(scratch),
                &token);
            TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                        token.profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT,
                "PSA Sign1 accepts preferred tstr header extension");

            (void)memcpy(unprotectedAlgToken, tokenBuf, 6u);
            (void)memcpy(&unprotectedAlgToken[6], contentTypeUnprotected,
                sizeof(contentTypeUnprotected));
            (void)memcpy(&unprotectedAlgToken[6u +
                sizeof(contentTypeUnprotected)], &tokenBuf[7], tokenLen - 7u);
            auxTokenLen = tokenLen + sizeof(contentTypeUnprotected) - 1u;
            testRet = wc_EatPsaToken_Verify(&key, unprotectedAlgToken,
                auxTokenLen, kNonce, sizeof(kNonce), scratch, sizeof(scratch),
                &token);
            TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                        token.profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT,
                "PSA Sign1 accepts unprotected content type");

            (void)memcpy(unprotectedAlgToken, tokenBuf, 6u);
            (void)memcpy(&unprotectedAlgToken[6], nonPreferredTextUnprotected,
                sizeof(nonPreferredTextUnprotected));
            (void)memcpy(&unprotectedAlgToken[6u +
                sizeof(nonPreferredTextUnprotected)], &tokenBuf[7],
                tokenLen - 7u);
            auxTokenLen = tokenLen + sizeof(nonPreferredTextUnprotected) - 1u;
            testRet = wc_EatPsaToken_Verify(&key, unprotectedAlgToken,
                auxTokenLen, kNonce, sizeof(kNonce), scratch, sizeof(scratch),
                &token);
            TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                        token.profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT,
                "PSA Sign1 accepts non-preferred tstr header extension");

            (void)memcpy(unprotectedAlgToken, tokenBuf, 6u);
            (void)memcpy(&unprotectedAlgToken[6], duplicateTextUnprotected,
                sizeof(duplicateTextUnprotected));
            (void)memcpy(&unprotectedAlgToken[6u +
                sizeof(duplicateTextUnprotected)], &tokenBuf[7],
                tokenLen - 7u);
            auxTokenLen = tokenLen + sizeof(duplicateTextUnprotected) - 1u;
            (void)memset(&token, 0xA5, sizeof(token));
            testRet = wc_CoseEatPsaToken_Verify(&key, unprotectedAlgToken,
                auxTokenLen, kNonce, sizeof(kNonce), scratch,
                sizeof(scratch), &token);
            TEST_ASSERT(testRet == WOLFCOSE_E_CBOR_MALFORMED &&
                        test_eat_psa_token_is_zero(&token) != 0,
                "reject duplicate text labels in one unprotected map");
        }
        else {
            TEST_ASSERT(0, "expected deterministic PSA Sign1 header layout");
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        static const uint8_t wrongArrayCount[] = {
            0xD2u, 0x83u, 0x40u, 0xA0u, 0x40u
        };
        static const uint8_t wrongProtectedType[] = {
            0xD2u, 0x84u, 0x00u, 0xA0u, 0x40u, 0x40u
        };
        static const uint8_t wrongPayloadType[] = {
            0xD2u, 0x84u, 0x43u, 0xA1u, 0x01u, 0x26u,
            0xA0u, 0x00u, 0x40u
        };
        static const uint8_t wrongAuthType[] = {
            0xD2u, 0x84u, 0x43u, 0xA1u, 0x01u, 0x26u,
            0xA0u, 0x40u, 0x00u
        };

        test_eat_psa_expect_envelope_failure(&key, wrongArrayCount,
            sizeof(wrongArrayCount), scratch, sizeof(scratch),
            WOLFCOSE_E_CBOR_MALFORMED,
            "reject PSA envelope with wrong array count and clear output");
        test_eat_psa_expect_envelope_failure(&key, wrongProtectedType,
            sizeof(wrongProtectedType), scratch, sizeof(scratch),
            WOLFCOSE_E_CBOR_TYPE,
            "reject PSA envelope with non-bstr protected header and clear output");
        test_eat_psa_expect_envelope_failure(&key, wrongPayloadType,
            sizeof(wrongPayloadType), scratch, sizeof(scratch),
            WOLFCOSE_E_CBOR_TYPE,
            "reject PSA envelope with non-bstr payload and clear output");
        test_eat_psa_expect_envelope_failure(&key, wrongAuthType,
            sizeof(wrongAuthType), scratch, sizeof(scratch),
            WOLFCOSE_E_CBOR_TYPE,
            "reject PSA envelope with non-bstr authentication data and clear output");
        if (tokenLen < sizeof(unprotectedAlgToken)) {
            (void)memcpy(unprotectedAlgToken, tokenBuf, tokenLen);
            unprotectedAlgToken[tokenLen] = 0x00u;
            test_eat_psa_expect_envelope_failure(&key, unprotectedAlgToken,
                tokenLen + 1u, scratch, sizeof(scratch),
                WOLFCOSE_E_CBOR_MALFORMED,
                "reject PSA envelope trailing data and clear output");
        }
        else {
            TEST_ASSERT(0, "room for PSA envelope trailing-data test");
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        test_eat_psa_nonce_and_hash_lengths(&key, &rng);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        test_eat_psa_claim_rejections(&key, &rng, &claims, scratch,
            sizeof(scratch));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        multiClaims = claims;
        multiComponents[0] = component;
        multiComponents[1] = component;
        multiClaims.components = multiComponents;
        multiClaims.componentCount = 2u;
        testRet = wc_CoseEatPsaToken_CreateSign1(&key, WOLFCOSE_ALG_ES256,
            &multiClaims, claimsBuf, sizeof(claimsBuf), scratch,
            sizeof(scratch), legacyToken, sizeof(legacyToken), &auxTokenLen,
            &rng);
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = wc_CoseEatPsaToken_Verify(&key, legacyToken,
                auxTokenLen, kNonce, sizeof(kNonce), scratch, sizeof(scratch),
                &token);
        }
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS && token.componentCount == 2u,
            "verify token with multiple components");
        if (testRet == WOLFCOSE_SUCCESS) {
            (void)memset(&componentCtx, 0, sizeof(componentCtx));
            componentCtx.fail = 1;
            testRet = wc_CoseEatPsaToken_ForEachComponent(&token,
                test_eat_psa_component, &componentCtx);
            TEST_ASSERT(testRet == WOLFCOSE_E_EAT_PSA_CLAIM &&
                        componentCtx.count == 1,
                "propagate component callback failure once");
            (void)memset(&componentCtx, 0, sizeof(componentCtx));
            token.componentCount++;
            testRet = wc_CoseEatPsaToken_ForEachComponent(&token,
                test_eat_psa_component, &componentCtx);
            TEST_ASSERT(testRet == WOLFCOSE_E_EAT_PSA_CLAIM &&
                        componentCtx.count == 0,
                "reject component count mismatch");
            token.componentCount--;
            (void)memset(&componentCtx, 0, sizeof(componentCtx));
            token.components.len--;
            testRet = wc_CoseEatPsaToken_ForEachComponent(&token,
                test_eat_psa_component, &componentCtx);
            TEST_ASSERT(testRet != WOLFCOSE_SUCCESS &&
                        componentCtx.count < 2,
                "reject truncated component data");
            token.components.len++;
            if (token.components.len < sizeof(variantPayload)) {
                (void)memcpy(variantPayload, token.components.data,
                    token.components.len);
                variantPayload[token.components.len] = 0x00u;
                iteratorToken = token;
                iteratorToken.components.data = variantPayload;
                iteratorToken.components.len++;
                (void)memset(&componentCtx, 0, sizeof(componentCtx));
                testRet = wc_CoseEatPsaToken_ForEachComponent(&iteratorToken,
                    test_eat_psa_component, &componentCtx);
                TEST_ASSERT(testRet == WOLFCOSE_E_EAT_PSA_CLAIM &&
                            componentCtx.count == 2,
                    "reject bytes trailing the component array");
            }
            else {
                TEST_ASSERT(0, "room for trailing component-array byte");
            }
        }
    }
    if ((ret == WOLFCOSE_SUCCESS) && (tokenLen > 1u)) {
        testRet = wc_EatPsaToken_Verify(&key, &tokenBuf[1], tokenLen - 1u,
            kNonce, sizeof(kNonce), scratch, sizeof(scratch), &token);
        TEST_ASSERT(testRet != WOLFCOSE_SUCCESS, "reject untagged PSA token");
    }
    if (ret == WOLFCOSE_SUCCESS) {
        if ((tokenLen > 7u) && (tokenBuf[0] == 0xD2u) &&
            (tokenBuf[1] == 0x84u) && (tokenBuf[6] == 0xA0u)) {
            (void)memcpy(unprotectedAlgToken, tokenBuf, 2u);
            unprotectedAlgToken[2] = 0x40u;
            unprotectedAlgToken[3] = 0xA1u;
            unprotectedAlgToken[4] = 0x01u;
            unprotectedAlgToken[5] = 0x26u;
            (void)memcpy(&unprotectedAlgToken[6], &tokenBuf[7],
                tokenLen - 7u);
            auxTokenLen = tokenLen - 1u;
            testRet = wc_EatPsaToken_Verify(&key, unprotectedAlgToken,
                auxTokenLen, kNonce, sizeof(kNonce), scratch,
                sizeof(scratch), &token);
            TEST_ASSERT(testRet == WOLFCOSE_E_COSE_BAD_HDR,
                "reject unauthenticated COSE algorithm");
        }
        else {
            TEST_ASSERT(0, "expected deterministic Sign1 header layout");
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        resolver.key = &key;
        resolver.called = 0;
        resolver.fail = 0;
        resolver.receivedProfile = WOLFCOSE_EAT_PSA_PROFILE_NONE;
        resolver.receivedAlg = WOLFCOSE_ALG_UNSET;
        ret = wc_EatPsaToken_VerifyByUeid(test_eat_psa_resolve, &resolver,
            tokenBuf, tokenLen, kNonce, sizeof(kNonce), scratch,
            sizeof(scratch), &token);
        TEST_ASSERT(ret == WOLFCOSE_SUCCESS && resolver.called == 1 &&
                    resolver.receivedProfile ==
                        WOLFCOSE_EAT_PSA_PROFILE_CURRENT &&
                    resolver.receivedAlg == WOLFCOSE_ALG_ES256,
                    "resolve current Sign1 key by UEID and COSE algorithm");
        testRet = wc_EatPsaToken_VerifyByUeid(test_eat_psa_resolve, &resolver,
            tokenBuf, tokenLen, kNonce, sizeof(kNonce), scratch,
            sizeof(scratch), NULL);
        TEST_ASSERT(testRet == WOLFCOSE_E_INVALID_ARG,
            "reject NULL UEID resolver output");
        (void)memset(&token, 0xA5, sizeof(token));
        resolver.fail = 1;
        testRet = wc_EatPsaToken_VerifyByUeid(test_eat_psa_resolve, &resolver,
            tokenBuf, tokenLen, kNonce, sizeof(kNonce), scratch,
            sizeof(scratch), &token);
        TEST_ASSERT(testRet == WOLFCOSE_E_EAT_PSA_KEY &&
                    test_eat_psa_token_is_zero(&token) != 0,
            "propagate resolver failure and clear token output");
        resolver.fail = 0;

        (void)memcpy(unprotectedAlgToken, tokenBuf, tokenLen);
        unprotectedAlgToken[tokenLen - 1u] ^= 0xFFu;
        (void)memset(&token, 0xA5, sizeof(token));
        resolver.called = 0;
        testRet = wc_EatPsaToken_VerifyByUeid(test_eat_psa_resolve, &resolver,
            unprotectedAlgToken, tokenLen, kNonce, sizeof(kNonce), scratch,
            sizeof(scratch), &token);
        TEST_ASSERT(testRet == WOLFCOSE_E_COSE_SIG_FAIL &&
                    resolver.called == 1 &&
                    test_eat_psa_token_is_zero(&token) != 0,
            "resolve Sign1 key before rejecting tampered signature and clear output");

        (void)memcpy(malformedUeid, kUeid, sizeof(malformedUeid));
        malformedUeid[0] = 0x02u;
        malformedClaims = claims;
        malformedClaims.ueid.data = malformedUeid;
        testRet = test_eat_psa_encode_current_raw_ex(&malformedClaims,
            currentProfile, sizeof(currentProfile) - 1u, 0u, 0u, 0, 0u,
            malformedClaims.componentCount, malformedPayload,
            sizeof(malformedPayload), &malformedPayloadLen);
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = test_eat_psa_sign1_payload(&key, &rng,
                malformedPayload, malformedPayloadLen, scratch,
                sizeof(scratch), malformedToken, sizeof(malformedToken),
                &malformedTokenLen);
        }
        resolver.called = 0;
        (void)memset(&token, 0xA5, sizeof(token));
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = wc_CoseEatPsaToken_VerifyByUeid(
                test_eat_psa_resolve, &resolver, malformedToken,
                malformedTokenLen, kNonce, sizeof(kNonce), scratch,
                sizeof(scratch), &token);
        }
        TEST_ASSERT(testRet == WOLFCOSE_E_EAT_PSA_CLAIM &&
                    resolver.called == 0 &&
                    test_eat_psa_token_is_zero(&token) != 0,
            "reject malformed routing UEID before invoking resolver");
    }
    if (ret == WOLFCOSE_SUCCESS) {
        if ((tokenLen > 7u) && (tokenBuf[0] == 0xD2u) &&
            (tokenBuf[1] == 0x84u) && (tokenBuf[6] == 0xA0u)) {
            (void)memcpy(legacyToken, tokenBuf, 6u);
            legacyToken[6] = 0xA1u;
            legacyToken[7] = 0x18u;
            legacyToken[8] = 0x21u;
            legacyToken[9] = 0x40u;
            (void)memcpy(&legacyToken[10], &tokenBuf[7], tokenLen - 7u);
            auxTokenLen = tokenLen + 3u;
            testRet = wc_EatPsaToken_Verify(&key, legacyToken, auxTokenLen,
                kNonce, sizeof(kNonce), scratch, sizeof(scratch), &token);
            TEST_ASSERT(testRet == WOLFCOSE_E_UNSUPPORTED,
                "reject x5chain without a certificate validator");
        }
        else {
            TEST_ASSERT(0, "expected deterministic Sign1 header layout");
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        (void)memcpy(legacyToken, tokenBuf, tokenLen);
        legacyToken[5] = 0x27u; /* EdDSA, which is not a TFM PSA algorithm. */
        testRet = wc_EatPsaToken_Verify(&key, legacyToken, tokenLen, kNonce,
            sizeof(kNonce), scratch, sizeof(scratch), &token);
        TEST_ASSERT(testRet == WOLFCOSE_E_COSE_BAD_ALG,
            "reject non-TFM PSA algorithm before cryptographic verification");
    }
    if (ret == WOLFCOSE_SUCCESS) {
        testRet = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0u,
            NULL, 0u, kNonce, sizeof(kNonce), NULL, 0u, scratch,
            sizeof(scratch), legacyToken, sizeof(legacyToken), &auxTokenLen,
            &rng);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS,
            "create detached Sign1 for PSA rejection test");
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = wc_EatPsaToken_Verify(&key, legacyToken, auxTokenLen,
                kNonce, sizeof(kNonce), scratch, sizeof(scratch), &token);
            TEST_ASSERT(testRet == WOLFCOSE_E_DETACHED_PAYLOAD,
                "reject detached PSA token");
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        static const uint8_t indefiniteClaims[] = { 0xBFu, 0xFFu };

        testRet = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0u,
            indefiniteClaims, sizeof(indefiniteClaims), NULL, 0u, NULL, 0u,
            scratch, sizeof(scratch), legacyToken, sizeof(legacyToken),
            &auxTokenLen, &rng);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS,
            "create indefinite CBOR PSA rejection token");
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = wc_EatPsaToken_Verify(&key, legacyToken, auxTokenLen,
                kNonce, sizeof(kNonce), scratch, sizeof(scratch), &token);
            TEST_ASSERT(testRet == WOLFCOSE_E_UNSUPPORTED,
                "reject indefinite-length PSA claims");
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        uint8_t wrongNonce[sizeof(kNonce)];
        (void)memcpy(wrongNonce, kNonce, sizeof(wrongNonce));
        wrongNonce[0] ^= 0xFFu;
        (void)memset(&token, 0xA5, sizeof(token));
        ret = wc_EatPsaToken_Verify(&key, tokenBuf, tokenLen, wrongNonce,
            sizeof(wrongNonce), scratch, sizeof(scratch), &token);
        TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_NONCE &&
                    test_eat_psa_token_is_zero(&token) != 0,
            "reject wrong nonce and clear token output");
        testRet = wc_EatPsaToken_Verify(&key, tokenBuf, tokenLen, NULL, 0u,
            scratch, sizeof(scratch), &token);
        TEST_ASSERT(testRet == WOLFCOSE_E_INVALID_ARG,
            "reject invalid expected nonce before verification");
        testRet = wc_EatPsaToken_Verify(&key, tokenBuf, tokenLen, kNonce,
            sizeof(kNonce), scratch, sizeof(scratch), NULL);
        TEST_ASSERT(testRet == WOLFCOSE_E_INVALID_ARG,
            "reject NULL verifier output");
        ret = wc_EatPsaToken_EncodeClaims(&claims, payload, sizeof(payload),
            &payloadLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        (void)memcpy(lifecyclePayload, payload, payloadLen);
        testRet = test_eat_psa_set_lifecycle(lifecyclePayload, payloadLen,
            0x00FFu);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS,
            "locate current lifecycle claim");
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0u,
                lifecyclePayload, payloadLen, NULL, 0u, NULL, 0u,
                scratch, sizeof(scratch), legacyToken, sizeof(legacyToken),
                &auxTokenLen, &rng);
        }
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS,
            "create signed unknown lifecycle token");
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = wc_EatPsaToken_Verify(&key, legacyToken, auxTokenLen,
                kNonce, sizeof(kNonce), scratch, sizeof(scratch), &token);
            TEST_ASSERT(testRet == WOLFCOSE_SUCCESS && token.lifecycle == 0x00FFu,
                "retain unknown lifecycle for application policy");
        }

        for (i = 0u; i < (sizeof(provisioningLifecycles) /
             sizeof(provisioningLifecycles[0])); i++) {
            (void)memcpy(lifecyclePayload, payload, payloadLen);
            testRet = test_eat_psa_set_lifecycle(lifecyclePayload,
                payloadLen, provisioningLifecycles[i]);
            if (testRet == WOLFCOSE_SUCCESS) {
                testRet = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
                    NULL, 0u, lifecyclePayload, payloadLen, NULL, 0u,
                    NULL, 0u, scratch, sizeof(scratch), legacyToken,
                    sizeof(legacyToken), &auxTokenLen, &rng);
            }
            if (testRet == WOLFCOSE_SUCCESS) {
                testRet = wc_EatPsaToken_Verify(&key, legacyToken,
                    auxTokenLen, kNonce, sizeof(kNonce), scratch,
                    sizeof(scratch), &token);
            }
            TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                token.lifecycle == provisioningLifecycles[i],
                "accept signed PSA RoT provisioning lifecycle boundaries");
        }
        (void)memcpy(lifecyclePayload, payload, payloadLen);
        testRet = test_eat_psa_set_lifecycle(lifecyclePayload, payloadLen,
            0x0100u);
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0u,
                lifecyclePayload, payloadLen, NULL, 0u, NULL, 0u, scratch,
                sizeof(scratch), legacyToken, sizeof(legacyToken),
                &auxTokenLen, &rng);
        }
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = wc_CoseEatPsaToken_Verify(&key, legacyToken, auxTokenLen,
                kNonce, sizeof(kNonce), scratch, sizeof(scratch), &token);
        }
        TEST_ASSERT(testRet == WOLFCOSE_E_EAT_PSA_CLAIM,
            "reject signed lifecycle outside RFC 9783 state ranges");
    }
    if (ret == WOLFCOSE_SUCCESS) {
        (void)memcpy(variantPayload, payload, 1u);
        variantPayload[1] = 0x18u;
        variantPayload[2] = 0x0Au;
        (void)memcpy(&variantPayload[3], &payload[2], payloadLen - 2u);
        variantLen = payloadLen + 1u;
        ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0u,
            variantPayload, variantLen, NULL, 0u, NULL, 0u, scratch,
            sizeof(scratch), tokenBuf, sizeof(tokenBuf), &tokenLen, &rng);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_EatPsaToken_Verify(&key, tokenBuf, tokenLen, kNonce,
            sizeof(kNonce), scratch, sizeof(scratch), &token);
        TEST_ASSERT(ret == WOLFCOSE_SUCCESS, "accept non-preferred claim label");
    }
    if (ret == WOLFCOSE_SUCCESS) {
        if ((payload[0] < 0xa0u) || (payload[0] >= 0xb7u)) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
        else {
            /* Add a second copy of the first current-profile nonce claim. */
            duplicatePayload[0] = (uint8_t)(payload[0] + 1u);
            (void)memcpy(&duplicatePayload[1], &payload[1], payloadLen - 1u);
            (void)memcpy(&duplicatePayload[payloadLen], &payload[1], 35u);
            duplicateLen = payloadLen + 35u;
            ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0u,
                duplicatePayload, duplicateLen, NULL, 0u, NULL, 0u, scratch,
                sizeof(scratch), tokenBuf, sizeof(tokenBuf), &tokenLen, &rng);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_EatPsaToken_Verify(&key, tokenBuf, tokenLen, kNonce,
            sizeof(kNonce), scratch, sizeof(scratch), &token);
        TEST_ASSERT(ret == WOLFCOSE_E_EAT_PSA_CLAIM,
                    "reject duplicate PSA claim");
        claims.bootSeed.data = kLegacyBootSeed;
        claims.bootSeed.len = sizeof(kLegacyBootSeed);
        ret = test_eat_psa_encode_legacy(&claims, payload, sizeof(payload),
            &payloadLen, 0, 0, 0);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0u, payload,
            payloadLen, NULL, 0u, NULL, 0u, scratch, sizeof(scratch),
            legacyToken, sizeof(legacyToken), &legacyLen, &rng);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_EatPsaToken_Verify(&key, legacyToken, legacyLen, kNonce,
            sizeof(kNonce), scratch, sizeof(scratch), &token);
        TEST_ASSERT(ret == WOLFCOSE_SUCCESS &&
                    token.profile == WOLFCOSE_EAT_PSA_PROFILE_OLD &&
                    token.verificationServiceIndicator.len ==
                        claims.verificationServiceIndicator.len &&
                    memcmp(token.verificationServiceIndicator.data,
                        claims.verificationServiceIndicator.data,
                        claims.verificationServiceIndicator.len) == 0,
                    "consume legacy PSA token with verification service indicator");
    }
    if (ret == WOLFCOSE_SUCCESS) {
        static const uint8_t validCert[] = "1234567890123";
        static const uint8_t shortCert[] = "123456789012";
        static const uint8_t nonDigitCert[] = "123456789012x";
        WOLFCOSE_EAT_PSA_SPAN certification;

        certification.data = validCert;
        certification.len = sizeof(validCert) - 1u;
        testRet = test_eat_psa_verify_legacy_raw(&key, &rng, &claims, 1, 1,
            0, 0u, &certification, scratch, sizeof(scratch), &token);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                    token.certificationReference.len == certification.len,
            "accept valid legacy certification reference");

        certification.data = shortCert;
        certification.len = sizeof(shortCert) - 1u;
        testRet = test_eat_psa_verify_legacy_raw(&key, &rng, &claims, 1, 1,
            0, 0u, &certification, scratch, sizeof(scratch), &token);
        TEST_ASSERT(testRet == WOLFCOSE_E_EAT_PSA_CLAIM &&
                    test_eat_psa_token_is_zero(&token) != 0,
            "reject short legacy certification reference");

        certification.data = nonDigitCert;
        certification.len = sizeof(nonDigitCert) - 1u;
        testRet = test_eat_psa_verify_legacy_raw(&key, &rng, &claims, 1, 1,
            0, 0u, &certification, scratch, sizeof(scratch), &token);
        TEST_ASSERT(testRet == WOLFCOSE_E_EAT_PSA_CLAIM &&
                    test_eat_psa_token_is_zero(&token) != 0,
            "reject nonnumeric legacy certification reference");

        testRet = test_eat_psa_verify_legacy_raw(&key, &rng, &claims, 1, 0,
            1, 2u, NULL, scratch, sizeof(scratch), &token);
        TEST_ASSERT(testRet == WOLFCOSE_E_EAT_PSA_CLAIM &&
                    test_eat_psa_token_is_zero(&token) != 0,
            "reject legacy no-measurements value other than one");

        testRet = test_eat_psa_verify_legacy_raw(&key, &rng, &claims, 1, 1,
            1, 1u, NULL, scratch, sizeof(scratch), &token);
        TEST_ASSERT(testRet == WOLFCOSE_E_EAT_PSA_CLAIM &&
                    test_eat_psa_token_is_zero(&token) != 0,
            "reject legacy token with components and no-measurements");

        testRet = test_eat_psa_verify_legacy_raw(&key, &rng, &claims, 1, 0,
            0, 0u, NULL, scratch, sizeof(scratch), &token);
        TEST_ASSERT(testRet == WOLFCOSE_E_EAT_PSA_CLAIM &&
                    test_eat_psa_token_is_zero(&token) != 0,
            "reject legacy token without components or no-measurements");
    }
    if (ret == WOLFCOSE_SUCCESS) {
        testRet = test_eat_psa_encode_legacy(&claims, payload,
            sizeof(payload), &payloadLen, 0, 0, 1);
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0u,
                payload, payloadLen, NULL, 0u, NULL, 0u, scratch,
                sizeof(scratch), legacyToken, sizeof(legacyToken), &legacyLen,
                &rng);
        }
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = wc_CoseEatPsaToken_Verify(&key, legacyToken, legacyLen,
                kNonce, sizeof(kNonce), scratch, sizeof(scratch), &token);
        }
        TEST_ASSERT(testRet == WOLFCOSE_E_EAT_PSA_PROFILE,
            "reject signed incompatible legacy profile");
    }
    if (ret == WOLFCOSE_SUCCESS) {
        testRet = test_eat_psa_encode_legacy(&claims, payload,
            sizeof(payload), &payloadLen, 1, 1, 0);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS,
            "encode legacy token without profile and measurements");
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0u,
                payload, payloadLen, NULL, 0u, NULL, 0u, scratch,
                sizeof(scratch), legacyToken, sizeof(legacyToken), &legacyLen,
                &rng);
        }
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS,
            "sign legacy token without profile and measurements");
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = wc_EatPsaToken_Verify(&key, legacyToken, legacyLen,
                kNonce, sizeof(kNonce), scratch, sizeof(scratch), &token);
        }
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                    token.profile == WOLFCOSE_EAT_PSA_PROFILE_OLD &&
                    token.noSoftwareMeasurements != 0u &&
                    token.componentCount == 0u,
                    "consume legacy no-measurements token");
        if (testRet == WOLFCOSE_SUCCESS) {
            (void)memset(&componentCtx, 0, sizeof(componentCtx));
            testRet = wc_EatPsaToken_ForEachComponent(&token,
                test_eat_psa_component, &componentCtx);
            TEST_ASSERT(testRet == WOLFCOSE_SUCCESS && componentCtx.count == 0,
                "iterate legacy no-measurements token");
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        claims.bootSeed.len--;
        testRet = test_eat_psa_encode_legacy(&claims, payload,
            sizeof(payload), &payloadLen, 0, 0, 0);
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0u,
                payload, payloadLen, NULL, 0u, NULL, 0u, scratch,
                sizeof(scratch), legacyToken, sizeof(legacyToken), &legacyLen,
                &rng);
        }
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = wc_EatPsaToken_Verify(&key, legacyToken, legacyLen,
                kNonce, sizeof(kNonce), scratch, sizeof(scratch), &token);
        }
        TEST_ASSERT(testRet == WOLFCOSE_E_EAT_PSA_CLAIM,
            "reject legacy boot seed that is not 32 bytes");
        claims.bootSeed.len++;
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

#if defined(WOLFCOSE_EXT_SIGN) && defined(WOLFCOSE_SIGN1_SIGN) && \
    defined(WOLFCOSE_SIGN1_VERIFY) && defined(WOLFCOSE_HAVE_ES256)
static void test_eat_psa_delegated_signer(void)
{
    WOLFCOSE_EAT_PSA_CLAIMS claims;
    WOLFCOSE_EAT_PSA_COMPONENT component;
    WOLFCOSE_EAT_PSA_TOKEN token;
    WOLFCOSE_KEY signKey;
    WOLFCOSE_KEY verifyKey;
    EAT_PSA_EXT_SIGN_CTX signCtx;
    ecc_key ecc;
    WC_RNG rng;
    uint8_t claimsBuf[512];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t tokenBuf[1024];
    size_t tokenLen = 0u;
    int ret;
    int rngInited = 0;
    int eccInited = 0;
    int signKeyInited = 0;
    int verifyKeyInited = 0;

    (void)printf("  [RFC 9783 delegated Sign1]\n");
    test_eat_psa_claims(&claims, &component);
    (void)memset(&signCtx, 0, sizeof(signCtx));
    ret = wc_InitRng(&rng);
    if (ret == WOLFCOSE_SUCCESS) {
        rngInited = 1;
        ret = wc_ecc_init(&ecc);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        eccInited = 1;
        ret = wc_ecc_make_key_ex(&rng, 32, &ecc, ECC_SECP256R1);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseKey_Init(&signKey);
        if (ret == WOLFCOSE_SUCCESS) {
            signKeyInited = 1;
            signKey.kty = WOLFCOSE_KTY_EC2;
            signKey.crv = WOLFCOSE_CRV_P256;
            signCtx.rng = &rng;
            signCtx.key = &ecc;
            ret = wc_CoseKey_SetExtSigner(&signKey, test_eat_psa_ext_sign_cb,
                &signCtx);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseKey_Init(&verifyKey);
        if (ret == WOLFCOSE_SUCCESS) {
            verifyKeyInited = 1;
            ret = wc_CoseKey_SetEcc(&verifyKey, WOLFCOSE_CRV_P256, &ecc);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        /* The key-handle signer owns its entropy. This is the PSA client
         * handoff path, so the wolfCOSE RNG argument remains NULL. */
        ret = wc_EatPsaToken_CreateSign1(&signKey, WOLFCOSE_ALG_ES256,
            &claims, claimsBuf, sizeof(claimsBuf), scratch, sizeof(scratch),
            tokenBuf, sizeof(tokenBuf), &tokenLen, NULL);
    }
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS && tokenLen > 0u &&
                signCtx.called == 1,
                "create PSA token with delegated signer and NULL RNG");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_EatPsaToken_Verify(&verifyKey, tokenBuf, tokenLen, kNonce,
            sizeof(kNonce), scratch, sizeof(scratch), &token);
        TEST_ASSERT(ret == WOLFCOSE_SUCCESS,
            "verify delegated PSA token");
    }
    if (ret == WOLFCOSE_SUCCESS) {
        signCtx.fail = 1;
        (void)memset(tokenBuf, 0xA5, sizeof(tokenBuf));
        tokenLen = 17u;
        ret = wc_EatPsaToken_CreateSign1(&signKey, WOLFCOSE_ALG_ES256,
            &claims, claimsBuf, sizeof(claimsBuf), scratch, sizeof(scratch),
            tokenBuf, sizeof(tokenBuf), &tokenLen, NULL);
        TEST_ASSERT(ret == WOLFCOSE_E_CRYPTO && signCtx.called == 2 &&
                    tokenLen == 0u && test_eat_psa_bytes_are_zero(tokenBuf,
                        sizeof(tokenBuf)) != 0,
            "propagate delegated PSA signer failure and clear token output");
    }

    if (verifyKeyInited != 0) {
        wc_CoseKey_Free(&verifyKey);
    }
    if (signKeyInited != 0) {
        wc_CoseKey_Free(&signKey);
    }
    if (eccInited != 0) {
        (void)wc_ecc_free(&ecc);
    }
    if (rngInited != 0) {
        (void)wc_FreeRng(&rng);
    }
}
#endif

#if defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_SIGN1_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES256) && \
    (defined(WOLFCOSE_HAVE_ES384) || defined(WOLFCOSE_HAVE_ES512))
static void test_eat_psa_sign_alg(int32_t alg, int keySize, int curve,
    int32_t coseCurve, const char* name)
{
    WOLFCOSE_EAT_PSA_CLAIMS claims;
    WOLFCOSE_EAT_PSA_COMPONENT component;
    WOLFCOSE_EAT_PSA_TOKEN token;
    WOLFCOSE_KEY key;
    ecc_key ecc;
    WC_RNG rng;
    uint8_t claimsBuf[768];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t tokenBuf[1300];
    size_t tokenLen = 0u;
    int ret;
    int rngInited = 0;
    int eccInited = 0;
    int keyInited = 0;

    (void)printf("  [RFC 9783 Sign1 %s]\n", name);
    test_eat_psa_claims(&claims, &component);
    ret = wc_InitRng(&rng);
    if (ret == WOLFCOSE_SUCCESS) {
        rngInited = 1;
        ret = wc_ecc_init(&ecc);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        eccInited = 1;
        ret = wc_ecc_make_key_ex(&rng, keySize, &ecc, curve);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseKey_Init(&key);
        if (ret == WOLFCOSE_SUCCESS) {
            keyInited = 1;
            ret = wc_CoseKey_SetEcc(&key, coseCurve, &ecc);
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_EatPsaToken_CreateSign1(&key, alg, &claims, claimsBuf,
            sizeof(claimsBuf), scratch, sizeof(scratch), tokenBuf,
            sizeof(tokenBuf), &tokenLen, &rng);
    }
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS && tokenLen > 0u,
        "create current TFM Sign1 token");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_EatPsaToken_Verify(&key, tokenBuf, tokenLen, kNonce,
            sizeof(kNonce), scratch, sizeof(scratch), &token);
        TEST_ASSERT(ret == WOLFCOSE_SUCCESS &&
                    token.protection == WOLFCOSE_EAT_PSA_PROTECTION_SIGN1,
                    "verify current TFM Sign1 token");
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

#if defined(WOLFCOSE_MAC0_CREATE) && defined(WOLFCOSE_MAC0_VERIFY) && \
    defined(WOLFCOSE_HAVE_HMAC256)
static int test_eat_psa_mac0_overlap_rejected(const WOLFCOSE_KEY* key,
    const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    uint8_t* claimsBuf, size_t claimsBufSz,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz)
{
    size_t outLen = 17u;
    int ret;

    (void)memset(out, 0xA5, outSz);
    ret = wc_CoseEatPsaToken_CreateMac0(key, WOLFCOSE_ALG_HMAC_256_256,
        claims, claimsBuf, claimsBufSz, scratch, scratchSz, out, outSz,
        &outLen);
    return ((ret == WOLFCOSE_E_INVALID_ARG) && (outLen == 0u) &&
            (test_eat_psa_bytes_are_zero(out, outSz) != 0)) ? 1 : 0;
}

static void test_eat_psa_expect_mac0_overlap(const WOLFCOSE_KEY* key,
    const WOLFCOSE_EAT_PSA_CLAIMS* claims,
    uint8_t* claimsBuf, size_t claimsBufSz,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, const char* name)
{
    TEST_ASSERT(test_eat_psa_mac0_overlap_rejected(key, claims, claimsBuf,
                    claimsBufSz, scratch, scratchSz, out, outSz) != 0,
        name);
}

static void test_eat_psa_mac0(void)
{
    WOLFCOSE_EAT_PSA_CLAIMS claims;
    WOLFCOSE_EAT_PSA_COMPONENT component;
    WOLFCOSE_EAT_PSA_TOKEN token;
    WOLFCOSE_KEY key;
    union {
        WOLFCOSE_EAT_PSA_CLAIMS claims;
        WOLFCOSE_EAT_PSA_COMPONENT component;
        uint8_t bytes[2048];
    } inputStorage;
    uint8_t claimsBuf[512];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t tokenBuf[1024];
    uint8_t modifiedToken[1024];
    uint8_t legacyPayload[512];
    uint8_t legacyToken[1024];
    uint8_t overlap[2048];
    size_t tokenLen = 0u;
    size_t legacyPayloadLen = 0u;
    size_t legacyTokenLen = 0u;
    size_t outLen = 17u;
    size_t argCase;
    size_t i;
    int ret;
    int testRet;
    int keyInited = 0;
    int spanChecks;
#if defined(WOLFCOSE_EAT_PSA_UEID_RESOLVER)
    EAT_PSA_RESOLVER_CTX resolver;
#endif

    (void)printf("  [RFC 9783 Mac0]\n");
    test_eat_psa_claims(&claims, &component);
    ret = wc_CoseKey_Init(&key);
    if (ret == WOLFCOSE_SUCCESS) {
        keyInited = 1;
        ret = wc_CoseKey_SetSymmetric(&key, kMac0TestKey,
            sizeof(kMac0TestKey));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_EatPsaToken_CreateMac0(&key, WOLFCOSE_ALG_HMAC_256_256,
            &claims, claimsBuf, sizeof(claimsBuf), scratch, sizeof(scratch),
            tokenBuf, sizeof(tokenBuf), &tokenLen);
    }
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS && tokenLen > 0u,
                "create current Mac0 token");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_EatPsaToken_Verify(&key, tokenBuf, tokenLen, kNonce,
            sizeof(kNonce), scratch, sizeof(scratch), &token);
        TEST_ASSERT(ret == WOLFCOSE_SUCCESS &&
                    token.profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT,
                    "verify current Mac0 token");
    }
    if (ret == WOLFCOSE_SUCCESS) {
        test_eat_psa_claims(&claims, &component);
        inputStorage.claims = claims;
        TEST_ASSERT(test_eat_psa_mac0_overlap_rejected(&key,
                        &inputStorage.claims, inputStorage.bytes,
                        sizeof(inputStorage.bytes), scratch, sizeof(scratch),
                        modifiedToken, sizeof(modifiedToken)) != 0,
            "Mac0 issuer rejects exact claims-structure overlap");
        test_eat_psa_claims(&claims, &component);
        inputStorage.claims = claims;
        TEST_ASSERT(test_eat_psa_mac0_overlap_rejected(&key,
                        &inputStorage.claims,
                        &inputStorage.bytes[sizeof(inputStorage.claims) / 2u],
                        sizeof(inputStorage.bytes) -
                            (sizeof(inputStorage.claims) / 2u),
                        scratch, sizeof(scratch), modifiedToken,
                        sizeof(modifiedToken)) != 0,
            "Mac0 issuer rejects partial claims-structure overlap");

        test_eat_psa_claims(&claims, &component);
        inputStorage.component = component;
        claims.components = &inputStorage.component;
        TEST_ASSERT(test_eat_psa_mac0_overlap_rejected(&key, &claims,
                        inputStorage.bytes, sizeof(inputStorage.bytes),
                        scratch, sizeof(scratch), modifiedToken,
                        sizeof(modifiedToken)) != 0,
            "Mac0 issuer rejects exact component-array overlap");
        test_eat_psa_claims(&claims, &component);
        inputStorage.component = component;
        claims.components = &inputStorage.component;
        TEST_ASSERT(test_eat_psa_mac0_overlap_rejected(&key, &claims,
                        &inputStorage.bytes[
                            sizeof(inputStorage.component) / 2u],
                        sizeof(inputStorage.bytes) -
                            (sizeof(inputStorage.component) / 2u),
                        scratch, sizeof(scratch), modifiedToken,
                        sizeof(modifiedToken)) != 0,
            "Mac0 issuer rejects partial component-array overlap");

        spanChecks = 1;
        for (i = 0u; i < TEST_EAT_PSA_INPUT_SPAN_COUNT; i++) {
            if ((test_eat_psa_alias_input_span(&claims, &component, i,
                     inputStorage.bytes, sizeof(inputStorage.bytes)) == 0) ||
                (test_eat_psa_mac0_overlap_rejected(&key, &claims,
                     inputStorage.bytes, sizeof(inputStorage.bytes), scratch,
                     sizeof(scratch), modifiedToken, sizeof(modifiedToken)) ==
                 0)) {
                spanChecks = 0;
            }
            if ((test_eat_psa_alias_input_span(&claims, &component, i,
                     inputStorage.bytes, sizeof(inputStorage.bytes)) == 0) ||
                (test_eat_psa_mac0_overlap_rejected(&key, &claims,
                     &inputStorage.bytes[1], sizeof(inputStorage.bytes) - 1u,
                     scratch, sizeof(scratch), modifiedToken,
                     sizeof(modifiedToken)) == 0)) {
                spanChecks = 0;
            }
        }
        TEST_ASSERT(spanChecks != 0,
            "Mac0 rejects exact/partial overlap for every input span");

        test_eat_psa_claims(&claims, &component);
        test_eat_psa_expect_mac0_overlap(&key, &claims,
            overlap, 512u, scratch, sizeof(scratch), overlap, 1024u,
            "Mac0 rejects exact claims/output overlap");
        test_eat_psa_expect_mac0_overlap(&key, &claims,
            &overlap[256], 512u, scratch, sizeof(scratch), overlap, 1024u,
            "Mac0 rejects partial claims/output overlap");
        test_eat_psa_expect_mac0_overlap(&key, &claims,
            overlap, 512u, overlap, 1024u, modifiedToken,
            sizeof(modifiedToken), "Mac0 rejects exact claims/scratch overlap");
        test_eat_psa_expect_mac0_overlap(&key, &claims,
            overlap, 512u, &overlap[256], 1024u, modifiedToken,
            sizeof(modifiedToken),
            "Mac0 rejects partial claims/scratch overlap");
        test_eat_psa_expect_mac0_overlap(&key, &claims,
            claimsBuf, sizeof(claimsBuf), overlap, 1024u, overlap, 1024u,
            "Mac0 rejects exact scratch/output overlap");
        test_eat_psa_expect_mac0_overlap(&key, &claims,
            claimsBuf, sizeof(claimsBuf), overlap, 1024u, &overlap[256],
            1024u, "Mac0 rejects partial scratch/output overlap");
    }
    if (ret == WOLFCOSE_SUCCESS) {
        test_eat_psa_nonpreferred_protected_mac0(&key);
        test_eat_psa_nonpreferred_unprotected_mac0(&key);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        static const uint8_t textUnprotected[] = {
            0xA1u, 0x66u, 'v', 'e', 'n', 'd', 'o', 'r', 0x00u
        };
        static const uint8_t contentTypeUnprotected[] = {
            0xA1u, 0x03u, 0x00u
        };
        static const uint8_t nonPreferredTextUnprotected[] = {
            0xA1u, 0x78u, 0x06u, 'v', 'e', 'n', 'd', 'o', 'r', 0x00u
        };

        if ((tokenLen > 6u) && (tokenBuf[0] == 0xD1u) &&
            (tokenBuf[1] == 0x84u) && (tokenBuf[2] == 0x43u) &&
            (tokenBuf[3] == 0xA1u) && (tokenBuf[4] == 0x01u) &&
            (tokenBuf[5] == 0x05u) && (tokenBuf[6] == 0xA0u) &&
            (tokenLen + sizeof(nonPreferredTextUnprotected) - 1u <=
             sizeof(modifiedToken))) {
            (void)memcpy(modifiedToken, tokenBuf, 6u);
            (void)memcpy(&modifiedToken[6], textUnprotected,
                sizeof(textUnprotected));
            (void)memcpy(&modifiedToken[6u + sizeof(textUnprotected)],
                &tokenBuf[7], tokenLen - 7u);
            legacyTokenLen = tokenLen + sizeof(textUnprotected) - 1u;
            testRet = wc_EatPsaToken_Verify(&key, modifiedToken, legacyTokenLen,
                kNonce, sizeof(kNonce), scratch, sizeof(scratch), &token);
            TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                        token.profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT,
                "PSA Mac0 accepts preferred tstr header extension");

            (void)memcpy(modifiedToken, tokenBuf, 6u);
            (void)memcpy(&modifiedToken[6], contentTypeUnprotected,
                sizeof(contentTypeUnprotected));
            (void)memcpy(&modifiedToken[6u + sizeof(contentTypeUnprotected)],
                &tokenBuf[7], tokenLen - 7u);
            legacyTokenLen = tokenLen + sizeof(contentTypeUnprotected) - 1u;
            testRet = wc_EatPsaToken_Verify(&key, modifiedToken,
                legacyTokenLen, kNonce, sizeof(kNonce), scratch,
                sizeof(scratch), &token);
            TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                        token.profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT,
                "PSA Mac0 accepts unprotected content type");

            (void)memcpy(modifiedToken, tokenBuf, 6u);
            (void)memcpy(&modifiedToken[6], nonPreferredTextUnprotected,
                sizeof(nonPreferredTextUnprotected));
            (void)memcpy(&modifiedToken[6u +
                sizeof(nonPreferredTextUnprotected)], &tokenBuf[7],
                tokenLen - 7u);
            legacyTokenLen = tokenLen + sizeof(nonPreferredTextUnprotected) - 1u;
            testRet = wc_EatPsaToken_Verify(&key, modifiedToken, legacyTokenLen,
                kNonce, sizeof(kNonce), scratch, sizeof(scratch), &token);
            TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                        token.profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT,
                "PSA Mac0 accepts non-preferred tstr header extension");
        }
        else {
            TEST_ASSERT(0, "expected deterministic PSA Mac0 header layout");
        }
    }
#if defined(WOLFCOSE_EAT_PSA_UEID_RESOLVER)
    if (ret == WOLFCOSE_SUCCESS) {
        resolver.key = &key;
        resolver.called = 0;
        resolver.fail = 0;
        resolver.receivedProfile = WOLFCOSE_EAT_PSA_PROFILE_NONE;
        resolver.receivedAlg = WOLFCOSE_ALG_UNSET;
        testRet = wc_EatPsaToken_VerifyByUeid(test_eat_psa_resolve,
            &resolver, tokenBuf, tokenLen, kNonce, sizeof(kNonce), scratch,
            sizeof(scratch), &token);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS && resolver.called == 1 &&
                    resolver.receivedProfile ==
                        WOLFCOSE_EAT_PSA_PROFILE_CURRENT &&
                    resolver.receivedAlg == WOLFCOSE_ALG_HMAC_256_256,
                    "resolve current Mac0 key by UEID and COSE algorithm");

        testRet = wc_EatPsaToken_VerifyByUeid(
            test_eat_psa_resolve_without_ctx, NULL, tokenBuf, tokenLen,
            kNonce, sizeof(kNonce), scratch, sizeof(scratch), &token);
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                    token.profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT,
            "UEID resolver permits NULL callback context");

        (void)memcpy(modifiedToken, tokenBuf, tokenLen);
        modifiedToken[tokenLen - 1u] ^= 0xFFu;
        (void)memset(&token, 0xA5, sizeof(token));
        resolver.called = 0;
        testRet = wc_EatPsaToken_VerifyByUeid(test_eat_psa_resolve,
            &resolver, modifiedToken, tokenLen, kNonce, sizeof(kNonce),
            scratch, sizeof(scratch), &token);
        TEST_ASSERT(testRet == WOLFCOSE_E_MAC_FAIL && resolver.called == 1 &&
                    test_eat_psa_token_is_zero(&token) != 0,
            "resolve Mac0 key before rejecting tampered tag and clear output");
    }
#endif
    if (ret == WOLFCOSE_SUCCESS) {
        claims.bootSeed.data = kBootSeed;
        claims.bootSeed.len = sizeof(kBootSeed);
        testRet = test_eat_psa_encode_legacy(&claims, legacyPayload,
            sizeof(legacyPayload), &legacyPayloadLen, 0, 0, 0);
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
                NULL, 0u, legacyPayload, legacyPayloadLen, NULL, 0u, NULL,
                0u, scratch, sizeof(scratch), legacyToken, sizeof(legacyToken),
                &legacyTokenLen);
        }
        if (testRet == WOLFCOSE_SUCCESS) {
            testRet = wc_CoseEatPsaToken_Verify(&key, legacyToken,
                legacyTokenLen, kNonce, sizeof(kNonce), scratch,
                sizeof(scratch), &token);
        }
        TEST_ASSERT(testRet == WOLFCOSE_SUCCESS &&
                    token.profile == WOLFCOSE_EAT_PSA_PROFILE_OLD &&
                    token.protection == WOLFCOSE_EAT_PSA_PROTECTION_MAC0,
            "consume legacy PSA Mac0 token");
#if defined(WOLFCOSE_EAT_PSA_UEID_RESOLVER)
        if (testRet == WOLFCOSE_SUCCESS) {
            resolver.called = 0;
            resolver.receivedProfile = WOLFCOSE_EAT_PSA_PROFILE_NONE;
            resolver.receivedAlg = WOLFCOSE_ALG_UNSET;
            testRet = wc_EatPsaToken_VerifyByUeid(test_eat_psa_resolve,
                &resolver, legacyToken, legacyTokenLen, kNonce,
                sizeof(kNonce), scratch, sizeof(scratch), &token);
            TEST_ASSERT(testRet == WOLFCOSE_SUCCESS && resolver.called == 1 &&
                        resolver.receivedProfile ==
                            WOLFCOSE_EAT_PSA_PROFILE_OLD &&
                        resolver.receivedAlg == WOLFCOSE_ALG_HMAC_256_256,
                        "resolve legacy Mac0 key by UEID and COSE algorithm");
        }
#endif
    }
    if (ret == WOLFCOSE_SUCCESS) {
        if ((tokenLen > 6u) && (tokenBuf[0] == 0xD1u) &&
            (tokenBuf[1] == 0x84u) && (tokenBuf[2] == 0x43u) &&
            (tokenBuf[3] == 0xA1u) && (tokenBuf[4] == 0x01u) &&
            (tokenBuf[5] == 0x05u)) {
            (void)memcpy(modifiedToken, tokenBuf, tokenLen);
            modifiedToken[5] = 0x27u;
            (void)memset(&token, 0xA5, sizeof(token));
            ret = wc_CoseEatPsaToken_Verify(&key, modifiedToken, tokenLen,
                kNonce, sizeof(kNonce), scratch, sizeof(scratch), &token);
            TEST_ASSERT(ret == WOLFCOSE_E_COSE_BAD_ALG &&
                        test_eat_psa_token_is_zero(&token) != 0,
                "reject unsupported PSA Mac0 algorithm before MAC verification");
        }
        else {
            TEST_ASSERT(0, "expected deterministic Mac0 protected header");
        }
    }
    if ((ret == WOLFCOSE_E_COSE_BAD_ALG) && (tokenLen > 0u)) {
        (void)memcpy(modifiedToken, tokenBuf, tokenLen);
        modifiedToken[tokenLen - 1u] ^= 0xFFu;
        (void)memset(&token, 0xA5, sizeof(token));
        ret = wc_CoseEatPsaToken_Verify(&key, modifiedToken, tokenLen,
            kNonce, sizeof(kNonce), scratch, sizeof(scratch), &token);
        TEST_ASSERT(ret == WOLFCOSE_E_MAC_FAIL &&
                    test_eat_psa_token_is_zero(&token) != 0,
            "reject tampered PSA Mac0 tag and clear token output");
    }
    (void)memset(modifiedToken, 0xA5, sizeof(modifiedToken));
    outLen = 17u;
    ret = wc_CoseEatPsaToken_CreateMac0(NULL, WOLFCOSE_ALG_HMAC_256_256,
        &claims, claimsBuf, sizeof(claimsBuf), scratch, sizeof(scratch),
        modifiedToken, sizeof(modifiedToken), &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG && outLen == 0u &&
                test_eat_psa_bytes_are_zero(modifiedToken,
                    sizeof(modifiedToken)) != 0,
        "clear Mac0 output after invalid arguments");
    for (argCase = 0u; argCase < 5u; argCase++) {
        const WOLFCOSE_EAT_PSA_CLAIMS* argClaims =
            (argCase == 0u) ? NULL : &claims;
        uint8_t* argClaimsBuf = (argCase == 1u) ? NULL : claimsBuf;
        uint8_t* argScratch = (argCase == 2u) ? NULL : scratch;
        uint8_t* argOut = (argCase == 3u) ? NULL : modifiedToken;
        size_t* argOutLen = (argCase == 4u) ? NULL : &outLen;
        int expected = (argCase == 0u) ? WOLFCOSE_E_EAT_PSA_CLAIM :
                                         WOLFCOSE_E_INVALID_ARG;

        (void)memset(modifiedToken, 0xA5, sizeof(modifiedToken));
        outLen = 17u;
        ret = wc_CoseEatPsaToken_CreateMac0(&key,
            WOLFCOSE_ALG_HMAC_256_256, argClaims, argClaimsBuf,
            sizeof(claimsBuf), argScratch, sizeof(scratch), argOut,
            sizeof(modifiedToken), argOutLen);
        TEST_ASSERT(ret == expected &&
                    ((argOutLen == NULL) || (outLen == 0u)) &&
                    ((argOut == NULL) || (test_eat_psa_bytes_are_zero(
                        modifiedToken, sizeof(modifiedToken)) != 0)),
            "Mac0 wrapper rejects each missing required pointer");
    }
    (void)memset(modifiedToken, 0xA5, sizeof(modifiedToken));
    outLen = 17u;
    ret = wc_CoseEatPsaToken_CreateMac0(&key, WOLFCOSE_ALG_ES256, &claims,
        claimsBuf, sizeof(claimsBuf), scratch, sizeof(scratch), modifiedToken,
        sizeof(modifiedToken), &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_BAD_ALG && outLen == 0u &&
                test_eat_psa_bytes_are_zero(modifiedToken,
                    sizeof(modifiedToken)) != 0,
        "clear Mac0 output after unsupported algorithm");
    (void)memset(modifiedToken, 0xA5, sizeof(modifiedToken));
    outLen = 17u;
    ret = wc_CoseEatPsaToken_CreateMac0(&key, WOLFCOSE_ALG_HMAC_256_256,
        &claims, claimsBuf, 1u, scratch, sizeof(scratch), modifiedToken,
        sizeof(modifiedToken), &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_BUFFER_TOO_SMALL && outLen == 0u &&
                test_eat_psa_bytes_are_zero(modifiedToken,
                    sizeof(modifiedToken)) != 0,
        "clear Mac0 output after claims-buffer failure");
    (void)memset(modifiedToken, 0xA5, sizeof(modifiedToken));
    outLen = 17u;
    ret = wc_CoseEatPsaToken_CreateMac0(&key, WOLFCOSE_ALG_HMAC_256_256,
        &claims, claimsBuf, sizeof(claimsBuf), scratch, 1u, modifiedToken,
        sizeof(modifiedToken), &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_BUFFER_TOO_SMALL && outLen == 0u &&
                test_eat_psa_bytes_are_zero(modifiedToken,
                    sizeof(modifiedToken)) != 0,
        "clear Mac0 output after scratch-buffer failure");
    (void)memset(modifiedToken, 0xA5, sizeof(modifiedToken));
    outLen = 17u;
    ret = wc_CoseEatPsaToken_CreateMac0(&key, WOLFCOSE_ALG_HMAC_256_256,
        &claims, claimsBuf, sizeof(claimsBuf), scratch, sizeof(scratch),
        modifiedToken, 1u, &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_BUFFER_TOO_SMALL && outLen == 0u &&
                test_eat_psa_bytes_are_zero(modifiedToken, 1u) != 0,
        "clear Mac0 output after token-buffer failure");
    if (keyInited != 0) {
        wc_CoseKey_Free(&key);
    }
}
#endif /* WOLFCOSE_MAC0_CREATE && WOLFCOSE_MAC0_VERIFY && HMAC256 */

#if defined(WOLFCOSE_MAC0_CREATE) && defined(WOLFCOSE_MAC0_VERIFY) && \
    defined(WOLFCOSE_HAVE_HMAC256) && \
    (defined(WOLFCOSE_HAVE_HMAC384) || defined(WOLFCOSE_HAVE_HMAC512))
static void test_eat_psa_mac_alg(int32_t alg, size_t keyLen, const char* name)
{
    WOLFCOSE_EAT_PSA_CLAIMS claims;
    WOLFCOSE_EAT_PSA_COMPONENT component;
    WOLFCOSE_EAT_PSA_TOKEN token;
    WOLFCOSE_KEY key;
    uint8_t hmacKey[64] = { 0 };
    uint8_t claimsBuf[768];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t tokenBuf[1024];
    size_t tokenLen = 0u;
    int ret;
    int keyInited = 0;

    (void)printf("  [RFC 9783 Mac0 %s]\n", name);
    test_eat_psa_claims(&claims, &component);
    ret = wc_CoseKey_Init(&key);
    if (ret == WOLFCOSE_SUCCESS) {
        keyInited = 1;
        ret = wc_CoseKey_SetSymmetric(&key, hmacKey, keyLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_EatPsaToken_CreateMac0(&key, alg, &claims, claimsBuf,
            sizeof(claimsBuf), scratch, sizeof(scratch), tokenBuf,
            sizeof(tokenBuf), &tokenLen);
    }
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS && tokenLen > 0u,
        "create current TFM Mac0 token");
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_EatPsaToken_Verify(&key, tokenBuf, tokenLen, kNonce,
            sizeof(kNonce), scratch, sizeof(scratch), &token);
        TEST_ASSERT(ret == WOLFCOSE_SUCCESS &&
                    token.protection == WOLFCOSE_EAT_PSA_PROTECTION_MAC0,
                    "verify current TFM Mac0 token");
    }

    if (keyInited != 0) {
        wc_CoseKey_Free(&key);
    }
}
#endif

#endif /* WOLFCOSE_EAT_PSA and test crypto */

int test_eat_psa(void)
{
    g_failures = 0;
#if defined(WOLFCOSE_TEST_EAT_PSA_FULL)
#if defined(WOLFCOSE_SIGN1_VERIFY) && defined(WOLFCOSE_HAVE_ES256)
    test_eat_psa_rfc9783_sign1();
    #if defined(WOLFCOSE_SIGN1_SIGN)
    test_eat_psa_sign1();
    #if defined(WOLFCOSE_EXT_SIGN)
    test_eat_psa_delegated_signer();
    #endif
    #endif
    #if defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_HAVE_ES384)
    test_eat_psa_sign_alg(WOLFCOSE_ALG_ES384, 48, ECC_SECP384R1,
        WOLFCOSE_CRV_P384, "ES384");
    #endif
    #if defined(WOLFCOSE_SIGN1_SIGN) && defined(WOLFCOSE_HAVE_ES512)
    test_eat_psa_sign_alg(WOLFCOSE_ALG_ES512, 66, ECC_SECP521R1,
        WOLFCOSE_CRV_P521, "ES512");
    #endif
    #endif
    #if defined(WOLFCOSE_MAC0_VERIFY) && defined(WOLFCOSE_HAVE_HMAC256)
    test_eat_psa_rfc9783_mac0();
    #if defined(WOLFCOSE_MAC0_CREATE)
    test_eat_psa_mac0();
    #if defined(WOLFCOSE_HAVE_HMAC384)
    test_eat_psa_mac_alg(WOLFCOSE_ALG_HMAC_384_384, 48u, "HMAC384/384");
    #endif
    #if defined(WOLFCOSE_HAVE_HMAC512)
    test_eat_psa_mac_alg(WOLFCOSE_ALG_HMAC_512_512, 64u, "HMAC512/512");
    #endif
    #endif
    #endif
#else
    (void)printf("  PSA/EAT unavailable in this build\n");
#endif
    return g_failures;
}
