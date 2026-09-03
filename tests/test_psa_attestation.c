/* test_psa_attestation.c
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

/*
 * Fixed RFC 9783 Appendix A PSA token vectors. They carry real EAT/PSA
 * claims in COSE_Sign1 and COSE_Mac0 envelopes produced by iat-verifier.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfcose/wolfcose.h>
#ifdef WOLFCOSE_HAVE_ES256
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#include <stdio.h>
#include <string.h>

#include "test_suite.h"

static int g_failures = 0;

#define TEST_ASSERT(cond, name) do {                           \
    if (!(cond)) {                                             \
        printf("  FAIL: %s (line %d)\n", (name), __LINE__);  \
        g_failures++;                                          \
    }                                                          \
    else {                                                     \
        printf("  PASS: %s\n", (name));                      \
    }                                                          \
} while (0)

#if defined(WOLFCOSE_HAVE_ES256) || defined(WOLFCOSE_HAVE_HMAC256)

#define PSA_UEID               256
#define PSA_NONCE              10
#define PSA_PROFILE             265
#define PSA_BOOT_SEED           268
#define PSA_CLIENT_ID           2394
#define PSA_LIFECYCLE           2395
#define PSA_IMPLEMENTATION_ID   2396
#define PSA_SW_COMPONENTS       2399

static const uint8_t psa_profile[] =
    "tag:psacertified.org,2023:psa#tfm";

static int psa_all_bytes(const uint8_t* data, size_t len, uint8_t value)
{
    size_t i;

    if (data == NULL)
        return 0;

    for (i = 0u; i < len; i++) {
        if (data[i] != value)
            return 0;
    }

    return 1;
}

static size_t psa_hex_decode(const char* hex, uint8_t* out, size_t out_sz)
{
    size_t hex_len = 0u;
    size_t i;

    if (hex == NULL || out == NULL)
        return 0u;

    while (hex[hex_len] != '\0')
        hex_len++;

    if ((hex_len & 1u) != 0u || hex_len / 2u > out_sz)
        return 0u;

    for (i = 0u; i < hex_len / 2u; i++) {
        uint8_t high;
        uint8_t low;
        char c = hex[i * 2u];

        if (c >= '0' && c <= '9')
            high = (uint8_t)(c - '0');
        else if (c >= 'a' && c <= 'f')
            high = (uint8_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            high = (uint8_t)(c - 'A' + 10);
        else
            return 0u;

        c = hex[i * 2u + 1u];
        if (c >= '0' && c <= '9')
            low = (uint8_t)(c - '0');
        else if (c >= 'a' && c <= 'f')
            low = (uint8_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            low = (uint8_t)(c - 'A' + 10);
        else
            return 0u;

        out[i] = (uint8_t)((high << 4u) | low);
    }

    return hex_len / 2u;
}

static int psa_expect_label(WOLFCOSE_CBOR_CTX* ctx, int64_t expected,
                            const char* name)
{
    WOLFCOSE_CBOR_LABEL label;
    int ret;

    ret = wc_CBOR_DecodeLabel(ctx, &label);
    TEST_ASSERT(ret == 0 && wc_CBOR_LabelIsInt(&label, expected), name);
    return ret == 0 && wc_CBOR_LabelIsInt(&label, expected) ? 0 : -1;
}

static void psa_parse_claims(const uint8_t* payload, size_t payload_len,
                             const uint8_t* expected_ueid)
{
    WOLFCOSE_CBOR_CTX ctx;
    const uint8_t* value = NULL;
    size_t count = 0u;
    size_t value_len = 0u;
    uint64_t uint_value = 0u;
    int64_t int_value = 0;
    int ret;

    ret = wc_CBOR_DecoderInit(&ctx, payload, payload_len);
    TEST_ASSERT(ret == 0, "PSA claims decoder init");
    if (ret != 0)
        return;

    ret = wc_CBOR_DecodeMapStart(&ctx, &count);
    TEST_ASSERT(ret == 0 && count == 8u, "PSA claims map");
    if (ret != 0 || count != 8u)
        return;

    if (psa_expect_label(&ctx, PSA_UEID, "PSA UEID label") != 0)
        return;
    ret = wc_CBOR_DecodeBstr(&ctx, &value, &value_len);
    TEST_ASSERT(ret == 0 && value_len == 33u &&
                memcmp(value, expected_ueid, value_len) == 0, "PSA UEID");
    if (ret != 0)
        return;

    if (psa_expect_label(&ctx, PSA_IMPLEMENTATION_ID,
                         "PSA implementation ID label") != 0)
        return;
    ret = wc_CBOR_DecodeBstr(&ctx, &value, &value_len);
    TEST_ASSERT(ret == 0 && value_len == 32u &&
                psa_all_bytes(value, value_len, 0x00u), "PSA implementation ID");
    if (ret != 0)
        return;

    if (psa_expect_label(&ctx, PSA_NONCE, "PSA nonce label") != 0)
        return;
    ret = wc_CBOR_DecodeBstr(&ctx, &value, &value_len);
    TEST_ASSERT(ret == 0 && value_len == 32u &&
                psa_all_bytes(value, value_len, 0x01u), "PSA nonce");
    if (ret != 0)
        return;

    if (psa_expect_label(&ctx, PSA_CLIENT_ID, "PSA client ID label") != 0)
        return;
    ret = wc_CBOR_DecodeInt(&ctx, &int_value);
    TEST_ASSERT(ret == 0 && int_value == 2147483647, "PSA client ID");
    if (ret != 0)
        return;

    if (psa_expect_label(&ctx, PSA_LIFECYCLE, "PSA lifecycle label") != 0)
        return;
    ret = wc_CBOR_DecodeUint(&ctx, &uint_value);
    TEST_ASSERT(ret == 0 && uint_value == 12288u, "PSA lifecycle");
    if (ret != 0)
        return;

    if (psa_expect_label(&ctx, PSA_PROFILE, "PSA EAT profile label") != 0)
        return;
    ret = wc_CBOR_DecodeTstr(&ctx, &value, &value_len);
    TEST_ASSERT(ret == 0 && value_len == sizeof(psa_profile) - 1u &&
                memcmp(value, psa_profile, value_len) == 0, "PSA EAT profile");
    if (ret != 0)
        return;

    if (psa_expect_label(&ctx, PSA_BOOT_SEED, "PSA boot seed label") != 0)
        return;
    ret = wc_CBOR_DecodeBstr(&ctx, &value, &value_len);
    TEST_ASSERT(ret == 0 && value_len == 8u &&
                psa_all_bytes(value, value_len, 0x00u), "PSA boot seed");
    if (ret != 0)
        return;

    if (psa_expect_label(&ctx, PSA_SW_COMPONENTS,
                         "PSA components label") != 0)
        return;
    ret = wc_CBOR_DecodeArrayStart(&ctx, &count);
    TEST_ASSERT(ret == 0 && count == 1u, "PSA components array");
    if (ret != 0 || count != 1u)
        return;

    ret = wc_CBOR_DecodeMapStart(&ctx, &count);
    TEST_ASSERT(ret == 0 && count == 3u, "PSA component map");
    if (ret != 0 || count != 3u)
        return;

    if (psa_expect_label(&ctx, 5, "PSA signer ID label") != 0)
        return;
    ret = wc_CBOR_DecodeBstr(&ctx, &value, &value_len);
    TEST_ASSERT(ret == 0 && value_len == 32u &&
                psa_all_bytes(value, value_len, 0x04u), "PSA signer ID");
    if (ret != 0)
        return;

    if (psa_expect_label(&ctx, 2, "PSA measurement value label") != 0)
        return;
    ret = wc_CBOR_DecodeBstr(&ctx, &value, &value_len);
    TEST_ASSERT(ret == 0 && value_len == 32u &&
                psa_all_bytes(value, value_len, 0x03u), "PSA measurement value");
    if (ret != 0)
        return;

    if (psa_expect_label(&ctx, 1, "PSA measurement type label") != 0)
        return;
    ret = wc_CBOR_DecodeTstr(&ctx, &value, &value_len);
    TEST_ASSERT(ret == 0 && value_len == 4u &&
                memcmp(value, "PRoT", value_len) == 0, "PSA measurement type");
    if (ret != 0)
        return;

    TEST_ASSERT(ctx.idx == payload_len, "PSA claims consume payload");
}

#endif /* WOLFCOSE_HAVE_ES256 || WOLFCOSE_HAVE_HMAC256 */

#ifdef WOLFCOSE_HAVE_ES256

static const uint8_t psa_sign1_x[] =
    "\x4e\x5e\x22\x09\x9e\x3b\xce\xb4\x5b\x44\x6d\x13\x55\xfd\x1d\xc3"
    "\xb5\x45\x94\x7b\x6f\xd7\xc1\xc8\x9d\x88\x67\x98\xc3\x72\x6e\x8f";
static const uint8_t psa_sign1_y[] =
    "\x80\xd7\x0b\x84\x0b\x25\x6a\xac\x34\xa6\x2e\xde\x10\x43\x36\x4f"
    "\x04\x40\x95\xf0\x03\x47\x4b\x91\xe0\x18\x20\x92\xaf\xb1\x3f\x2e";
static const uint8_t psa_sign1_ueid[] =
    "\x01\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"
    "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"
    "\x02";
static const char psa_sign1_hex[] =
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

static void test_psa_sign1_token(void)
{
    WOLFCOSE_KEY cose_key;
    WOLFCOSE_HDR hdr;
    const uint8_t* payload = NULL;
    size_t payload_len = 0u;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t token[512];
    size_t token_len;
    ecc_key ecc_key;
    int cose_key_inited = 0;
    int ecc_key_inited = 0;
    int ret;

    printf("  [RFC 9783 COSE_Sign1 PSA token]\n");

    token_len = psa_hex_decode(psa_sign1_hex, token, sizeof(token));
    TEST_ASSERT(token_len > 0u, "PSA Sign1 vector decode");
    if (token_len == 0u)
        return;

    ret = wc_ecc_init(&ecc_key);
    TEST_ASSERT(ret == 0, "PSA Sign1 ECC init");
    if (ret == 0) {
        ecc_key_inited = 1;
        ret = wc_ecc_import_unsigned(&ecc_key, psa_sign1_x, psa_sign1_y,
                                     NULL, ECC_SECP256R1);
        TEST_ASSERT(ret == 0, "PSA Sign1 public key import");
    }
    if (ret == 0) {
        ret = wc_CoseKey_Init(&cose_key);
        TEST_ASSERT(ret == 0, "PSA Sign1 COSE key init");
        if (ret == 0)
            cose_key_inited = 1;
    }
    if (ret == 0) {
        ret = wc_CoseKey_SetEcc(&cose_key, WOLFCOSE_CRV_P256, &ecc_key);
        TEST_ASSERT(ret == 0, "PSA Sign1 COSE key set");
    }
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&cose_key, token, token_len,
                                  NULL, 0u, NULL, 0u, scratch, sizeof(scratch),
                                  &hdr, &payload, &payload_len);
        TEST_ASSERT(ret == 0, "PSA Sign1 signature verifies");
    }
    if (ret == 0) {
        uint8_t tampered[512];

        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_ES256, "PSA Sign1 algorithm");
        psa_parse_claims(payload, payload_len, psa_sign1_ueid);
        memcpy(tampered, token, token_len);
        tampered[token_len - 1u] ^= 0x01u;
        ret = wc_CoseSign1_Verify(&cose_key, tampered, token_len,
                                  NULL, 0u, NULL, 0u, scratch, sizeof(scratch),
                                  &hdr, &payload, &payload_len);
        TEST_ASSERT(ret != 0, "PSA Sign1 rejects tampered signature");
    }

    if (cose_key_inited != 0)
        wc_CoseKey_Free(&cose_key);
    if (ecc_key_inited != 0)
        wc_ecc_free(&ecc_key);
}

#endif /* WOLFCOSE_HAVE_ES256 */

#ifdef WOLFCOSE_HAVE_HMAC256

static const uint8_t psa_mac0_key[] =
    "\xde\x03\x8b\x34\xac\xa1\x25\x76\x8c\x5e\x33\x57\xab\x8d\x06\xb3"
    "\x67\xb9\xab\x0d\x7e\x8b\xe1\x24\xed\xca\x47\xfe\x03\x3a\x5b\xb7"
    "\xa9\x3d\x30\x7f\xf2\x29\xaa\x36\xff\x24\x6c\x12\x95\x96\x4f\xac"
    "\xf7\x1a\xb7\xaa\x6e\xc4\xfd\x61\x02\xb7\xb3\x98\x32\x55\xad\x92";
static const uint8_t psa_mac0_ueid[] =
    "\x01\xc5\x57\xbd\x4f\xad\xc8\x3f\x75\x6f\xca\x2c\xd5\xea\x2d\xcc"
    "\x8b\x82\x15\x9b\xb4\xe7\x45\x3d\x6a\x74\x4d\x4e\xec\xd6\xd0\xac"
    "\x60";
static const char psa_mac0_hex[] =
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

static void test_psa_mac0_token(void)
{
    WOLFCOSE_KEY cose_key;
    WOLFCOSE_HDR hdr;
    const uint8_t* payload = NULL;
    size_t payload_len = 0u;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t token[512];
    size_t token_len;
    int cose_key_inited = 0;
    int ret;

    printf("  [RFC 9783 COSE_Mac0 PSA token]\n");

    token_len = psa_hex_decode(psa_mac0_hex, token, sizeof(token));
    TEST_ASSERT(token_len > 0u, "PSA Mac0 vector decode");
    if (token_len == 0u)
        return;

    ret = wc_CoseKey_Init(&cose_key);
    TEST_ASSERT(ret == 0, "PSA Mac0 COSE key init");
    if (ret == 0) {
        cose_key_inited = 1;
        ret = wc_CoseKey_SetSymmetric(&cose_key, psa_mac0_key,
                                      sizeof(psa_mac0_key) - 1u);
        TEST_ASSERT(ret == 0, "PSA Mac0 COSE key set");
    }
    if (ret == 0) {
        ret = wc_CoseMac0_Verify(&cose_key, token, token_len,
                                 NULL, 0u, NULL, 0u, scratch, sizeof(scratch),
                                 &hdr, &payload, &payload_len);
        TEST_ASSERT(ret == 0, "PSA Mac0 tag verifies");
    }
    if (ret == 0) {
        uint8_t tampered[512];

        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC_256_256,
                    "PSA Mac0 algorithm");
        psa_parse_claims(payload, payload_len, psa_mac0_ueid);
        memcpy(tampered, token, token_len);
        tampered[token_len - 1u] ^= 0x01u;
        ret = wc_CoseMac0_Verify(&cose_key, tampered, token_len,
                                 NULL, 0u, NULL, 0u, scratch, sizeof(scratch),
                                 &hdr, &payload, &payload_len);
        TEST_ASSERT(ret != 0, "PSA Mac0 rejects tampered tag");
    }

    if (cose_key_inited != 0)
        wc_CoseKey_Free(&cose_key);
}

#endif /* WOLFCOSE_HAVE_HMAC256 */

int test_psa_attestation(void)
{
    g_failures = 0;

    printf("=== PSA Attestation Token Tests ===\n\n");

#ifdef WOLFCOSE_HAVE_ES256
    test_psa_sign1_token();
#endif
#ifdef WOLFCOSE_HAVE_HMAC256
    test_psa_mac0_token();
#endif

    printf("  PSA attestation: %d failure(s)\n", g_failures);
    return g_failures;
}
