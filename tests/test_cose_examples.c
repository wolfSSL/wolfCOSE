/* test_cose_examples.c
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
 * Curated fixed vectors from cose-wg/Examples commit
 * 53c9d634333bb4f529d78f5980fffa2667ee2c12. The test deliberately
 * keeps the small supported subset in source, so make test is offline and
 * deterministic. Source paths are named beside each vector below.
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

#define EXAMPLE_ENCRYPT_CIPHERTEXT_OFFSET 24u
#define EXAMPLE_ENCRYPT_CIPHERTEXT_LEN    36u
#define EXAMPLE_ENCRYPT_TAG_OFFSET \
    (EXAMPLE_ENCRYPT_CIPHERTEXT_OFFSET + EXAMPLE_ENCRYPT_CIPHERTEXT_LEN - 1u)

static const uint8_t example_payload[] = "This is the content.";

static size_t example_hex_decode(const char* hex, uint8_t* out, size_t out_sz)
{
    size_t hex_len = 0u;
    size_t i;

    if ((hex == NULL) || (out == NULL)) {
        return 0u;
    }

    while (hex[hex_len] != '\0') {
        hex_len++;
    }
    if (((hex_len & 1u) != 0u) || ((hex_len / 2u) > out_sz)) {
        return 0u;
    }

    for (i = 0u; i < hex_len / 2u; i++) {
        uint8_t high;
        uint8_t low;
        char c = hex[i * 2u];

        if ((c >= '0') && (c <= '9')) {
            high = (uint8_t)(c - '0');
        }
        else if ((c >= 'a') && (c <= 'f')) {
            high = (uint8_t)(c - 'a' + 10);
        }
        else if ((c >= 'A') && (c <= 'F')) {
            high = (uint8_t)(c - 'A' + 10);
        }
        else {
            return 0u;
        }

        c = hex[i * 2u + 1u];
        if ((c >= '0') && (c <= '9')) {
            low = (uint8_t)(c - '0');
        }
        else if ((c >= 'a') && (c <= 'f')) {
            low = (uint8_t)(c - 'a' + 10);
        }
        else if ((c >= 'A') && (c <= 'F')) {
            low = (uint8_t)(c - 'A' + 10);
        }
        else {
            return 0u;
        }

        out[i] = (uint8_t)((high << 4u) | low);
    }

    return hex_len / 2u;
}

#ifdef WOLFCOSE_HAVE_ES256

/* sign1-tests/sign-pass-02.json and sign1-tests/sign-fail-01.json. */
static const uint8_t example_p256_x[] =
    "\xba\xc5\xb1\x1c\xad\x8f\x99\xf9\xc7\x2b\x05\xcf\x4b\x9e\x26\xd2"
    "\x44\xdc\x18\x9f\x74\x52\x28\x25\x5a\x21\x9a\x86\xd6\xa0\x9e\xff";
static const uint8_t example_p256_y[] =
    "\x20\x13\x8b\xf8\x2d\xc1\xb6\xd5\x62\xbe\x0f\xa5\x4a\xb7\x80\x4a"
    "\x3a\x64\xb6\xd7\x2c\xcf\xed\x6b\x6f\xb6\xed\x28\xbb\xfc\x11\x7e";
static const uint8_t example_sign1_aad[] = {
    0x11u, 0xaau, 0x22u, 0xbbu, 0x33u, 0xccu,
    0x44u, 0xddu, 0x55u, 0x00u, 0x66u, 0x99u
};
static const char example_sign1_pass_hex[] =
    "d28443a10126a10442313154546869732069732074686520636f6e74656e742e"
    "584010729cd711cb3813d8d8e944a8da7111e7b258c9bdca6135f7ae1adbee95"
    "09891267837e1e33bd36c150326ae62755c6bd8e540c3e8f92d7d225e8db72b8"
    "820b";
static const char example_sign1_bad_tag_hex[] =
    "d903e68443a10126a10442313154546869732069732074686520636f6e74656e"
    "742e58408eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91ae"
    "f0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c3"
    "45cacb36";

static void test_example_sign1(void)
{
    WOLFCOSE_KEY cose_key;
    WOLFCOSE_HDR hdr;
    const uint8_t* payload = NULL;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[256];
    size_t message_len;
    size_t payload_len = 0u;
    ecc_key ecc_key;
    int cose_key_inited = 0;
    int ecc_key_inited = 0;
    int ret;

    printf("  [COSE WG Examples COSE_Sign1 ES256]\n");
    message_len = example_hex_decode(example_sign1_pass_hex, message,
                                     sizeof(message));
    TEST_ASSERT(message_len > 0u, "Examples Sign1 pass vector decode");
    if (message_len == 0u) {
        return;
    }

    ret = wc_ecc_init(&ecc_key);
    TEST_ASSERT(ret == 0, "Examples Sign1 ECC init");
    if (ret == 0) {
        ecc_key_inited = 1;
        ret = wc_ecc_import_unsigned(&ecc_key, example_p256_x, example_p256_y,
                                     NULL, ECC_SECP256R1);
        TEST_ASSERT(ret == 0, "Examples Sign1 public key import");
    }
    if (ret == 0) {
        ret = wc_CoseKey_Init(&cose_key);
        TEST_ASSERT(ret == 0, "Examples Sign1 COSE key init");
        if (ret == 0) {
            cose_key_inited = 1;
        }
    }
    if (ret == 0) {
        ret = wc_CoseKey_SetEcc(&cose_key, WOLFCOSE_CRV_P256, &ecc_key);
        TEST_ASSERT(ret == 0, "Examples Sign1 COSE key set");
        cose_key.alg = WOLFCOSE_ALG_ES256;
    }
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&cose_key, message, message_len, NULL, 0u,
                                  example_sign1_aad, sizeof(example_sign1_aad),
                                  scratch, sizeof(scratch), &hdr, &payload,
                                  &payload_len);
        TEST_ASSERT(ret == 0, "Examples Sign1 verifies");
    }
    if (ret == 0) {
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_ES256,
                    "Examples Sign1 algorithm");
        TEST_ASSERT((payload_len == sizeof(example_payload) - 1u) &&
                    (memcmp(payload, example_payload, payload_len) == 0),
                    "Examples Sign1 payload");

        message_len = example_hex_decode(example_sign1_bad_tag_hex, message,
                                         sizeof(message));
        TEST_ASSERT(message_len > 0u, "Examples Sign1 bad tag vector decode");
        if (message_len > 0u) {
            ret = wc_CoseSign1_Verify(&cose_key, message, message_len, NULL,
                                      0u, example_sign1_aad,
                                      sizeof(example_sign1_aad), scratch,
                                      sizeof(scratch), &hdr, &payload,
                                      &payload_len);
            TEST_ASSERT(ret != 0, "Examples Sign1 rejects wrong tag");
        }
    }

    if (cose_key_inited != 0) {
        wc_CoseKey_Free(&cose_key);
    }
    if (ecc_key_inited != 0) {
        wc_ecc_free(&ecc_key);
    }
}

#if defined(WOLFCOSE_SIGN_VERIFY)

/* sign-tests/sign-pass-02.json. */
static const char example_sign_pass_hex[] =
    "d8628440a054546869732069732074686520636f6e74656e742e818343a10126"
    "a1044231315840cbb8dad9beafb890e1a414124d8bfbc26bedf2a94fcb5a882"
    "432bff6d63e15f574eeb2ab51d83fa2cbf62672ebf4c7d993b0f4c2447647d8"
    "31ba57cca86b930a";

static void test_example_sign(void)
{
    WOLFCOSE_KEY cose_key;
    WOLFCOSE_HDR hdr;
    const uint8_t* payload = NULL;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[256];
    size_t message_len;
    size_t payload_len = 0u;
    ecc_key ecc_key;
    int cose_key_inited = 0;
    int ecc_key_inited = 0;
    int ret;

    printf("  [COSE WG Examples COSE_Sign ES256]\n");
    message_len = example_hex_decode(example_sign_pass_hex, message,
                                     sizeof(message));
    TEST_ASSERT(message_len > 0u, "Examples Sign pass vector decode");
    if (message_len == 0u) {
        return;
    }

    ret = wc_ecc_init(&ecc_key);
    TEST_ASSERT(ret == 0, "Examples Sign ECC init");
    if (ret == 0) {
        ecc_key_inited = 1;
        ret = wc_ecc_import_unsigned(&ecc_key, example_p256_x, example_p256_y,
                                     NULL, ECC_SECP256R1);
        TEST_ASSERT(ret == 0, "Examples Sign public key import");
    }
    if (ret == 0) {
        ret = wc_CoseKey_Init(&cose_key);
        TEST_ASSERT(ret == 0, "Examples Sign COSE key init");
        if (ret == 0) {
            cose_key_inited = 1;
        }
    }
    if (ret == 0) {
        ret = wc_CoseKey_SetEcc(&cose_key, WOLFCOSE_CRV_P256, &ecc_key);
        TEST_ASSERT(ret == 0, "Examples Sign COSE key set");
        cose_key.alg = WOLFCOSE_ALG_ES256;
    }
    if (ret == 0) {
        ret = wc_CoseSign_Verify(&cose_key, 0u, message, message_len, NULL,
                                 0u, example_sign1_aad,
                                 sizeof(example_sign1_aad), scratch,
                                 sizeof(scratch), &hdr, &payload,
                                 &payload_len);
        TEST_ASSERT(ret == 0, "Examples Sign verifies");
    }
    if (ret == 0) {
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_ES256,
                    "Examples Sign algorithm");
        TEST_ASSERT((payload_len == sizeof(example_payload) - 1u) &&
                    (memcmp(payload, example_payload, payload_len) == 0),
                    "Examples Sign payload");

        message[message_len - 1u] ^= 0x01u;
        ret = wc_CoseSign_Verify(&cose_key, 0u, message, message_len, NULL,
                                 0u, example_sign1_aad,
                                 sizeof(example_sign1_aad), scratch,
                                 sizeof(scratch), &hdr, &payload,
                                 &payload_len);
        TEST_ASSERT(ret != 0, "Examples Sign rejects modified signature");
    }

    if (cose_key_inited != 0) {
        wc_CoseKey_Free(&cose_key);
    }
    if (ecc_key_inited != 0) {
        wc_ecc_free(&ecc_key);
    }
}

#endif /* WOLFCOSE_SIGN_VERIFY */

#endif /* WOLFCOSE_HAVE_ES256 */

#ifdef WOLFCOSE_HAVE_HMAC256

/* mac0-tests/mac-pass-02.json and mac0-tests/mac-fail-01.json. */
static const uint8_t example_hmac_key[] =
    "\x84\x9b\x57\x21\x9d\xae\x48\xde\x64\x6d\x07\xdb\xb5\x33\x56\x6e"
    "\x97\x66\x86\x45\x7c\x14\x91\xbe\x3a\x76\xdc\xea\x6c\x42\x71\x88";
static const uint8_t example_mac0_aad[] = {
    0xffu, 0x00u, 0xeeu, 0x11u, 0xddu, 0x22u, 0xccu,
    0x33u, 0xbbu, 0x44u, 0xaau, 0x55u, 0x99u, 0x66u
};
static const char example_mac0_pass_hex[] =
    "d18440a1010554546869732069732074686520636f6e74656e742e58200fecaec"
    "59bb46cc8a488aaca4b205e322dd52696b75a45768d3c302dd4bae2f7";
static const char example_mac0_bad_tag_hex[] =
    "d903e08443a10105a054546869732069732074686520636f6e74656e742e5820"
    "a1a848d3471f9d61ee49018d244c824772f223ad4f935293f1789fc3a08d8c58";

static void test_example_mac0(void)
{
    WOLFCOSE_KEY cose_key;
    WOLFCOSE_HDR hdr;
    const uint8_t* payload = NULL;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[128];
    size_t message_len;
    size_t payload_len = 0u;
    int cose_key_inited = 0;
    int ret;

    printf("  [COSE WG Examples COSE_Mac0 HMAC-256]\n");
    message_len = example_hex_decode(example_mac0_pass_hex, message,
                                     sizeof(message));
    TEST_ASSERT(message_len > 0u, "Examples Mac0 pass vector decode");
    if (message_len == 0u) {
        return;
    }

    ret = wc_CoseKey_Init(&cose_key);
    TEST_ASSERT(ret == 0, "Examples Mac0 COSE key init");
    if (ret == 0) {
        cose_key_inited = 1;
        ret = wc_CoseKey_SetSymmetric(&cose_key, example_hmac_key,
                                      sizeof(example_hmac_key) - 1u);
        TEST_ASSERT(ret == 0, "Examples Mac0 COSE key set");
        cose_key.alg = WOLFCOSE_ALG_HMAC_256_256;
    }
    if (ret == 0) {
        ret = wc_CoseMac0_Verify(&cose_key, message, message_len, NULL, 0u,
                                 example_mac0_aad, sizeof(example_mac0_aad),
                                 scratch, sizeof(scratch), &hdr, &payload,
                                 &payload_len);
        TEST_ASSERT(ret == 0, "Examples Mac0 verifies");
    }
    if (ret == 0) {
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC_256_256,
                    "Examples Mac0 algorithm");
        TEST_ASSERT((payload_len == sizeof(example_payload) - 1u) &&
                    (memcmp(payload, example_payload, payload_len) == 0),
                    "Examples Mac0 payload");

        message_len = example_hex_decode(example_mac0_bad_tag_hex, message,
                                         sizeof(message));
        TEST_ASSERT(message_len > 0u, "Examples Mac0 bad tag vector decode");
        if (message_len > 0u) {
            ret = wc_CoseMac0_Verify(&cose_key, message, message_len, NULL,
                                     0u, example_mac0_aad,
                                     sizeof(example_mac0_aad), scratch,
                                     sizeof(scratch), &hdr, &payload,
                                     &payload_len);
            TEST_ASSERT(ret != 0, "Examples Mac0 rejects wrong tag");
        }
    }

    if (cose_key_inited != 0) {
        wc_CoseKey_Free(&cose_key);
    }
}

#endif /* WOLFCOSE_HAVE_HMAC256 */

#ifdef WOLFCOSE_HAVE_AESGCM

/* encrypted-tests/enc-pass-02.json and enc-fail-01.json. */
static const uint8_t example_a128gcm_key[] =
    "\x84\x9b\x57\x21\x9d\xae\x48\xde\x64\x6d\x07\xdb\xb5\x33\x56\x6e";
static const uint8_t example_encrypt0_aad[] = {
    0x00u, 0x11u, 0xbbu, 0xccu, 0x22u, 0xddu,
    0x44u, 0x55u, 0xddu, 0x22u, 0x00u, 0x99u
};
static const char example_encrypt0_pass_hex[] =
    "d08343a10101a1054c02d1f7e6f26c43d4868d87ce582460973a94bb2898009ee"
    "52ecfd9ab1dd25867374b1dc3a143880ca2883a5630da08ae1e6e";
static const char example_encrypt0_bad_tag_hex[] =
    "d903e38343a10101a1054c02d1f7e6f26c43d4868d87ce582460973a94bb28980"
    "09ee52ecfd9ab1dd25867374b162e2c03568b41f57c3cc16f9166250a";

static void test_example_encrypt0(void)
{
    WOLFCOSE_KEY cose_key;
    WOLFCOSE_HDR hdr;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[128];
    uint8_t plaintext[64];
    size_t message_len;
    size_t plaintext_len = 0u;
    int cose_key_inited = 0;
    int ret;

    printf("  [COSE WG Examples COSE_Encrypt0 A128GCM]\n");
    message_len = example_hex_decode(example_encrypt0_pass_hex, message,
                                     sizeof(message));
    TEST_ASSERT(message_len > 0u, "Examples Encrypt0 pass vector decode");
    if (message_len == 0u) {
        return;
    }

    ret = wc_CoseKey_Init(&cose_key);
    TEST_ASSERT(ret == 0, "Examples Encrypt0 COSE key init");
    if (ret == 0) {
        cose_key_inited = 1;
        ret = wc_CoseKey_SetSymmetric(&cose_key, example_a128gcm_key,
                                      sizeof(example_a128gcm_key) - 1u);
        TEST_ASSERT(ret == 0, "Examples Encrypt0 COSE key set");
        cose_key.alg = WOLFCOSE_ALG_A128GCM;
    }
    if (ret == 0) {
        ret = wc_CoseEncrypt0_Decrypt(&cose_key, message, message_len, NULL,
                                      0u, example_encrypt0_aad,
                                      sizeof(example_encrypt0_aad), scratch,
                                      sizeof(scratch), &hdr, plaintext,
                                      sizeof(plaintext), &plaintext_len);
        TEST_ASSERT(ret == 0, "Examples Encrypt0 decrypts");
    }
    if (ret == 0) {
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A128GCM,
                    "Examples Encrypt0 algorithm");
        TEST_ASSERT((plaintext_len == sizeof(example_payload) - 1u) &&
                    (memcmp(plaintext, example_payload, plaintext_len) == 0),
                    "Examples Encrypt0 plaintext");

        message_len = example_hex_decode(example_encrypt0_bad_tag_hex, message,
                                         sizeof(message));
        TEST_ASSERT(message_len > 0u,
                    "Examples Encrypt0 bad tag vector decode");
        if (message_len > 0u) {
            ret = wc_CoseEncrypt0_Decrypt(&cose_key, message, message_len,
                                          NULL, 0u, example_encrypt0_aad,
                                          sizeof(example_encrypt0_aad), scratch,
                                          sizeof(scratch), &hdr, plaintext,
                                          sizeof(plaintext), &plaintext_len);
            TEST_ASSERT(ret != 0, "Examples Encrypt0 rejects wrong tag");
        }
    }

    if (cose_key_inited != 0) {
        wc_CoseKey_Free(&cose_key);
    }
}

#if defined(WOLFCOSE_ENCRYPT_DECRYPT)

static const uint8_t example_encrypt_kid[] = "our-secret";
static const char example_encrypt_direct_pass_hex[] =
    "d8608443a10101a1054c02d1f7e6f26c43d4868d87ce582460973a94bb289800"
    "9ee52ecfd9ab1dd25867374b7cde42d4f7e6dd896e231c71fdd6fc99818340a2"
    "0125044a6f75722d73656372657440";

static void test_example_encrypt_direct(void)
{
    WOLFCOSE_KEY cose_key;
    WOLFCOSE_RECIPIENT recipient;
    WOLFCOSE_HDR hdr;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[256];
    uint8_t plaintext[64];
    size_t message_len;
    size_t plaintext_len = 0u;
    int cose_key_inited = 0;
    int ret;

    printf("  [COSE WG Examples COSE_Encrypt direct A128GCM]\n");
    message_len = example_hex_decode(example_encrypt_direct_pass_hex, message,
                                     sizeof(message));
    TEST_ASSERT(message_len > 0u, "Examples Encrypt direct vector decode");
    if (message_len == 0u) {
        return;
    }

    ret = wc_CoseKey_Init(&cose_key);
    TEST_ASSERT(ret == 0, "Examples Encrypt direct COSE key init");
    if (ret == 0) {
        cose_key_inited = 1;
        ret = wc_CoseKey_SetSymmetric(&cose_key, example_a128gcm_key,
                                      sizeof(example_a128gcm_key) - 1u);
        TEST_ASSERT(ret == 0, "Examples Encrypt direct COSE key set");
        cose_key.alg = WOLFCOSE_ALG_A128GCM;
    }
    if (ret == 0) {
        recipient.algId = WOLFCOSE_ALG_DIRECT;
        recipient.key = &cose_key;
        recipient.kid = example_encrypt_kid;
        recipient.kidLen = sizeof(example_encrypt_kid) - 1u;
        ret = wc_CoseEncrypt_Decrypt(&recipient, 0u, message, message_len,
            NULL, 0u, example_encrypt0_aad, sizeof(example_encrypt0_aad),
            scratch, sizeof(scratch), &hdr, plaintext, sizeof(plaintext),
            &plaintext_len);
        TEST_ASSERT(ret == 0, "Examples Encrypt direct decrypts");
    }
    if (ret == 0) {
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A128GCM,
                    "Examples Encrypt direct algorithm");
        TEST_ASSERT((plaintext_len == sizeof(example_payload) - 1u) &&
                    (memcmp(plaintext, example_payload, plaintext_len) == 0),
                    "Examples Encrypt direct plaintext");

        TEST_ASSERT(message_len > EXAMPLE_ENCRYPT_TAG_OFFSET,
                    "Examples Encrypt direct tag offset");
        if (message_len > EXAMPLE_ENCRYPT_TAG_OFFSET) {
            message[EXAMPLE_ENCRYPT_TAG_OFFSET] ^= 0x01u;
            ret = wc_CoseEncrypt_Decrypt(&recipient, 0u, message, message_len,
                NULL, 0u, example_encrypt0_aad, sizeof(example_encrypt0_aad),
                scratch, sizeof(scratch), &hdr, plaintext, sizeof(plaintext),
                &plaintext_len);
            TEST_ASSERT(ret == WOLFCOSE_E_COSE_DECRYPT_FAIL,
                        "Examples Encrypt direct rejects modified tag");
        }
    }

    if (cose_key_inited != 0) {
        wc_CoseKey_Free(&cose_key);
    }
}

#if defined(WOLFCOSE_KEY_WRAP)

/* aes-wrap-examples/aes-wrap-128-04.json. */
static const char example_encrypt_a128kw_pass_hex[] =
    "d8608443a10101a1054cdddc08972df9be62855291a158246f5556d71834cd1b"
    "d3fdcbfff28cfa0f7d598c138d23b40c225af5e3f2096a46c766813d818340a2"
    "0122044a6f75722d7365637265745818112872f405a5ac48a2ede46ac20e93e3"
    "d3a38b9762d0a3e8";

static void test_example_encrypt_a128kw(void)
{
    WOLFCOSE_KEY cose_key;
    WOLFCOSE_RECIPIENT recipient;
    WOLFCOSE_HDR hdr;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[256];
    uint8_t plaintext[64];
    size_t message_len;
    size_t plaintext_len = 0u;
    int cose_key_inited = 0;
    int ret;

    printf("  [COSE WG Examples COSE_Encrypt A128KW]\n");
    message_len = example_hex_decode(example_encrypt_a128kw_pass_hex, message,
                                     sizeof(message));
    TEST_ASSERT(message_len > 0u, "Examples A128KW vector decode");
    if (message_len == 0u) {
        return;
    }

    ret = wc_CoseKey_Init(&cose_key);
    TEST_ASSERT(ret == 0, "Examples A128KW COSE key init");
    if (ret == 0) {
        cose_key_inited = 1;
        ret = wc_CoseKey_SetSymmetric(&cose_key, example_a128gcm_key,
                                      sizeof(example_a128gcm_key) - 1u);
        TEST_ASSERT(ret == 0, "Examples A128KW COSE key set");
        cose_key.alg = WOLFCOSE_ALG_A128KW;
    }
    if (ret == 0) {
        recipient.algId = WOLFCOSE_ALG_A128KW;
        recipient.key = &cose_key;
        recipient.kid = example_encrypt_kid;
        recipient.kidLen = sizeof(example_encrypt_kid) - 1u;
        ret = wc_CoseEncrypt_Decrypt(&recipient, 0u, message, message_len,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr, plaintext,
            sizeof(plaintext), &plaintext_len);
        TEST_ASSERT(ret == 0, "Examples A128KW decrypts");
    }
    if (ret == 0) {
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A128GCM,
                    "Examples A128KW algorithm");
        TEST_ASSERT((plaintext_len == sizeof(example_payload) - 1u) &&
                    (memcmp(plaintext, example_payload, plaintext_len) == 0),
                    "Examples A128KW plaintext");

        TEST_ASSERT(message_len > EXAMPLE_ENCRYPT_TAG_OFFSET,
                    "Examples A128KW tag offset");
        if (message_len > EXAMPLE_ENCRYPT_TAG_OFFSET) {
            message[EXAMPLE_ENCRYPT_TAG_OFFSET] ^= 0x01u;
            ret = wc_CoseEncrypt_Decrypt(&recipient, 0u, message, message_len,
                NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr, plaintext,
                sizeof(plaintext), &plaintext_len);
            TEST_ASSERT(ret == WOLFCOSE_E_COSE_DECRYPT_FAIL,
                        "Examples A128KW rejects modified tag");
        }
    }

    if (cose_key_inited != 0) {
        wc_CoseKey_Free(&cose_key);
    }
}

#endif /* WOLFCOSE_KEY_WRAP */

#endif /* WOLFCOSE_ENCRYPT_DECRYPT */

#endif /* WOLFCOSE_HAVE_AESGCM */

#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(WOLFCOSE_HAVE_ES256) && \
    defined(HAVE_HKDF) && defined(WOLFCOSE_ENCRYPT_DECRYPT)

/* ecdh-direct-examples/p256-hkdf-256-01.json. */
static const uint8_t example_ecdh_private[] = {
    0xafu, 0xf9u, 0x07u, 0xc9u, 0x9fu, 0x9au, 0xd3u, 0xaau,
    0xe6u, 0xc4u, 0xcdu, 0xf2u, 0x11u, 0x22u, 0xbcu, 0xe2u,
    0xbdu, 0x68u, 0xb5u, 0x28u, 0x3eu, 0x69u, 0x07u, 0x15u,
    0x4au, 0xd9u, 0x11u, 0x84u, 0x0fu, 0xa2u, 0x08u, 0xcfu
};
static const uint8_t example_ecdh_public[] = {
    0x04u,
    0x65u, 0xedu, 0xa5u, 0xa1u, 0x25u, 0x77u, 0xc2u, 0xbau,
    0xe8u, 0x29u, 0x43u, 0x7fu, 0xe3u, 0x38u, 0x70u, 0x1au,
    0x10u, 0xaau, 0xa3u, 0x75u, 0xe1u, 0xbbu, 0x5bu, 0x5du,
    0xe1u, 0x08u, 0xdeu, 0x43u, 0x9cu, 0x08u, 0x55u, 0x1du,
    0x1eu, 0x52u, 0xedu, 0x75u, 0x70u, 0x11u, 0x63u, 0xf7u,
    0xf9u, 0xe4u, 0x0du, 0xdfu, 0x9fu, 0x34u, 0x1bu, 0x3du,
    0xc9u, 0xbau, 0x86u, 0x0au, 0xf7u, 0xe0u, 0xcau, 0x7cu,
    0xa7u, 0xe9u, 0xeeu, 0xcdu, 0x00u, 0x84u, 0xd1u, 0x9cu
};
static const uint8_t example_ecdh_kid[] =
    "meriadoc.brandybuck@buckland.example";
static const char example_encrypt_ecdh_pass_hex[] =
    "d8608443a10101a1054cc9cf4df2fe6c632bf788641358247adbe2709ca818fb"
    "415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0818344a1"
    "013818a220a40102200121582098f50a4ff6c05861c8860d13a638ea56c3f5ad"
    "7590bbfbf054e1c7b4d91d6280225820f01400b089867804b8e9fc96c3932161"
    "f1934f4223069170d924b7e03bf822bb0458246d65726961646f632e6272616e"
    "64796275636b406275636b6c616e642e6578616d706c6540";

static void test_example_encrypt_ecdh(void)
{
    WOLFCOSE_KEY cose_key;
    WOLFCOSE_RECIPIENT recipient;
    WOLFCOSE_HDR hdr;
    ecc_key ecc_key;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[384];
    uint8_t plaintext[64];
    size_t message_len;
    size_t plaintext_len = 0u;
    int cose_key_inited = 0;
    int ecc_key_inited = 0;
    int ret;

    printf("  [COSE WG Examples COSE_Encrypt ECDH-ES]\n");
    message_len = example_hex_decode(example_encrypt_ecdh_pass_hex, message,
                                     sizeof(message));
    TEST_ASSERT(message_len > 0u, "Examples ECDH-ES vector decode");
    if (message_len == 0u) {
        return;
    }

    ret = wc_ecc_init(&ecc_key);
    TEST_ASSERT(ret == 0, "Examples ECDH-ES ECC init");
    if (ret == 0) {
        ecc_key_inited = 1;
        ret = wc_ecc_import_private_key_ex(example_ecdh_private,
            (word32)sizeof(example_ecdh_private), example_ecdh_public,
            (word32)sizeof(example_ecdh_public), &ecc_key, ECC_SECP256R1);
        TEST_ASSERT(ret == 0, "Examples ECDH-ES private key import");
    }
    if (ret == 0) {
        ret = wc_CoseKey_Init(&cose_key);
        TEST_ASSERT(ret == 0, "Examples ECDH-ES COSE key init");
        if (ret == 0) {
            cose_key_inited = 1;
        }
    }
    if (ret == 0) {
        ret = wc_CoseKey_SetEcc(&cose_key, WOLFCOSE_CRV_P256, &ecc_key);
        TEST_ASSERT(ret == 0, "Examples ECDH-ES COSE key set");
        cose_key.hasPrivate = 1u;
    }
    if (ret == 0) {
        recipient.algId = WOLFCOSE_ALG_ECDH_ES_HKDF_256;
        recipient.key = &cose_key;
        recipient.kid = example_ecdh_kid;
        recipient.kidLen = sizeof(example_ecdh_kid) - 1u;
        ret = wc_CoseEncrypt_Decrypt(&recipient, 0u, message, message_len,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr, plaintext,
            sizeof(plaintext), &plaintext_len);
        TEST_ASSERT(ret == 0, "Examples ECDH-ES decrypts");
    }
    if (ret == 0) {
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A128GCM,
                    "Examples ECDH-ES algorithm");
        TEST_ASSERT((plaintext_len == sizeof(example_payload) - 1u) &&
                    (memcmp(plaintext, example_payload, plaintext_len) == 0),
                    "Examples ECDH-ES plaintext");

        TEST_ASSERT(message_len > EXAMPLE_ENCRYPT_TAG_OFFSET,
                    "Examples ECDH-ES tag offset");
        if (message_len > EXAMPLE_ENCRYPT_TAG_OFFSET) {
            message[EXAMPLE_ENCRYPT_TAG_OFFSET] ^= 0x01u;
            ret = wc_CoseEncrypt_Decrypt(&recipient, 0u, message, message_len,
                NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr, plaintext,
                sizeof(plaintext), &plaintext_len);
            TEST_ASSERT(ret == WOLFCOSE_E_COSE_DECRYPT_FAIL,
                        "Examples ECDH-ES rejects modified tag");
        }
    }

    if (cose_key_inited != 0) {
        wc_CoseKey_Free(&cose_key);
    }
    if (ecc_key_inited != 0) {
        wc_ecc_free(&ecc_key);
    }
}

#endif /* ECDH_ES_DIRECT && ES256 && HAVE_HKDF */

int test_cose_examples(void)
{
    g_failures = 0;
    printf("\n  COSE WG Examples vectors:\n");

#ifdef WOLFCOSE_HAVE_ES256
    test_example_sign1();
    #if defined(WOLFCOSE_SIGN_VERIFY)
    test_example_sign();
    #endif
#endif
#ifdef WOLFCOSE_HAVE_HMAC256
    test_example_mac0();
#endif
#ifdef WOLFCOSE_HAVE_AESGCM
    test_example_encrypt0();
    #if defined(WOLFCOSE_ENCRYPT_DECRYPT)
    test_example_encrypt_direct();
    #ifdef WOLFCOSE_KEY_WRAP
    test_example_encrypt_a128kw();
    #endif
    #endif
#endif
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(WOLFCOSE_HAVE_ES256) && \
    defined(HAVE_HKDF) && defined(WOLFCOSE_ENCRYPT_DECRYPT)
    test_example_encrypt_ecdh();
#endif

    return g_failures;
}
