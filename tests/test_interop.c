/* test_interop.c
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
 * COSE Interoperability Tests
 *
 * Tests wolfCOSE against known-good test vectors from:
 * - COSE Working Group Examples (https://github.com/cose-wg/Examples)
 * - RFC 9052 Appendix examples
 *
 * These tests prove RFC correctness by verifying that:
 * 1. wolfCOSE can decode/verify messages created by reference implementations
 * 2. Messages created by wolfCOSE can be verified by reference implementations
 * 3. Round-trip encode/decode preserves data integrity
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfcose/wolfcose.h>
#include "test_suite.h"
#include <wolfssl/wolfcrypt/random.h>
#ifdef WOLFCOSE_HAVE_ES256
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef WOLFCOSE_HAVE_EDDSA
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#include <stdio.h>
#include <string.h>

static int g_failures = 0;

#define TEST_ASSERT(cond, name) do {                           \
    if (!(cond)) {                                             \
        printf("  FAIL: %s (line %d)\n", (name), __LINE__);   \
        g_failures++;                                          \
    } else {                                                   \
        printf("  PASS: %s\n", (name));                        \
    }                                                          \
} while (0)

/* ----- COSE_Sign1 Test Vectors (RFC 9052 / COSE WG Examples) ----- */

/*
 * Test Vector: sign1-pass-01
 * Algorithm: ES256
 * Payload: "This is the content."
 * Source: Derived from COSE WG sign1-tests
 *
 * Key (P-256):
 *   x: 65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d
 *   y: 1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c
 *   d: aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf
 */
static const uint8_t sign1_vec1_keyX[] = {
    0x65, 0xed, 0xa5, 0xa1, 0x25, 0x77, 0xc2, 0xba,
    0xe8, 0x29, 0x43, 0x7f, 0xe3, 0x38, 0x70, 0x1a,
    0x10, 0xaa, 0xa3, 0x75, 0xe1, 0xbb, 0x5b, 0x5d,
    0xe1, 0x08, 0xde, 0x43, 0x9c, 0x08, 0x55, 0x1d
};
static const uint8_t sign1_vec1_keyY[] = {
    0x1e, 0x52, 0xed, 0x75, 0x70, 0x11, 0x63, 0xf7,
    0xf9, 0xe4, 0x0d, 0xdf, 0x9f, 0x34, 0x1b, 0x3d,
    0xc9, 0xba, 0x86, 0x0a, 0xf7, 0xe0, 0xca, 0x7c,
    0xa7, 0xe9, 0xee, 0xcd, 0x00, 0x84, 0xd1, 0x9c
};
static const uint8_t sign1_vec1_keyD[] = {
    0xaf, 0xf9, 0x07, 0xc9, 0x9f, 0x9a, 0xd3, 0xaa,
    0xe6, 0xc4, 0xcd, 0xf2, 0x11, 0x22, 0xbc, 0xe2,
    0xbd, 0x68, 0xb5, 0x28, 0x3e, 0x69, 0x07, 0x15,
    0x4a, 0xd9, 0x11, 0x84, 0x0f, 0xa2, 0x08, 0xcf
};

static const uint8_t sign1_vec1_payload[] = "This is the content.";

#if defined(WOLFCOSE_COUNTERSIGN_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES256)
/* RFC 9338 Appendix A.1.1 COSE_Sign countersignature example. */
static const uint8_t countersign_rfc9338_sign_key_x[] = {
    0xba, 0xc5, 0xb1, 0x1c, 0xad, 0x8f, 0x99, 0xf9,
    0xc7, 0x2b, 0x05, 0xcf, 0x4b, 0x9e, 0x26, 0xd2,
    0x44, 0xdc, 0x18, 0x9f, 0x74, 0x52, 0x28, 0x25,
    0x5a, 0x21, 0x9a, 0x86, 0xd6, 0xa0, 0x9e, 0xff
};
static const uint8_t countersign_rfc9338_sign_key_y[] = {
    0x20, 0x13, 0x8b, 0xf8, 0x2d, 0xc1, 0xb6, 0xd5,
    0x62, 0xbe, 0x0f, 0xa5, 0x4a, 0xb7, 0x80, 0x4a,
    0x3a, 0x64, 0xb6, 0xd7, 0x2c, 0xcf, 0xed, 0x6b,
    0x6f, 0xb6, 0xed, 0x28, 0xbb, 0xfc, 0x11, 0x7e
};
static const uint8_t countersign_rfc9338_sign_message[] = {
    0xd8, 0x62, 0x84, 0x40, 0xa1, 0x0b, 0x83, 0x43,
    0xa1, 0x01, 0x26, 0xa1, 0x04, 0x42, 0x31, 0x31,
    0x58, 0x40, 0x5a, 0xc0, 0x5e, 0x28, 0x9d, 0x5d,
    0x0e, 0x1b, 0x0a, 0x7f, 0x04, 0x8a, 0x5d, 0x2b,
    0x64, 0x38, 0x13, 0xde, 0xd5, 0x0b, 0xc9, 0xe4,
    0x92, 0x20, 0xf4, 0xf7, 0x27, 0x8f, 0x85, 0xf1,
    0x9d, 0x4a, 0x77, 0xd6, 0x55, 0xc9, 0xd3, 0xb5,
    0x1e, 0x80, 0x5a, 0x74, 0xb0, 0x99, 0xe1, 0xe0,
    0x85, 0xaa, 0xcd, 0x97, 0xfc, 0x29, 0xd7, 0x2f,
    0x88, 0x7e, 0x88, 0x02, 0xbb, 0x66, 0x50, 0xcc,
    0xeb, 0x2c, 0x54, 0x54, 0x68, 0x69, 0x73, 0x20,
    0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63,
    0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x81,
    0x83, 0x43, 0xa1, 0x01, 0x26, 0xa1, 0x04, 0x42,
    0x31, 0x31, 0x58, 0x40, 0xe2, 0xae, 0xaf, 0xd4,
    0x0d, 0x69, 0xd1, 0x9d, 0xfe, 0x6e, 0x52, 0x07,
    0x7c, 0x5d, 0x7f, 0xf4, 0xe4, 0x08, 0x28, 0x2c,
    0xbe, 0xfb, 0x5d, 0x06, 0xcb, 0xf4, 0x14, 0xaf,
    0x2e, 0x19, 0xd9, 0x82, 0xac, 0x45, 0xac, 0x98,
    0xb8, 0x54, 0x4c, 0x90, 0x8b, 0x45, 0x07, 0xde,
    0x1e, 0x90, 0xb7, 0x17, 0xc3, 0xd3, 0x48, 0x16,
    0xfe, 0x92, 0x6a, 0x2b, 0x98, 0xf5, 0x3a, 0xfd,
    0x2f, 0xa0, 0xf3, 0x0a
};
#endif

#if defined(WOLFCOSE_COUNTERSIGN_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES512)
/* RFC 9338 Appendix A.2.1 COSE_Sign1 countersignature example. */
static const uint8_t countersign_rfc9338_key_x[] = {
    0x00, 0x72, 0x99, 0x2c, 0xb3, 0xac, 0x08, 0xec,
    0xf3, 0xe5, 0xc6, 0x3d, 0xed, 0xec, 0x0d, 0x51,
    0xa8, 0xc1, 0xf7, 0x9e, 0xf2, 0xf8, 0x2f, 0x94,
    0xf3, 0xc7, 0x37, 0xbf, 0x5d, 0xe7, 0x98, 0x66,
    0x71, 0xea, 0xc6, 0x25, 0xfe, 0x82, 0x57, 0xbb,
    0xd0, 0x39, 0x46, 0x44, 0xca, 0xaa, 0x3a, 0xaf,
    0x8f, 0x27, 0xa4, 0x58, 0x5f, 0xbb, 0xca, 0xd0,
    0xf2, 0x45, 0x76, 0x20, 0x08, 0x5e, 0x5c, 0x8f,
    0x42, 0xad
};
static const uint8_t countersign_rfc9338_key_y[] = {
    0x01, 0xdc, 0xa6, 0x94, 0x7b, 0xce, 0x88, 0xbc,
    0x57, 0x90, 0x48, 0x5a, 0xc9, 0x74, 0x27, 0x34,
    0x2b, 0xc3, 0x5f, 0x88, 0x7d, 0x86, 0xd6, 0x5a,
    0x08, 0x93, 0x77, 0xe2, 0x47, 0xe6, 0x0b, 0xaa,
    0x55, 0xe4, 0xe8, 0x50, 0x1e, 0x2a, 0xda, 0x57,
    0x24, 0xac, 0x51, 0xd6, 0x90, 0x90, 0x08, 0x03,
    0x3e, 0xbc, 0x10, 0xac, 0x99, 0x9b, 0x9d, 0x7f,
    0x5c, 0xc2, 0x51, 0x9f, 0x3f, 0xe1, 0xea, 0x1d,
    0x94, 0x75
};
static const uint8_t countersign_rfc9338_message[] = {
    0xd2, 0x84, 0x45, 0xa2, 0x01, 0x26, 0x03, 0x00,
    0xa2, 0x04, 0x42, 0x31, 0x31, 0x0b, 0x83, 0x44,
    0xa1, 0x01, 0x38, 0x23, 0xa1, 0x04, 0x58, 0x1e,
    0x62, 0x69, 0x6c, 0x62, 0x6f, 0x2e, 0x62, 0x61,
    0x67, 0x67, 0x69, 0x6e, 0x73, 0x40, 0x68, 0x6f,
    0x62, 0x62, 0x69, 0x74, 0x6f, 0x6e, 0x2e, 0x65,
    0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x58, 0x84,
    0x01, 0xb1, 0x29, 0x1b, 0x0e, 0x60, 0xa7, 0x9c,
    0x45, 0x9a, 0x4a, 0x91, 0x84, 0xa0, 0xd3, 0x93,
    0xe0, 0x34, 0xb3, 0x4a, 0xf0, 0x69, 0xa1, 0xcc,
    0xa3, 0x4f, 0x5a, 0x91, 0x3a, 0xff, 0xff, 0x69,
    0x80, 0x02, 0x29, 0x5f, 0xa9, 0xf8, 0xfc, 0xbf,
    0xb6, 0xfd, 0xff, 0x59, 0x13, 0x2f, 0xc0, 0xc4,
    0x06, 0xe9, 0x87, 0x54, 0xa9, 0x8f, 0x1f, 0xbf,
    0xe8, 0x1c, 0x03, 0x09, 0x5f, 0x48, 0x18, 0x56,
    0xbc, 0x47, 0x01, 0x70, 0x22, 0x72, 0x06, 0xfa,
    0x5b, 0xee, 0x3c, 0x04, 0x31, 0xc5, 0x6a, 0x66,
    0x82, 0x4e, 0x7a, 0xaf, 0x69, 0x29, 0x85, 0x95,
    0x2e, 0x31, 0x27, 0x14, 0x34, 0xb2, 0xba, 0x2e,
    0x47, 0xa3, 0x35, 0xc6, 0x58, 0xb5, 0xe9, 0x95,
    0xae, 0xb5, 0xd6, 0x3c, 0xf2, 0xd0, 0xce, 0xd3,
    0x67, 0xd3, 0xe4, 0xcc, 0x8f, 0xff, 0xd5, 0x3b,
    0x70, 0xd1, 0x15, 0xba, 0xa9, 0xe8, 0x69, 0x61,
    0xfb, 0xd1, 0xa5, 0xcf, 0x54, 0x54, 0x68, 0x69,
    0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65,
    0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
    0x2e, 0x58, 0x40, 0xbb, 0x58, 0x7d, 0x6b, 0x15,
    0xf4, 0x7b, 0xfd, 0x54, 0xd2, 0xcb, 0xfc, 0xec,
    0xef, 0x75, 0x45, 0x1e, 0x92, 0xb0, 0x8a, 0x51,
    0x4b, 0xd4, 0x39, 0xfa, 0x3a, 0xa6, 0x5c, 0x6a,
    0xc9, 0x2d, 0xf0, 0xd7, 0x32, 0x8c, 0x4a, 0x47,
    0x52, 0x9b, 0x32, 0xad, 0xd3, 0xdd, 0x1b, 0x4e,
    0x94, 0x00, 0x71, 0xc0, 0x21, 0xe9, 0xa8, 0xf2,
    0x64, 0x1f, 0x1d, 0x8e, 0x3b, 0x05, 0x3d, 0xdd,
    0x65, 0xae, 0x52
};
#endif

#if defined(WOLFCOSE_COUNTERSIGN_VERIFY) && \
    defined(WOLFCOSE_HAVE_EDDSA)
static const uint8_t countersign_legacy_key[] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
};
static const uint8_t countersign_legacy_message[] = {
    0xd2, 0x84, 0x45, 0xa2, 0x01, 0x27, 0x03, 0x00,
    0xa2, 0x07, 0x83, 0x43, 0xa1, 0x01, 0x27, 0xa1,
    0x04, 0x42, 0x31, 0x31, 0x58, 0x40, 0x6d, 0xae,
    0xd1, 0x58, 0xaf, 0xe4, 0x03, 0x2e, 0x8d, 0xd4,
    0x77, 0xd3, 0xd2, 0xb7, 0xf6, 0x67, 0xe7, 0x95,
    0x7a, 0xa8, 0x30, 0x2b, 0xb5, 0xe5, 0x68, 0xb4,
    0xdc, 0xbc, 0xce, 0x3c, 0xf0, 0xed, 0x5a, 0x90,
    0xf8, 0x31, 0x35, 0x1c, 0x85, 0xd6, 0x15, 0x5a,
    0x42, 0xa1, 0x7c, 0xa1, 0xf2, 0x5f, 0x50, 0x1c,
    0xc1, 0x3f, 0x67, 0x10, 0x8a, 0xe5, 0x3b, 0xda,
    0x92, 0xdb, 0x88, 0x27, 0x2e, 0x00, 0x04, 0x42,
    0x31, 0x31, 0x54, 0x54, 0x68, 0x69, 0x73, 0x20,
    0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63,
    0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x58,
    0x40, 0x71, 0x42, 0xfd, 0x2f, 0xf9, 0x6d, 0x56,
    0xdb, 0x85, 0xbe, 0xe9, 0x05, 0xa7, 0x6b, 0xa1,
    0xd0, 0xb7, 0x32, 0x1a, 0x95, 0xc8, 0xc4, 0xd3,
    0x60, 0x7c, 0x57, 0x81, 0x93, 0x2b, 0x7a, 0xfb,
    0x87, 0x11, 0x49, 0x7d, 0xfa, 0x75, 0x1b, 0xf4,
    0x0b, 0x58, 0xb3, 0xbc, 0xc3, 0x23, 0x00, 0xb1,
    0x48, 0x7f, 0x3d, 0xb3, 0x40, 0x85, 0xee, 0xf0,
    0x13, 0xbf, 0x08, 0xf4, 0xa4, 0x4d, 0x6f, 0xef,
    0x0d
};
static const uint8_t countersign0_legacy_message[] = {
    0xd2, 0x84, 0x45, 0xa2, 0x01, 0x27, 0x03, 0x00,
    0xa2, 0x09, 0x58, 0x40, 0x58, 0xa1, 0x5e, 0x38,
    0xe6, 0xf0, 0x6d, 0x58, 0xef, 0xfe, 0x37, 0xfa,
    0x01, 0x1f, 0x74, 0x82, 0xd9, 0xfd, 0x58, 0xa4,
    0x8a, 0x71, 0x4e, 0x37, 0x33, 0x76, 0x28, 0x9a,
    0x07, 0x93, 0xec, 0x3f, 0xda, 0x92, 0x9d, 0xff,
    0xef, 0xa5, 0x71, 0xc9, 0x8c, 0x27, 0xe3, 0x74,
    0x9b, 0xff, 0xcd, 0xd0, 0x53, 0xb6, 0xc8, 0x4b,
    0x93, 0xdd, 0xa6, 0x07, 0xb6, 0x03, 0xda, 0xed,
    0xe2, 0x03, 0x0a, 0x08, 0x04, 0x42, 0x31, 0x31,
    0x54, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73,
    0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6f, 0x6e,
    0x74, 0x65, 0x6e, 0x74, 0x2e, 0x58, 0x40, 0x71,
    0x42, 0xfd, 0x2f, 0xf9, 0x6d, 0x56, 0xdb, 0x85,
    0xbe, 0xe9, 0x05, 0xa7, 0x6b, 0xa1, 0xd0, 0xb7,
    0x32, 0x1a, 0x95, 0xc8, 0xc4, 0xd3, 0x60, 0x7c,
    0x57, 0x81, 0x93, 0x2b, 0x7a, 0xfb, 0x87, 0x11,
    0x49, 0x7d, 0xfa, 0x75, 0x1b, 0xf4, 0x0b, 0x58,
    0xb3, 0xbc, 0xc3, 0x23, 0x00, 0xb1, 0x48, 0x7f,
    0x3d, 0xb3, 0x40, 0x85, 0xee, 0xf0, 0x13, 0xbf,
    0x08, 0xf4, 0xa4, 0x4d, 0x6f, 0xef, 0x0d
};
#endif

/* ----- COSE_Encrypt0 Test Vectors ----- */

/*
 * Test Vector: encrypt0-pass-01
 * Algorithm: A128GCM
 * Payload: "This is the content."
 * Key: 849b57219dae48de646d07dbb533566e (16 bytes)
 * IV:  02d1f7e6f26c43d4868d87ce
 */
static const uint8_t enc0_vec1_key[] = {
    0x84, 0x9b, 0x57, 0x21, 0x9d, 0xae, 0x48, 0xde,
    0x64, 0x6d, 0x07, 0xdb, 0xb5, 0x33, 0x56, 0x6e
};

static const uint8_t enc0_vec1_iv[] = {
    0x02, 0xd1, 0xf7, 0xe6, 0xf2, 0x6c, 0x43, 0xd4,
    0x86, 0x8d, 0x87, 0xce
};

static const uint8_t enc0_vec1_payload[] = "This is the content.";

/* ----- COSE_Mac0 Test Vectors ----- */

/*
 * Test Vector: mac0-pass-01
 * Algorithm: HMAC-256/256
 * Payload: "This is the content."
 * Key: 849b57219dae48de646d07dbb533566e... (32 bytes)
 */
static const uint8_t mac0_vec1_key[] = {
    0x84, 0x9b, 0x57, 0x21, 0x9d, 0xae, 0x48, 0xde,
    0x64, 0x6d, 0x07, 0xdb, 0xb5, 0x33, 0x56, 0x6e,
    0x84, 0x9b, 0x57, 0x21, 0x9d, 0xae, 0x48, 0xde,
    0x64, 0x6d, 0x07, 0xdb, 0xb5, 0x33, 0x56, 0x6e
};

static const uint8_t mac0_vec1_payload[] = "This is the content.";

/* ----- Sign1 Interop Tests ----- */
#ifdef WOLFCOSE_HAVE_ES256
static void test_interop_sign1_roundtrip(void)
{
    WOLFCOSE_KEY signKey;
    ecc_key eccKey;
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int eccInited = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign1 ES256 Round-trip]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    if (ret == 0) {
        ret = wc_ecc_init(&eccKey);
        if (ret != 0) {
            TEST_ASSERT(0, "ecc init");
        }
        else {
            eccInited = 1;
        }
    }

    /* Import the test vector key */
    if (ret == 0) {
        ret = wc_ecc_import_unsigned(&eccKey,
            sign1_vec1_keyX, sign1_vec1_keyY, sign1_vec1_keyD,
            ECC_SECP256R1);
        TEST_ASSERT(ret == 0, "import test vector key");
    }

    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        ret = wc_CoseKey_SetEcc(&signKey, WOLFCOSE_CRV_P256, &eccKey);
        TEST_ASSERT(ret == 0, "set ecc key");
    }

    /* Sign the payload */
    if (ret == 0) {
        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_ES256,
            NULL, 0, /* kid */
            sign1_vec1_payload, sizeof(sign1_vec1_payload) - 1,
            NULL, 0, /* detached */
            NULL, 0, /* extAad */
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0 && outLen > 0, "sign message");
    }

    /* Verify with same key */
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&signKey, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify signature");
        TEST_ASSERT(decPayloadLen == sizeof(sign1_vec1_payload) - 1,
                    "payload length match");
        TEST_ASSERT(memcmp(decPayload, sign1_vec1_payload, decPayloadLen) == 0,
                    "payload content match");
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_ES256, "algorithm match");
    }

    if (eccInited != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}

#if defined(WOLFCOSE_HAVE_ES384)
static void test_interop_sign1_es384_roundtrip(void)
{
    WOLFCOSE_KEY signKey;
    ecc_key eccKey;
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int eccInited = 0;
    uint8_t payload[] = "ES384 test payload for interop";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign1 ES384 Round-trip]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    if (ret == 0) {
        ret = wc_ecc_init(&eccKey);
        if (ret != 0) {
            TEST_ASSERT(0, "ecc init");
        }
        else {
            eccInited = 1;
        }
    }

    /* Generate P-384 key */
    if (ret == 0) {
        ret = wc_ecc_make_key(&rng, 48, &eccKey);
        TEST_ASSERT(ret == 0, "generate P-384 key");
    }

    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        ret = wc_CoseKey_SetEcc(&signKey, WOLFCOSE_CRV_P384, &eccKey);
        TEST_ASSERT(ret == 0, "set ecc key P-384");
    }

    /* Sign with ES384 */
    if (ret == 0) {
        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_ES384,
            NULL, 0,
            payload, sizeof(payload) - 1,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0 && outLen > 0, "sign ES384");
    }

    /* Verify */
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&signKey, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify ES384");
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_ES384, "ES384 algorithm match");
    }

    if (eccInited != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}
#endif /* WOLFCOSE_HAVE_ES384 */

#if defined(WOLFCOSE_HAVE_ES512)
static void test_interop_sign1_es512_roundtrip(void)
{
    WOLFCOSE_KEY signKey;
    ecc_key eccKey;
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int eccInited = 0;
    uint8_t payload[] = "ES512 test payload for interop testing";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[640]; /* ES512 signatures are larger */
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign1 ES512 Round-trip]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    if (ret == 0) {
        ret = wc_ecc_init(&eccKey);
        if (ret != 0) {
            TEST_ASSERT(0, "ecc init");
        }
        else {
            eccInited = 1;
        }
    }

    /* Generate P-521 key */
    if (ret == 0) {
        ret = wc_ecc_make_key(&rng, 66, &eccKey);
        TEST_ASSERT(ret == 0, "generate P-521 key");
    }

    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        ret = wc_CoseKey_SetEcc(&signKey, WOLFCOSE_CRV_P521, &eccKey);
        TEST_ASSERT(ret == 0, "set ecc key P-521");
    }

    /* Sign with ES512 */
    if (ret == 0) {
        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_ES512,
            NULL, 0,
            payload, sizeof(payload) - 1,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0 && outLen > 0, "sign ES512");
    }

    /* Verify */
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&signKey, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify ES512");
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_ES512, "ES512 algorithm match");
    }

    if (eccInited != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}
#endif /* WOLFCOSE_HAVE_ES512 */

static void test_interop_sign1_with_aad_roundtrip(void)
{
    WOLFCOSE_KEY signKey;
    ecc_key eccKey;
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int eccInited = 0;
    uint8_t payload[] = "Payload with external AAD";
    uint8_t extAad[] = "application-specific-context";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign1 with External AAD]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    if (ret == 0) {
        ret = wc_ecc_init(&eccKey);
        if (ret != 0) {
            TEST_ASSERT(0, "ecc init");
        }
        else {
            eccInited = 1;
        }
    }

    if (ret == 0) {
        ret = wc_ecc_make_key(&rng, 32, &eccKey);
        if (ret != 0) {
            TEST_ASSERT(0, "keygen");
        }
    }

    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        wc_CoseKey_SetEcc(&signKey, WOLFCOSE_CRV_P256, &eccKey);

        /* Sign with AAD */
        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_ES256,
            NULL, 0,
            payload, sizeof(payload) - 1,
            NULL, 0,
            extAad, sizeof(extAad) - 1,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0, "sign with AAD");
    }

    /* Verify with correct AAD */
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&signKey, out, outLen,
            NULL, 0,
            extAad, sizeof(extAad) - 1,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify with correct AAD");
    }

    /* Verify with wrong AAD must fail */
    if (ret == 0) {
        uint8_t wrongAad[] = "wrong-context";
        int verifyRet;
        verifyRet = wc_CoseSign1_Verify(&signKey, out, outLen,
            NULL, 0,
            wrongAad, sizeof(wrongAad) - 1,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(verifyRet != 0, "verify with wrong AAD fails");
    }

    if (eccInited != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}

static void test_interop_sign1_detached_roundtrip(void)
{
    WOLFCOSE_KEY signKey;
    ecc_key eccKey;
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int eccInited = 0;
    uint8_t payload[] = "Detached payload content";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign1 Detached Payload]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    if (ret == 0) {
        ret = wc_ecc_init(&eccKey);
        if (ret != 0) {
            TEST_ASSERT(0, "ecc init");
        }
        else {
            eccInited = 1;
        }
    }

    if (ret == 0) {
        ret = wc_ecc_make_key(&rng, 32, &eccKey);
        if (ret != 0) {
            TEST_ASSERT(0, "keygen");
        }
    }

    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        wc_CoseKey_SetEcc(&signKey, WOLFCOSE_CRV_P256, &eccKey);

        /* Sign with detached payload */
        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_ES256,
            NULL, 0,
            NULL, 0, /* no inline payload */
            payload, sizeof(payload) - 1, /* detached payload */
            NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0, "sign detached");
    }

    /* Verify with detached payload */
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&signKey, out, outLen,
            payload, sizeof(payload) - 1,
            NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify detached");
        TEST_ASSERT((hdr.flags & WOLFCOSE_HDR_FLAG_DETACHED) != 0, "detached flag set");
    }

    /* Wrong detached payload must fail */
    if (ret == 0) {
        uint8_t wrongPayload[] = "Wrong payload";
        int verifyRet;
        verifyRet = wc_CoseSign1_Verify(&signKey, out, outLen,
            wrongPayload, sizeof(wrongPayload) - 1,
            NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(verifyRet != 0, "wrong detached payload fails");
    }

    if (eccInited != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}
#endif /* WOLFCOSE_HAVE_ES256 */

/* ----- Encrypt0 Interop Tests ----- */
#ifdef WOLFCOSE_HAVE_AESGCM
static void test_interop_encrypt0_roundtrip(void)
{
    WOLFCOSE_KEY key;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Encrypt0 A128GCM Round-trip]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, enc0_vec1_key, sizeof(enc0_vec1_key));
    TEST_ASSERT(ret == 0, "set symmetric key");

    /* Encrypt */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        enc0_vec1_iv, sizeof(enc0_vec1_iv),
        enc0_vec1_payload, sizeof(enc0_vec1_payload) - 1,
        NULL, 0, NULL,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "encrypt A128GCM");

    /* Decrypt */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt A128GCM");
    TEST_ASSERT(plaintextLen == sizeof(enc0_vec1_payload) - 1, "payload length");
    TEST_ASSERT(memcmp(plaintext, enc0_vec1_payload, plaintextLen) == 0,
                "payload match");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A128GCM, "algorithm match");
}

static void test_interop_encrypt0_a192gcm_roundtrip(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[24] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
    };
    uint8_t iv[12] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66
    };
    uint8_t payload[] = "A192GCM interop test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Encrypt0 A192GCM Round-trip]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "set 192-bit key");

    /* Encrypt with A192GCM */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A192GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0, NULL,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "encrypt A192GCM");

    /* Decrypt */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt A192GCM");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A192GCM, "A192GCM algorithm");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1, "payload length");
}

static void test_interop_encrypt0_a256gcm_roundtrip(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t iv[12] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66
    };
    uint8_t payload[] = "A256GCM interop test payload data";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Encrypt0 A256GCM Round-trip]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "set 256-bit key");

    /* Encrypt with A256GCM */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A256GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0, NULL,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "encrypt A256GCM");

    /* Decrypt */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt A256GCM");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A256GCM, "A256GCM algorithm");
}

static void test_interop_encrypt0_with_aad(void)
{
    WOLFCOSE_KEY key;
    uint8_t extAad[] = "encryption-context-data";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Encrypt0 with External AAD]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, enc0_vec1_key, sizeof(enc0_vec1_key));

    /* Encrypt with AAD */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        enc0_vec1_iv, sizeof(enc0_vec1_iv),
        enc0_vec1_payload, sizeof(enc0_vec1_payload) - 1,
        NULL, 0, NULL,
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "encrypt with AAD");

    /* Decrypt with correct AAD */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0,
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt with correct AAD");

    /* Decrypt with wrong AAD must fail */
    /* empty-brace-scan: allow - test-local temporary scope */
    {
        uint8_t wrongAad[] = "wrong-context";
        ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
            NULL, 0,
            wrongAad, sizeof(wrongAad) - 1,
            scratch, sizeof(scratch),
            &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
        TEST_ASSERT(ret != 0, "wrong AAD fails");
    }
}

static void test_interop_encrypt0_detached(void)
{
    WOLFCOSE_KEY key;
    uint8_t payload[] = "Detached ciphertext payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t detachedCt[256];
    size_t detachedCtLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Encrypt0 Detached Ciphertext]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, enc0_vec1_key, sizeof(enc0_vec1_key));

    /* Encrypt with detached ciphertext */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        enc0_vec1_iv, sizeof(enc0_vec1_iv),
        payload, sizeof(payload) - 1,
        detachedCt, sizeof(detachedCt), &detachedCtLen,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "encrypt detached");
    TEST_ASSERT(detachedCtLen > 0, "detached ct length");

    /* Decrypt with detached ciphertext */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        detachedCt, detachedCtLen,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt detached");
    TEST_ASSERT((hdr.flags & WOLFCOSE_HDR_FLAG_DETACHED) != 0, "detached flag");
}
#endif /* WOLFCOSE_HAVE_AESGCM */

/* ----- Mac0 Interop Tests ----- */
#ifdef WOLFCOSE_HAVE_HMAC256
static void test_interop_mac0_roundtrip(void)
{
    WOLFCOSE_KEY key;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Mac0 HMAC-256/256 Round-trip]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, mac0_vec1_key, sizeof(mac0_vec1_key));
    TEST_ASSERT(ret == 0, "set HMAC key");

    /* Create MAC */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0, /* kid, kidLen */
        mac0_vec1_payload, sizeof(mac0_vec1_payload) - 1,
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "create MAC");

    /* Verify */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify MAC");
    TEST_ASSERT(decPayloadLen == sizeof(mac0_vec1_payload) - 1, "payload length");
    TEST_ASSERT(memcmp(decPayload, mac0_vec1_payload, decPayloadLen) == 0,
                "payload match");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC_256_256, "algorithm match");
}

static void test_interop_mac0_with_aad(void)
{
    WOLFCOSE_KEY key;
    uint8_t extAad[] = "mac-context-data";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Mac0 with External AAD]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, mac0_vec1_key, sizeof(mac0_vec1_key));

    /* Create MAC with AAD */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0, /* kid, kidLen */
        mac0_vec1_payload, sizeof(mac0_vec1_payload) - 1,
        NULL, 0, /* detachedPayload, detachedLen */
        extAad, sizeof(extAad) - 1, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "create MAC with AAD");

    /* Verify with correct AAD */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0,
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify with correct AAD");

    /* Wrong AAD must fail */
    /* empty-brace-scan: allow - test-local temporary scope */
    {
        uint8_t wrongAad[] = "wrong";
        ret = wc_CoseMac0_Verify(&key, out, outLen,
            NULL, 0,
            wrongAad, sizeof(wrongAad) - 1,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret != 0, "wrong AAD fails");
    }
}

#endif /* WOLFCOSE_HAVE_HMAC256 */

#ifdef WOLFCOSE_HAVE_AESMAC
static void test_interop_mac0_aes_cbc_mac_128_64(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t payload[] = "AES-CBC-MAC-128-64 test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Mac0 AES-MAC-128/64]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "set AES key");

    /* Create MAC */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_AES_MAC_128_64,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload) - 1,
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "create AES-MAC-128/64");

    /* Verify */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify AES-MAC-128/64");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_AES_MAC_128_64, "algorithm");
}

static void test_interop_mac0_aes_cbc_mac_256_128(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t payload[] = "AES-CBC-MAC-256-128 test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Mac0 AES-MAC-256/128]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "set AES-256 key");

    /* Create MAC */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_AES_MAC_256_128,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload) - 1,
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "create AES-MAC-256/128");

    /* Verify */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify AES-MAC-256/128");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_AES_MAC_256_128, "algorithm");
}
#endif /* WOLFCOSE_HAVE_AESMAC */

#ifdef WOLFCOSE_HAVE_HMAC256
static void test_interop_mac0_detached(void)
{
    WOLFCOSE_KEY key;
    uint8_t payload[] = "Detached MAC payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Mac0 Detached Payload]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, mac0_vec1_key, sizeof(mac0_vec1_key));

    /* Create MAC with detached payload */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0, /* kid, kidLen */
        NULL, 0, /* no inline payload */
        payload, sizeof(payload) - 1, /* detached */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "create detached MAC");

    /* Verify with detached payload */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify detached MAC");
    TEST_ASSERT((hdr.flags & WOLFCOSE_HDR_FLAG_DETACHED) != 0, "detached flag");

    /* Wrong detached payload must fail */
    /* empty-brace-scan: allow - test-local temporary scope */
    {
        uint8_t wrongPayload[] = "Wrong";
        ret = wc_CoseMac0_Verify(&key, out, outLen,
            wrongPayload, sizeof(wrongPayload) - 1,
            NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret != 0, "wrong detached payload fails");
    }
}
#endif /* WOLFCOSE_HAVE_HMAC256 */

/* ----- EdDSA Interop Tests ----- */
#ifdef WOLFCOSE_HAVE_EDDSA
static void test_interop_sign1_eddsa_roundtrip(void)
{
    WOLFCOSE_KEY signKey;
    ed25519_key edKey;
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int edInited = 0;
    uint8_t payload[] = "EdDSA interoperability test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign1 EdDSA Round-trip]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    if (ret == 0) {
        ret = wc_ed25519_init(&edKey);
        if (ret != 0) {
            TEST_ASSERT(0, "ed init");
        }
        else {
            edInited = 1;
        }
    }

    if (ret == 0) {
        ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &edKey);
        TEST_ASSERT(ret == 0, "generate Ed25519 key");
    }

    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        ret = wc_CoseKey_SetEd25519(&signKey, &edKey);
        TEST_ASSERT(ret == 0, "set Ed25519 key");
    }

    /* Sign with EdDSA */
    if (ret == 0) {
        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_EDDSA,
            NULL, 0,
            payload, sizeof(payload) - 1,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0 && outLen > 0, "sign EdDSA");
    }

    /* Verify */
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&signKey, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify EdDSA");
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_EDDSA, "EdDSA algorithm");
        TEST_ASSERT(decPayloadLen == sizeof(payload) - 1, "payload length");
    }

    if (edInited != 0) {
        wc_ed25519_free(&edKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}

static void test_interop_sign1_eddsa_with_aad(void)
{
    WOLFCOSE_KEY signKey;
    ed25519_key edKey;
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int edInited = 0;
    uint8_t payload[] = "EdDSA with AAD";
    uint8_t extAad[] = "eddsa-context";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign1 EdDSA with AAD]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    if (ret == 0) {
        ret = wc_ed25519_init(&edKey);
        if (ret != 0) {
            TEST_ASSERT(0, "ed init");
        }
        else {
            edInited = 1;
        }
    }

    if (ret == 0) {
        ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &edKey);
        if (ret != 0) {
            TEST_ASSERT(0, "keygen");
        }
    }

    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        wc_CoseKey_SetEd25519(&signKey, &edKey);

        /* Sign with AAD */
        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_EDDSA,
            NULL, 0,
            payload, sizeof(payload) - 1,
            NULL, 0,
            extAad, sizeof(extAad) - 1,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0, "sign EdDSA with AAD");
    }

    /* Verify with correct AAD */
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&signKey, out, outLen,
            NULL, 0,
            extAad, sizeof(extAad) - 1,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify EdDSA with AAD");
    }

    if (edInited != 0) {
        wc_ed25519_free(&edKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}
#endif /* WOLFCOSE_HAVE_EDDSA */

#if defined(WOLFCOSE_COUNTERSIGN_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES256)
static void test_interop_countersign_rfc9338_sign(void)
{
    static const uint8_t expectedKid[] = "11";
    WOLFCOSE_KEY counterKey;
    ecc_key eccKey;
    WOLFCOSE_HDR hdr;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    int eccInited = 0;
    int keyInited = 0;
    int ret;

    printf("  [RFC 9338 Appendix A.1.1 COSE_Sign Countersignature]\n");

    ret = wc_ecc_init(&eccKey);
    if (ret == 0) {
        eccInited = 1;
        ret = wc_ecc_import_unsigned(&eccKey,
            countersign_rfc9338_sign_key_x,
            countersign_rfc9338_sign_key_y, NULL, ECC_SECP256R1);
    }
    TEST_ASSERT(ret == 0, "import RFC 9338 COSE_Sign countersigner key");
    if (ret == 0) {
        ret = wc_CoseKey_Init(&counterKey);
        keyInited = (ret == 0) ? 1 : 0;
    }
    if (ret == 0) {
        ret = wc_CoseKey_SetEcc(&counterKey, WOLFCOSE_CRV_P256,
                                &eccKey);
    }
    if (ret == 0) {
        ret = wc_Cose_VerifyCounterSignature(&counterKey, 0u,
            countersign_rfc9338_sign_message,
            sizeof(countersign_rfc9338_sign_message),
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr);
    }
    TEST_ASSERT(ret == 0,
                "verify RFC 9338 COSE_Sign countersignature vector");
    if (ret == 0) {
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_ES256 &&
                    hdr.kidLen == sizeof(expectedKid) - 1u &&
                    memcmp(hdr.kid, expectedKid, hdr.kidLen) == 0,
                    "decode RFC 9338 COSE_Sign countersigner headers");
    }

    if (keyInited != 0) {
        wc_CoseKey_Free(&counterKey);
    }
    if (eccInited != 0) {
        wc_ecc_free(&eccKey);
    }
}
#endif

#if defined(WOLFCOSE_COUNTERSIGN_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES512)
static void test_interop_countersign_rfc9338_sign1(void)
{
    static const uint8_t expectedKid[] =
        "bilbo.baggins@hobbiton.example";
    WOLFCOSE_KEY counterKey;
    ecc_key eccKey;
    WOLFCOSE_HDR hdr;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t tampered[sizeof(countersign_rfc9338_message)];
    int eccInited = 0;
    int keyInited = 0;
    int ret;

    printf("  [RFC 9338 Appendix A.2.1 Countersignature]\n");

    ret = wc_ecc_init(&eccKey);
    if (ret == 0) {
        eccInited = 1;
        ret = wc_ecc_import_unsigned(&eccKey,
            countersign_rfc9338_key_x, countersign_rfc9338_key_y,
            NULL, ECC_SECP521R1);
    }
    TEST_ASSERT(ret == 0, "import RFC 9338 countersigner key");
    if (ret == 0) {
        ret = wc_CoseKey_Init(&counterKey);
        keyInited = (ret == 0) ? 1 : 0;
    }
    if (ret == 0) {
        ret = wc_CoseKey_SetEcc(&counterKey, WOLFCOSE_CRV_P521,
                                &eccKey);
    }
    if (ret == 0) {
        ret = wc_Cose_VerifyCounterSignature(&counterKey, 0u,
            countersign_rfc9338_message,
            sizeof(countersign_rfc9338_message), NULL, 0u, NULL, 0u,
            scratch, sizeof(scratch), &hdr);
    }
    TEST_ASSERT(ret == 0, "verify RFC 9338 countersignature vector");
    if (ret == 0) {
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_ES512 &&
                    hdr.kidLen == sizeof(expectedKid) - 1u &&
                    memcmp(hdr.kid, expectedKid, hdr.kidLen) == 0,
                    "decode RFC 9338 countersigner headers");
        (void)memcpy(tampered, countersign_rfc9338_message,
                     sizeof(tampered));
        tampered[sizeof(tampered) - 1u] ^= 1u;
        TEST_ASSERT(wc_Cose_VerifyCounterSignature(&counterKey, 0u,
            tampered, sizeof(tampered), NULL, 0u, NULL, 0u,
            scratch, sizeof(scratch), &hdr) != 0,
            "RFC 9338 vector covers primary signature");
    }

    if (keyInited != 0) {
        wc_CoseKey_Free(&counterKey);
    }
    if (eccInited != 0) {
        wc_ecc_free(&eccKey);
    }
}
#endif

#if defined(WOLFCOSE_COUNTERSIGN_VERIFY) && \
    defined(WOLFCOSE_HAVE_EDDSA)
static void test_interop_countersign_legacy(void)
{
    WOLFCOSE_KEY counterKey;
    WOLFCOSE_COUNTERSIGNATURE0 counterSigner0;
    WOLFCOSE_HDR hdr;
    ed25519_key edKey;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    int edInited = 0;
    int keyInited = 0;
    int ret;

    printf("  [RFC 8152 Legacy Countersignatures]\n");

    ret = wc_ed25519_init(&edKey);
    if (ret == 0) {
        edInited = 1;
        ret = wc_ed25519_import_public(countersign_legacy_key,
            (word32)sizeof(countersign_legacy_key), &edKey);
    }
    TEST_ASSERT(ret == 0, "import legacy countersigner key");
    if (ret == 0) {
        ret = wc_CoseKey_Init(&counterKey);
        keyInited = (ret == 0) ? 1 : 0;
    }
    if (ret == 0) {
        ret = wc_CoseKey_SetEd25519(&counterKey, &edKey);
    }
    if (ret == 0) {
        ret = wc_Cose_VerifyCounterSignature(&counterKey, 0u,
            countersign_legacy_message,
            sizeof(countersign_legacy_message), NULL, 0u, NULL, 0u,
            scratch, sizeof(scratch), &hdr);
    }
    TEST_ASSERT(ret == 0 && hdr.alg == WOLFCOSE_ALG_EDDSA,
                "verify deprecated label 7 countersignature");

    counterSigner0.algId = WOLFCOSE_ALG_EDDSA;
    counterSigner0.key = &counterKey;
    if (ret == 0) {
        ret = wc_Cose_VerifyCounterSignature0(&counterSigner0,
            countersign0_legacy_message,
            sizeof(countersign0_legacy_message), NULL, 0u, NULL, 0u,
            scratch, sizeof(scratch));
    }
    TEST_ASSERT(ret == 0,
                "verify deprecated label 9 countersignature");

    if (keyInited != 0) {
        wc_CoseKey_Free(&counterKey);
    }
    if (edInited != 0) {
        wc_ed25519_free(&edKey);
    }
}
#endif

/* ----- Multi-Signer Interop Tests ----- */
#if defined(WOLFCOSE_SIGN) && defined(WOLFCOSE_HAVE_ES256)
static void test_interop_sign_multi_signer(void)
{
    WOLFCOSE_KEY key1, key2;
    ecc_key eccKey1, eccKey2;
    WOLFCOSE_SIGNATURE signers[2];
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int ecc1Inited = 0;
    int ecc2Inited = 0;
    uint8_t payload[] = "Multi-signer payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[1024];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign Multi-Signer]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    /* Initialize keys */
    if (ret == 0) {
        ret = wc_ecc_init(&eccKey1);
        if (ret == 0) {
            ecc1Inited = 1;
        }
    }

    if (ret == 0) {
        ret = wc_ecc_init(&eccKey2);
        if (ret == 0) {
            ecc2Inited = 1;
        }
    }

    if (ret == 0) {
        ret = wc_ecc_make_key(&rng, 32, &eccKey1);
        if (ret != 0) {
            TEST_ASSERT(0, "keygen1");
        }
    }

    if (ret == 0) {
        ret = wc_ecc_make_key(&rng, 32, &eccKey2);
        if (ret != 0) {
            TEST_ASSERT(0, "keygen2");
        }
    }

    if (ret == 0) {
        wc_CoseKey_Init(&key1);
        wc_CoseKey_SetEcc(&key1, WOLFCOSE_CRV_P256, &eccKey1);

        wc_CoseKey_Init(&key2);
        wc_CoseKey_SetEcc(&key2, WOLFCOSE_CRV_P256, &eccKey2);

        /* Setup signers array */
        signers[0].algId = WOLFCOSE_ALG_ES256;
        signers[0].key = &key1;
        signers[0].kid = (const uint8_t*)"signer-1";
        signers[0].kidLen = 8;

        signers[1].algId = WOLFCOSE_ALG_ES256;
        signers[1].key = &key2;
        signers[1].kid = (const uint8_t*)"signer-2";
        signers[1].kidLen = 8;

        /* Sign with both signers */
        ret = wc_CoseSign_Sign(signers, 2,
            payload, sizeof(payload) - 1,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0 && outLen > 0, "multi-sign");
    }

    /* Verify with first signer */
    if (ret == 0) {
        ret = wc_CoseSign_Verify(&key1, 0, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify signer 0");
    }

    /* Verify with second signer */
    if (ret == 0) {
        ret = wc_CoseSign_Verify(&key2, 1, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify signer 1");
    }

    if (ecc1Inited != 0) {
        wc_ecc_free(&eccKey1);
    }
    if (ecc2Inited != 0) {
        wc_ecc_free(&eccKey2);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}

#ifdef WOLFCOSE_HAVE_ES384
static void test_interop_sign_mixed_algorithms(void)
{
    WOLFCOSE_KEY eccKey256, eccKey384;
    ecc_key ecc256, ecc384;
    WOLFCOSE_SIGNATURE signers[2];
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int ecc256Inited = 0;
    int ecc384Inited = 0;
    uint8_t payload[] = "Mixed algorithm payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[1024];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign Mixed ES256 + ES384]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    if (ret == 0) {
        ret = wc_ecc_init(&ecc256);
        if (ret == 0) {
            ecc256Inited = 1;
        }
    }

    if (ret == 0) {
        ret = wc_ecc_init(&ecc384);
        if (ret == 0) {
            ecc384Inited = 1;
        }
    }

    if (ret == 0) {
        ret = wc_ecc_make_key(&rng, 32, &ecc256);
        if (ret != 0) {
            TEST_ASSERT(0, "keygen P-256");
        }
    }

    if (ret == 0) {
        ret = wc_ecc_make_key(&rng, 48, &ecc384);
        if (ret != 0) {
            TEST_ASSERT(0, "keygen P-384");
        }
    }

    if (ret == 0) {
        wc_CoseKey_Init(&eccKey256);
        wc_CoseKey_SetEcc(&eccKey256, WOLFCOSE_CRV_P256, &ecc256);

        wc_CoseKey_Init(&eccKey384);
        wc_CoseKey_SetEcc(&eccKey384, WOLFCOSE_CRV_P384, &ecc384);

        /* Mixed algorithm signers */
        signers[0].algId = WOLFCOSE_ALG_ES256;
        signers[0].key = &eccKey256;
        signers[0].kid = (const uint8_t*)"p256";
        signers[0].kidLen = 4;

        signers[1].algId = WOLFCOSE_ALG_ES384;
        signers[1].key = &eccKey384;
        signers[1].kid = (const uint8_t*)"p384";
        signers[1].kidLen = 4;

        /* Sign */
        ret = wc_CoseSign_Sign(signers, 2,
            payload, sizeof(payload) - 1,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0, "multi-sign mixed");
    }

    /* Verify ES256 signer */
    if (ret == 0) {
        ret = wc_CoseSign_Verify(&eccKey256, 0, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify ES256");
    }

    /* Verify ES384 signer */
    if (ret == 0) {
        ret = wc_CoseSign_Verify(&eccKey384, 1, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify ES384");
    }

    if (ecc256Inited != 0) {
        wc_ecc_free(&ecc256);
    }
    if (ecc384Inited != 0) {
        wc_ecc_free(&ecc384);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}
#endif /* WOLFCOSE_HAVE_ES384 */
#endif /* WOLFCOSE_SIGN */

/* ----- Multi-Recipient Interop Tests ----- */
#if defined(WOLFCOSE_ENCRYPT) && defined(WOLFCOSE_HAVE_AESGCM)
static void test_interop_encrypt_multi_recipient(void)
{
    WOLFCOSE_KEY cek, kek1, kek2;
    WOLFCOSE_RECIPIENT recipients[2];
    uint8_t cekData[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t kekData1[16] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00
    };
    uint8_t kekData2[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
    };
    uint8_t iv[12] = {
        0x02, 0xD1, 0xF7, 0xE6, 0xF2, 0x6C, 0x43, 0xD4,
        0x86, 0x8D, 0x87, 0xCE
    };
    uint8_t payload[] = "Multi-recipient encrypted payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[1024];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    WC_RNG rng;
    int ret;

    (void)kekData1;
    (void)kekData2;
    (void)kek1;
    (void)kek2;

    printf("  [Interop Encrypt Multi-Recipient]\n");

    ret = wc_InitRng(&rng);
    TEST_ASSERT(ret == 0, "init RNG");

    wc_CoseKey_Init(&cek);
    wc_CoseKey_SetSymmetric(&cek, cekData, sizeof(cekData));

    wc_CoseKey_Init(&kek1);
    wc_CoseKey_SetSymmetric(&kek1, kekData1, sizeof(kekData1));

    wc_CoseKey_Init(&kek2);
    wc_CoseKey_SetSymmetric(&kek2, kekData2, sizeof(kekData2));

    /* Setup recipients with direct key */
    XMEMSET(recipients, 0, sizeof(recipients));
    recipients[0].algId = WOLFCOSE_ALG_DIRECT;
    recipients[0].key = &cek;
    recipients[0].kid = (const uint8_t*)"recipient-1";
    recipients[0].kidLen = 11;

    recipients[1].algId = WOLFCOSE_ALG_DIRECT;
    recipients[1].key = &cek;
    recipients[1].kid = (const uint8_t*)"recipient-2";
    recipients[1].kidLen = 11;

    /* Encrypt - correct argument order per API */
    ret = wc_CoseEncrypt_Encrypt(recipients, 2,
        WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);
    TEST_ASSERT(ret == 0, "multi-recipient encrypt");

    /* Decrypt with first recipient */
    ret = wc_CoseEncrypt_Decrypt(&recipients[0], 0, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt recipient 0");

    /* Decrypt with second recipient */
    ret = wc_CoseEncrypt_Decrypt(&recipients[1], 1, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt recipient 1");

    wc_FreeRng(&rng);
}
#endif /* WOLFCOSE_ENCRYPT */

#if defined(WOLFCOSE_MAC) && defined(WOLFCOSE_HAVE_HMAC256)
static void test_interop_mac_multi_recipient(void)
{
    WOLFCOSE_KEY key;
    WOLFCOSE_RECIPIENT recipients[2];
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t payload[] = "Multi-recipient MAC payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[1024];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Mac Multi-Recipient]\n");

    ret = wc_CoseKey_Init(&key);
    TEST_ASSERT(ret == 0, "multi-recipient MAC key init");
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "multi-recipient MAC key set");

    /* Setup recipients with direct key */
    XMEMSET(recipients, 0, sizeof(recipients));
    recipients[0].algId = WOLFCOSE_ALG_DIRECT;
    recipients[0].key = &key;
    recipients[0].kid = (const uint8_t*)"mac-rcpt-1";
    recipients[0].kidLen = 10;

    recipients[1].algId = WOLFCOSE_ALG_DIRECT;
    recipients[1].key = &key;
    recipients[1].kid = (const uint8_t*)"mac-rcpt-2";
    recipients[1].kidLen = 10;

    /* Create MAC - correct argument order per API */
    ret = wc_CoseMac_Create(recipients, 2,
        WOLFCOSE_ALG_HMAC_256_256,
        payload, sizeof(payload) - 1,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "multi-recipient MAC create");

    /* Verify with first recipient */
    ret = wc_CoseMac_Verify(&recipients[0], 0, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify recipient 0");

    /* Verify with second recipient */
    ret = wc_CoseMac_Verify(&recipients[1], 1, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify recipient 1");
}
#endif /* WOLFCOSE_MAC */

/* ----- Entry point ----- */
int test_interop(void)
{
    g_failures = 0;

    printf("=== COSE Interoperability Tests ===\n\n");

    printf("[Sign1 Tests]\n");
#ifdef WOLFCOSE_HAVE_ES256
    test_interop_sign1_roundtrip();
#if defined(WOLFCOSE_HAVE_ES384)
    test_interop_sign1_es384_roundtrip();
#endif
#if defined(WOLFCOSE_HAVE_ES512)
    test_interop_sign1_es512_roundtrip();
#endif
    test_interop_sign1_with_aad_roundtrip();
    test_interop_sign1_detached_roundtrip();
#endif

#ifdef WOLFCOSE_HAVE_EDDSA
    test_interop_sign1_eddsa_roundtrip();
    test_interop_sign1_eddsa_with_aad();
#endif
#if defined(WOLFCOSE_COUNTERSIGN_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES256)
    test_interop_countersign_rfc9338_sign();
#endif
#if defined(WOLFCOSE_COUNTERSIGN_VERIFY) && \
    defined(WOLFCOSE_HAVE_ES512)
    test_interop_countersign_rfc9338_sign1();
#endif
#if defined(WOLFCOSE_COUNTERSIGN_VERIFY) && \
    defined(WOLFCOSE_HAVE_EDDSA)
    test_interop_countersign_legacy();
#endif

    printf("\n[Encrypt0 Tests]\n");
#ifdef WOLFCOSE_HAVE_AESGCM
    test_interop_encrypt0_roundtrip();
    test_interop_encrypt0_a192gcm_roundtrip();
    test_interop_encrypt0_a256gcm_roundtrip();
    test_interop_encrypt0_with_aad();
    test_interop_encrypt0_detached();
#endif

    printf("\n[Mac0 Tests]\n");
#ifdef WOLFCOSE_HAVE_HMAC256
    test_interop_mac0_roundtrip();
    test_interop_mac0_with_aad();
    test_interop_mac0_detached();
#endif
#ifdef WOLFCOSE_HAVE_AESMAC
    test_interop_mac0_aes_cbc_mac_128_64();
    test_interop_mac0_aes_cbc_mac_256_128();
#endif

    printf("\n[Multi-Signer Tests]\n");
#if defined(WOLFCOSE_SIGN) && defined(WOLFCOSE_HAVE_ES256)
    test_interop_sign_multi_signer();
#ifdef WOLFCOSE_HAVE_ES384
    test_interop_sign_mixed_algorithms();
#endif
#endif

    printf("\n[Multi-Recipient Tests]\n");
#if defined(WOLFCOSE_ENCRYPT) && defined(WOLFCOSE_HAVE_AESGCM)
    test_interop_encrypt_multi_recipient();
#endif
#if defined(WOLFCOSE_MAC) && defined(WOLFCOSE_HAVE_HMAC256)
    test_interop_mac_multi_recipient();
#endif

    printf("\n=== Interop Results: %s ===\n",
           (g_failures == 0) ? "ALL PASSED" : "FAILURES");
    if (g_failures > 0) {
        printf("%d test(s) failed.\n", g_failures);
    }

    return g_failures;
}

/* Standalone main for interop tests only */
#ifdef WOLFCOSE_INTEROP_TEST_MAIN
int main(void)
{
    return test_interop();
}
#endif
