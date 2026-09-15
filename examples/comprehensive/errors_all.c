/* errors_all.c
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

/* Comprehensive error case testing for COSE operations.
 *
 * Compile-time gates:
 *   WOLFCOSE_EXAMPLE_ERRORS_ALL       - Enable this example (default: enabled)
 *   WOLFCOSE_NO_ERRORS_ALL_SIGN       - Exclude sign error tests
 *   WOLFCOSE_NO_ERRORS_ALL_ENCRYPT    - Exclude encrypt error tests
 *   WOLFCOSE_NO_ERRORS_ALL_MAC        - Exclude MAC error tests
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

/* Default: enabled */
#ifndef WOLFCOSE_NO_EXAMPLE_ERRORS_ALL
    #define WOLFCOSE_EXAMPLE_ERRORS_ALL
#endif

#ifdef WOLFCOSE_EXAMPLE_ERRORS_ALL

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/random.h>
#ifdef WOLFCOSE_HAVE_ES256
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef WOLFCOSE_HAVE_EDDSA
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#include <stdio.h>
#include <string.h>

/* ----- Test Macros ----- */
#define PRINT_TEST(name) printf("  Testing: %s... ", (name))
#define CHECK_SHOULD_FAIL(r, name) do {                 \
    if ((r) != 0) {                                     \
        printf("PASS (correctly rejected)\n");          \
        passed++;                                       \
    } else {                                            \
        printf("FAIL (should have been rejected)\n");   \
        failed++;                                       \
    }                                                   \
} while (0)

#define CHECK_RESULT(r, name) do {                      \
    (void)(name);                                       \
    if ((r) == 0) {                                     \
        printf("PASS\n");                               \
        passed++;                                       \
    } else {                                            \
        printf("FAIL (ret=%d)\n", (r));                \
        failed++;                                       \
    }                                                   \
} while (0)

/* ----- Sign1 Tamper Tests ----- */
#ifdef WOLFCOSE_HAVE_ES256
static int test_sign1_tamper(int tamperPos)
{
    int ret = 0;
    ecc_key eccKey;
    int eccInit = 0;
    WOLFCOSE_KEY cosKey;
    WC_RNG rng;
    int rngInit = 0;
    const uint8_t payload[] = "tamper test payload";
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t tampered[512];
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wc_ecc_init(&eccKey);
    }
    if (ret == 0) {
        eccInit = 1;
        ret = wc_ecc_make_key(&rng, 32, &eccKey);
    }
    if (ret == 0) {
        wc_CoseKey_Init(&cosKey);
        ret = wc_CoseKey_SetEcc(&cosKey, WOLFCOSE_CRV_P256, &eccKey);
    }
    if (ret == 0) {
        /* Create valid signature */
        ret = wc_CoseSign1_Sign(&cosKey, WOLFCOSE_ALG_ESP256,
            NULL, 0,
            payload, sizeof(payload) - 1u,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
    }
    if (ret == 0) {
        /* Tamper with message */
        XMEMCPY(tampered, out, outLen);
        if (tamperPos == 0) {
            /* Tamper at first byte */
            tampered[0] ^= 0xFF;
        }
        else if (tamperPos == 1) {
            /* Tamper at middle */
            tampered[outLen / 2u] ^= 0xFF;
        }
        else {
            /* Tamper at last byte */
            tampered[outLen - 1u] ^= 0xFF;
        }

        /* Verify should fail */
        ret = wc_CoseSign1_Verify(&cosKey, tampered, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        if (ret == 0) {
            /* Should have failed */
            ret = -100;
        }
        else {
            /* Reset for success */
            ret = 0;
        }
    }

    /* Cleanup */
    if (eccInit != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_ES256 */

/* ----- Encrypt0 Tamper Tests ----- */
#ifdef WOLFCOSE_HAVE_AESGCM
static int test_encrypt0_tamper(int tamperPos)
{
    int ret = 0;
    WOLFCOSE_KEY cosKey;
    uint8_t keyData[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t iv[12] = {
        0x02, 0xD1, 0xF7, 0xE6, 0xF2, 0x6C, 0x43, 0xD4,
        0x86, 0x8D, 0x87, 0xCE
    };
    const uint8_t payload[] = "tamper test payload";
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t tampered[512];
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;

    wc_CoseKey_Init(&cosKey);
    ret = wc_CoseKey_SetSymmetric(&cosKey, keyData, sizeof(keyData));
    if (ret == 0) {
        /* Encrypt */
        ret = wc_CoseEncrypt0_Encrypt(&cosKey, WOLFCOSE_ALG_A128GCM,
            iv, sizeof(iv),
            payload, sizeof(payload) - 1u,
            NULL, 0, NULL,
            NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen);
    }
    if (ret == 0) {
        /* Tamper with message */
        XMEMCPY(tampered, out, outLen);
        if (tamperPos == 0) {
            tampered[0] ^= 0xFF;
        }
        else if (tamperPos == 1) {
            tampered[outLen / 2u] ^= 0xFF;
        }
        else {
            tampered[outLen - 1u] ^= 0xFF;
        }

        /* Decrypt should fail */
        ret = wc_CoseEncrypt0_Decrypt(&cosKey, tampered, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
        if (ret == 0) {
            ret = -100;
        }
        else {
            ret = 0;
        }
    }

    return ret;
}
#endif /* WOLFCOSE_HAVE_AESGCM */

/* ----- Mac0 Tamper Tests ----- */
#ifdef WOLFCOSE_HAVE_HMAC256
static int test_mac0_tamper(int tamperPos)
{
    int ret = 0;
    WOLFCOSE_KEY cosKey;
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    const uint8_t payload[] = "tamper test payload";
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t tampered[512];
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    wc_CoseKey_Init(&cosKey);
    ret = wc_CoseKey_SetSymmetric(&cosKey, keyData, sizeof(keyData));
    if (ret == 0) {
        /* Create MAC */
        ret = wc_CoseMac0_Create(&cosKey, WOLFCOSE_ALG_HMAC_256_256,
            NULL, 0,
            payload, sizeof(payload) - 1u,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen);
    }
    if (ret == 0) {
        /* Tamper with message */
        XMEMCPY(tampered, out, outLen);
        if (tamperPos == 0) {
            tampered[0] ^= 0xFF;
        }
        else if (tamperPos == 1) {
            tampered[outLen / 2u] ^= 0xFF;
        }
        else {
            tampered[outLen - 1u] ^= 0xFF;
        }

        /* Verify should fail */
        ret = wc_CoseMac0_Verify(&cosKey, tampered, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        if (ret == 0) {
            ret = -100;
        }
        else {
            ret = 0;
        }
    }

    return ret;
}
#endif /* WOLFCOSE_HAVE_HMAC256 */

/* ----- Truncated Input Tests ----- */
#ifdef WOLFCOSE_HAVE_ES256
static int test_sign1_truncated(void)
{
    int ret = 0;
    ecc_key eccKey;
    int eccInit = 0;
    WOLFCOSE_KEY cosKey;
    WC_RNG rng;
    int rngInit = 0;
    const uint8_t payload[] = "truncation test payload";
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wc_ecc_init(&eccKey);
    }
    if (ret == 0) {
        eccInit = 1;
        ret = wc_ecc_make_key(&rng, 32, &eccKey);
    }
    if (ret == 0) {
        wc_CoseKey_Init(&cosKey);
        ret = wc_CoseKey_SetEcc(&cosKey, WOLFCOSE_CRV_P256, &eccKey);
    }
    if (ret == 0) {
        /* Create valid message */
        ret = wc_CoseSign1_Sign(&cosKey, WOLFCOSE_ALG_ESP256,
            NULL, 0,
            payload, sizeof(payload) - 1u,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
    }
    if (ret == 0) {
        /* Truncate to half and verify - should fail */
        ret = wc_CoseSign1_Verify(&cosKey, out, outLen / 2u,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        if (ret == 0) {
            ret = -100;
        }
        else {
            ret = 0;
        }
    }

    /* Cleanup */
    if (eccInit != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_ES256 */

#ifdef WOLFCOSE_HAVE_AESGCM
static int test_encrypt0_truncated(void)
{
    int ret = 0;
    WOLFCOSE_KEY cosKey;
    uint8_t keyData[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t iv[12] = {
        0x02, 0xD1, 0xF7, 0xE6, 0xF2, 0x6C, 0x43, 0xD4,
        0x86, 0x8D, 0x87, 0xCE
    };
    const uint8_t payload[] = "truncation test payload";
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;

    wc_CoseKey_Init(&cosKey);
    ret = wc_CoseKey_SetSymmetric(&cosKey, keyData, sizeof(keyData));
    if (ret == 0) {
        /* Encrypt */
        ret = wc_CoseEncrypt0_Encrypt(&cosKey, WOLFCOSE_ALG_A128GCM,
            iv, sizeof(iv),
            payload, sizeof(payload) - 1u,
            NULL, 0, NULL,
            NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen);
    }
    if (ret == 0) {
        /* Truncate and decrypt - should fail */
        ret = wc_CoseEncrypt0_Decrypt(&cosKey, out, outLen / 2u,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
        if (ret == 0) {
            ret = -100;
        }
        else {
            ret = 0;
        }
    }

    return ret;
}
#endif /* WOLFCOSE_HAVE_AESGCM */

#ifdef WOLFCOSE_HAVE_HMAC256
static int test_mac0_truncated(void)
{
    int ret = 0;
    WOLFCOSE_KEY cosKey;
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    const uint8_t payload[] = "truncation test payload";
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    wc_CoseKey_Init(&cosKey);
    ret = wc_CoseKey_SetSymmetric(&cosKey, keyData, sizeof(keyData));
    if (ret == 0) {
        /* Create MAC */
        ret = wc_CoseMac0_Create(&cosKey, WOLFCOSE_ALG_HMAC_256_256,
            NULL, 0,
            payload, sizeof(payload) - 1u,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen);
    }
    if (ret == 0) {
        /* Truncate and verify - should fail */
        ret = wc_CoseMac0_Verify(&cosKey, out, outLen / 2u,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        if (ret == 0) {
            ret = -100;
        }
        else {
            ret = 0;
        }
    }

    return ret;
}
#endif /* WOLFCOSE_HAVE_HMAC256 */

/* ----- AAD Mismatch Tests ----- */
#ifdef WOLFCOSE_HAVE_ES256
static int test_sign1_aad_mismatch(void)
{
    int ret = 0;
    ecc_key eccKey;
    int eccInit = 0;
    WOLFCOSE_KEY cosKey;
    WC_RNG rng;
    int rngInit = 0;
    const uint8_t payload[] = "AAD mismatch test";
    const uint8_t aad[] = "correct aad";
    const uint8_t wrongAad[] = "wrong aad";
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wc_ecc_init(&eccKey);
    }
    if (ret == 0) {
        eccInit = 1;
        ret = wc_ecc_make_key(&rng, 32, &eccKey);
    }
    if (ret == 0) {
        wc_CoseKey_Init(&cosKey);
        ret = wc_CoseKey_SetEcc(&cosKey, WOLFCOSE_CRV_P256, &eccKey);
    }
    if (ret == 0) {
        /* Sign with AAD */
        ret = wc_CoseSign1_Sign(&cosKey, WOLFCOSE_ALG_ESP256,
            NULL, 0,
            payload, sizeof(payload) - 1u,
            NULL, 0,
            aad, sizeof(aad) - 1u,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
    }
    if (ret == 0) {
        /* Verify with wrong AAD - should fail */
        ret = wc_CoseSign1_Verify(&cosKey, out, outLen,
            NULL, 0,
            wrongAad, sizeof(wrongAad) - 1u,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        if (ret == 0) {
            ret = -100;
        }
        else {
            ret = 0;
        }
    }

    /* Cleanup */
    if (eccInit != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_ES256 */

#ifdef WOLFCOSE_HAVE_AESGCM
static int test_encrypt0_aad_mismatch(void)
{
    int ret = 0;
    WOLFCOSE_KEY cosKey;
    uint8_t keyData[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t iv[12] = {
        0x02, 0xD1, 0xF7, 0xE6, 0xF2, 0x6C, 0x43, 0xD4,
        0x86, 0x8D, 0x87, 0xCE
    };
    const uint8_t payload[] = "AAD mismatch test";
    const uint8_t aad[] = "correct aad";
    const uint8_t wrongAad[] = "wrong aad";
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;

    wc_CoseKey_Init(&cosKey);
    ret = wc_CoseKey_SetSymmetric(&cosKey, keyData, sizeof(keyData));
    if (ret == 0) {
        /* Encrypt with AAD */
        ret = wc_CoseEncrypt0_Encrypt(&cosKey, WOLFCOSE_ALG_A128GCM,
            iv, sizeof(iv),
            payload, sizeof(payload) - 1u,
            NULL, 0, NULL,
            aad, sizeof(aad) - 1u,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen);
    }
    if (ret == 0) {
        /* Decrypt with wrong AAD - should fail */
        ret = wc_CoseEncrypt0_Decrypt(&cosKey, out, outLen,
            NULL, 0,
            wrongAad, sizeof(wrongAad) - 1u,
            scratch, sizeof(scratch),
            &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
        if (ret == 0) {
            ret = -100;
        }
        else {
            ret = 0;
        }
    }

    return ret;
}
#endif /* WOLFCOSE_HAVE_AESGCM */

#ifdef WOLFCOSE_HAVE_HMAC256
static int test_mac0_aad_mismatch(void)
{
    int ret = 0;
    WOLFCOSE_KEY cosKey;
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    const uint8_t payload[] = "AAD mismatch test";
    const uint8_t aad[] = "correct aad";
    const uint8_t wrongAad[] = "wrong aad";
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    wc_CoseKey_Init(&cosKey);
    ret = wc_CoseKey_SetSymmetric(&cosKey, keyData, sizeof(keyData));
    if (ret == 0) {
        /* Create MAC with AAD */
        ret = wc_CoseMac0_Create(&cosKey, WOLFCOSE_ALG_HMAC_256_256,
            NULL, 0,
            payload, sizeof(payload) - 1u,
            NULL, 0,
            aad, sizeof(aad) - 1u,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen);
    }
    if (ret == 0) {
        /* Verify with wrong AAD - should fail */
        ret = wc_CoseMac0_Verify(&cosKey, out, outLen,
            NULL, 0,
            wrongAad, sizeof(wrongAad) - 1u,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        if (ret == 0) {
            ret = -100;
        }
        else {
            ret = 0;
        }
    }

    return ret;
}
#endif /* WOLFCOSE_HAVE_HMAC256 */

/* ----- Detached Payload Missing Tests ----- */
#ifdef WOLFCOSE_HAVE_ES256
static int test_sign1_detached_missing(void)
{
    int ret = 0;
    ecc_key eccKey;
    int eccInit = 0;
    WOLFCOSE_KEY cosKey;
    WC_RNG rng;
    int rngInit = 0;
    const uint8_t payload[] = "detached payload";
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wc_ecc_init(&eccKey);
    }
    if (ret == 0) {
        eccInit = 1;
        ret = wc_ecc_make_key(&rng, 32, &eccKey);
    }
    if (ret == 0) {
        wc_CoseKey_Init(&cosKey);
        ret = wc_CoseKey_SetEcc(&cosKey, WOLFCOSE_CRV_P256, &eccKey);
    }
    if (ret == 0) {
        /* Sign with detached payload */
        ret = wc_CoseSign1_Sign(&cosKey, WOLFCOSE_ALG_ESP256,
            NULL, 0,
            NULL, 0,  /* no inline payload */
            payload, sizeof(payload) - 1u,  /* detached */
            NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
    }
    if (ret == 0) {
        /* Verify without providing detached payload - should fail */
        ret = wc_CoseSign1_Verify(&cosKey, out, outLen,
            NULL, 0,  /* missing detached payload */
            NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        if (ret == 0) {
            ret = -100;
        }
        else {
            ret = 0;
        }
    }

    /* Cleanup */
    if (eccInit != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_ES256 */

/* ----- Wrong Key Type Tests ----- */
#ifdef WOLFCOSE_HAVE_ES256
static int test_sign1_with_symmetric_key(void)
{
    int ret = 0;
    WOLFCOSE_KEY cosKey;
    WC_RNG rng;
    int rngInit = 0;
    uint8_t keyData[32] = {0};
    const uint8_t payload[] = "wrong key type test";
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        /* Try to sign with a symmetric key */
        wc_CoseKey_Init(&cosKey);
        ret = wc_CoseKey_SetSymmetric(&cosKey, keyData, sizeof(keyData));
    }
    if (ret == 0) {
        ret = wc_CoseSign1_Sign(&cosKey, WOLFCOSE_ALG_ESP256,
            NULL, 0,
            payload, sizeof(payload) - 1u,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        if (ret == 0) {
            ret = -100;
        }
        else {
            ret = 0;
        }
    }

    /* Cleanup */
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_ES256 */

#if defined(WOLFCOSE_HAVE_ES256) && defined(WOLFCOSE_HAVE_AESGCM)
static int test_encrypt0_with_signing_key(void)
{
    int ret = 0;
    ecc_key eccKey;
    int eccInit = 0;
    WOLFCOSE_KEY cosKey;
    WC_RNG rng;
    int rngInit = 0;
    uint8_t iv[12] = {
        0x02, 0xD1, 0xF7, 0xE6, 0xF2, 0x6C, 0x43, 0xD4,
        0x86, 0x8D, 0x87, 0xCE
    };
    const uint8_t payload[] = "wrong key type test";
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wc_ecc_init(&eccKey);
    }
    if (ret == 0) {
        eccInit = 1;
        ret = wc_ecc_make_key(&rng, 32, &eccKey);
    }
    if (ret == 0) {
        /* Try to encrypt with an ECC key (wrong type) */
        wc_CoseKey_Init(&cosKey);
        ret = wc_CoseKey_SetEcc(&cosKey, WOLFCOSE_CRV_P256, &eccKey);
    }
    if (ret == 0) {
        ret = wc_CoseEncrypt0_Encrypt(&cosKey, WOLFCOSE_ALG_A128GCM,
            iv, sizeof(iv),
            payload, sizeof(payload) - 1u,
            NULL, 0, NULL,
            NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen);
        if (ret == 0) {
            ret = -100;
        }
        else {
            ret = 0;
        }
    }

    /* Cleanup */
    if (eccInit != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_ES256 && WOLFCOSE_HAVE_AESGCM */

/* ----- Empty Payload Tests ----- */
#ifdef WOLFCOSE_HAVE_ES256
static int test_sign1_empty_payload(void)
{
    int ret = 0;
    ecc_key eccKey;
    int eccInit = 0;
    WOLFCOSE_KEY cosKey;
    WC_RNG rng;
    int rngInit = 0;
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wc_ecc_init(&eccKey);
    }
    if (ret == 0) {
        eccInit = 1;
        ret = wc_ecc_make_key(&rng, 32, &eccKey);
    }
    if (ret == 0) {
        wc_CoseKey_Init(&cosKey);
        ret = wc_CoseKey_SetEcc(&cosKey, WOLFCOSE_CRV_P256, &eccKey);
    }
    if (ret == 0) {
        /* Sign empty payload (edge case, should work) */
        ret = wc_CoseSign1_Sign(&cosKey, WOLFCOSE_ALG_ESP256,
            NULL, 0,
            (const uint8_t*)"", 0,  /* empty payload */
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
    }
    if (ret == 0) {
        /* Verify */
        ret = wc_CoseSign1_Verify(&cosKey, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
    }
    if (ret == 0) {
        /* Empty payload expected */
        if (decPayloadLen != 0u) {
            ret = -101;
        }
    }

    /* Cleanup */
    if (eccInit != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_ES256 */

/* ----- Error Test Runners ----- */
#if defined(WOLFCOSE_HAVE_ES256) && !defined(WOLFCOSE_NO_ERRORS_ALL_SIGN)
static int test_sign_errors_all(void)
{
    int ret = 0;
    int passed = 0;
    int failed = 0;

    printf("\n=== Sign1 Error Tests ===\n\n");

    /* Tamper tests */
    PRINT_TEST("sign1_tamper_first_byte");
    ret = test_sign1_tamper(0);
    CHECK_RESULT(ret, "sign1_tamper_first_byte");

    PRINT_TEST("sign1_tamper_middle_byte");
    ret = test_sign1_tamper(1);
    CHECK_RESULT(ret, "sign1_tamper_middle_byte");

    PRINT_TEST("sign1_tamper_last_byte");
    ret = test_sign1_tamper(2);
    CHECK_RESULT(ret, "sign1_tamper_last_byte");

    /* Truncation test */
    PRINT_TEST("sign1_truncated_input");
    ret = test_sign1_truncated();
    CHECK_RESULT(ret, "sign1_truncated_input");

    /* AAD mismatch */
    PRINT_TEST("sign1_aad_mismatch");
    ret = test_sign1_aad_mismatch();
    CHECK_RESULT(ret, "sign1_aad_mismatch");

    /* Detached payload missing */
    PRINT_TEST("sign1_detached_missing");
    ret = test_sign1_detached_missing();
    CHECK_RESULT(ret, "sign1_detached_missing");

    /* Wrong key type */
    PRINT_TEST("sign1_with_symmetric_key");
    ret = test_sign1_with_symmetric_key();
    CHECK_RESULT(ret, "sign1_with_symmetric_key");

    /* Empty payload (edge case) */
    PRINT_TEST("sign1_empty_payload");
    ret = test_sign1_empty_payload();
    CHECK_RESULT(ret, "sign1_empty_payload");

    printf("\nSign1 Error Summary: %d passed, %d failed\n", passed, failed);
    return failed;
}
#endif /* WOLFCOSE_HAVE_ES256 && !WOLFCOSE_NO_ERRORS_ALL_SIGN */

#if defined(WOLFCOSE_HAVE_AESGCM) && !defined(WOLFCOSE_NO_ERRORS_ALL_ENCRYPT)
static int test_encrypt_errors_all(void)
{
    int ret = 0;
    int passed = 0;
    int failed = 0;

    printf("\n=== Encrypt0 Error Tests ===\n\n");

    /* Tamper tests */
    PRINT_TEST("encrypt0_tamper_first_byte");
    ret = test_encrypt0_tamper(0);
    CHECK_RESULT(ret, "encrypt0_tamper_first_byte");

    PRINT_TEST("encrypt0_tamper_middle_byte");
    ret = test_encrypt0_tamper(1);
    CHECK_RESULT(ret, "encrypt0_tamper_middle_byte");

    PRINT_TEST("encrypt0_tamper_last_byte");
    ret = test_encrypt0_tamper(2);
    CHECK_RESULT(ret, "encrypt0_tamper_last_byte");

    /* Truncation test */
    PRINT_TEST("encrypt0_truncated_input");
    ret = test_encrypt0_truncated();
    CHECK_RESULT(ret, "encrypt0_truncated_input");

    /* AAD mismatch */
    PRINT_TEST("encrypt0_aad_mismatch");
    ret = test_encrypt0_aad_mismatch();
    CHECK_RESULT(ret, "encrypt0_aad_mismatch");

#ifdef WOLFCOSE_HAVE_ES256
    /* Wrong key type */
    PRINT_TEST("encrypt0_with_signing_key");
    ret = test_encrypt0_with_signing_key();
    CHECK_RESULT(ret, "encrypt0_with_signing_key");
#endif

    printf("\nEncrypt0 Error Summary: %d passed, %d failed\n", passed, failed);
    return failed;
}
#endif /* WOLFCOSE_HAVE_AESGCM && !WOLFCOSE_NO_ERRORS_ALL_ENCRYPT */

#if defined(WOLFCOSE_HAVE_HMAC256) && !defined(WOLFCOSE_NO_ERRORS_ALL_MAC)
static int test_mac_errors_all(void)
{
    int ret = 0;
    int passed = 0;
    int failed = 0;

    printf("\n=== Mac0 Error Tests ===\n\n");

    /* Tamper tests */
    PRINT_TEST("mac0_tamper_first_byte");
    ret = test_mac0_tamper(0);
    CHECK_RESULT(ret, "mac0_tamper_first_byte");

    PRINT_TEST("mac0_tamper_middle_byte");
    ret = test_mac0_tamper(1);
    CHECK_RESULT(ret, "mac0_tamper_middle_byte");

    PRINT_TEST("mac0_tamper_last_byte");
    ret = test_mac0_tamper(2);
    CHECK_RESULT(ret, "mac0_tamper_last_byte");

    /* Truncation test */
    PRINT_TEST("mac0_truncated_input");
    ret = test_mac0_truncated();
    CHECK_RESULT(ret, "mac0_truncated_input");

    /* AAD mismatch */
    PRINT_TEST("mac0_aad_mismatch");
    ret = test_mac0_aad_mismatch();
    CHECK_RESULT(ret, "mac0_aad_mismatch");

    printf("\nMac0 Error Summary: %d passed, %d failed\n", passed, failed);
    return failed;
}
#endif /* WOLFCOSE_HAVE_HMAC256 && !WOLFCOSE_NO_ERRORS_ALL_MAC */

/* ----- Main Entry Point ----- */
int main(void)
{
    int totalFailed = 0;

    printf("========================================\n");
    printf("wolfCOSE Comprehensive Error Tests\n");
    printf("========================================\n");

#if defined(WOLFCOSE_HAVE_ES256) && !defined(WOLFCOSE_NO_ERRORS_ALL_SIGN)
    totalFailed += test_sign_errors_all();
#endif

#if defined(WOLFCOSE_HAVE_AESGCM) && !defined(WOLFCOSE_NO_ERRORS_ALL_ENCRYPT)
    totalFailed += test_encrypt_errors_all();
#endif

#if defined(WOLFCOSE_HAVE_HMAC256) && !defined(WOLFCOSE_NO_ERRORS_ALL_MAC)
    totalFailed += test_mac_errors_all();
#endif

    printf("\n========================================\n");
    printf("Total: %d failures\n", totalFailed);
    printf("========================================\n");

    return totalFailed;
}

#else /* !WOLFCOSE_EXAMPLE_ERRORS_ALL */

int main(void)
{
    printf("errors_all: example disabled (WOLFCOSE_NO_EXAMPLE_ERRORS_ALL defined)\n");
    return 0;
}

#endif /* WOLFCOSE_EXAMPLE_ERRORS_ALL */
