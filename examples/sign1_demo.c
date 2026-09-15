/* sign1_demo.c
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

/* Comprehensive COSE_Sign1 demonstration
 * Tests all signature algorithms: ES256, ES384, ES512, EdDSA
 */

#include <stdio.h>
#include <string.h>
#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/random.h>

#define DEMO_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s\n", (msg)); \
        return -1; \
    } \
} while(0)

/* All buffers on stack - no dynamic allocation */
#ifdef WOLFCOSE_HAVE_ES256
static int demo_sign1_es256(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    const uint8_t payload[] ="ESP256 test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Sign1 ESP256 (P-256) ---\n");
    printf("  Payload: \"%s\" (%zu bytes)\n", payload, sizeof(payload) - 1u);

    ret = wc_InitRng(&rng);
    DEMO_ASSERT(ret == 0, "Init RNG");

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    DEMO_ASSERT(ret == 0, "Generate P-256 key");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);
    DEMO_ASSERT(ret == 0, "Set ECC key");

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ESP256,
        NULL, 0,                           /* kid, kidLen */
        payload, sizeof(payload) - 1u,      /* payload, payloadLen */
        NULL, 0,                           /* detachedPayload, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    DEMO_ASSERT(ret == 0, "Sign");
    printf("  COSE_Sign1: %zu bytes\n", outLen);

    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0,                           /* detachedPayload, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify");
    DEMO_ASSERT(decPayloadLen == sizeof(payload) - 1u, "Payload length");
    DEMO_ASSERT(memcmp(decPayload, payload, decPayloadLen) == 0, "Payload match");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_ESP256, "Algorithm");

    (void)wc_ecc_free(&eccKey);
    (void)wc_FreeRng(&rng);
    printf("  Result: PASS\n");
    return 0;
}

#ifdef WOLFCOSE_HAVE_ES384
static int demo_sign1_es384(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    const uint8_t payload[] ="ESP384 test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Sign1 ESP384 (P-384) ---\n");
    printf("  Payload: \"%s\" (%zu bytes)\n", payload, sizeof(payload) - 1u);

    ret = wc_InitRng(&rng);
    DEMO_ASSERT(ret == 0, "Init RNG");

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 48, &eccKey);
    DEMO_ASSERT(ret == 0, "Generate P-384 key");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P384, &eccKey);
    DEMO_ASSERT(ret == 0, "Set ECC key");

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ESP384,
        NULL, 0,                           /* kid, kidLen */
        payload, sizeof(payload) - 1u,      /* payload, payloadLen */
        NULL, 0,                           /* detachedPayload, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    DEMO_ASSERT(ret == 0, "Sign");
    printf("  COSE_Sign1: %zu bytes\n", outLen);

    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0,                           /* detachedPayload, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_ESP384, "Algorithm");

    (void)wc_ecc_free(&eccKey);
    (void)wc_FreeRng(&rng);
    printf("  Result: PASS\n");
    return 0;
}
#endif

#ifdef WOLFCOSE_HAVE_ES512
static int demo_sign1_es512(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    const uint8_t payload[] ="ESP512 test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[640];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Sign1 ESP512 (P-521) ---\n");
    printf("  Payload: \"%s\" (%zu bytes)\n", payload, sizeof(payload) - 1u);

    ret = wc_InitRng(&rng);
    DEMO_ASSERT(ret == 0, "Init RNG");

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 66, &eccKey);
    DEMO_ASSERT(ret == 0, "Generate P-521 key");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P521, &eccKey);
    DEMO_ASSERT(ret == 0, "Set ECC key");

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ESP512,
        NULL, 0,                           /* kid, kidLen */
        payload, sizeof(payload) - 1u,      /* payload, payloadLen */
        NULL, 0,                           /* detachedPayload, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    DEMO_ASSERT(ret == 0, "Sign");
    printf("  COSE_Sign1: %zu bytes\n", outLen);

    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0,                           /* detachedPayload, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_ESP512, "Algorithm");

    (void)wc_ecc_free(&eccKey);
    (void)wc_FreeRng(&rng);
    printf("  Result: PASS\n");
    return 0;
}
#endif

static int demo_sign1_with_aad(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    const uint8_t payload[] ="Payload with AAD";
    const uint8_t aad[] ="Additional authenticated data";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    static const uint8_t wrongAad[] = {
        0x57u, 0x72u, 0x6Fu, 0x6Eu, 0x67u, 0x20u, 0x41u, 0x41u, 0x44u
    };
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Sign1 with External AAD ---\n");
    printf("  Payload: \"%s\"\n", payload);
    printf("  AAD: \"%s\"\n", aad);

    ret = wc_InitRng(&rng);
    DEMO_ASSERT(ret == 0, "Init RNG");

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    DEMO_ASSERT(ret == 0, "Generate key");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);
    DEMO_ASSERT(ret == 0, "Set ECC key");

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ESP256,
        NULL, 0,                           /* kid, kidLen */
        payload, sizeof(payload) - 1u,      /* payload, payloadLen */
        NULL, 0,                           /* detachedPayload, detachedLen */
        aad, sizeof(aad) - 1u,             /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    DEMO_ASSERT(ret == 0, "Sign with AAD");
    printf("  COSE_Sign1: %zu bytes\n", outLen);

    /* Verify with correct AAD */
    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0,                           /* detachedPayload, detachedLen */
        aad, sizeof(aad) - 1u,             /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify with correct AAD");

    /* Verify wrong AAD fails */
    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0,                           /* detachedPayload, detachedLen */
        wrongAad, sizeof(wrongAad) - 1u,   /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret != 0, "Wrong AAD rejected");

    (void)wc_ecc_free(&eccKey);
    (void)wc_FreeRng(&rng);
    printf("  Result: PASS\n");
    return 0;
}
#endif /* WOLFCOSE_HAVE_ES256 */

#ifdef WOLFCOSE_HAVE_EDDSA
static int demo_sign1_eddsa(void)
{
    WOLFCOSE_KEY key;
    ed25519_key edKey;
    WC_RNG rng;
    const uint8_t payload[] ="Ed25519 test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Sign1 Ed25519 ---\n");
    printf("  Payload: \"%s\" (%zu bytes)\n", payload, sizeof(payload) - 1u);

    ret = wc_InitRng(&rng);
    DEMO_ASSERT(ret == 0, "Init RNG");

    wc_ed25519_init(&edKey);
    ret = wc_ed25519_make_key(&rng, 32, &edKey);
    DEMO_ASSERT(ret == 0, "Generate Ed25519 key");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetEd25519(&key, &edKey);
    DEMO_ASSERT(ret == 0, "Set Ed25519 key");

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ED25519,
        NULL, 0,                           /* kid, kidLen */
        payload, sizeof(payload) - 1u,      /* payload, payloadLen */
        NULL, 0,                           /* detachedPayload, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    DEMO_ASSERT(ret == 0, "Sign");
    printf("  COSE_Sign1: %zu bytes\n", outLen);

    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0,                           /* detachedPayload, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_ED25519, "Algorithm");

    (void)wc_ed25519_free(&edKey);
    (void)wc_FreeRng(&rng);
    printf("  Result: PASS\n");
    return 0;
}
#endif

int main(void)
{
    int failures = 0;

    printf("=== wolfCOSE Sign1 Demo ===\n\n");

#ifdef WOLFCOSE_HAVE_ES256
    if (demo_sign1_es256() != 0) {
        failures++;
    }
#ifdef WOLFCOSE_HAVE_ES384
    if (demo_sign1_es384() != 0) {
        failures++;
    }
#endif
#ifdef WOLFCOSE_HAVE_ES512
    if (demo_sign1_es512() != 0) {
        failures++;
    }
#endif
    if (demo_sign1_with_aad() != 0) {
        failures++;
    }
#endif

#ifdef WOLFCOSE_HAVE_EDDSA
    if (demo_sign1_eddsa() != 0) {
        failures++;
    }
#endif

    printf("\n=== Results: %d failure(s) ===\n", failures);
    return failures;
}
