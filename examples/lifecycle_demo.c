/* lifecycle_demo.c
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
 * lifecycle_demo.c -- Edge-to-Cloud COSE Lifecycle Demo
 *
 * Simulates a produce -> transport -> consume lifecycle for all COSE
 * message types:
 *
 *   COSE_Sign1:    ES256, EdDSA, PS256, ML-DSA-44
 *   COSE_Encrypt0: A128GCM, A256GCM, ChaCha20, AES-CCM
 *   COSE_Mac0:     HMAC256, HMAC384, HMAC512
 *
 * Usage:
 *   ./lifecycle_demo              Run all available algorithms
 *   ./lifecycle_demo -a ES256     Run only ES256
 *   ./lifecycle_demo -a HMAC256   Run only HMAC-256
 *   ./lifecycle_demo -a all       Run all available algorithms
 *
 * Goal: prove full COSE security lifecycle with minimal RAM
 *       (ECC/EdDSA/AEAD fit in <1KB; ML-DSA requires larger buffers).
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/random.h>
#ifdef WOLFCOSE_HAVE_ES256
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef WOLFCOSE_HAVE_EDDSA
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef WOLFCOSE_HAVE_RSAPSS
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef WOLFCOSE_HAVE_MLDSA
    #include <wolfssl/wolfcrypt/wc_mldsa.h>
#endif
#include <stdio.h>
#include <string.h>

/* Stack measurement via GCC builtin */
#ifdef __GNUC__
    #define STACK_MARKER()  ((size_t)__builtin_frame_address(0))
#else
    #define STACK_MARKER()  ((size_t)0u)
#endif

static const uint8_t g_kid[] = "edge-sensor-01";

/* ----- Shared: CBOR-encode sensor payload ----- */
static int encode_sensor_payload(uint8_t* payload, size_t payloadSz,
                                  size_t* payloadLen)
{
    int ret;
    WOLFCOSE_CBOR_CTX cbor;

    ret = wc_CBOR_EncoderInit(&cbor, payload, payloadSz);

    /* {"temp": 22, "humidity": 45} */
    if (ret == 0) {
        ret = wc_CBOR_EncodeMapStart(&cbor, 2);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeTstr(&cbor, (const uint8_t*)"temp", 4);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&cbor, 22);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeTstr(&cbor, (const uint8_t*)"humidity", 8);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&cbor, 45);
    }
    if (ret == 0) {
        *payloadLen = cbor.idx;
    }
    return ret;
}

/* ----- COSE_Sign1 lifecycle: ES256 ----- */
#ifdef WOLFCOSE_HAVE_ES256
static int demo_sign1_es256(void)
{
    int ret = 0;
    ecc_key eccKey;
    WOLFCOSE_KEY signKey;
    WOLFCOSE_KEY verifyKey;
    WC_RNG rng;
    uint8_t payload[64];
    size_t payloadLen = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t packet[512];
    size_t packetLen = 0;
    WOLFCOSE_HDR hdr;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    int rngInited = 0;
    int eccInited = 0;

    printf("--- COSE_Sign1 ES256 ---\n");

    ret = encode_sensor_payload(payload, sizeof(payload), &payloadLen);
    if (ret != 0) {
        printf("  CBOR encode failed: %d\n", ret);
    }
    if (ret == 0) {
        printf("  [Producer] Sensor payload: %zu bytes\n", payloadLen);
        ret = wc_InitRng(&rng);
        if (ret == 0) {
            rngInited = 1;
        }
    }
    if (ret == 0) {
        wc_ecc_init(&eccKey);
        eccInited = 1;
        ret = wc_ecc_make_key(&rng, 32, &eccKey);
        if (ret != 0) {
            printf("  ECC keygen failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        wc_CoseKey_SetEcc(&signKey, WOLFCOSE_CRV_P256, &eccKey);

        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_ES256,
            g_kid, sizeof(g_kid) - 1u,
            payload, payloadLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            packet, sizeof(packet), &packetLen, &rng);
        if (ret != 0) {
            printf("  Sign failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        printf("  [Producer] COSE_Sign1: %zu bytes\n", packetLen);

        wc_CoseKey_Init(&verifyKey);
        wc_CoseKey_SetEcc(&verifyKey, WOLFCOSE_CRV_P256, &eccKey);

        ret = wc_CoseSign1_Verify(&verifyKey, packet, packetLen,
            NULL, 0, NULL, 0, scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        if (ret != 0) {
            printf("  Verify FAILED: %d\n", ret);
        }
        else {
            printf("  [Consumer] Verified OK, payload: %zu bytes, alg: %d\n",
                   decPayloadLen, hdr.alg);
        }
    }

    if (eccInited != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
    printf("  Result: %s\n\n", (ret == 0) ? "PASS" : "FAIL");

    return ret;
}
#endif /* WOLFCOSE_HAVE_ES256 */

/* ----- COSE_Sign1 lifecycle: EdDSA (Ed25519) ----- */
#ifdef WOLFCOSE_HAVE_EDDSA
static int demo_sign1_eddsa(void)
{
    int ret = 0;
    ed25519_key edKey;
    WOLFCOSE_KEY signKey;
    WC_RNG rng;
    uint8_t payload[64];
    size_t payloadLen = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t packet[512];
    size_t packetLen = 0;
    WOLFCOSE_HDR hdr;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    int rngInited = 0;
    int edInited = 0;

    printf("--- COSE_Sign1 EdDSA (Ed25519) ---\n");

    ret = encode_sensor_payload(payload, sizeof(payload), &payloadLen);
    if (ret == 0) {
        printf("  [Producer] Sensor payload: %zu bytes\n", payloadLen);
        ret = wc_InitRng(&rng);
        if (ret == 0) {
            rngInited = 1;
        }
    }
    if (ret == 0) {
        wc_ed25519_init(&edKey);
        edInited = 1;
        ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &edKey);
        if (ret != 0) {
            printf("  Ed25519 keygen failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        wc_CoseKey_SetEd25519(&signKey, &edKey);

        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_EDDSA,
            g_kid, sizeof(g_kid) - 1u,
            payload, payloadLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            packet, sizeof(packet), &packetLen, &rng);
        if (ret != 0) {
            printf("  Sign failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        printf("  [Producer] COSE_Sign1: %zu bytes\n", packetLen);

        ret = wc_CoseSign1_Verify(&signKey, packet, packetLen,
            NULL, 0, NULL, 0, scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        if (ret != 0) {
            printf("  Verify FAILED: %d\n", ret);
        }
        else {
            printf("  [Consumer] Verified OK, payload: %zu bytes, alg: %d\n",
                   decPayloadLen, hdr.alg);
        }
    }

    if (edInited != 0) {
        wc_ed25519_free(&edKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
    printf("  Result: %s\n\n", (ret == 0) ? "PASS" : "FAIL");

    return ret;
}
#endif /* WOLFCOSE_HAVE_EDDSA */

/* ----- COSE_Sign1 lifecycle: RSA-PSS (PS256) ----- */
#if defined(WOLFCOSE_HAVE_RSAPSS) && defined(WOLFSSL_KEY_GEN)
static int demo_sign1_ps256(void)
{
    int ret = 0;
    RsaKey rsaKey;
    WOLFCOSE_KEY signKey;
    WC_RNG rng;
    uint8_t payload[64];
    size_t payloadLen = 0;
    uint8_t scratch[1024];
    uint8_t packet[1024];
    size_t packetLen = 0;
    WOLFCOSE_HDR hdr;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    int rngInited = 0;
    int rsaInited = 0;

    printf("--- COSE_Sign1 PS256 (RSA-PSS) ---\n");

    ret = encode_sensor_payload(payload, sizeof(payload), &payloadLen);
    if (ret == 0) {
        printf("  [Producer] Sensor payload: %zu bytes\n", payloadLen);
        ret = wc_InitRng(&rng);
        if (ret == 0) {
            rngInited = 1;
        }
    }
    if (ret == 0) {
        ret = wc_InitRsaKey(&rsaKey, NULL);
        if (ret == 0) {
            rsaInited = 1;
        }
    }
    if (ret == 0) {
        ret = wc_MakeRsaKey(&rsaKey, 2048, WC_RSA_EXPONENT, &rng);
        if (ret != 0) {
            printf("  RSA keygen failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        wc_CoseKey_SetRsa(&signKey, &rsaKey);

        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_PS256,
            g_kid, sizeof(g_kid) - 1u,
            payload, payloadLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            packet, sizeof(packet), &packetLen, &rng);
        if (ret != 0) {
            printf("  Sign failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        printf("  [Producer] COSE_Sign1: %zu bytes\n", packetLen);

        ret = wc_CoseSign1_Verify(&signKey, packet, packetLen,
            NULL, 0, NULL, 0, scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        if (ret != 0) {
            printf("  Verify FAILED: %d\n", ret);
        }
        else {
            printf("  [Consumer] Verified OK, payload: %zu bytes, alg: %d\n",
                   decPayloadLen, hdr.alg);
        }
    }

    if (rsaInited != 0) {
        wc_FreeRsaKey(&rsaKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
    printf("  Result: %s\n\n", (ret == 0) ? "PASS" : "FAIL");

    return ret;
}
#endif /* WOLFCOSE_HAVE_RSAPSS && WOLFSSL_KEY_GEN */

/* ----- COSE_Sign1 lifecycle: ML-DSA-44 ----- */
#ifdef WOLFCOSE_HAVE_MLDSA
static int demo_sign1_ml_dsa_44(void)
{
    int ret = 0;
    wc_MlDsaKey dlKey;
    WOLFCOSE_KEY signKey;
    WC_RNG rng;
    uint8_t payload[64];
    size_t payloadLen = 0;
    uint8_t scratch[8192];
    uint8_t packet[8192];
    size_t packetLen = 0;
    WOLFCOSE_HDR hdr;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    int rngInited = 0;
    int dlInited = 0;

    printf("--- COSE_Sign1 ML-DSA-44 (PQC) ---\n");

    ret = encode_sensor_payload(payload, sizeof(payload), &payloadLen);
    if (ret == 0) {
        printf("  [Producer] Sensor payload: %zu bytes\n", payloadLen);
        ret = wc_InitRng(&rng);
        if (ret == 0) {
            rngInited = 1;
        }
    }
    if (ret == 0) {
        ret = wc_MlDsaKey_Init(&dlKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            dlInited = 1;
        }
    }
    if (ret == 0) {
        ret = wc_MlDsaKey_SetParams(&dlKey, WC_ML_DSA_44);
    }
    if (ret == 0) {
        ret = wc_MlDsaKey_MakeKey(&dlKey, &rng);
        if (ret != 0) {
            printf("  ML-DSA keygen failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        wc_CoseKey_SetMlDsa(&signKey, WOLFCOSE_ALG_ML_DSA_44, &dlKey);

        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_ML_DSA_44,
            g_kid, sizeof(g_kid) - 1u,
            payload, payloadLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            packet, sizeof(packet), &packetLen, &rng);
        if (ret != 0) {
            printf("  Sign failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        printf("  [Producer] COSE_Sign1: %zu bytes\n", packetLen);

        ret = wc_CoseSign1_Verify(&signKey, packet, packetLen,
            NULL, 0, NULL, 0, scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        if (ret != 0) {
            printf("  Verify FAILED: %d\n", ret);
        }
        else {
            printf("  [Consumer] Verified OK, payload: %zu bytes, alg: %d\n",
                   decPayloadLen, hdr.alg);
        }
    }

    if (dlInited != 0) {
        wc_MlDsaKey_Free(&dlKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
    printf("  Result: %s\n\n", (ret == 0) ? "PASS" : "FAIL");

    return ret;
}
#endif /* WOLFCOSE_HAVE_MLDSA */

/* ----- COSE_Encrypt0 lifecycle: AES-GCM ----- */
#ifdef WOLFCOSE_HAVE_AESGCM
static int demo_encrypt0_aesgcm(int32_t alg)
{
    int ret;
    WOLFCOSE_KEY key;
    WC_RNG rng;
    uint8_t payload[64];
    size_t payloadLen = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t packet[512];
    size_t packetLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    uint8_t iv[WOLFCOSE_AES_GCM_NONCE_SZ];
    size_t keyLen;
    uint8_t keyData[32];
    const char* algName;

    if (alg == WOLFCOSE_ALG_A128GCM) {
        keyLen = 16;
        algName = "A128GCM";
    }
    else {
        keyLen = 32;
        algName = "A256GCM";
    }

    printf("--- COSE_Encrypt0 %s ---\n", algName);

    ret = encode_sensor_payload(payload, sizeof(payload), &payloadLen);
    if (ret != 0) { return ret; }
    printf("  [Producer] Sensor payload: %zu bytes\n", payloadLen);

    ret = wc_InitRng(&rng);
    if (ret != 0) { return ret; }

    ret = wc_RNG_GenerateBlock(&rng, keyData, (word32)keyLen);
    if (ret != 0) { wc_FreeRng(&rng); return ret; }

    ret = wc_RNG_GenerateBlock(&rng, iv, sizeof(iv));
    if (ret != 0) { wc_FreeRng(&rng); return ret; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, keyLen);

    ret = wc_CoseEncrypt0_Encrypt(&key, alg,
        iv, sizeof(iv),
        payload, payloadLen, NULL, 0, NULL,
        NULL, 0, scratch, sizeof(scratch),
        packet, sizeof(packet), &packetLen);
    if (ret != 0) {
        printf("  Encrypt failed: %d\n", ret);
        wc_FreeRng(&rng);
        printf("  Result: FAIL\n\n");
        return ret;
    }
    printf("  [Producer] COSE_Encrypt0: %zu bytes\n", packetLen);

    ret = wc_CoseEncrypt0_Decrypt(&key, packet, packetLen,
        NULL, 0, NULL, 0, scratch, sizeof(scratch), &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    if (ret != 0) {
        printf("  Decrypt FAILED: %d\n", ret);
    }
    else {
        printf("  [Consumer] Decrypted OK, payload: %zu bytes, alg: %d\n",
               plaintextLen, hdr.alg);
    }

    wc_FreeRng(&rng);
    printf("  Result: %s\n\n", (ret == 0) ? "PASS" : "FAIL");
    return ret;
}
#endif /* WOLFCOSE_HAVE_AESGCM */

/* ----- COSE_Encrypt0 lifecycle: ChaCha20-Poly1305 ----- */
#if defined(WOLFCOSE_HAVE_CHACHA20)
static int demo_encrypt0_chacha20(void)
{
    int ret;
    WOLFCOSE_KEY key;
    WC_RNG rng;
    uint8_t payload[64];
    size_t payloadLen = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t packet[512];
    size_t packetLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    uint8_t iv[WOLFCOSE_CHACHA_NONCE_SZ];
    uint8_t keyData[WOLFCOSE_CHACHA_KEY_SZ];

    printf("--- COSE_Encrypt0 ChaCha20-Poly1305 ---\n");

    ret = encode_sensor_payload(payload, sizeof(payload), &payloadLen);
    if (ret != 0) { return ret; }
    printf("  [Producer] Sensor payload: %zu bytes\n", payloadLen);

    ret = wc_InitRng(&rng);
    if (ret != 0) { return ret; }

    ret = wc_RNG_GenerateBlock(&rng, keyData, sizeof(keyData));
    if (ret != 0) { wc_FreeRng(&rng); return ret; }

    ret = wc_RNG_GenerateBlock(&rng, iv, sizeof(iv));
    if (ret != 0) { wc_FreeRng(&rng); return ret; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_CHACHA20_POLY1305,
        iv, sizeof(iv),
        payload, payloadLen, NULL, 0, NULL,
        NULL, 0, scratch, sizeof(scratch),
        packet, sizeof(packet), &packetLen);
    if (ret != 0) {
        printf("  Encrypt failed: %d\n", ret);
        wc_FreeRng(&rng);
        printf("  Result: FAIL\n\n");
        return ret;
    }
    printf("  [Producer] COSE_Encrypt0: %zu bytes\n", packetLen);

    ret = wc_CoseEncrypt0_Decrypt(&key, packet, packetLen,
        NULL, 0, NULL, 0, scratch, sizeof(scratch), &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    if (ret != 0) {
        printf("  Decrypt FAILED: %d\n", ret);
    }
    else {
        printf("  [Consumer] Decrypted OK, payload: %zu bytes, alg: %d\n",
               plaintextLen, hdr.alg);
    }

    wc_FreeRng(&rng);
    printf("  Result: %s\n\n", (ret == 0) ? "PASS" : "FAIL");
    return ret;
}
#endif /* WOLFCOSE_HAVE_CHACHA20 && WOLFCOSE_HAVE_CHACHA20 */

/* ----- COSE_Encrypt0 lifecycle: AES-CCM ----- */
#ifdef WOLFCOSE_HAVE_AESCCM
static int demo_encrypt0_aes_ccm(void)
{
    int ret;
    WOLFCOSE_KEY key;
    WC_RNG rng;
    uint8_t payload[64];
    size_t payloadLen = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t packet[512];
    size_t packetLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    uint8_t iv[13]; /* nonce=13 for CCM-16 variants */
    uint8_t keyData[16];

    printf("--- COSE_Encrypt0 AES-CCM-16-128-128 ---\n");

    ret = encode_sensor_payload(payload, sizeof(payload), &payloadLen);
    if (ret != 0) { return ret; }
    printf("  [Producer] Sensor payload: %zu bytes\n", payloadLen);

    ret = wc_InitRng(&rng);
    if (ret != 0) { return ret; }

    ret = wc_RNG_GenerateBlock(&rng, keyData, sizeof(keyData));
    if (ret != 0) { wc_FreeRng(&rng); return ret; }

    ret = wc_RNG_GenerateBlock(&rng, iv, sizeof(iv));
    if (ret != 0) { wc_FreeRng(&rng); return ret; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_AES_CCM_16_128_128,
        iv, sizeof(iv),
        payload, payloadLen, NULL, 0, NULL,
        NULL, 0, scratch, sizeof(scratch),
        packet, sizeof(packet), &packetLen);
    if (ret != 0) {
        printf("  Encrypt failed: %d\n", ret);
        wc_FreeRng(&rng);
        printf("  Result: FAIL\n\n");
        return ret;
    }
    printf("  [Producer] COSE_Encrypt0: %zu bytes\n", packetLen);

    ret = wc_CoseEncrypt0_Decrypt(&key, packet, packetLen,
        NULL, 0, NULL, 0, scratch, sizeof(scratch), &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    if (ret != 0) {
        printf("  Decrypt FAILED: %d\n", ret);
    }
    else {
        printf("  [Consumer] Decrypted OK, payload: %zu bytes, alg: %d\n",
               plaintextLen, hdr.alg);
    }

    wc_FreeRng(&rng);
    printf("  Result: %s\n\n", (ret == 0) ? "PASS" : "FAIL");
    return ret;
}
#endif /* WOLFCOSE_HAVE_AESCCM */

/* ----- COSE_Mac0 lifecycle: HMAC ----- */
#if defined(WOLFCOSE_HAVE_HMAC256)
static int demo_mac0_hmac(int32_t alg)
{
    int ret;
    WOLFCOSE_KEY key;
    WC_RNG rng;
    uint8_t payload[64];
    size_t payloadLen = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t packet[512];
    size_t packetLen = 0;
    WOLFCOSE_HDR hdr;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    size_t keyLen;
    uint8_t keyData[64];
    const char* algName;

    if (alg == WOLFCOSE_ALG_HMAC256) {
        keyLen = 32;
        algName = "HMAC-256";
    }
    else if (alg == WOLFCOSE_ALG_HMAC384) {
        keyLen = 48;
        algName = "HMAC-384";
    }
    else {
        keyLen = 64;
        algName = "HMAC-512";
    }

    printf("--- COSE_Mac0 %s ---\n", algName);

    ret = encode_sensor_payload(payload, sizeof(payload), &payloadLen);
    if (ret != 0) { return ret; }
    printf("  [Producer] Sensor payload: %zu bytes\n", payloadLen);

    ret = wc_InitRng(&rng);
    if (ret != 0) { return ret; }

    ret = wc_RNG_GenerateBlock(&rng, keyData, (word32)keyLen);
    wc_FreeRng(&rng);
    if (ret != 0) { return ret; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, keyLen);

    ret = wc_CoseMac0_Create(&key, alg,
        g_kid, sizeof(g_kid) - 1u,
        payload, payloadLen, NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        packet, sizeof(packet), &packetLen);
    if (ret != 0) {
        printf("  MAC create failed: %d\n", ret);
        printf("  Result: FAIL\n\n");
        return ret;
    }
    printf("  [Producer] COSE_Mac0: %zu bytes\n", packetLen);

    ret = wc_CoseMac0_Verify(&key, packet, packetLen,
        NULL, 0, NULL, 0, scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    if (ret != 0) {
        printf("  MAC verify FAILED: %d\n", ret);
    }
    else {
        printf("  [Consumer] MAC verified OK, payload: %zu bytes, alg: %d\n",
               decPayloadLen, hdr.alg);
    }

    printf("  Result: %s\n\n", (ret == 0) ? "PASS" : "FAIL");
    return ret;
}
#endif /* WOLFCOSE_HAVE_HMAC256 */

/* ----- Algorithm name parser ----- */
enum {
    DEMO_ALG_ALL = 0,
    DEMO_ALG_ES256,
    DEMO_ALG_EDDSA,
    DEMO_ALG_PS256,
    DEMO_ALG_A128GCM,
    DEMO_ALG_A256GCM,
    DEMO_ALG_HMAC256,
    DEMO_ALG_HMAC384,
    DEMO_ALG_HMAC512,
    DEMO_ALG_CHACHA20,
    DEMO_ALG_ML_DSA_44,
    DEMO_ALG_AES_CCM
};

static int parse_demo_alg(const char* name)
{
    if ((name == NULL) || (strcmp(name, "all") == 0)) {
        return DEMO_ALG_ALL;
    }
    if (strcmp(name, "ES256") == 0) {
        return DEMO_ALG_ES256;
    }
    if (strcmp(name, "EdDSA") == 0) {
        return DEMO_ALG_EDDSA;
    }
    if (strcmp(name, "PS256") == 0) {
        return DEMO_ALG_PS256;
    }
    if (strcmp(name, "A128GCM") == 0) {
        return DEMO_ALG_A128GCM;
    }
    if (strcmp(name, "A256GCM") == 0) {
        return DEMO_ALG_A256GCM;
    }
    if (strcmp(name, "HMAC256") == 0) {
        return DEMO_ALG_HMAC256;
    }
    if (strcmp(name, "HMAC384") == 0) {
        return DEMO_ALG_HMAC384;
    }
    if (strcmp(name, "HMAC512") == 0) {
        return DEMO_ALG_HMAC512;
    }
    if (strcmp(name, "ChaCha20") == 0) {
        return DEMO_ALG_CHACHA20;
    }
    if (strcmp(name, "ML-DSA-44") == 0) {
        return DEMO_ALG_ML_DSA_44;
    }
    if (strcmp(name, "AES-CCM") == 0) {
        return DEMO_ALG_AES_CCM;
    }
    return -1;
}

/* ----- main ----- */
int main(int argc, char* argv[])
{
    int demoAlg = DEMO_ALG_ALL;
    int failures = 0;
    int tests = 0;

    /* Parse -a <alg> flag */
    if ((argc == 3) && (strcmp(argv[1], "-a") == 0)) {
        demoAlg = parse_demo_alg(argv[2]);
        if (demoAlg < 0) {
            fprintf(stderr, "Unknown algorithm: %s\n", argv[2]);
            fprintf(stderr,
                "Usage: %s [-a <alg>]\n"
                "  alg: all, ES256, EdDSA, PS256, ML-DSA-44, A128GCM,\n"
                "       A256GCM, HMAC256, HMAC384, HMAC512, ChaCha20,\n"
                "       AES-CCM\n",
                argv[0]);
            return 1;
        }
    }
    else if (argc != 1) {
        fprintf(stderr,
            "Usage: %s [-a <alg>]\n"
            "  alg: all, ES256, EdDSA, PS256, ML-DSA-44, A128GCM,\n"
            "       A256GCM, HMAC256, HMAC384, HMAC512, ChaCha20,\n"
            "       AES-CCM\n", argv[0]);
        return 1;
    }

    printf("=== wolfCOSE Lifecycle Demo ===\n\n");

    /* COSE_Sign1 demos */
#ifdef WOLFCOSE_HAVE_ES256
    if ((demoAlg == DEMO_ALG_ALL) || (demoAlg == DEMO_ALG_ES256)) {
        tests++;
        if (demo_sign1_es256() != 0) { failures++; }
    }
#endif
#ifdef WOLFCOSE_HAVE_EDDSA
    if ((demoAlg == DEMO_ALG_ALL) || (demoAlg == DEMO_ALG_EDDSA)) {
        tests++;
        if (demo_sign1_eddsa() != 0) { failures++; }
    }
#endif
#if defined(WOLFCOSE_HAVE_RSAPSS) && defined(WOLFSSL_KEY_GEN)
    if ((demoAlg == DEMO_ALG_ALL) || (demoAlg == DEMO_ALG_PS256)) {
        tests++;
        if (demo_sign1_ps256() != 0) { failures++; }
    }
#endif
#ifdef WOLFCOSE_HAVE_MLDSA
    if ((demoAlg == DEMO_ALG_ALL) || (demoAlg == DEMO_ALG_ML_DSA_44)) {
        tests++;
        if (demo_sign1_ml_dsa_44() != 0) { failures++; }
    }
#endif

    /* COSE_Encrypt0 demos */
#ifdef WOLFCOSE_HAVE_AESGCM
    if ((demoAlg == DEMO_ALG_ALL) || (demoAlg == DEMO_ALG_A128GCM)) {
        tests++;
        if (demo_encrypt0_aesgcm(WOLFCOSE_ALG_A128GCM) != 0) { failures++; }
    }
    if ((demoAlg == DEMO_ALG_ALL) || (demoAlg == DEMO_ALG_A256GCM)) {
        tests++;
        if (demo_encrypt0_aesgcm(WOLFCOSE_ALG_A256GCM) != 0) { failures++; }
    }
#endif
#if defined(WOLFCOSE_HAVE_CHACHA20)
    if ((demoAlg == DEMO_ALG_ALL) || (demoAlg == DEMO_ALG_CHACHA20)) {
        tests++;
        if (demo_encrypt0_chacha20() != 0) { failures++; }
    }
#endif
#ifdef WOLFCOSE_HAVE_AESCCM
    if ((demoAlg == DEMO_ALG_ALL) || (demoAlg == DEMO_ALG_AES_CCM)) {
        tests++;
        if (demo_encrypt0_aes_ccm() != 0) { failures++; }
    }
#endif

    /* COSE_Mac0 demos */
#if defined(WOLFCOSE_HAVE_HMAC256)
    if ((demoAlg == DEMO_ALG_ALL) || (demoAlg == DEMO_ALG_HMAC256)) {
        tests++;
        if (demo_mac0_hmac(WOLFCOSE_ALG_HMAC256) != 0) { failures++; }
    }
#ifdef WOLFCOSE_HAVE_HMAC384
    if ((demoAlg == DEMO_ALG_ALL) || (demoAlg == DEMO_ALG_HMAC384)) {
        tests++;
        if (demo_mac0_hmac(WOLFCOSE_ALG_HMAC384) != 0) { failures++; }
    }
#endif
#ifdef WOLFCOSE_HAVE_HMAC512
    if ((demoAlg == DEMO_ALG_ALL) || (demoAlg == DEMO_ALG_HMAC512)) {
        tests++;
        if (demo_mac0_hmac(WOLFCOSE_ALG_HMAC512) != 0) { failures++; }
    }
#endif
#endif /* WOLFCOSE_HAVE_HMAC256 */

    printf("=== Results: %d/%d passed", tests - failures, tests);
    if (failures > 0) {
        printf(" (%d FAILED)", failures);
    }
    printf(" ===\n");

    return (failures > 0) ? 1 : 0;
}
