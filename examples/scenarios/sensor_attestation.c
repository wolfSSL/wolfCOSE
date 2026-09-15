/* sensor_attestation.c
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

/* Sensor Attestation Token (EAT-style)
 *
 * Scenario: Embedded sensor signs reading with device key and includes
 * hardware nonce as AAD for replay protection. Demonstrates COSE_Sign1
 * with external AAD for Entity Attestation Token (EAT) style attestation.
 *
 * Compile-time gate:
 *   WOLFCOSE_EXAMPLE_SENSOR_ATTEST  - Enable this example (default: enabled)
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfcose/settings.h>
#include <stdio.h>

/* Default: enabled */
#ifndef WOLFCOSE_NO_EXAMPLE_SENSOR_ATTEST
    #define WOLFCOSE_EXAMPLE_SENSOR_ATTEST
#endif

#if defined(WOLFCOSE_EXAMPLE_SENSOR_ATTEST) && defined(WOLFCOSE_HAVE_ES256)

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <stdio.h>
#include <string.h>

/* Simulated sensor reading (would be CBOR in real EAT) */
static const uint8_t g_sensorReading[] = {
    /* Simplified sensor payload */
    0xA4,  /* CBOR map with 4 entries */
    0x01, 0x78, 0x0D,  /* key 1: sensor-id string */
    's', 'e', 'n', 's', 'o', 'r', '-', '0', '0', '1', '-', 'a', 'b',
    0x02, 0x19, 0x01, 0x8F,  /* key 2: temperature = 399 (39.9C * 10) */
    0x03, 0x18, 0x3E,        /* key 3: humidity = 62% */
    0x04, 0x1A, 0x65, 0xE4, 0x77, 0x80  /* key 4: timestamp */
};

/* ----- Sensor: Initialize device attestation key ----- */
static int sensor_init_key(ecc_key* eccKey, WOLFCOSE_KEY* cosKey, WC_RNG* rng)
{
    int ret;

    printf("[Sensor] Initializing device attestation key...\n");

    ret = wc_ecc_init(eccKey);
    if (ret != 0) {
        printf("  ERROR: wc_ecc_init failed: %d\n", ret);
        return ret;
    }

    /* Generate device key (in real device, this would be provisioned) */
    ret = wc_ecc_make_key(rng, 32, eccKey);
    if (ret != 0) {
        printf("  ERROR: wc_ecc_make_key failed: %d\n", ret);
        return ret;
    }

    wc_CoseKey_Init(cosKey);
    ret = wc_CoseKey_SetEcc(cosKey, WOLFCOSE_CRV_P256, eccKey);
    if (ret != 0) {
        printf("  ERROR: wc_CoseKey_SetEcc failed: %d\n", ret);
        return ret;
    }

    printf("  SUCCESS: Device attestation key ready\n");
    return 0;
}

/* ----- Verifier: Generate challenge nonce ----- */
static int verifier_generate_nonce(uint8_t* nonce, size_t nonceLen, WC_RNG* rng)
{
    int ret;
    size_t i;

    printf("[Verifier] Generating challenge nonce...\n");

    ret = wc_RNG_GenerateBlock(rng, nonce, (word32)nonceLen);
    if (ret != 0) {
        printf("  ERROR: Failed to generate nonce: %d\n", ret);
        return ret;
    }

    printf("  Nonce: ");
    for (i = 0u; (i < nonceLen) && (i < 8u); i++) {
        printf("%02X", nonce[i]);
    }
    printf("...\n");
    return 0;
}

/* ----- Sensor: Create attestation token with reading + nonce in AAD ----- */
static int sensor_create_attestation(WOLFCOSE_KEY* deviceKey,
                                      const uint8_t* reading, size_t readingLen,
                                      const uint8_t* nonce, size_t nonceLen,
                                      uint8_t* tokenOut, size_t tokenOutSz,
                                      size_t* tokenLen, WC_RNG* rng)
{
    int ret;
    uint8_t scratch[512];
    const uint8_t kid[] = "device-attestation-key-001";

    printf("[Sensor] Creating attestation token...\n");
    printf("  Reading size: %zu bytes\n", readingLen);
    printf("  Nonce (AAD) size: %zu bytes\n", nonceLen);

    /* Sign with nonce as external AAD */
    ret = wc_CoseSign1_Sign(deviceKey, WOLFCOSE_ALG_ESP256,
        kid, sizeof(kid) - 1u,
        reading, readingLen,
        NULL, 0,  /* No detached payload */
        nonce, nonceLen,  /* Nonce as external AAD */
        scratch, sizeof(scratch),
        tokenOut, tokenOutSz, tokenLen, rng);

    if (ret != 0) {
        printf("  ERROR: wc_CoseSign1_Sign failed: %d\n", ret);
        return ret;
    }

    printf("  SUCCESS: Attestation token created (%zu bytes)\n", *tokenLen);
    printf("  Nonce bound to signature via AAD\n");
    return 0;
}

/* ----- Verifier: Verify attestation token ----- */
static int verifier_check_attestation(WOLFCOSE_KEY* devicePubKey,
                                       const uint8_t* token, size_t tokenLen,
                                       const uint8_t* expectedNonce, size_t nonceLen)
{
    int ret;
    uint8_t scratch[512];
    const uint8_t* payload = NULL;
    size_t payloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("[Verifier] Verifying attestation token...\n");

    /* Verify with expected nonce as AAD */
    ret = wc_CoseSign1_Verify(devicePubKey, token, tokenLen,
        NULL, 0,  /* No detached payload */
        expectedNonce, nonceLen,  /* Verify with challenge nonce */
        scratch, sizeof(scratch),
        &hdr, &payload, &payloadLen);

    if (ret != 0) {
        printf("  ERROR: Signature verification failed: %d\n", ret);
        return ret;
    }

    printf("  SUCCESS: Signature valid\n");
    printf("  Nonce binding verified (replay protection)\n");
    printf("  Payload: %zu bytes of sensor data\n", payloadLen);

    if (hdr.kidLen > 0u) {
        printf("  Key ID: %.*s\n", (int)hdr.kidLen, hdr.kid);
    }

    return 0;
}

/* ----- Verifier: Replay attack detection (wrong nonce must fail) ----- */
static int verifier_detect_replay(WOLFCOSE_KEY* devicePubKey,
                                   const uint8_t* token, size_t tokenLen,
                                   const uint8_t* wrongNonce, size_t nonceLen)
{
    int ret;
    uint8_t scratch[512];
    const uint8_t* payload = NULL;
    size_t payloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("[Verifier] Testing replay attack detection...\n");

    /* Verify with different nonce - should fail */
    ret = wc_CoseSign1_Verify(devicePubKey, token, tokenLen,
        NULL, 0,
        wrongNonce, nonceLen,  /* Wrong nonce */
        scratch, sizeof(scratch),
        &hdr, &payload, &payloadLen);

    if (ret == 0) {
        printf("  ERROR: Replay attack not detected!\n");
        return -100;
    }

    printf("  SUCCESS: Replay attack detected and rejected\n");
    return 0;
}

/* ----- Main Demo ----- */
int main(void)
{
    int ret = 0;
    WC_RNG rng;
    int rngInit = 0;
    ecc_key eccKey;
    int eccInit = 0;
    WOLFCOSE_KEY deviceKey;
    uint8_t nonce[16];
    uint8_t wrongNonce[16];
    uint8_t token[512];
    size_t tokenLen = 0;

    printf("================================================\n");
    printf("Sensor Attestation Scenario (EAT-style)\n");
    printf("================================================\n\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("ERROR: wc_InitRng failed: %d\n", ret);
        return ret;
    }
    rngInit = 1;

    /* Initialize sensor's device key */
    if (ret == 0) {
        ret = sensor_init_key(&eccKey, &deviceKey, &rng);
        if (ret == 0) {
            eccInit = 1;
        }
    }

    if (ret == 0) {
        printf("\n");
    }

    /* Verifier generates challenge nonce */
    if (ret == 0) {
        ret = verifier_generate_nonce(nonce, sizeof(nonce), &rng);
    }

    if (ret == 0) {
        printf("\n");
    }

    /* Sensor creates attestation token */
    if (ret == 0) {
        ret = sensor_create_attestation(&deviceKey,
            g_sensorReading, sizeof(g_sensorReading),
            nonce, sizeof(nonce),
            token, sizeof(token), &tokenLen, &rng);
    }

    if (ret == 0) {
        printf("\n");
    }

    /* Verifier checks attestation */
    if (ret == 0) {
        ret = verifier_check_attestation(&deviceKey, token, tokenLen,
            nonce, sizeof(nonce));
    }

    if (ret == 0) {
        printf("\n");
    }

    /* Generate different nonce for replay test */
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(&rng, wrongNonce, sizeof(wrongNonce));
    }

    /* Test replay detection */
    if (ret == 0) {
        ret = verifier_detect_replay(&deviceKey, token, tokenLen,
            wrongNonce, sizeof(wrongNonce));
    }

    if (ret == 0) {
        printf("\n================================================\n");
        printf("Sensor Attestation: SUCCESS\n");
        printf("- Device identity verified via signature\n");
        printf("- Freshness guaranteed via nonce binding\n");
        printf("- Replay attacks detected and blocked\n");
        printf("================================================\n");
    }

    /* Cleanup */
    if (eccInit != 0) { wc_ecc_free(&eccKey); }
    if (rngInit != 0) { wc_FreeRng(&rng); }

    if (ret != 0) {
        printf("\n================================================\n");
        printf("Sensor Attestation: FAILED (%d)\n", ret);
        printf("================================================\n");
    }

    return ret;
}

#else /* Build guards not met */

int main(void)
{
#ifndef WOLFCOSE_EXAMPLE_SENSOR_ATTEST
    printf("sensor_attestation: example disabled\n");
#elif !defined(WOLFCOSE_HAVE_ES256)
    printf("sensor_attestation: requires ECC support\n");
#endif
    return 0;
}

#endif /* WOLFCOSE_EXAMPLE_SENSOR_ATTEST && WOLFCOSE_HAVE_ES256 */
