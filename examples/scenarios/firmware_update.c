/* firmware_update.c
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
 *
 * Firmware Update with Post-Quantum Signature
 *
 * Scenario: OEM signs firmware binary with ML-DSA-65 (or ESP256 fallback),
 * embedded device verifies before installing. Uses detached payload since
 * firmware binary is transmitted separately from the COSE manifest.
 *
 * Compile-time gate:
 *   WOLFCOSE_EXAMPLE_FIRMWARE_UPDATE  - Enable this example (default: enabled)
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

/* Default: enabled */
#ifndef WOLFCOSE_NO_EXAMPLE_FIRMWARE_UPDATE
    #define WOLFCOSE_EXAMPLE_FIRMWARE_UPDATE
#endif

#ifdef WOLFCOSE_EXAMPLE_FIRMWARE_UPDATE

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#ifdef WOLFCOSE_HAVE_ES256
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef WOLFCOSE_HAVE_MLDSA
    #include <wolfssl/wolfcrypt/wc_mldsa.h>
#endif
#include <stdio.h>
#include <string.h>

/* Simulated firmware binary */
static const uint8_t g_firmwareBinary[] = {
    0x7F, 0x45, 0x4C, 0x46, /* ELF magic */
    0x02, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    /* ... simulated firmware content ... */
    0xDE, 0xAD, 0xBE, 0xEF,
    0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08
};

/* ----- Step 1: OEM generates signing key (done once, stored securely) ----- */
#ifdef WOLFCOSE_HAVE_MLDSA
static int oem_generate_key_mldsa(wc_MlDsaKey* key, WC_RNG* rng)
{
    int ret;

    printf("[OEM] Generating ML-DSA-65 key pair...\n");

    ret = wc_MlDsaKey_Init(key, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("  ERROR: wc_MlDsaKey_Init failed: %d\n", ret);
        return ret;
    }

    ret = wc_MlDsaKey_SetParams(key, WC_ML_DSA_65);
    if (ret != 0) {
        printf("  ERROR: wc_MlDsaKey_SetParams failed: %d\n", ret);
        return ret;
    }

    ret = wc_MlDsaKey_MakeKey(key, rng);
    if (ret != 0) {
        printf("  ERROR: wc_MlDsaKey_MakeKey failed: %d\n", ret);
        return ret;
    }

    printf("  SUCCESS: ML-DSA-65 key generated\n");
    return 0;
}
#endif

#if defined(WOLFCOSE_HAVE_ES256) && !defined(WOLFCOSE_HAVE_MLDSA)
static int oem_generate_key_ecdsa(ecc_key* key, WC_RNG* rng)
{
    int ret;

    printf("[OEM] Generating ECDSA P-256 key pair...\n");

    ret = wc_ecc_init(key);
    if (ret != 0) {
        printf("  ERROR: wc_ecc_init failed: %d\n", ret);
        return ret;
    }

    ret = wc_ecc_make_key(rng, 32, key);
    if (ret != 0) {
        printf("  ERROR: wc_ecc_make_key failed: %d\n", ret);
        return ret;
    }

    printf("  SUCCESS: ECDSA P-256 key generated\n");
    return 0;
}
#endif /* WOLFCOSE_HAVE_ES256 && !WOLFCOSE_HAVE_MLDSA */

/* ----- Step 2: OEM signs firmware with detached payload ----- */
static int oem_sign_firmware(WOLFCOSE_KEY* signingKey, int32_t alg,
                              const uint8_t* firmware, size_t firmwareSz,
                              uint8_t* manifestOut, size_t manifestOutSz,
                              size_t* manifestLen, WC_RNG* rng)
{
    int ret;
    int i;
    uint8_t scratch[8192];  /* Larger for PQC */
    const uint8_t kid[] = "OEM-firmware-signing-key-v1";
    uint8_t firmwareHash[32];
    wc_Sha256 sha;

    printf("[OEM] Signing firmware (%zu bytes)...\n", firmwareSz);

    /* Hash the firmware for logging (not required by COSE) */
    ret = wc_InitSha256(&sha);
    if (ret == 0) {
        ret = wc_Sha256Update(&sha, firmware, (word32)firmwareSz);
    }
    if (ret == 0) {
        ret = wc_Sha256Final(&sha, firmwareHash);
    }
    if (ret == 0) {
        printf("  Firmware SHA-256: ");
        for (i = 0; i < 8; i++) {
            printf("%02X", firmwareHash[i]);
        }
        printf("...\n");
    }

    /* Sign with detached payload */
    ret = wc_CoseSign1_Sign(signingKey, alg,
        kid, sizeof(kid) - 1u,
        NULL, 0,  /* No inline payload */
        firmware, firmwareSz,  /* Detached payload */
        NULL, 0,  /* No AAD */
        scratch, sizeof(scratch),
        manifestOut, manifestOutSz, manifestLen, rng);

    if (ret != 0) {
        printf("  ERROR: wc_CoseSign1_Sign failed: %d\n", ret);
        return ret;
    }

    printf("  SUCCESS: COSE manifest created (%zu bytes)\n", *manifestLen);
    printf("  Firmware binary transmitted separately (detached)\n");
    return 0;
}

/* ----- Step 3: Device verifies firmware signature before installing ----- */
static int device_verify_firmware(WOLFCOSE_KEY* oemPubKey,
                                   const uint8_t* manifest, size_t manifestLen,
                                   const uint8_t* firmware, size_t firmwareSz)
{
    int ret;
    uint8_t scratch[8192];
    const uint8_t* payload = NULL;
    size_t payloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("[DEVICE] Verifying firmware signature...\n");

    /* Verify with detached payload */
    ret = wc_CoseSign1_Verify(oemPubKey, manifest, manifestLen,
        firmware, firmwareSz,  /* Detached payload */
        NULL, 0,  /* No AAD */
        scratch, sizeof(scratch),
        &hdr, &payload, &payloadLen);

    if (ret != 0) {
        printf("  ERROR: Signature verification failed: %d\n", ret);
        printf("  FIRMWARE REJECTED - possible tampering\n");
        return ret;
    }

    printf("  SUCCESS: Signature verified\n");
    printf("  Algorithm: %d\n", hdr.alg);
    if (hdr.kidLen > 0u) {
        printf("  Key ID: %.*s\n", (int)hdr.kidLen, hdr.kid);
    }
    printf("  FIRMWARE APPROVED for installation\n");
    return 0;
}

/* ----- Step 4: Tampered firmware must be rejected ----- */
static int device_reject_tampered(WOLFCOSE_KEY* oemPubKey,
                                   const uint8_t* manifest, size_t manifestLen,
                                   const uint8_t* firmware, size_t firmwareSz)
{
    int ret;
    uint8_t scratch[8192];
    const uint8_t* payload = NULL;
    size_t payloadLen = 0;
    WOLFCOSE_HDR hdr;
    uint8_t tamperedFirmware[256];

    printf("[DEVICE] Testing tampered firmware rejection...\n");

    /* Create tampered copy */
    if (firmwareSz > sizeof(tamperedFirmware)) {
        printf("  ERROR: Firmware too large for test buffer\n");
        return -1;
    }
    XMEMCPY(tamperedFirmware, firmware, firmwareSz);
    tamperedFirmware[0] ^= 0xFF;  /* Tamper with first byte */

    /* Verify should fail */
    ret = wc_CoseSign1_Verify(oemPubKey, manifest, manifestLen,
        tamperedFirmware, firmwareSz,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &payload, &payloadLen);

    if (ret == 0) {
        printf("  ERROR: Tampered firmware was accepted!\n");
        return -100;
    }

    printf("  SUCCESS: Tampered firmware correctly rejected\n");
    return 0;
}

/* ----- Main Demo ----- */
int main(void)
{
    int ret = 0;
    WC_RNG rng;
    int rngInit = 0;
    uint8_t manifest[8192];
    size_t manifestLen = 0;
    WOLFCOSE_KEY signingKey;
    int32_t alg = 0;

#ifdef WOLFCOSE_HAVE_MLDSA
    wc_MlDsaKey dlKey;
    int dlInit = 0;
#endif
#ifdef WOLFCOSE_HAVE_ES256
    ecc_key eccKey;
    int eccInit = 0;
#endif

    printf("================================================\n");
    printf("Firmware Update Scenario\n");
    printf("================================================\n\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("ERROR: wc_InitRng failed: %d\n", ret);
        return ret;
    }
    rngInit = 1;

#ifdef WOLFCOSE_HAVE_MLDSA
    /* Prefer ML-DSA (post-quantum) if available */
    if (ret == 0) {
        ret = oem_generate_key_mldsa(&dlKey, &rng);
        if (ret == 0) {
            dlInit = 1;
        }
    }

    if (ret == 0) {
        wc_CoseKey_Init(&signingKey);
        ret = wc_CoseKey_SetMlDsa(&signingKey, WOLFCOSE_ALG_ML_DSA_65,
                                      &dlKey);
        if (ret != 0) {
            printf("ERROR: wc_CoseKey_SetMlDsa failed: %d\n", ret);
        }
    }

    if (ret == 0) {
        alg = WOLFCOSE_ALG_ML_DSA_65;
        printf("Using post-quantum ML-DSA-65 algorithm\n\n");
    }

#elif defined(WOLFCOSE_HAVE_ES256)
    /* Fallback to ECDSA */
    if (ret == 0) {
        ret = oem_generate_key_ecdsa(&eccKey, &rng);
        if (ret == 0) {
            eccInit = 1;
        }
    }

    if (ret == 0) {
        wc_CoseKey_Init(&signingKey);
        ret = wc_CoseKey_SetEcc(&signingKey, WOLFCOSE_CRV_P256, &eccKey);
        if (ret != 0) {
            printf("ERROR: wc_CoseKey_SetEcc failed: %d\n", ret);
        }
    }

    if (ret == 0) {
        alg = WOLFCOSE_ALG_ESP256;
        printf("Using ECDSA ESP256 algorithm (ML-DSA not available)\n\n");
    }

#else
    printf("ERROR: No signing algorithm available\n");
    ret = -1;
#endif

    /* OEM signs firmware */
    if (ret == 0) {
        ret = oem_sign_firmware(&signingKey, alg,
            g_firmwareBinary, sizeof(g_firmwareBinary),
            manifest, sizeof(manifest), &manifestLen, &rng);
    }

    if (ret == 0) {
        printf("\n");
    }

    /* Device verifies authentic firmware */
    if (ret == 0) {
        ret = device_verify_firmware(&signingKey,
            manifest, manifestLen,
            g_firmwareBinary, sizeof(g_firmwareBinary));
    }

    if (ret == 0) {
        printf("\n");
    }

    /* Device rejects tampered firmware */
    if (ret == 0) {
        ret = device_reject_tampered(&signingKey,
            manifest, manifestLen,
            g_firmwareBinary, sizeof(g_firmwareBinary));
    }

    if (ret == 0) {
        printf("\n================================================\n");
        printf("Firmware Update Scenario: SUCCESS\n");
        printf("================================================\n");
    }

    /* Cleanup */
#ifdef WOLFCOSE_HAVE_MLDSA
    if (dlInit != 0) { wc_MlDsaKey_Free(&dlKey); }
#endif
#ifdef WOLFCOSE_HAVE_ES256
    if (eccInit != 0) { wc_ecc_free(&eccKey); }
#endif
    if (rngInit != 0) { wc_FreeRng(&rng); }

    if (ret != 0) {
        printf("\n================================================\n");
        printf("Firmware Update Scenario: FAILED (%d)\n", ret);
        printf("================================================\n");
    }

    return ret;
}

#else /* !WOLFCOSE_EXAMPLE_FIRMWARE_UPDATE */

int main(void)
{
    printf("firmware_update: example disabled\n");
    return 0;
}

#endif /* WOLFCOSE_EXAMPLE_FIRMWARE_UPDATE */
