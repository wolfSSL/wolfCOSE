/* multi_party_approval.c
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

/* Multi-Party Firmware Approval (Dual Control)
 *
 * Scenario: Firmware must be signed by BOTH silicon vendor (ESP256)
 * and OEM (ESP384) before device accepts it. Demonstrates COSE_Sign
 * with multiple signers using mixed algorithms.
 *
 * Compile-time gate:
 *   WOLFCOSE_EXAMPLE_MULTI_PARTY  - Enable this example (default: enabled)
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
#ifndef WOLFCOSE_NO_EXAMPLE_MULTI_PARTY
    #define WOLFCOSE_EXAMPLE_MULTI_PARTY
#endif

#if defined(WOLFCOSE_EXAMPLE_MULTI_PARTY) && defined(WOLFCOSE_HAVE_ES256) && \
    defined(WOLFCOSE_SIGN)

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <stdio.h>
#include <string.h>

/* Simulated firmware manifest content */
static const uint8_t g_firmwareManifest[] = {
    /* This would be a SUIT manifest or similar */
    0xA2,  /* CBOR map with 2 entries */
    0x01, 0x78, 0x18, /* key 1: firmware-id string */
    'f', 'i', 'r', 'm', 'w', 'a', 'r', 'e',
    '-', 'v', '1', '.', '0', '.', '0', '-',
    's', 'e', 'c', 'u', 'r', 'e', '-', 'u',
    0x02, 0x1A, 0x00, 0x01, 0x00, 0x00  /* key 2: size = 65536 */
};

/* ----- Silicon Vendor Key Generation ----- */
static int silicon_vendor_init(ecc_key* key, WOLFCOSE_KEY* cosKey, WC_RNG* rng)
{
    int ret;

    printf("[Silicon Vendor] Generating ESP256 signing key...\n");

    ret = wc_ecc_init(key);
    if (ret != 0) {
        printf("  ERROR: wc_ecc_init failed: %d\n", ret);
        return ret;
    }

    ret = wc_ecc_make_key(rng, 32, key);  /* P-256 */
    if (ret != 0) {
        printf("  ERROR: wc_ecc_make_key failed: %d\n", ret);
        return ret;
    }

    wc_CoseKey_Init(cosKey);
    ret = wc_CoseKey_SetEcc(cosKey, WOLFCOSE_CRV_P256, key);
    if (ret != 0) {
        printf("  ERROR: wc_CoseKey_SetEcc failed: %d\n", ret);
        return ret;
    }

    printf("  SUCCESS: Silicon vendor key ready (P-256)\n");
    return 0;
}

/* ----- OEM Key Generation ----- */
#ifdef WOLFCOSE_HAVE_ES384
static int oem_init(ecc_key* key, WOLFCOSE_KEY* cosKey, WC_RNG* rng)
{
    int ret;

    printf("[OEM] Generating ESP384 signing key...\n");

    ret = wc_ecc_init(key);
    if (ret != 0) {
        printf("  ERROR: wc_ecc_init failed: %d\n", ret);
        return ret;
    }

    ret = wc_ecc_make_key(rng, 48, key);  /* P-384 */
    if (ret != 0) {
        printf("  ERROR: wc_ecc_make_key failed: %d\n", ret);
        return ret;
    }

    wc_CoseKey_Init(cosKey);
    ret = wc_CoseKey_SetEcc(cosKey, WOLFCOSE_CRV_P384, key);
    if (ret != 0) {
        printf("  ERROR: wc_CoseKey_SetEcc failed: %d\n", ret);
        return ret;
    }

    printf("  SUCCESS: OEM key ready (P-384)\n");
    return 0;
}
#endif

/* ----- Multi-Party Signing ----- */
static int sign_with_dual_control(WOLFCOSE_KEY* vendorKey, WOLFCOSE_KEY* oemKey,
                                   const uint8_t* manifest, size_t manifestLen,
                                   uint8_t* signedOut, size_t signedOutSz,
                                   size_t* signedLen, WC_RNG* rng)
{
    int ret;
    WOLFCOSE_SIGNATURE signers[2];
    uint8_t scratch[512];
    const uint8_t vendorKid[] = "silicon-vendor-cert-001";
    const uint8_t oemKid[] = "oem-production-key-v2";

    printf("[Signing] Creating dual-signed firmware approval...\n");

    /* Setup signers array */
    XMEMSET(signers, 0, sizeof(signers));

    signers[0].algId = WOLFCOSE_ALG_ESP256;
    signers[0].key = vendorKey;
    signers[0].kid = vendorKid;
    signers[0].kidLen = sizeof(vendorKid) - 1u;

#ifdef WOLFCOSE_HAVE_ES384
    signers[1].algId = WOLFCOSE_ALG_ESP384;
    signers[1].key = oemKey;
    signers[1].kid = oemKid;
    signers[1].kidLen = sizeof(oemKid) - 1u;
#else
    signers[1].algId = WOLFCOSE_ALG_ESP256;
    signers[1].key = oemKey;
    signers[1].kid = oemKid;
    signers[1].kidLen = sizeof(oemKid) - 1u;
#endif

    /* Sign with both parties */
    ret = wc_CoseSign_Sign(signers, 2,
        manifest, manifestLen,
        NULL, 0,  /* No detached payload */
        NULL, 0,  /* No AAD */
        scratch, sizeof(scratch),
        signedOut, signedOutSz, signedLen, rng);

    if (ret != 0) {
        printf("  ERROR: wc_CoseSign_Sign failed: %d\n", ret);
        return ret;
    }

    printf("  SUCCESS: Dual-signed message created (%zu bytes)\n", *signedLen);
    printf("  Signer 0: Silicon Vendor (ESP256)\n");
#ifdef WOLFCOSE_HAVE_ES384
    printf("  Signer 1: OEM (ESP384)\n");
#else
    printf("  Signer 1: OEM (ESP256)\n");
#endif
    return 0;
}

/* ----- Device Verification (Both Signatures Required) ----- */
static int device_verify_dual(WOLFCOSE_KEY* vendorPubKey, WOLFCOSE_KEY* oemPubKey,
                               const uint8_t* signedMsg, size_t signedMsgLen)
{
    int ret;
    uint8_t scratch[512];
    const uint8_t* payload = NULL;
    size_t payloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("[Device] Verifying dual signatures...\n");

    /* Verify silicon vendor signature (index 0) */
    printf("  Checking Silicon Vendor signature (index 0)...\n");
    ret = wc_CoseSign_Verify(vendorPubKey, 0, signedMsg, signedMsgLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &payload, &payloadLen);
    if (ret != 0) {
        printf("  ERROR: Silicon vendor signature invalid: %d\n", ret);
        return ret;
    }
    printf("    PASS: Silicon vendor signature valid\n");

    /* Verify OEM signature (index 1) */
    printf("  Checking OEM signature (index 1)...\n");
    ret = wc_CoseSign_Verify(oemPubKey, 1, signedMsg, signedMsgLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &payload, &payloadLen);
    if (ret != 0) {
        printf("  ERROR: OEM signature invalid: %d\n", ret);
        return ret;
    }
    printf("    PASS: OEM signature valid\n");

    printf("  SUCCESS: Both signatures verified\n");
    printf("  Payload length: %zu bytes\n", payloadLen);
    return 0;
}

/* ----- Main Demo ----- */
int main(void)
{
    int ret = 0;
    WC_RNG rng;
    int rngInit = 0;
    ecc_key vendorEccKey, oemEccKey;
    int vendorInit = 0, oemInit = 0;
    WOLFCOSE_KEY vendorKey, oemKey;
    uint8_t signedMsg[1024];
    size_t signedMsgLen = 0;

    printf("================================================\n");
    printf("Multi-Party Approval Scenario\n");
    printf("================================================\n\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("ERROR: wc_InitRng failed: %d\n", ret);
        return ret;
    }
    rngInit = 1;

    /* Initialize both parties' keys */
    if (ret == 0) {
        ret = silicon_vendor_init(&vendorEccKey, &vendorKey, &rng);
        if (ret == 0) {
            vendorInit = 1;
        }
    }

#ifdef WOLFCOSE_HAVE_ES384
    if (ret == 0) {
        ret = oem_init(&oemEccKey, &oemKey, &rng);
        if (ret == 0) {
            oemInit = 1;
        }
    }
#else
    /* Fallback: use ESP256 for both if SHA384 not available */
    if (ret == 0) {
        printf("[OEM] Generating ESP256 signing key (SHA384 not available)...\n");
        ret = wc_ecc_init(&oemEccKey);
        if (ret == 0) {
            ret = wc_ecc_make_key(&rng, 32, &oemEccKey);
        }
        if (ret == 0) {
            wc_CoseKey_Init(&oemKey);
            ret = wc_CoseKey_SetEcc(&oemKey, WOLFCOSE_CRV_P256, &oemEccKey);
        }
        if (ret == 0) {
            printf("  SUCCESS: OEM key ready (P-256 fallback)\n");
            oemInit = 1;
        }
    }
#endif

    if (ret == 0) {
        printf("\n");
    }

    /* Both parties sign */
    if (ret == 0) {
        ret = sign_with_dual_control(&vendorKey, &oemKey,
            g_firmwareManifest, sizeof(g_firmwareManifest),
            signedMsg, sizeof(signedMsg), &signedMsgLen, &rng);
    }

    if (ret == 0) {
        printf("\n");
    }

    /* Device verifies both signatures */
    if (ret == 0) {
        ret = device_verify_dual(&vendorKey, &oemKey, signedMsg, signedMsgLen);
    }

    if (ret == 0) {
        printf("\n================================================\n");
        printf("Multi-Party Approval: SUCCESS\n");
        printf("Both Silicon Vendor and OEM signatures verified.\n");
        printf("Firmware manifest is approved for deployment.\n");
        printf("================================================\n");
    }

    /* Cleanup */
    if (vendorInit != 0) { wc_ecc_free(&vendorEccKey); }
    if (oemInit != 0) { wc_ecc_free(&oemEccKey); }
    if (rngInit != 0) { wc_FreeRng(&rng); }

    if (ret != 0) {
        printf("\n================================================\n");
        printf("Multi-Party Approval: FAILED (%d)\n", ret);
        printf("================================================\n");
    }

    return ret;
}

#else /* Build guards not met */

#include <stdio.h>

int main(void)
{
#ifndef WOLFCOSE_EXAMPLE_MULTI_PARTY
    printf("multi_party_approval: example disabled\n");
#elif !defined(WOLFCOSE_HAVE_ES256)
    printf("multi_party_approval: requires ECC support\n");
#elif !defined(WOLFCOSE_SIGN)
    printf("multi_party_approval: requires WOLFCOSE_SIGN\n");
#endif
    return 0;
}

#endif /* WOLFCOSE_EXAMPLE_MULTI_PARTY && WOLFCOSE_HAVE_ES256 && WOLFCOSE_SIGN */
