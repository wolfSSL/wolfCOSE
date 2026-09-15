/* sign1_verify_lean.c
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

/* Verify-only lean build example.
 *
 * Build this with -DWOLFCOSE_LEAN_VERIFY. That profile compiles in only the
 * COSE_Sign1 verify path. It is the common on-device case: a device verifies a
 * signed firmware image or attestation, and signing happens off-device on a
 * server or HSM. Signing and the RNG it needs are not compiled in at all, while
 * full RFC 9052 verification (header decode, crit enforcement, duplicate-label
 * detection, Sig_structure rebuild) stays intact.
 *
 * The device holds only a public key. Here both the P-256 public key and a
 * COSE_Sign1 message produced off-device are embedded as fixed test vectors.
 */

#include <stdio.h>
#include <string.h>
#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/ecc.h>

/* P-256 public key (X and Y, 32 bytes each). The matching private key lives
 * off-device and is never present in a lean verify build. */
static const uint8_t PUB_X[32] = {
    7,46,52,83,101,83,150,186,25,53,18,206,127,177,205,220,45,101,26,221,16,156,
    28,95,25,176,216,47,196,158,197,239};
static const uint8_t PUB_Y[32] = {
    136,120,156,232,172,90,142,203,146,225,21,226,197,205,215,56,46,213,218,74,224,185,
    96,77,100,142,235,118,138,87,130,46};

/* A COSE_Sign1 (ESP256) over the payload below, signed off-device. */
static const uint8_t COSE_SIGN1[] = {
    210,132,67,161,1,40,160,88,31,119,111,108,102,67,79,83,69,32,115,105,122,101,
    32,98,101,110,99,104,109,97,114,107,32,112,97,121,108,111,97,100,88,64,201,105,
    152,70,230,206,246,14,94,132,181,86,158,232,224,236,190,163,136,180,211,146,73,94,
    129,79,132,234,145,88,96,128,225,174,150,178,60,0,15,105,119,226,69,59,241,46,
    27,78,198,17,132,23,66,110,230,137,133,202,168,126,125,81,163,203};

static const char EXPECTED_PAYLOAD[] = "wolfCOSE size benchmark payload";

int main(void)
{
    ecc_key        eccKey;
    WOLFCOSE_KEY   key;
    WOLFCOSE_HDR   hdr;
    uint8_t scratch[256];
    const uint8_t* payload = NULL;
    size_t         payloadLen = 0;
    int            ret;
    int            rc = 1;

    if (wc_ecc_init(&eccKey) != 0) {
        (void)printf("wc_ecc_init failed\n");
        return 1;
    }

    /* Import the public key only. A NULL private scalar keeps this public. */
    ret = wc_ecc_import_unsigned(&eccKey, (byte*)PUB_X, (byte*)PUB_Y, NULL,
                                 ECC_SECP256R1);
    if (ret == 0) {
        ret = wc_CoseKey_Init(&key);
    }
    if (ret == 0) {
        ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);
    }

    if (ret == 0) {
        (void)memset(&hdr, 0, sizeof(hdr));
        ret = wc_CoseSign1_Verify(&key, COSE_SIGN1, sizeof(COSE_SIGN1),
                                  NULL, 0, NULL, 0,
                                  scratch, sizeof(scratch), &hdr,
                                  &payload, &payloadLen);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        if ((payloadLen == (sizeof(EXPECTED_PAYLOAD) - 1)) &&
            (payload != NULL) &&
            (memcmp(payload, EXPECTED_PAYLOAD, payloadLen) == 0)) {
            (void)printf("lean verify-only: COSE_Sign1 ESP256 verified, "
                         "payload = \"%.*s\"\n", (int)payloadLen, payload);
            rc = 0;
        }
        else {
            (void)printf("lean verify-only: payload mismatch\n");
        }
    }
    else {
        (void)printf("lean verify-only: verify failed (%d)\n", ret);
    }

    wc_CoseKey_Free(&key);
    wc_ecc_free(&eccKey);
    return rc;
}
