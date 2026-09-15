/* wolfcose_test.c
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

#include "wolfcose_test.h"

#include <stdio.h>
#include <string.h>

int wolfCOSETest(void)
{
#if defined(WOLFCOSE_HAVE_ES256) && defined(WOLFCOSE_SIGN1_SIGN) && \
    defined(WOLFCOSE_SIGN1_VERIFY)
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    WOLFCOSE_HDR hdr;
    const uint8_t payload[] = "wolfCOSE STM32 self test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    const uint8_t* decPayload = NULL;
    size_t payloadLen = sizeof(payload) - 1u;
    size_t outLen = 0;
    size_t decPayloadLen = 0;
    int rngInited = 0;
    int eccInited = 0;
    int keyInited = 0;
    int ret;

    printf("Running wolfCOSE test (COSE_Sign1 ESP256)...\n");

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInited = 1;
        ret = wc_ecc_init(&eccKey);
    }
    if (ret == 0) {
        eccInited = 1;
        ret = wc_ecc_make_key(&rng, 32, &eccKey);
    }
    if (ret == 0) {
        ret = wc_CoseKey_Init(&key);
    }
    if (ret == 0) {
        keyInited = 1;
        ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);
    }
    if (ret == 0) {
        ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ESP256,
            NULL, 0, payload, payloadLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch), out, sizeof(out), &outLen, &rng);
    }
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&key, out, outLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch), &hdr, &decPayload, &decPayloadLen);
    }
    if (ret == 0) {
        if ((decPayload == NULL) || (decPayloadLen != payloadLen) ||
            (memcmp(decPayload, payload, decPayloadLen) != 0) ||
            (hdr.alg != WOLFCOSE_ALG_ESP256)) {
            ret = -1;
        }
    }

    if (keyInited != 0) {
        wc_CoseKey_Free(&key);
    }
    if (eccInited != 0) {
        (void)wc_ecc_free(&eccKey);
    }
    if (rngInited != 0) {
        (void)wc_FreeRng(&rng);
    }

    if (ret == 0) {
        printf("wolfCOSE test: PASS (COSE_Sign1 %lu bytes)\n", (unsigned long)outLen);
    }
    else {
        printf("wolfCOSE test: FAIL, ret %d\n", ret);
    }
    return ret;
#else
    /* ESP256 COSE_Sign1 not compiled in; report not run so it is not read as pass */
    printf("wolfCOSE test: needs ESP256 with COSE_Sign1 sign and verify\n");
    return -1;
#endif
}
