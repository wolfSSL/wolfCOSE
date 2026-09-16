/* sign1_lms.c
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

/* Post-quantum COSE_Sign1 sign + verify with HSS/LMS (RFC 8778).
 *
 * Full round trip: generate an LMS key (SP 800-208, L1/H10/W8), sign a
 * payload into a COSE_Sign1 with alg HSS-LMS (-46), then verify it. LMS is
 * a stateful scheme: the private key state is persisted through the
 * wolfCrypt read/write callbacks, memory-backed here for the demo.
 * Requires wolfSSL built with LMS (./configure --enable-lms). For the
 * verify-only on-device case see sign1_verify_lms.c and the
 * WOLFCOSE_LEAN_VERIFY_LMS build profile.
 */

#include <stdio.h>
#include <string.h>
#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/wc_lms.h>
#include <wolfssl/wolfcrypt/random.h>

static const char PAYLOAD[] = "wolfCOSE HSS-LMS payload";
static const char PAYLOAD2[] = "wolfCOSE HSS-LMS second firmware payload";

/* This example persists the compact LMS private key. WOLFSSL_WC_LMS_SERIALIZE_STATE
 * instead hands the callback the full serialized working state, which is larger
 * than HSS_MAX_PRIVATE_KEY_LEN and needs a bigger backing store. */
#ifdef WOLFSSL_WC_LMS_SERIALIZE_STATE
    #error "sign1_lms.c assumes compact LMS persistence; WOLFSSL_WC_LMS_SERIALIZE_STATE needs a larger gPrivStore"
#endif

/* LMS signatures run ~1.5KB for L1/H10/W8; keep buffers off the stack. */
static uint8_t gScratch[8192];
static uint8_t gMsg[4096];
static uint8_t gMsg2[4096];
static uint8_t gPrivStore[HSS_MAX_PRIVATE_KEY_LEN];
static unsigned int gWriteCount;

static int lms_write_cb(const byte* priv, word32 privSz, void* context)
{
    int ret = (int)WC_LMS_RC_WRITE_FAIL;

    if ((priv != NULL) && (context != NULL) &&
        (privSz <= (word32)sizeof(gPrivStore))) {
        (void)memcpy(context, priv, (size_t)privSz);
        gWriteCount++;
        ret = (int)WC_LMS_RC_SAVED_TO_NV_MEMORY;
    }
    return ret;
}

static int lms_read_cb(byte* priv, word32 privSz, void* context)
{
    int ret = (int)WC_LMS_RC_READ_FAIL;

    if ((priv != NULL) && (context != NULL) &&
        (privSz <= (word32)sizeof(gPrivStore))) {
        (void)memcpy(priv, context, (size_t)privSz);
        ret = (int)WC_LMS_RC_READ_TO_MEMORY;
    }
    return ret;
}

int main(void)
{
    LmsKey         lmsKey;
    WOLFCOSE_KEY   key;
    WOLFCOSE_HDR   hdr;
    WC_RNG         rng;
    const uint8_t* payload = NULL;
    size_t         payloadLen = 0;
    size_t         msgLen = 0;
    size_t         msgLen2 = 0;
    unsigned int   writesBefore;
    int            ret;
    int            rc = 1;

    if (wc_InitRng(&rng) != 0) {
        (void)printf("wc_InitRng failed\n");
        return 1;
    }

    ret = wc_LmsKey_Init(&lmsKey, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_LmsKey_SetLmsParm(&lmsKey, WC_LMS_PARM_L1_H10_W8);
    }
    if (ret == 0) {
        ret = wc_LmsKey_SetWriteCb(&lmsKey, lms_write_cb);
    }
    if (ret == 0) {
        ret = wc_LmsKey_SetReadCb(&lmsKey, lms_read_cb);
    }
    if (ret == 0) {
        ret = wc_LmsKey_SetContext(&lmsKey, gPrivStore);
    }
    if (ret == 0) {
        ret = wc_LmsKey_MakeKey(&lmsKey, &rng);
    }
    if (ret == 0) {
        ret = wc_CoseKey_Init(&key);
    }
    if (ret == 0) {
        ret = wc_CoseKey_SetLms(&key, &lmsKey);
    }

    /* Sign */
    if (ret == 0) {
        ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_HSS_LMS, NULL, 0,
                                (const uint8_t*)PAYLOAD, sizeof(PAYLOAD) - 1,
                                NULL, 0, NULL, 0,
                                gScratch, sizeof(gScratch),
                                gMsg, sizeof(gMsg), &msgLen, &rng);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        (void)printf("HSS-LMS sign:   COSE_Sign1 produced, %u bytes "
                     "(signatures remaining: %s)\n", (unsigned int)msgLen,
                     (wc_LmsKey_SigsLeft(&lmsKey) != 0) ? "yes" : "exhausted");
    }
    else {
        (void)printf("HSS-LMS sign failed (%d)\n", ret);
    }

    /* Verify the message we just signed */
    if (ret == WOLFCOSE_SUCCESS) {
        (void)memset(&hdr, 0, sizeof(hdr));
        ret = wc_CoseSign1_Verify(&key, gMsg, msgLen, NULL, 0, NULL, 0,
                                  gScratch, sizeof(gScratch), &hdr,
                                  &payload, &payloadLen);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (payloadLen == (sizeof(PAYLOAD) - 1)) && (payload != NULL) &&
        (memcmp(payload, PAYLOAD, payloadLen) == 0)) {
        (void)printf("HSS-LMS verify: OK, payload = \"%.*s\"\n",
                     (int)payloadLen, payload);
        rc = 0;
    }
    else if (ret == WOLFCOSE_SUCCESS) {
        (void)printf("HSS-LMS verify: payload mismatch\n");
    }
    else {
        (void)printf("HSS-LMS verify failed (%d)\n", ret);
    }

    writesBefore = gWriteCount;
    if (rc == 0) {
        ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_HSS_LMS, NULL, 0,
            (const uint8_t*)PAYLOAD2, sizeof(PAYLOAD2) - 1u, NULL, 0,
            NULL, 0, gScratch, sizeof(gScratch), gMsg2, sizeof(gMsg2),
            &msgLen2, &rng);
        if ((ret != WOLFCOSE_SUCCESS) || (gWriteCount <= writesBefore) ||
            ((msgLen == msgLen2) && (memcmp(gMsg, gMsg2, msgLen) == 0))) {
            (void)printf("HSS-LMS state did not advance safely\n");
            rc = 1;
        }
    }
    if (rc == 0) {
        ret = wc_CoseSign1_Verify(&key, gMsg2, msgLen2, NULL, 0, NULL, 0,
            gScratch, sizeof(gScratch), &hdr, &payload, &payloadLen);
        if ((ret != WOLFCOSE_SUCCESS) ||
            (payloadLen != (sizeof(PAYLOAD2) - 1u)) || (payload == NULL) ||
            (memcmp(payload, PAYLOAD2, payloadLen) != 0)) {
            (void)printf("HSS-LMS second signature failed verification\n");
            rc = 1;
        }
    }
    if (rc == 0) {
        gMsg2[msgLen2 - 1u] ^= 0x01u;
        ret = wc_CoseSign1_Verify(&key, gMsg2, msgLen2, NULL, 0, NULL, 0,
            gScratch, sizeof(gScratch), &hdr, &payload, &payloadLen);
        if (ret == WOLFCOSE_SUCCESS) {
            (void)printf("HSS-LMS accepted a modified signature\n");
            rc = 1;
        }
        else {
            (void)printf("HSS-LMS state advance and tamper checks: OK\n");
        }
    }

    wc_CoseKey_Free(&key);
    wc_LmsKey_Free(&lmsKey);
    wc_FreeRng(&rng);
    return rc;
}
