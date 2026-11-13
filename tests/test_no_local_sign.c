/* test_no_local_sign.c
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

/* WOLFCOSE_NO_LOCAL_SIGN: a key with local private material is refused and
 * the external signer still signs messages that verify. */

#include <stdio.h>
#include <string.h>

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#if !defined(WOLFCOSE_NO_LOCAL_SIGN) || !defined(WOLFCOSE_HAVE_ES256) || \
    !defined(WOLFCOSE_SIGN1_SIGN) || !defined(WOLFCOSE_SIGN1_VERIFY)
    #error "test_no_local_sign needs WOLFCOSE_NO_LOCAL_SIGN with ES256 Sign1"
#endif

static int g_failures = 0;

#define NLS_ASSERT(cond, name) do {                              \
    if (!(cond)) {                                               \
        (void)printf("  FAIL: %s (line %d)\n", (name), __LINE__); \
        g_failures++;                                            \
    }                                                            \
    else {                                                       \
        (void)printf("  PASS: %s\n", (name));                    \
    }                                                            \
} while (0)

typedef struct {
    WC_RNG*  rng;
    ecc_key* key;
} nls_signer;

/* Stands in for a secure element: digest in, fixed-width r||s out. */
static int nls_sign_cb(void* cbCtx, int32_t alg, const uint8_t* tbs,
                       size_t tbsLen, uint8_t* sig, size_t sigSz,
                       size_t* sigLen)
{
    nls_signer* se = (nls_signer*)cbCtx;
    uint8_t der[ECC_MAX_SIG_SIZE];
    word32 derLen = (word32)sizeof(der);
    int ret = 0;
#ifndef NO_ASN
    word32 rLen = 32u;
    word32 sLen = 32u;
#endif

    if ((alg != WOLFCOSE_ALG_ESP256) || (sigSz < 64u)) {
        ret = -1;
    }
    if (ret == 0) {
        ret = wc_ecc_sign_hash(tbs, (word32)tbsLen, der, &derLen, se->rng,
                               se->key);
    }
#ifdef NO_ASN
    if ((ret == 0) && (derLen != 64u)) {
        ret = -1;
    }
    if (ret == 0) {
        (void)memcpy(sig, der, 64u);
    }
#else
    if (ret == 0) {
        (void)memset(sig, 0, 64u);
        ret = wc_ecc_sig_to_rs(der, derLen, sig, &rLen, &sig[32], &sLen);
    }
    if ((ret == 0) && ((rLen > 32u) || (sLen > 32u))) {
        ret = -1;
    }
    if (ret == 0) {
        (void)memmove(&sig[32u - rLen], sig, rLen);
        (void)memset(sig, 0, 32u - rLen);
        (void)memmove(&sig[32u + (32u - sLen)], &sig[32], sLen);
        (void)memset(&sig[32], 0, 32u - sLen);
    }
#endif
    if (ret == 0) {
        *sigLen = 64u;
    }
    return (ret == 0) ? 0 : -1;
}

int main(void)
{
    static const uint8_t payload[] = "external signer only";
    WC_RNG rng;
    ecc_key eccKey;
    nls_signer se;
    WOLFCOSE_KEY localKey;
    WOLFCOSE_KEY extKey;
    WOLFCOSE_HDR hdr;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[256];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    int rngInited = 0;
    int eccInited = 0;
    int ret;
#if defined(WOLFCOSE_SIGN_SIGN)
    WOLFCOSE_SIGNATURE signer;
#endif
#if defined(WOLFCOSE_COUNTERSIGN_SIGN) && defined(WOLFCOSE_COUNTERSIGN_VERIFY)
    WOLFCOSE_COUNTERSIGNATURE counterSigner;
    uint8_t csOut[512];
    size_t csOutLen = 0;
#endif

    (void)printf("=== wolfCOSE WOLFCOSE_NO_LOCAL_SIGN Tests ===\n");

    ret = wc_InitRng(&rng);
    NLS_ASSERT(ret == 0, "rng init");
    if (ret == 0) {
        rngInited = 1;
        ret = wc_ecc_init(&eccKey);
        NLS_ASSERT(ret == 0, "ecc init");
    }
    if (ret == 0) {
        eccInited = 1;
        ret = wc_ecc_make_key(&rng, 32, &eccKey);
        NLS_ASSERT(ret == 0, "ecc keygen");
    }
    if (ret == 0) {
        (void)wc_CoseKey_Init(&localKey);
        ret = wc_CoseKey_SetEcc(&localKey, WOLFCOSE_CRV_P256, &eccKey);
        NLS_ASSERT(ret == 0, "local key set");
    }
    if (ret == 0) {
        ret = wc_CoseSign1_Sign(&localKey, WOLFCOSE_ALG_ESP256, NULL, 0,
            payload, sizeof(payload) - 1u, NULL, 0, NULL, 0,
            scratch, sizeof(scratch), out, sizeof(out), &outLen, &rng);
        NLS_ASSERT(ret == WOLFCOSE_E_COSE_KEY_TYPE,
                   "Sign1 refuses a local private key");
        ret = 0;
    }
#if defined(WOLFCOSE_SIGN_SIGN)
    if (ret == 0) {
        (void)memset(&signer, 0, sizeof(signer));
        signer.algId = WOLFCOSE_ALG_ESP256;
        signer.key = &localKey;
        ret = wc_CoseSign_Sign(&signer, 1u, payload, sizeof(payload) - 1u,
            NULL, 0, NULL, 0, scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        NLS_ASSERT(ret == WOLFCOSE_E_COSE_KEY_TYPE,
                   "Sign refuses a local private key");
        ret = 0;
    }
#endif
    if (ret == 0) {
        se.rng = &rng;
        se.key = &eccKey;
        (void)wc_CoseKey_Init(&extKey);
        ret = wc_CoseKey_SetEcc(&extKey, WOLFCOSE_CRV_P256, &eccKey);
        if (ret == 0) {
            ret = wc_CoseKey_SetExtSigner(&extKey, nls_sign_cb, &se);
        }
        NLS_ASSERT(ret == 0, "external signer attached");
    }
    if (ret == 0) {
        ret = wc_CoseSign1_Sign(&extKey, WOLFCOSE_ALG_ESP256, NULL, 0,
            payload, sizeof(payload) - 1u, NULL, 0, NULL, 0,
            scratch, sizeof(scratch), out, sizeof(out), &outLen, NULL);
        NLS_ASSERT(ret == 0, "Sign1 through the external signer");
    }
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&localKey, out, outLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch), &hdr, &decPayload, &decPayloadLen);
        NLS_ASSERT(ret == 0, "Sign1 verifies");
        NLS_ASSERT((ret != 0) ||
                   ((decPayloadLen == (sizeof(payload) - 1u)) &&
                    (memcmp(decPayload, payload, decPayloadLen) == 0)),
                   "Sign1 payload round-trips");
    }
#if defined(WOLFCOSE_COUNTERSIGN_SIGN) && defined(WOLFCOSE_COUNTERSIGN_VERIFY)
    if (ret == 0) {
        (void)memset(&counterSigner, 0, sizeof(counterSigner));
        counterSigner.algId = WOLFCOSE_ALG_ESP256;
        counterSigner.key = &localKey;
        ret = wc_Cose_AddCounterSignature(&counterSigner, out, outLen,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch),
            csOut, sizeof(csOut), &csOutLen, &rng);
        NLS_ASSERT(ret == WOLFCOSE_E_COSE_KEY_TYPE,
                   "countersign refuses a local private key");
        ret = 0;
    }
    if (ret == 0) {
        counterSigner.key = &extKey;
        ret = wc_Cose_AddCounterSignature(&counterSigner, out, outLen,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch),
            csOut, sizeof(csOut), &csOutLen, NULL);
        NLS_ASSERT(ret == 0, "countersignature through the external signer");
    }
    if (ret == 0) {
        ret = wc_Cose_VerifyCounterSignature(&localKey, 0u, csOut, csOutLen,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr);
        NLS_ASSERT(ret == 0, "countersignature verifies");
    }
#endif
#if defined(WOLFCOSE_SIGN_SIGN) && defined(WOLFCOSE_SIGN_VERIFY)
    if (ret == 0) {
        signer.key = &extKey;
        ret = wc_CoseSign_Sign(&signer, 1u, payload, sizeof(payload) - 1u,
            NULL, 0, NULL, 0, scratch, sizeof(scratch),
            out, sizeof(out), &outLen, NULL);
        NLS_ASSERT(ret == 0, "Sign through the external signer");
    }
    if (ret == 0) {
        ret = wc_CoseSign_Verify(&localKey, 0u, out, outLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch), &hdr, &decPayload, &decPayloadLen);
        NLS_ASSERT(ret == 0, "Sign verifies");
    }
#endif

    if (eccInited != 0) {
        (void)wc_ecc_free(&eccKey);
    }
    if (rngInited != 0) {
        (void)wc_FreeRng(&rng);
    }
    (void)printf("=== Results: %s ===\n",
                 (g_failures == 0) ? "ALL PASSED" : "FAILURES");
    return (g_failures == 0) ? 0 : 1;
}
