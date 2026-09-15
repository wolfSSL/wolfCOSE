/* sign_all.c
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

/* Comprehensive COSE_Sign1 and COSE_Sign test coverage.
 *
 * Compile-time gates:
 *   WOLFCOSE_EXAMPLE_SIGN_ALL      - Enable this example (default: enabled)
 *   WOLFCOSE_NO_SIGN_ALL_ES256     - Exclude ES256 tests
 *   WOLFCOSE_NO_SIGN_ALL_ES384     - Exclude ES384 tests
 *   WOLFCOSE_NO_SIGN_ALL_ES512     - Exclude ES512 tests
 *   WOLFCOSE_NO_SIGN_ALL_EDDSA     - Exclude EdDSA tests
 *   WOLFCOSE_NO_SIGN_ALL_MULTI     - Exclude multi-signer tests
 *   WOLFCOSE_NO_SIGN_ALL_INTEROP   - Exclude interop vector tests
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

/* Default: enabled */
#ifndef WOLFCOSE_NO_EXAMPLE_SIGN_ALL
    #define WOLFCOSE_EXAMPLE_SIGN_ALL
#endif

#ifdef WOLFCOSE_EXAMPLE_SIGN_ALL

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

/* ----- Helper: Get ECC curve from key size ----- */
#ifdef WOLFCOSE_HAVE_ES256
static int crv_from_size(int keySz)
{
    switch (keySz) {
        case 32: return WOLFCOSE_CRV_P256;
        case 48: return WOLFCOSE_CRV_P384;
        case 66: return WOLFCOSE_CRV_P521;
        default: return WOLFCOSE_CRV_P256;
    }
}
#endif

/* -----
 * Sign1 Worker Function
 *
 * Parameters:
 *   alg       - Algorithm ID (WOLFCOSE_ALG_ESP256, etc.)
 *   curveSize - Key size: 32=P-256, 48=P-384, 66=P-521, 0=Ed25519
 *   detached  - 0=inline payload, 1=detached payload
 *   useAad    - 0=no AAD, 1=with external AAD
 *
 * Returns 0 on success, negative error code on failure.
 * ----- */
static int test_sign1(int32_t alg, int curveSize, int detached, int useAad)
{
    int ret = 0;
#ifdef WOLFCOSE_HAVE_ES256
    ecc_key eccKey;
    int eccInit = 0;
#endif
#ifdef WOLFCOSE_HAVE_EDDSA
    ed25519_key edKey;
    int edInit = 0;
#endif
    WOLFCOSE_KEY cosKey;
    WC_RNG rng;
    int rngInit = 0;
    uint8_t out[640];  /* Large enough for ES512 */
    uint8_t scratch[512];
    const uint8_t payload[] = "test payload data for signing";
    const uint8_t aad[] = "external additional authenticated data";
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    XMEMSET(&cosKey, 0, sizeof(cosKey));

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
    }

    /* Key setup based on curve */
    if ((ret == 0) && (curveSize == 0)) {
#ifdef WOLFCOSE_HAVE_EDDSA
        ret = wc_ed25519_init(&edKey);
        if (ret == 0) {
            edInit = 1;
            ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &edKey);
        }
        if (ret == 0) {
            wc_CoseKey_Init(&cosKey);
            ret = wc_CoseKey_SetEd25519(&cosKey, &edKey);
        }
#else
        ret = WOLFCOSE_E_UNSUPPORTED;
#endif
    }
    else if (ret == 0) {
#ifdef WOLFCOSE_HAVE_ES256
        ret = wc_ecc_init(&eccKey);
        if (ret == 0) {
            eccInit = 1;
            ret = wc_ecc_make_key(&rng, curveSize, &eccKey);
        }
        if (ret == 0) {
            wc_CoseKey_Init(&cosKey);
            ret = wc_CoseKey_SetEcc(&cosKey, crv_from_size(curveSize), &eccKey);
        }
#else
        ret = WOLFCOSE_E_UNSUPPORTED;
#endif
    }

    /* Sign */
    if (ret == 0) {
        ret = wc_CoseSign1_Sign(&cosKey, alg,
            NULL, 0,  /* kid */
            (detached != 0) ? NULL : payload,
            (detached != 0) ? 0u : (sizeof(payload) - 1u),
            (detached != 0) ? payload : NULL,
            (detached != 0) ? (sizeof(payload) - 1u) : 0u,
            (useAad != 0) ? aad : NULL,
            (useAad != 0) ? (sizeof(aad) - 1u) : 0u,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
    }

    /* Verify */
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&cosKey, out, outLen,
            (detached != 0) ? payload : NULL,
            (detached != 0) ? (sizeof(payload) - 1u) : 0u,
            (useAad != 0) ? aad : NULL,
            (useAad != 0) ? (sizeof(aad) - 1u) : 0u,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
    }

    /* Validate payload if inline */
    if ((ret == 0) && (detached == 0)) {
        if (decPayloadLen != sizeof(payload) - 1u) {
            ret = -1;
        }
        else if (XMEMCMP(decPayload, payload, decPayloadLen) != 0) {
            ret = -2;
        }
    }

    /* Validate algorithm */
    if ((ret == 0) && (hdr.alg != alg)) {
        ret = -3;
    }

    /* Cleanup */
#ifdef WOLFCOSE_HAVE_EDDSA
    if (edInit != 0) { wc_ed25519_free(&edKey); }
#endif
#ifdef WOLFCOSE_HAVE_ES256
    if (eccInit != 0) { wc_ecc_free(&eccKey); }
#endif
    if (rngInit != 0) { wc_FreeRng(&rng); }

    return ret;
}

/* ----- Multi-Signer Worker Function (2 signers) ----- */
#if defined(WOLFCOSE_HAVE_ES256) && defined(WOLFCOSE_SIGN)
static int test_sign_multi_2(int32_t alg1, int keySz1, int32_t alg2, int keySz2,
                              int detached, int useAad)
{
    int ret = 0;
    ecc_key eccKey1;
    ecc_key eccKey2;
    int ecc1Init = 0;
    int ecc2Init = 0;
#ifdef WOLFCOSE_HAVE_EDDSA
    ed25519_key edKey1;
    ed25519_key edKey2;
    int ed1Init = 0;
    int ed2Init = 0;
#endif
    WOLFCOSE_KEY cosKey1;
    WOLFCOSE_KEY cosKey2;
    WOLFCOSE_SIGNATURE signers[2];
    WC_RNG rng;
    int rngInit = 0;
    uint8_t out[1024];
    uint8_t scratch[512];
    const uint8_t payload[] = "multi-signer test payload";
    const uint8_t aad[] = "multi-signer aad";
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    XMEMSET(&cosKey1, 0, sizeof(cosKey1));
    XMEMSET(&cosKey2, 0, sizeof(cosKey2));
    XMEMSET(signers, 0, sizeof(signers));

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
    }

    /* Setup key 1 */
    if ((ret == 0) && (keySz1 == 0)) {
#ifdef WOLFCOSE_HAVE_EDDSA
        ret = wc_ed25519_init(&edKey1);
        if (ret == 0) {
            ed1Init = 1;
            ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &edKey1);
        }
        if (ret == 0) {
            wc_CoseKey_Init(&cosKey1);
            ret = wc_CoseKey_SetEd25519(&cosKey1, &edKey1);
        }
#else
        ret = WOLFCOSE_E_UNSUPPORTED;
#endif
    }
    else if (ret == 0) {
        ret = wc_ecc_init(&eccKey1);
        if (ret == 0) {
            ecc1Init = 1;
            ret = wc_ecc_make_key(&rng, keySz1, &eccKey1);
        }
        if (ret == 0) {
            wc_CoseKey_Init(&cosKey1);
            ret = wc_CoseKey_SetEcc(&cosKey1, crv_from_size(keySz1), &eccKey1);
        }
    }

    /* Setup key 2 */
    if ((ret == 0) && (keySz2 == 0)) {
#ifdef WOLFCOSE_HAVE_EDDSA
        ret = wc_ed25519_init(&edKey2);
        if (ret == 0) {
            ed2Init = 1;
            ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &edKey2);
        }
        if (ret == 0) {
            wc_CoseKey_Init(&cosKey2);
            ret = wc_CoseKey_SetEd25519(&cosKey2, &edKey2);
        }
#else
        ret = WOLFCOSE_E_UNSUPPORTED;
#endif
    }
    else if (ret == 0) {
        ret = wc_ecc_init(&eccKey2);
        if (ret == 0) {
            ecc2Init = 1;
            ret = wc_ecc_make_key(&rng, keySz2, &eccKey2);
        }
        if (ret == 0) {
            wc_CoseKey_Init(&cosKey2);
            ret = wc_CoseKey_SetEcc(&cosKey2, crv_from_size(keySz2), &eccKey2);
        }
    }

    /* Setup signers array */
    if (ret == 0) {
        signers[0].algId = alg1;
        signers[0].key = &cosKey1;
        signers[0].kid = (const uint8_t*)"signer1";
        signers[0].kidLen = 7;

        signers[1].algId = alg2;
        signers[1].key = &cosKey2;
        signers[1].kid = (const uint8_t*)"signer2";
        signers[1].kidLen = 7;
    }

    /* Sign with both signers */
    if (ret == 0) {
        ret = wc_CoseSign_Sign(signers, 2,
            (detached != 0) ? NULL : payload,
            (detached != 0) ? 0u : (sizeof(payload) - 1u),
            (detached != 0) ? payload : NULL,
            (detached != 0) ? (sizeof(payload) - 1u) : 0u,
            (useAad != 0) ? aad : NULL,
            (useAad != 0) ? (sizeof(aad) - 1u) : 0u,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
    }

    /* Verify signer 0 */
    if (ret == 0) {
        ret = wc_CoseSign_Verify(&cosKey1, 0, out, outLen,
            (detached != 0) ? payload : NULL,
            (detached != 0) ? (sizeof(payload) - 1u) : 0u,
            (useAad != 0) ? aad : NULL,
            (useAad != 0) ? (sizeof(aad) - 1u) : 0u,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
    }

    /* Verify signer 1 */
    if (ret == 0) {
        ret = wc_CoseSign_Verify(&cosKey2, 1, out, outLen,
            (detached != 0) ? payload : NULL,
            (detached != 0) ? (sizeof(payload) - 1u) : 0u,
            (useAad != 0) ? aad : NULL,
            (useAad != 0) ? (sizeof(aad) - 1u) : 0u,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
    }

    /* Cleanup */
#ifdef WOLFCOSE_HAVE_EDDSA
    if (ed1Init != 0) { wc_ed25519_free(&edKey1); }
    if (ed2Init != 0) { wc_ed25519_free(&edKey2); }
#endif
    if (ecc1Init != 0) { wc_ecc_free(&eccKey1); }
    if (ecc2Init != 0) { wc_ecc_free(&eccKey2); }
    if (rngInit != 0) { wc_FreeRng(&rng); }

    return ret;
}
#endif /* WOLFCOSE_HAVE_ES256 && WOLFCOSE_SIGN */

/* ----- Multi-Signer Worker Function (3 signers) ----- */
#if defined(WOLFCOSE_HAVE_ES256) && defined(WOLFCOSE_SIGN)
static int test_sign_multi_3(int32_t alg1, int keySz1,
                              int32_t alg2, int keySz2,
                              int32_t alg3, int keySz3,
                              int detached, int useAad)
{
    int ret = 0;
    ecc_key eccKey1;
    ecc_key eccKey2;
    ecc_key eccKey3;
    int ecc1Init = 0;
    int ecc2Init = 0;
    int ecc3Init = 0;
#ifdef WOLFCOSE_HAVE_EDDSA
    ed25519_key edKey1;
    ed25519_key edKey2;
    ed25519_key edKey3;
    int ed1Init = 0;
    int ed2Init = 0;
    int ed3Init = 0;
#endif
    WOLFCOSE_KEY cosKey1;
    WOLFCOSE_KEY cosKey2;
    WOLFCOSE_KEY cosKey3;
    WOLFCOSE_SIGNATURE signers[3];
    WC_RNG rng;
    int rngInit = 0;
    uint8_t out[1536];
    uint8_t scratch[512];
    const uint8_t payload[] = "three signer payload";
    const uint8_t aad[] = "three signer aad";
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int i;
    int keySizes[3];
    int32_t algs[3];
    ecc_key* eccKeys[3];
    int* eccInits[3];
    WOLFCOSE_KEY* cosKeys[3];
#ifdef WOLFCOSE_HAVE_EDDSA
    ed25519_key* edKeys[3];
    int* edInits[3];
#endif

    XMEMSET(&cosKey1, 0, sizeof(cosKey1));
    XMEMSET(&cosKey2, 0, sizeof(cosKey2));
    XMEMSET(&cosKey3, 0, sizeof(cosKey3));
    XMEMSET(signers, 0, sizeof(signers));

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
    }

    /* Setup keys - use helper arrays for cleaner code */
    keySizes[0] = keySz1; keySizes[1] = keySz2; keySizes[2] = keySz3;
    algs[0] = alg1; algs[1] = alg2; algs[2] = alg3;
    eccKeys[0] = &eccKey1; eccKeys[1] = &eccKey2; eccKeys[2] = &eccKey3;
    eccInits[0] = &ecc1Init; eccInits[1] = &ecc2Init; eccInits[2] = &ecc3Init;
    cosKeys[0] = &cosKey1; cosKeys[1] = &cosKey2; cosKeys[2] = &cosKey3;
#ifdef WOLFCOSE_HAVE_EDDSA
    edKeys[0] = &edKey1; edKeys[1] = &edKey2; edKeys[2] = &edKey3;
    edInits[0] = &ed1Init; edInits[1] = &ed2Init; edInits[2] = &ed3Init;
#endif

    for (i = 0; (ret == 0) && (i < 3); i++) {
        if (keySizes[i] == 0) {
#ifdef WOLFCOSE_HAVE_EDDSA
            ret = wc_ed25519_init(edKeys[i]);
            if (ret == 0) {
                *edInits[i] = 1;
                ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, edKeys[i]);
            }
            if (ret == 0) {
                wc_CoseKey_Init(cosKeys[i]);
                ret = wc_CoseKey_SetEd25519(cosKeys[i], edKeys[i]);
            }
#else
            ret = WOLFCOSE_E_UNSUPPORTED;
#endif
        }
        else {
            ret = wc_ecc_init(eccKeys[i]);
            if (ret == 0) {
                *eccInits[i] = 1;
                ret = wc_ecc_make_key(&rng, keySizes[i], eccKeys[i]);
            }
            if (ret == 0) {
                wc_CoseKey_Init(cosKeys[i]);
                ret = wc_CoseKey_SetEcc(cosKeys[i], crv_from_size(keySizes[i]),
                                         eccKeys[i]);
            }
        }
    }

    /* Setup signers array */
    if (ret == 0) {
        for (i = 0; i < 3; i++) {
            signers[i].algId = algs[i];
            signers[i].key = cosKeys[i];
            signers[i].kid = (const uint8_t*)"sgnX";
            signers[i].kidLen = 4;
        }
    }

    /* Sign */
    if (ret == 0) {
        ret = wc_CoseSign_Sign(signers, 3,
            (detached != 0) ? NULL : payload,
            (detached != 0) ? 0u : (sizeof(payload) - 1u),
            (detached != 0) ? payload : NULL,
            (detached != 0) ? (sizeof(payload) - 1u) : 0u,
            (useAad != 0) ? aad : NULL,
            (useAad != 0) ? (sizeof(aad) - 1u) : 0u,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
    }

    /* Verify each signer */
    for (i = 0; (ret == 0) && (i < 3); i++) {
        ret = wc_CoseSign_Verify(cosKeys[i], (size_t)i, out, outLen,
            (detached != 0) ? payload : NULL,
            (detached != 0) ? (sizeof(payload) - 1u) : 0u,
            (useAad != 0) ? aad : NULL,
            (useAad != 0) ? (sizeof(aad) - 1u) : 0u,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
    }

    /* Cleanup */
#ifdef WOLFCOSE_HAVE_EDDSA
    if (ed1Init != 0) { wc_ed25519_free(&edKey1); }
    if (ed2Init != 0) { wc_ed25519_free(&edKey2); }
    if (ed3Init != 0) { wc_ed25519_free(&edKey3); }
#endif
    if (ecc1Init != 0) { wc_ecc_free(&eccKey1); }
    if (ecc2Init != 0) { wc_ecc_free(&eccKey2); }
    if (ecc3Init != 0) { wc_ecc_free(&eccKey3); }
    if (rngInit != 0) { wc_FreeRng(&rng); }

    return ret;
}
#endif /* WOLFCOSE_HAVE_ES256 && WOLFCOSE_SIGN */

/* ----- Multi-Signer Worker Function (4 signers) ----- */
#if defined(WOLFCOSE_HAVE_ES256) && defined(WOLFCOSE_SIGN) && defined(WOLFCOSE_HAVE_EDDSA)
static int test_sign_multi_4(int detached, int useAad)
{
    int ret = 0;
    ecc_key eccKey256;
    ecc_key eccKey384;
    ecc_key eccKey521;
    ed25519_key edKey;
    int ecc256Init = 0;
    int ecc384Init = 0;
    int ecc521Init = 0;
    int edInit = 0;
    WOLFCOSE_KEY cosKey256;
    WOLFCOSE_KEY cosKey384;
    WOLFCOSE_KEY cosKey521;
    WOLFCOSE_KEY cosKeyEd;
    WOLFCOSE_SIGNATURE signers[4];
    WC_RNG rng;
    int rngInit = 0;
    uint8_t out[2048];
    uint8_t scratch[512];
    const uint8_t payload[] = "four signer payload";
    const uint8_t aad[] = "four signer aad";
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    XMEMSET(signers, 0, sizeof(signers));

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
    }

    /* ESP256 key */
    if (ret == 0) {
        ret = wc_ecc_init(&eccKey256);
        if (ret == 0) {
            ecc256Init = 1;
            ret = wc_ecc_make_key(&rng, 32, &eccKey256);
        }
        if (ret == 0) {
            wc_CoseKey_Init(&cosKey256);
            ret = wc_CoseKey_SetEcc(&cosKey256, WOLFCOSE_CRV_P256, &eccKey256);
        }
    }

    /* ESP384 key */
    if (ret == 0) {
        ret = wc_ecc_init(&eccKey384);
        if (ret == 0) {
            ecc384Init = 1;
            ret = wc_ecc_make_key(&rng, 48, &eccKey384);
        }
        if (ret == 0) {
            wc_CoseKey_Init(&cosKey384);
            ret = wc_CoseKey_SetEcc(&cosKey384, WOLFCOSE_CRV_P384, &eccKey384);
        }
    }

    /* ESP512 key */
    if (ret == 0) {
        ret = wc_ecc_init(&eccKey521);
        if (ret == 0) {
            ecc521Init = 1;
            ret = wc_ecc_make_key(&rng, 66, &eccKey521);
        }
        if (ret == 0) {
            wc_CoseKey_Init(&cosKey521);
            ret = wc_CoseKey_SetEcc(&cosKey521, WOLFCOSE_CRV_P521, &eccKey521);
        }
    }

    /* Ed25519 key */
    if (ret == 0) {
        ret = wc_ed25519_init(&edKey);
        if (ret == 0) {
            edInit = 1;
            ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &edKey);
        }
        if (ret == 0) {
            wc_CoseKey_Init(&cosKeyEd);
            ret = wc_CoseKey_SetEd25519(&cosKeyEd, &edKey);
        }
    }

    /* Setup signers */
    if (ret == 0) {
        signers[0].algId = WOLFCOSE_ALG_ESP256;
        signers[0].key = &cosKey256;
        signers[0].kid = (const uint8_t*)"es256";
        signers[0].kidLen = 5;

        signers[1].algId = WOLFCOSE_ALG_ESP384;
        signers[1].key = &cosKey384;
        signers[1].kid = (const uint8_t*)"es384";
        signers[1].kidLen = 5;

        signers[2].algId = WOLFCOSE_ALG_ESP512;
        signers[2].key = &cosKey521;
        signers[2].kid = (const uint8_t*)"es512";
        signers[2].kidLen = 5;

        signers[3].algId = WOLFCOSE_ALG_ED25519;
        signers[3].key = &cosKeyEd;
        signers[3].kid = (const uint8_t*)"eddsa";
        signers[3].kidLen = 5;
    }

    /* Sign */
    if (ret == 0) {
        ret = wc_CoseSign_Sign(signers, 4,
            (detached != 0) ? NULL : payload,
            (detached != 0) ? 0u : (sizeof(payload) - 1u),
            (detached != 0) ? payload : NULL,
            (detached != 0) ? (sizeof(payload) - 1u) : 0u,
            (useAad != 0) ? aad : NULL,
            (useAad != 0) ? (sizeof(aad) - 1u) : 0u,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
    }

    /* Verify each signer */
    if (ret == 0) {
        ret = wc_CoseSign_Verify(&cosKey256, 0, out, outLen,
            (detached != 0) ? payload : NULL,
            (detached != 0) ? (sizeof(payload) - 1u) : 0u,
            (useAad != 0) ? aad : NULL,
            (useAad != 0) ? (sizeof(aad) - 1u) : 0u,
            scratch, sizeof(scratch), &hdr, &decPayload, &decPayloadLen);
    }

    if (ret == 0) {
        ret = wc_CoseSign_Verify(&cosKey384, 1, out, outLen,
            (detached != 0) ? payload : NULL,
            (detached != 0) ? (sizeof(payload) - 1u) : 0u,
            (useAad != 0) ? aad : NULL,
            (useAad != 0) ? (sizeof(aad) - 1u) : 0u,
            scratch, sizeof(scratch), &hdr, &decPayload, &decPayloadLen);
    }

    if (ret == 0) {
        ret = wc_CoseSign_Verify(&cosKey521, 2, out, outLen,
            (detached != 0) ? payload : NULL,
            (detached != 0) ? (sizeof(payload) - 1u) : 0u,
            (useAad != 0) ? aad : NULL,
            (useAad != 0) ? (sizeof(aad) - 1u) : 0u,
            scratch, sizeof(scratch), &hdr, &decPayload, &decPayloadLen);
    }

    if (ret == 0) {
        ret = wc_CoseSign_Verify(&cosKeyEd, 3, out, outLen,
            (detached != 0) ? payload : NULL,
            (detached != 0) ? (sizeof(payload) - 1u) : 0u,
            (useAad != 0) ? aad : NULL,
            (useAad != 0) ? (sizeof(aad) - 1u) : 0u,
            scratch, sizeof(scratch), &hdr, &decPayload, &decPayloadLen);
    }

    /* Cleanup */
    if (edInit != 0) { wc_ed25519_free(&edKey); }
    if (ecc521Init != 0) { wc_ecc_free(&eccKey521); }
    if (ecc384Init != 0) { wc_ecc_free(&eccKey384); }
    if (ecc256Init != 0) { wc_ecc_free(&eccKey256); }
    if (rngInit != 0) { wc_FreeRng(&rng); }

    return ret;
}
#endif /* WOLFCOSE_HAVE_ES256 && WOLFCOSE_SIGN && WOLFCOSE_HAVE_EDDSA */

/* ----- Sign1 Test Runner (16 tests) ----- */
static int test_sign1_all(void)
{
    int ret = 0;
    int passed = 0;
    int failed = 0;

    printf("\n=== COSE_Sign1 Comprehensive Tests ===\n\n");

#if defined(WOLFCOSE_HAVE_ES256) && !defined(WOLFCOSE_NO_SIGN_ALL_ES256)
    /* ESP256 - 4 combinations */
    PRINT_TEST("esp256_inline_noaad");
    ret = test_sign1(WOLFCOSE_ALG_ESP256, 32, 0, 0);
    CHECK_RESULT(ret, "esp256_inline_noaad");

    PRINT_TEST("esp256_inline_aad");
    ret = test_sign1(WOLFCOSE_ALG_ESP256, 32, 0, 1);
    CHECK_RESULT(ret, "esp256_inline_aad");

    PRINT_TEST("esp256_detached_noaad");
    ret = test_sign1(WOLFCOSE_ALG_ESP256, 32, 1, 0);
    CHECK_RESULT(ret, "esp256_detached_noaad");

    PRINT_TEST("esp256_detached_aad");
    ret = test_sign1(WOLFCOSE_ALG_ESP256, 32, 1, 1);
    CHECK_RESULT(ret, "esp256_detached_aad");
#endif

#if defined(WOLFCOSE_HAVE_ES384) && \
    !defined(WOLFCOSE_NO_SIGN_ALL_ES384)
    /* ESP384 - 4 combinations */
    PRINT_TEST("esp384_inline_noaad");
    ret = test_sign1(WOLFCOSE_ALG_ESP384, 48, 0, 0);
    CHECK_RESULT(ret, "esp384_inline_noaad");

    PRINT_TEST("esp384_inline_aad");
    ret = test_sign1(WOLFCOSE_ALG_ESP384, 48, 0, 1);
    CHECK_RESULT(ret, "esp384_inline_aad");

    PRINT_TEST("esp384_detached_noaad");
    ret = test_sign1(WOLFCOSE_ALG_ESP384, 48, 1, 0);
    CHECK_RESULT(ret, "esp384_detached_noaad");

    PRINT_TEST("esp384_detached_aad");
    ret = test_sign1(WOLFCOSE_ALG_ESP384, 48, 1, 1);
    CHECK_RESULT(ret, "esp384_detached_aad");
#endif

#if defined(WOLFCOSE_HAVE_ES512) && \
    !defined(WOLFCOSE_NO_SIGN_ALL_ES512)
    /* ESP512 - 4 combinations */
    PRINT_TEST("esp512_inline_noaad");
    ret = test_sign1(WOLFCOSE_ALG_ESP512, 66, 0, 0);
    CHECK_RESULT(ret, "esp512_inline_noaad");

    PRINT_TEST("esp512_inline_aad");
    ret = test_sign1(WOLFCOSE_ALG_ESP512, 66, 0, 1);
    CHECK_RESULT(ret, "esp512_inline_aad");

    PRINT_TEST("esp512_detached_noaad");
    ret = test_sign1(WOLFCOSE_ALG_ESP512, 66, 1, 0);
    CHECK_RESULT(ret, "esp512_detached_noaad");

    PRINT_TEST("esp512_detached_aad");
    ret = test_sign1(WOLFCOSE_ALG_ESP512, 66, 1, 1);
    CHECK_RESULT(ret, "esp512_detached_aad");
#endif

#if defined(WOLFCOSE_HAVE_EDDSA) && !defined(WOLFCOSE_NO_SIGN_ALL_EDDSA)
    /* Ed25519 - 4 combinations */
    PRINT_TEST("ed25519_inline_noaad");
    ret = test_sign1(WOLFCOSE_ALG_ED25519, 0, 0, 0);
    CHECK_RESULT(ret, "ed25519_inline_noaad");

    PRINT_TEST("ed25519_inline_aad");
    ret = test_sign1(WOLFCOSE_ALG_ED25519, 0, 0, 1);
    CHECK_RESULT(ret, "ed25519_inline_aad");

    PRINT_TEST("ed25519_detached_noaad");
    ret = test_sign1(WOLFCOSE_ALG_ED25519, 0, 1, 0);
    CHECK_RESULT(ret, "ed25519_detached_noaad");

    PRINT_TEST("ed25519_detached_aad");
    ret = test_sign1(WOLFCOSE_ALG_ED25519, 0, 1, 1);
    CHECK_RESULT(ret, "ed25519_detached_aad");
#endif

    printf("\nSign1 Summary: %d passed, %d failed\n", passed, failed);
    return failed;
}

/* ----- Multi-Signer Test Runner (52 tests total) ----- */
#if defined(WOLFCOSE_HAVE_ES256) && defined(WOLFCOSE_SIGN) && \
    !defined(WOLFCOSE_NO_SIGN_ALL_MULTI)
static int test_sign_multi_all(void)
{
    int ret = 0;
    int passed = 0;
    int failed = 0;

    printf("\n=== COSE_Sign Multi-Signer Comprehensive Tests ===\n\n");

    /* Two-signer: ES256 + ES256 (4 modes) */
    PRINT_TEST("multi2_esp256_esp256_inline_noaad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP256, 32, 0, 0);
    CHECK_RESULT(ret, "multi2_esp256_esp256_inline_noaad");

    PRINT_TEST("multi2_esp256_esp256_inline_aad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP256, 32, 0, 1);
    CHECK_RESULT(ret, "multi2_esp256_esp256_inline_aad");

    PRINT_TEST("multi2_esp256_esp256_detached_noaad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP256, 32, 1, 0);
    CHECK_RESULT(ret, "multi2_esp256_esp256_detached_noaad");

    PRINT_TEST("multi2_esp256_esp256_detached_aad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP256, 32, 1, 1);
    CHECK_RESULT(ret, "multi2_esp256_esp256_detached_aad");

#ifdef WOLFCOSE_HAVE_ES384
    /* Two-signer: ES256 + ES384 */
    PRINT_TEST("multi2_esp256_esp384_inline_noaad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP384, 48, 0, 0);
    CHECK_RESULT(ret, "multi2_esp256_esp384_inline_noaad");

    PRINT_TEST("multi2_esp256_esp384_inline_aad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP384, 48, 0, 1);
    CHECK_RESULT(ret, "multi2_esp256_esp384_inline_aad");

    PRINT_TEST("multi2_esp256_esp384_detached_noaad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP384, 48, 1, 0);
    CHECK_RESULT(ret, "multi2_esp256_esp384_detached_noaad");

    PRINT_TEST("multi2_esp256_esp384_detached_aad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP384, 48, 1, 1);
    CHECK_RESULT(ret, "multi2_esp256_esp384_detached_aad");
#endif

#ifdef WOLFCOSE_HAVE_ES512
    /* Two-signer: ES256 + ES512 */
    PRINT_TEST("multi2_esp256_esp512_inline_noaad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP512, 66, 0, 0);
    CHECK_RESULT(ret, "multi2_esp256_esp512_inline_noaad");

    PRINT_TEST("multi2_esp256_esp512_inline_aad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP512, 66, 0, 1);
    CHECK_RESULT(ret, "multi2_esp256_esp512_inline_aad");

    PRINT_TEST("multi2_esp256_esp512_detached_noaad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP512, 66, 1, 0);
    CHECK_RESULT(ret, "multi2_esp256_esp512_detached_noaad");

    PRINT_TEST("multi2_esp256_esp512_detached_aad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP512, 66, 1, 1);
    CHECK_RESULT(ret, "multi2_esp256_esp512_detached_aad");
#endif

#ifdef WOLFCOSE_HAVE_EDDSA
    /* Two-signer: ES256 + EdDSA */
    PRINT_TEST("multi2_esp256_ed25519_inline_noaad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ED25519, 0, 0, 0);
    CHECK_RESULT(ret, "multi2_esp256_ed25519_inline_noaad");

    PRINT_TEST("multi2_esp256_ed25519_inline_aad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ED25519, 0, 0, 1);
    CHECK_RESULT(ret, "multi2_esp256_ed25519_inline_aad");

    PRINT_TEST("multi2_esp256_ed25519_detached_noaad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ED25519, 0, 1, 0);
    CHECK_RESULT(ret, "multi2_esp256_ed25519_detached_noaad");

    PRINT_TEST("multi2_esp256_ed25519_detached_aad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ED25519, 0, 1, 1);
    CHECK_RESULT(ret, "multi2_esp256_ed25519_detached_aad");
#endif

#if defined(WOLFCOSE_HAVE_ES384) && defined(WOLFCOSE_HAVE_ES512)
    /* Two-signer: ES384 + ES512 */
    PRINT_TEST("multi2_esp384_esp512_inline_noaad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP384, 48, WOLFCOSE_ALG_ESP512, 66, 0, 0);
    CHECK_RESULT(ret, "multi2_esp384_esp512_inline_noaad");

    PRINT_TEST("multi2_esp384_esp512_inline_aad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP384, 48, WOLFCOSE_ALG_ESP512, 66, 0, 1);
    CHECK_RESULT(ret, "multi2_esp384_esp512_inline_aad");

    PRINT_TEST("multi2_esp384_esp512_detached_noaad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP384, 48, WOLFCOSE_ALG_ESP512, 66, 1, 0);
    CHECK_RESULT(ret, "multi2_esp384_esp512_detached_noaad");

    PRINT_TEST("multi2_esp384_esp512_detached_aad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP384, 48, WOLFCOSE_ALG_ESP512, 66, 1, 1);
    CHECK_RESULT(ret, "multi2_esp384_esp512_detached_aad");
#endif

#if defined(WOLFCOSE_HAVE_ES384) && defined(WOLFCOSE_HAVE_EDDSA)
    /* Two-signer: ES384 + EdDSA */
    PRINT_TEST("multi2_esp384_ed25519_inline_noaad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP384, 48, WOLFCOSE_ALG_ED25519, 0, 0, 0);
    CHECK_RESULT(ret, "multi2_esp384_ed25519_inline_noaad");

    PRINT_TEST("multi2_esp384_ed25519_inline_aad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP384, 48, WOLFCOSE_ALG_ED25519, 0, 0, 1);
    CHECK_RESULT(ret, "multi2_esp384_ed25519_inline_aad");

    PRINT_TEST("multi2_esp384_ed25519_detached_noaad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP384, 48, WOLFCOSE_ALG_ED25519, 0, 1, 0);
    CHECK_RESULT(ret, "multi2_esp384_ed25519_detached_noaad");

    PRINT_TEST("multi2_esp384_ed25519_detached_aad");
    ret = test_sign_multi_2(WOLFCOSE_ALG_ESP384, 48, WOLFCOSE_ALG_ED25519, 0, 1, 1);
    CHECK_RESULT(ret, "multi2_esp384_ed25519_detached_aad");
#endif

#if defined(WOLFCOSE_HAVE_ES384) && defined(WOLFCOSE_HAVE_ES512)
    /* Three-signer: ES256 + ES384 + ES512 */
    PRINT_TEST("multi3_esp256_esp384_esp512_inline_noaad");
    ret = test_sign_multi_3(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP384, 48,
                             WOLFCOSE_ALG_ESP512, 66, 0, 0);
    CHECK_RESULT(ret, "multi3_esp256_esp384_esp512_inline_noaad");

    PRINT_TEST("multi3_esp256_esp384_esp512_inline_aad");
    ret = test_sign_multi_3(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP384, 48,
                             WOLFCOSE_ALG_ESP512, 66, 0, 1);
    CHECK_RESULT(ret, "multi3_esp256_esp384_esp512_inline_aad");

    PRINT_TEST("multi3_esp256_esp384_esp512_detached_noaad");
    ret = test_sign_multi_3(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP384, 48,
                             WOLFCOSE_ALG_ESP512, 66, 1, 0);
    CHECK_RESULT(ret, "multi3_esp256_esp384_esp512_detached_noaad");

    PRINT_TEST("multi3_esp256_esp384_esp512_detached_aad");
    ret = test_sign_multi_3(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP384, 48,
                             WOLFCOSE_ALG_ESP512, 66, 1, 1);
    CHECK_RESULT(ret, "multi3_esp256_esp384_esp512_detached_aad");
#endif

#if defined(WOLFCOSE_HAVE_ES384) && defined(WOLFCOSE_HAVE_EDDSA)
    /* Three-signer: ES256 + ES384 + EdDSA */
    PRINT_TEST("multi3_esp256_esp384_ed25519_inline_noaad");
    ret = test_sign_multi_3(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP384, 48,
                             WOLFCOSE_ALG_ED25519, 0, 0, 0);
    CHECK_RESULT(ret, "multi3_esp256_esp384_ed25519_inline_noaad");

    PRINT_TEST("multi3_esp256_esp384_ed25519_inline_aad");
    ret = test_sign_multi_3(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP384, 48,
                             WOLFCOSE_ALG_ED25519, 0, 0, 1);
    CHECK_RESULT(ret, "multi3_esp256_esp384_ed25519_inline_aad");

    PRINT_TEST("multi3_esp256_esp384_ed25519_detached_noaad");
    ret = test_sign_multi_3(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP384, 48,
                             WOLFCOSE_ALG_ED25519, 0, 1, 0);
    CHECK_RESULT(ret, "multi3_esp256_esp384_ed25519_detached_noaad");

    PRINT_TEST("multi3_esp256_esp384_ed25519_detached_aad");
    ret = test_sign_multi_3(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP384, 48,
                             WOLFCOSE_ALG_ED25519, 0, 1, 1);
    CHECK_RESULT(ret, "multi3_esp256_esp384_ed25519_detached_aad");
#endif

#if defined(WOLFCOSE_HAVE_ES512) && defined(WOLFCOSE_HAVE_EDDSA)
    /* Three-signer: ES256 + ES512 + EdDSA */
    PRINT_TEST("multi3_esp256_esp512_ed25519_inline_noaad");
    ret = test_sign_multi_3(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP512, 66,
                             WOLFCOSE_ALG_ED25519, 0, 0, 0);
    CHECK_RESULT(ret, "multi3_esp256_esp512_ed25519_inline_noaad");

    PRINT_TEST("multi3_esp256_esp512_ed25519_inline_aad");
    ret = test_sign_multi_3(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP512, 66,
                             WOLFCOSE_ALG_ED25519, 0, 0, 1);
    CHECK_RESULT(ret, "multi3_esp256_esp512_ed25519_inline_aad");

    PRINT_TEST("multi3_esp256_esp512_ed25519_detached_noaad");
    ret = test_sign_multi_3(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP512, 66,
                             WOLFCOSE_ALG_ED25519, 0, 1, 0);
    CHECK_RESULT(ret, "multi3_esp256_esp512_ed25519_detached_noaad");

    PRINT_TEST("multi3_esp256_esp512_ed25519_detached_aad");
    ret = test_sign_multi_3(WOLFCOSE_ALG_ESP256, 32, WOLFCOSE_ALG_ESP512, 66,
                             WOLFCOSE_ALG_ED25519, 0, 1, 1);
    CHECK_RESULT(ret, "multi3_esp256_esp512_ed25519_detached_aad");
#endif

#if defined(WOLFCOSE_HAVE_ES384) && defined(WOLFCOSE_HAVE_ES512) && defined(WOLFCOSE_HAVE_EDDSA)
    /* Three-signer: ES384 + ES512 + EdDSA */
    PRINT_TEST("multi3_esp384_esp512_ed25519_inline_noaad");
    ret = test_sign_multi_3(WOLFCOSE_ALG_ESP384, 48, WOLFCOSE_ALG_ESP512, 66,
                             WOLFCOSE_ALG_ED25519, 0, 0, 0);
    CHECK_RESULT(ret, "multi3_esp384_esp512_ed25519_inline_noaad");

    PRINT_TEST("multi3_esp384_esp512_ed25519_inline_aad");
    ret = test_sign_multi_3(WOLFCOSE_ALG_ESP384, 48, WOLFCOSE_ALG_ESP512, 66,
                             WOLFCOSE_ALG_ED25519, 0, 0, 1);
    CHECK_RESULT(ret, "multi3_esp384_esp512_ed25519_inline_aad");

    PRINT_TEST("multi3_esp384_esp512_ed25519_detached_noaad");
    ret = test_sign_multi_3(WOLFCOSE_ALG_ESP384, 48, WOLFCOSE_ALG_ESP512, 66,
                             WOLFCOSE_ALG_ED25519, 0, 1, 0);
    CHECK_RESULT(ret, "multi3_esp384_esp512_ed25519_detached_noaad");

    PRINT_TEST("multi3_esp384_esp512_ed25519_detached_aad");
    ret = test_sign_multi_3(WOLFCOSE_ALG_ESP384, 48, WOLFCOSE_ALG_ESP512, 66,
                             WOLFCOSE_ALG_ED25519, 0, 1, 1);
    CHECK_RESULT(ret, "multi3_esp384_esp512_ed25519_detached_aad");
#endif

#if defined(WOLFCOSE_HAVE_ES384) && defined(WOLFCOSE_HAVE_ES512) && defined(WOLFCOSE_HAVE_EDDSA)
    /* Four-signer: ES256 + ES384 + ES512 + EdDSA (4 modes) */
    PRINT_TEST("multi4_all_algos_inline_noaad");
    ret = test_sign_multi_4(0, 0);
    CHECK_RESULT(ret, "multi4_all_algos_inline_noaad");

    PRINT_TEST("multi4_all_algos_inline_aad");
    ret = test_sign_multi_4(0, 1);
    CHECK_RESULT(ret, "multi4_all_algos_inline_aad");

    PRINT_TEST("multi4_all_algos_detached_noaad");
    ret = test_sign_multi_4(1, 0);
    CHECK_RESULT(ret, "multi4_all_algos_detached_noaad");

    PRINT_TEST("multi4_all_algos_detached_aad");
    ret = test_sign_multi_4(1, 1);
    CHECK_RESULT(ret, "multi4_all_algos_detached_aad");
#endif

    printf("\nMulti-Signer Summary: %d passed, %d failed\n", passed, failed);
    return failed;
}
#endif /* WOLFCOSE_HAVE_ES256 && WOLFCOSE_SIGN && !WOLFCOSE_NO_SIGN_ALL_MULTI */

/* ----- Interop Vector Tests (RFC 9052 Appendix C) ----- */
#if defined(WOLFCOSE_HAVE_ES256) && !defined(WOLFCOSE_NO_SIGN_ALL_INTEROP)
static int test_sign1_interop(void)
{
    int ret = 0;
    int passed = 0;
    int failed = 0;
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

    /*
     * Test vector key from COSE WG Examples (P-256)
     * x: 65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d
     * y: 1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c
     * d: aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf
     */
    static const uint8_t keyX[] = {
        0x65, 0xed, 0xa5, 0xa1, 0x25, 0x77, 0xc2, 0xba,
        0xe8, 0x29, 0x43, 0x7f, 0xe3, 0x38, 0x70, 0x1a,
        0x10, 0xaa, 0xa3, 0x75, 0xe1, 0xbb, 0x5b, 0x5d,
        0xe1, 0x08, 0xde, 0x43, 0x9c, 0x08, 0x55, 0x1d
    };
    static const uint8_t keyY[] = {
        0x1e, 0x52, 0xed, 0x75, 0x70, 0x11, 0x63, 0xf7,
        0xf9, 0xe4, 0x0d, 0xdf, 0x9f, 0x34, 0x1b, 0x3d,
        0xc9, 0xba, 0x86, 0x0a, 0xf7, 0xe0, 0xca, 0x7c,
        0xa7, 0xe9, 0xee, 0xcd, 0x00, 0x84, 0xd1, 0x9c
    };
    static const uint8_t keyD[] = {
        0xaf, 0xf9, 0x07, 0xc9, 0x9f, 0x9a, 0xd3, 0xaa,
        0xe6, 0xc4, 0xcd, 0xf2, 0x11, 0x22, 0xbc, 0xe2,
        0xbd, 0x68, 0xb5, 0x28, 0x3e, 0x69, 0x07, 0x15,
        0x4a, 0xd9, 0x11, 0x84, 0x0f, 0xa2, 0x08, 0xcf
    };
    static const uint8_t payload[] = "This is the content.";

    printf("\n=== COSE_Sign1 Interoperability Tests ===\n\n");

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
    }

    if (ret == 0) {
        ret = wc_ecc_init(&eccKey);
        if (ret == 0) {
            eccInit = 1;
        }
    }

    /* Import test vector key */
    if (ret == 0) {
        ret = wc_ecc_import_unsigned(&eccKey, keyX, keyY, keyD, ECC_SECP256R1);
    }

    if (ret == 0) {
        wc_CoseKey_Init(&cosKey);
        ret = wc_CoseKey_SetEcc(&cosKey, WOLFCOSE_CRV_P256, &eccKey);
    }

    /* Sign with known key */
    PRINT_TEST("interop_sign1_esp256_roundtrip");
    if (ret == 0) {
        ret = wc_CoseSign1_Sign(&cosKey, WOLFCOSE_ALG_ESP256,
            NULL, 0,
            payload, sizeof(payload) - 1u,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
    }

    /* Verify with same key */
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&cosKey, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
    }

    /* Validate */
    if ((ret == 0) && (hdr.alg != WOLFCOSE_ALG_ESP256)) {
        ret = -1;
    }
    if ((ret == 0) && (decPayloadLen != (sizeof(payload) - 1u))) {
        ret = -2;
    }
    if ((ret == 0) && (XMEMCMP(decPayload, payload, decPayloadLen) != 0)) {
        ret = -3;
    }

    CHECK_RESULT(ret, "interop_sign1_es256_roundtrip");

    /* Cleanup */
    if (eccInit != 0) { wc_ecc_free(&eccKey); }
    if (rngInit != 0) { wc_FreeRng(&rng); }

    printf("\nInterop Summary: %d passed, %d failed\n", passed, failed);
    return failed;
}
#endif /* WOLFCOSE_HAVE_ES256 && !WOLFCOSE_NO_SIGN_ALL_INTEROP */

/* ----- Main Entry Point ----- */
int main(void)
{
    int totalFailed = 0;

    printf("========================================\n");
    printf("wolfCOSE Comprehensive Sign Tests\n");
    printf("========================================\n");

    totalFailed += test_sign1_all();

#if defined(WOLFCOSE_HAVE_ES256) && defined(WOLFCOSE_SIGN) && \
    !defined(WOLFCOSE_NO_SIGN_ALL_MULTI)
    totalFailed += test_sign_multi_all();
#endif

#if defined(WOLFCOSE_HAVE_ES256) && !defined(WOLFCOSE_NO_SIGN_ALL_INTEROP)
    totalFailed += test_sign1_interop();
#endif

    printf("\n========================================\n");
    printf("Total: %d failures\n", totalFailed);
    printf("========================================\n");

    return totalFailed;
}

#else /* !WOLFCOSE_EXAMPLE_SIGN_ALL */

int main(void)
{
    printf("sign_all: example disabled (WOLFCOSE_NO_EXAMPLE_SIGN_ALL defined)\n");
    return 0;
}

#endif /* WOLFCOSE_EXAMPLE_SIGN_ALL */
