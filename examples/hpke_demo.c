/* hpke_demo.c
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

/* Experimental COSE-HPKE P0 demonstration.
 *
 * The draft binding requires WOLFCOSE_EXPERIMENTAL plus its operation gates.
 * This program demonstrates the two currently supported P0 constructions:
 *   - HPKE-0: one-recipient COSE_Encrypt0 integrated encryption
 *   - HPKE-0-KE: COSE_Encrypt with one HPKE-protected CEK per recipient
 */

#include <stdio.h>
#include <string.h>

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#if defined(WOLFCOSE_HPKE_0_ENCRYPT) && \
    defined(WOLFCOSE_HPKE_0_DECRYPT) && \
    defined(WOLFCOSE_HPKE_0_KE_ENCRYPT) && \
    defined(WOLFCOSE_HPKE_0_KE_DECRYPT)

#define HPKE_DEMO_RECIPIENTS 2u

static int demo_hpke_encrypt0(void)
{
    static const uint8_t kid[] = "recipient-a";
    static const uint8_t payload[] = "HPKE-0 integrated encryption";
    WC_RNG rng;
    ecc_key recipient;
    WOLFCOSE_KEY recipientKey;
    WOLFCOSE_HDR hdr;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t cose[512];
    uint8_t plaintext[sizeof(payload)];
    size_t coseLen = 0u;
    size_t plaintextLen = 0u;
    int rngInit = 0;
    int eccInit = 0;
    int ret;

    printf("--- HPKE-0 COSE_Encrypt0 ---\n");

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wc_ecc_init(&recipient);
    }
    if (ret == 0) {
        eccInit = 1;
        ret = wc_ecc_make_key(&rng, 32, &recipient);
    }
    if (ret == 0) {
        wc_CoseKey_Init(&recipientKey);
        ret = wc_CoseKey_SetEcc(&recipientKey, WOLFCOSE_CRV_P256,
                                &recipient);
        recipientKey.alg = WOLFCOSE_ALG_HPKE_0;
        recipientKey.hasPrivate = 0u;
    }
    if (ret == 0) {
        ret = wc_CoseHpkeEncrypt0_Encrypt(&recipientKey, kid,
            sizeof(kid) - 1u, payload, sizeof(payload) - 1u,
            NULL, 0u, NULL, NULL, 0u, scratch, sizeof(scratch), cose,
            sizeof(cose), &coseLen, &rng);
    }
    if (ret == 0) {
        recipientKey.hasPrivate = 1u;
        ret = wc_CoseHpkeEncrypt0_Decrypt(&recipientKey, cose, coseLen,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr, plaintext,
            sizeof(plaintext), &plaintextLen);
    }
    if ((ret == 0) &&
        ((hdr.alg != WOLFCOSE_ALG_HPKE_0) ||
         (plaintextLen != (sizeof(payload) - 1u)) ||
         (memcmp(plaintext, payload, plaintextLen) != 0))) {
        ret = -1;
    }

    if (eccInit != 0) {
        wc_ecc_free(&recipient);
    }
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }

    printf("  %s (%zu byte COSE_Encrypt0)\n", ret == 0 ? "PASS" : "FAIL",
           coseLen);
    return ret;
}

static int demo_hpke_key_encryption(void)
{
    static const uint8_t kid[HPKE_DEMO_RECIPIENTS][12] = {
        "recipient-a", "recipient-b"
    };
    static const uint8_t payload[] = "HPKE-0-KE multi-recipient encryption";
    WC_RNG rng;
    ecc_key recipientEcc[HPKE_DEMO_RECIPIENTS];
    WOLFCOSE_KEY recipientKey[HPKE_DEMO_RECIPIENTS];
    WOLFCOSE_RECIPIENT recipients[HPKE_DEMO_RECIPIENTS];
    WOLFCOSE_HDR hdr;
    uint8_t iv[12];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t cose[1024];
    uint8_t plaintext[sizeof(payload)];
    size_t coseLen = 0u;
    size_t plaintextLen = 0u;
    size_t i;
    size_t eccCount = 0u;
    int rngInit = 0;
    int ret;

    printf("--- HPKE-0-KE COSE_Encrypt ---\n");
    (void)memset(recipients, 0, sizeof(recipients));

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
    }
    for (i = 0u; (ret == 0) && (i < HPKE_DEMO_RECIPIENTS); i++) {
        ret = wc_ecc_init(&recipientEcc[i]);
        if (ret == 0) {
            eccCount++;
            ret = wc_ecc_make_key(&rng, 32, &recipientEcc[i]);
        }
        if (ret == 0) {
            wc_CoseKey_Init(&recipientKey[i]);
            ret = wc_CoseKey_SetEcc(&recipientKey[i], WOLFCOSE_CRV_P256,
                                    &recipientEcc[i]);
            recipientKey[i].alg = WOLFCOSE_ALG_HPKE_0_KE;
            recipientKey[i].hasPrivate = 0u;
        }
        if (ret == 0) {
            recipients[i].algId = WOLFCOSE_ALG_HPKE_0_KE;
            recipients[i].key = &recipientKey[i];
            recipients[i].kid = kid[i];
            recipients[i].kidLen = sizeof(kid[i]) - 1u;
        }
    }
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(&rng, iv, (word32)sizeof(iv));
    }
    if (ret == 0) {
        ret = wc_CoseEncrypt_Encrypt(recipients, HPKE_DEMO_RECIPIENTS,
            WOLFCOSE_ALG_A128GCM, iv, sizeof(iv), payload,
            sizeof(payload) - 1u, NULL, 0u, NULL, 0u, scratch,
            sizeof(scratch), cose, sizeof(cose), &coseLen, &rng);
    }
    if (ret == 0) {
        for (i = 0u; i < HPKE_DEMO_RECIPIENTS; i++) {
            recipientKey[i].hasPrivate = 1u;
        }
    }
    for (i = 0u; (ret == 0) && (i < HPKE_DEMO_RECIPIENTS); i++) {
        plaintextLen = 0u;
        ret = wc_CoseEncrypt_Decrypt(&recipients[i], i, cose, coseLen,
            NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr, plaintext,
            sizeof(plaintext), &plaintextLen);
        if ((ret == 0) &&
            ((hdr.alg != WOLFCOSE_ALG_A128GCM) ||
             (plaintextLen != (sizeof(payload) - 1u)) ||
             (memcmp(plaintext, payload, plaintextLen) != 0))) {
            ret = -1;
        }
    }

    while (eccCount > 0u) {
        eccCount--;
        wc_ecc_free(&recipientEcc[eccCount]);
    }
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }

    printf("  %s (%zu byte COSE_Encrypt, %u recipients)\n",
           ret == 0 ? "PASS" : "FAIL", coseLen,
           (unsigned int)HPKE_DEMO_RECIPIENTS);
    return ret;
}

int main(void)
{
    int ret;

    printf("Experimental COSE-HPKE P0 example\n\n");
    ret = demo_hpke_encrypt0();
    if (ret == 0) {
        ret = demo_hpke_key_encryption();
    }
    return ret == 0 ? 0 : 1;
}

#else

int main(void)
{
    fprintf(stderr,
        "This example requires WOLFCOSE_EXPERIMENTAL and the four "
        "WOLFCOSE_ENABLE_HPKE_0_* macros.\n");
    return 1;
}

#endif
