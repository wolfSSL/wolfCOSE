/* psa_eat_demo.c
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

/* RFC 9783 device-onboarding example.
 *
 * Build and run with:
 *   make psa-eat-demo
 *
 * The device measures a firmware image and issues a COSE_Sign1 PSA token.
 * The verifier authenticates the challenge, checks device policy, and
 * appraises the authenticated software component against a reference value.
 */

#include <stdio.h>
#include <string.h>

#include <wolfcose/eat_psa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>

#ifndef WOLFCOSE_EAT_PSA_TFM_FULL
    #error "The onboarding demo requires a complete RFC 9783 receiver"
#endif

#if !defined(WOLFCOSE_EAT_PSA_SIGN1_ISSUE) || \
    !defined(WOLFCOSE_EAT_PSA_COMPONENT_ITERATOR)
    #error "The onboarding demo requires Sign1 issue and component iteration"
#endif

#define DEMO_PSA_SECURED_MAJOR 0x3000u

static const uint8_t kDeviceUeid[33] = {
    0x01, 0xA4, 0x56, 0x51, 0xDB, 0x52, 0x7A, 0x39,
    0x2C, 0xE8, 0x20, 0x23, 0x61, 0x15, 0x6D, 0x2A,
    0x8B, 0x92, 0x5F, 0x01, 0x48, 0x91, 0xC3, 0x37,
    0x6A, 0x73, 0x04, 0xE1, 0x58, 0xB4, 0x2D, 0xC9,
    0x70
};

static const uint8_t kImplementationId[32] = {
    0x90, 0x1C, 0x9A, 0x06, 0x6A, 0xAE, 0xE7, 0x20,
    0xC2, 0xB8, 0x1D, 0xE5, 0xE3, 0x4A, 0x44, 0xF0,
    0x55, 0xB4, 0xB2, 0xD6, 0x12, 0x90, 0x4D, 0x3D,
    0x29, 0x63, 0x15, 0x25, 0x42, 0x93, 0xC7, 0xD1
};

static const uint8_t kSignerId[32] = {
    0x4F, 0xC4, 0xA7, 0x26, 0x8D, 0xC2, 0xA1, 0xD4,
    0x0E, 0x7B, 0x45, 0x90, 0x66, 0x63, 0x21, 0xB3,
    0x7E, 0xA1, 0x25, 0xC1, 0x47, 0x74, 0x8A, 0x19,
    0x28, 0x3A, 0xE1, 0x5C, 0x84, 0x11, 0x36, 0xB0
};

static const uint8_t kApprovedMeasurement[WC_SHA256_DIGEST_SIZE] = {
    0x0B, 0xBE, 0x1B, 0x80, 0xCD, 0x71, 0xAB, 0x92,
    0x09, 0x7D, 0x92, 0xAE, 0x9A, 0x6D, 0x34, 0x00,
    0xFB, 0xCE, 0x4A, 0xF1, 0x20, 0x19, 0x31, 0x0F,
    0xA6, 0xFB, 0x47, 0xD8, 0xD6, 0x22, 0x14, 0x9A
};

static const uint8_t kFirmwareImage[] =
    "wolfTrust secure partition firmware v1.4.2";
static const uint8_t kComponentType[] = "PRoT";
static const uint8_t kComponentVersion[] = "1.4.2";
static const uint8_t kMeasurementDescription[] = "sha-256";

typedef struct DEMO_APPRAISAL_CTX {
    const uint8_t* expectedMeasurement;
    size_t expectedMeasurementLen;
    size_t componentCount;
} DEMO_APPRAISAL_CTX;

typedef struct DEMO_RESOLVER_CTX {
    const WOLFCOSE_KEY* verifyKey;
} DEMO_RESOLVER_CTX;

static int span_matches(const WOLFCOSE_EAT_PSA_SPAN* span,
    const uint8_t* expected, size_t expectedLen)
{
    return ((span != NULL) && (expected != NULL) &&
            (span->data != NULL) && (span->len == expectedLen) &&
            (memcmp(span->data, expected, expectedLen) == 0)) ? 1 : 0;
}

static int appraise_component(void* ctx,
    const WOLFCOSE_EAT_PSA_COMPONENT* component)
{
    DEMO_APPRAISAL_CTX* appraisal = (DEMO_APPRAISAL_CTX*)ctx;
    int ret = WOLFCOSE_SUCCESS;

    if ((appraisal == NULL) || (component == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((span_matches(&component->measurementType, kComponentType,
                  sizeof(kComponentType) - 1u) == 0) ||
             (span_matches(&component->version, kComponentVersion,
                  sizeof(kComponentVersion) - 1u) == 0) ||
             (span_matches(&component->measurementDesc,
                  kMeasurementDescription,
                  sizeof(kMeasurementDescription) - 1u) == 0) ||
             (span_matches(&component->measurementValue,
                  appraisal->expectedMeasurement,
                  appraisal->expectedMeasurementLen) == 0) ||
             (span_matches(&component->signerId, kSignerId,
                  sizeof(kSignerId)) == 0)) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }
    else {
        appraisal->componentCount++;
        (void)printf("verifier: accepted %.*s firmware version %.*s\n",
            (int)component->measurementType.len,
            (const char*)component->measurementType.data,
            (int)component->version.len,
            (const char*)component->version.data);
    }

    return ret;
}

static int resolve_iak(void* ctx, WOLFCOSE_EAT_PSA_PROFILE profile,
    const uint8_t* ueid, size_t ueidLen, int32_t alg, WOLFCOSE_KEY* key)
{
    DEMO_RESOLVER_CTX* resolver = (DEMO_RESOLVER_CTX*)ctx;
    int ret = WOLFCOSE_SUCCESS;

    if ((resolver == NULL) || (resolver->verifyKey == NULL) || (key == NULL) ||
        (profile != WOLFCOSE_EAT_PSA_PROFILE_CURRENT) ||
        (alg != WOLFCOSE_ALG_ES256) || (ueid == NULL) ||
        (ueidLen != sizeof(kDeviceUeid)) ||
        (memcmp(ueid, kDeviceUeid, sizeof(kDeviceUeid)) != 0)) {
        ret = WOLFCOSE_E_EAT_PSA_KEY;
    }
    else {
        *key = *resolver->verifyKey;
    }

    return ret;
}

static int appraise_token(const WOLFCOSE_EAT_PSA_TOKEN* token,
    const uint8_t* expectedMeasurement, size_t expectedMeasurementLen)
{
    DEMO_APPRAISAL_CTX appraisal;
    int ret = WOLFCOSE_SUCCESS;

    if ((token == NULL) || (expectedMeasurement == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((token->profile != WOLFCOSE_EAT_PSA_PROFILE_CURRENT) ||
             (token->protection != WOLFCOSE_EAT_PSA_PROTECTION_SIGN1) ||
             (token->clientId != -1) ||
             ((token->lifecycle & 0xFF00u) != DEMO_PSA_SECURED_MAJOR) ||
             (span_matches(&token->ueid, kDeviceUeid,
                  sizeof(kDeviceUeid)) == 0) ||
             (span_matches(&token->implementationId, kImplementationId,
                  sizeof(kImplementationId)) == 0)) {
        ret = WOLFCOSE_E_EAT_PSA_CLAIM;
    }
    else {
        (void)memset(&appraisal, 0, sizeof(appraisal));
        appraisal.expectedMeasurement = expectedMeasurement;
        appraisal.expectedMeasurementLen = expectedMeasurementLen;
        ret = wc_CoseEatPsaToken_ForEachComponent(token,
            appraise_component, &appraisal);
        if ((ret == WOLFCOSE_SUCCESS) &&
            (appraisal.componentCount != 1u)) {
            ret = WOLFCOSE_E_EAT_PSA_CLAIM;
        }
    }

    return ret;
}

static void set_claims(WOLFCOSE_EAT_PSA_CLAIMS* claims,
    WOLFCOSE_EAT_PSA_COMPONENT* component,
    const uint8_t* challenge, const uint8_t* bootSeed,
    const uint8_t* measurement)
{
    (void)memset(claims, 0, sizeof(*claims));
    (void)memset(component, 0, sizeof(*component));

    component->measurementType.data = kComponentType;
    component->measurementType.len = sizeof(kComponentType) - 1u;
    component->measurementValue.data = measurement;
    component->measurementValue.len = WC_SHA256_DIGEST_SIZE;
    component->version.data = kComponentVersion;
    component->version.len = sizeof(kComponentVersion) - 1u;
    component->signerId.data = kSignerId;
    component->signerId.len = sizeof(kSignerId);
    component->measurementDesc.data = kMeasurementDescription;
    component->measurementDesc.len = sizeof(kMeasurementDescription) - 1u;

    claims->nonce.data = challenge;
    claims->nonce.len = 32u;
    claims->ueid.data = kDeviceUeid;
    claims->ueid.len = sizeof(kDeviceUeid);
    claims->implementationId.data = kImplementationId;
    claims->implementationId.len = sizeof(kImplementationId);
    claims->bootSeed.data = bootSeed;
    claims->bootSeed.len = 32u;
    claims->clientId = -1;
    claims->lifecycle = DEMO_PSA_SECURED_MAJOR;
    claims->components = component;
    claims->componentCount = 1u;
}

int main(void)
{
    WC_RNG rng;
    ecc_key privateIak;
    ecc_key publicIak;
    WOLFCOSE_KEY signKey;
    WOLFCOSE_KEY verifyKey;
    WOLFCOSE_EAT_PSA_CLAIMS claims;
    WOLFCOSE_EAT_PSA_COMPONENT component;
    WOLFCOSE_EAT_PSA_TOKEN verified;
    DEMO_RESOLVER_CTX resolver;
    uint8_t challenge[32];
    uint8_t wrongChallenge[32];
    uint8_t bootSeed[32];
    uint8_t measurement[WC_SHA256_DIGEST_SIZE];
    uint8_t publicX[32];
    uint8_t publicY[32];
    uint8_t claimsBuf[768];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t tokenBuf[1024];
    word32 publicXLen = (word32)sizeof(publicX);
    word32 publicYLen = (word32)sizeof(publicY);
    size_t tokenLen = 0u;
    int ret;
    int rngInitialized = 0;
    int privateIakInitialized = 0;
    int publicIakInitialized = 0;
    int signKeyInitialized = 0;
    int verifyKeyInitialized = 0;

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInitialized = 1;
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_RNG_GenerateBlock(&rng, challenge,
            (word32)sizeof(challenge));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_RNG_GenerateBlock(&rng, bootSeed,
            (word32)sizeof(bootSeed));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_Sha256Hash(kFirmwareImage,
            (word32)(sizeof(kFirmwareImage) - 1u), measurement);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_ecc_init(&privateIak);
        if (ret == WOLFCOSE_SUCCESS) {
            privateIakInitialized = 1;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_ecc_make_key_ex(&rng, 32, &privateIak, ECC_SECP256R1);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_ecc_export_public_raw(&privateIak, publicX, &publicXLen,
            publicY, &publicYLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_ecc_init(&publicIak);
        if (ret == WOLFCOSE_SUCCESS) {
            publicIakInitialized = 1;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_ecc_import_unsigned(&publicIak, publicX, publicY, NULL,
            ECC_SECP256R1);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseKey_Init(&signKey);
        if (ret == WOLFCOSE_SUCCESS) {
            signKeyInitialized = 1;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseKey_SetEcc(&signKey, WOLFCOSE_CRV_P256, &privateIak);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseKey_Init(&verifyKey);
        if (ret == WOLFCOSE_SUCCESS) {
            verifyKeyInitialized = 1;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseKey_SetEcc(&verifyKey, WOLFCOSE_CRV_P256, &publicIak);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        set_claims(&claims, &component, challenge, bootSeed, measurement);
        ret = wc_CoseEatPsaToken_CreateSign1(&signKey,
            WOLFCOSE_ALG_ES256, &claims, claimsBuf, sizeof(claimsBuf),
            scratch, sizeof(scratch), tokenBuf, sizeof(tokenBuf), &tokenLen,
            &rng);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        (void)printf("device: issued %zu-byte RFC 9783 COSE_Sign1 token\n",
            tokenLen);
        resolver.verifyKey = &verifyKey;
        (void)memcpy(wrongChallenge, challenge, sizeof(wrongChallenge));
        wrongChallenge[0] ^= 0x01u;
        ret = wc_CoseEatPsaToken_VerifyByUeid(resolve_iak, &resolver,
            tokenBuf, tokenLen, wrongChallenge, sizeof(wrongChallenge),
            scratch, sizeof(scratch), &verified);
        if (ret == WOLFCOSE_E_EAT_PSA_NONCE) {
            (void)printf("verifier: rejected token for the wrong challenge\n");
            ret = WOLFCOSE_SUCCESS;
        }
        else if (ret == WOLFCOSE_SUCCESS) {
            ret = WOLFCOSE_E_EAT_PSA_NONCE;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseEatPsaToken_VerifyByUeid(resolve_iak, &resolver,
            tokenBuf, tokenLen, challenge, sizeof(challenge), scratch,
            sizeof(scratch), &verified);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = appraise_token(&verified, kApprovedMeasurement,
            sizeof(kApprovedMeasurement));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        (void)printf("onboarding: accepted secured device with one trusted "
                     "component\n");
    }
    else {
        (void)printf("onboarding: rejected token (%d)\n", ret);
    }

    if (verifyKeyInitialized != 0) {
        wc_CoseKey_Free(&verifyKey);
    }
    if (signKeyInitialized != 0) {
        wc_CoseKey_Free(&signKey);
    }
    if (publicIakInitialized != 0) {
        wc_ecc_free(&publicIak);
    }
    if (privateIakInitialized != 0) {
        wc_ecc_free(&privateIak);
    }
    if (rngInitialized != 0) {
        wc_FreeRng(&rng);
    }

    return (ret == WOLFCOSE_SUCCESS) ? 0 : 1;
}
