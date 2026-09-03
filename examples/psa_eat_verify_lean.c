/* psa_eat_verify_lean.c
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

/* Verify-only full RFC 9783 PSA/EAT receiver.
 *
 * Build with:
 *   make psa-eat-lean-verify
 *
 * A production caller obtains the byte string in kTokenHex from
 * psa_initial_attest_get_token(), retains its challenge as the expected nonce,
 * resolves the IAK public key from the UEID, and passes the raw token directly
 * to wc_CoseEatPsaToken_Verify() or wc_CoseEatPsaToken_VerifyByUeid(). No PSA headers
 * or dynamic allocation are required by wolfCOSE.
 *
 * The fixed inputs are the RFC 9783 Appendix A.1 Sign1 and Mac0 tokens,
 * produced by the external TF-M iat-verifier reference implementation. They
 * also use non-preferred CBOR lengths, which RFC 9783 requires a PSA token
 * receiver to accept.
 */

#include <stdio.h>
#include <string.h>

#include <wolfcose/eat_psa.h>
#include <wolfssl/wolfcrypt/ecc.h>

#ifndef WOLFCOSE_EAT_PSA_TFM_FULL
    #error "This RFC 9783 #tfm example requires the complete receiver profile"
#endif

static const uint8_t kExpectedNonce[32] = {
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
};

static const uint8_t kIakX[32] = {
    0x4E, 0x5E, 0x22, 0x09, 0x9E, 0x3B, 0xCE, 0xB4,
    0x5B, 0x44, 0x6D, 0x13, 0x55, 0xFD, 0x1D, 0xC3,
    0xB5, 0x45, 0x94, 0x7B, 0x6F, 0xD7, 0xC1, 0xC8,
    0x9D, 0x88, 0x67, 0x98, 0xC3, 0x72, 0x6E, 0x8F
};

static const uint8_t kIakY[32] = {
    0x80, 0xD7, 0x0B, 0x84, 0x0B, 0x25, 0x6A, 0xAC,
    0x34, 0xA6, 0x2E, 0xDE, 0x10, 0x43, 0x36, 0x4F,
    0x04, 0x40, 0x95, 0xF0, 0x03, 0x47, 0x4B, 0x91,
    0xE0, 0x18, 0x20, 0x92, 0xAF, 0xB1, 0x3F, 0x2E
};

static const char kTokenHex[] =
    "d28443a10126a0590100a819010058210102020202020202020202020202"
    "0202020202020202020202020202020202020219095c5820000000000000"
    "00000000000000000000000000000000000000000000000000000a582001"
    "010101010101010101010101010101010101010101010101010101010101"
    "0119095a1a7fffffff19095b19300019010978217461673a707361636572"
    "7469666965642e6f72672c323032333a7073612374666d19010c48000000"
    "000000000019095f81a30558200404040404040404040404040404040404"
    "040404040404040404040404040404025820030303030303030303030303"
    "0303030303030303030303030303030303030303016450526f545840786e"
    "937a4c42667af3847399319ca95c7e7dbabdc9b50fdb8de3f6bff4ab82ff"
    "80c42140e2a488000219e3e10663193da69c75f52b798ea10b2f7041a90e"
    "8e5a";

static const uint8_t kMac0Key[64] = {
    0xDE, 0x03, 0x8B, 0x34, 0xAC, 0xA1, 0x25, 0x76,
    0x8C, 0x5E, 0x33, 0x57, 0xAB, 0x8D, 0x06, 0xB3,
    0x67, 0xB9, 0xAB, 0x0D, 0x7E, 0x8B, 0xE1, 0x24,
    0xED, 0xCA, 0x47, 0xFE, 0x03, 0x3A, 0x5B, 0xB7,
    0xA9, 0x3D, 0x30, 0x7F, 0xF2, 0x29, 0xAA, 0x36,
    0xFF, 0x24, 0x6C, 0x12, 0x95, 0x96, 0x4F, 0xAC,
    0xF7, 0x1A, 0xB7, 0xAA, 0x6E, 0xC4, 0xFD, 0x61,
    0x02, 0xB7, 0xB3, 0x98, 0x32, 0x55, 0xAD, 0x92
};

static const char kMac0TokenHex[] =
    "d18443a10105a0590100a8190100582101c557bd4fadc83f756fca2cd5ea"
    "2dcc8b82159bb4e7453d6a744d4eecd6d0ac6019095c5820000000000000"
    "00000000000000000000000000000000000000000000000000000a582001"
    "010101010101010101010101010101010101010101010101010101010101"
    "0119095a1a7fffffff19095b19300019010978217461673a707361636572"
    "7469666965642e6f72672c323032333a7073612374666d19010c48000000"
    "000000000019095f81a30558200404040404040404040404040404040404"
    "040404040404040404040404040404025820030303030303030303030303"
    "0303030303030303030303030303030303030303016450526f545820cf88"
    "d330e7a5366a95cf744a4dbf0d50304d405edd8b2530e243eddbd3177820";

static int hex_nibble(uint8_t in, uint8_t* out)
{
    int ret = WOLFCOSE_SUCCESS;

    if (out == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if ((in >= (uint8_t)'0') && (in <= (uint8_t)'9')) {
        *out = (uint8_t)(in - (uint8_t)'0');
    }
    else if ((in >= (uint8_t)'a') && (in <= (uint8_t)'f')) {
        *out = (uint8_t)(in - (uint8_t)'a' + 10u);
    }
    else {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    return ret;
}

static int hex_decode(const char* hex, uint8_t* out, size_t outSz,
    size_t* outLen)
{
    int ret = WOLFCOSE_SUCCESS;
    size_t i;
    size_t hexLen;

    if (outLen != NULL) {
        *outLen = 0u;
    }
    if ((hex == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        hexLen = strlen(hex);
        if (((hexLen & 1u) != 0u) || ((hexLen / 2u) > outSz)) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }
        for (i = 0u; (ret == WOLFCOSE_SUCCESS) && (i < (hexLen / 2u)); i++) {
            uint8_t high;
            uint8_t low;

            ret = hex_nibble((uint8_t)hex[i * 2u], &high);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = hex_nibble((uint8_t)hex[(i * 2u) + 1u], &low);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                out[i] = (uint8_t)((high << 4) | low);
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            *outLen = hexLen / 2u;
        }
    }

    return ret;
}

int main(void)
{
    ecc_key eccKey;
    WOLFCOSE_KEY key;
    WOLFCOSE_KEY macKey;
    WOLFCOSE_EAT_PSA_TOKEN token;
    uint8_t rawToken[512];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    size_t rawTokenLen = 0u;
    int ret;
    int rc = 1;
    int eccInitialized = 0;
    int keyInitialized = 0;
    int macKeyInitialized = 0;
    int sign1Verified = 0;
    int mac0Verified = 0;

    ret = hex_decode(kTokenHex, rawToken, sizeof(rawToken), &rawTokenLen);
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_ecc_init(&eccKey);
        if (ret == WOLFCOSE_SUCCESS) {
            eccInitialized = 1;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_ecc_import_unsigned(&eccKey, (byte*)kIakX, (byte*)kIakY,
            NULL, ECC_SECP256R1);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseKey_Init(&key);
        if (ret == WOLFCOSE_SUCCESS) {
            keyInitialized = 1;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseEatPsaToken_Verify(&key, rawToken, rawTokenLen,
            kExpectedNonce, sizeof(kExpectedNonce), scratch, sizeof(scratch),
            &token);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (token.profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT) &&
        (token.protection == WOLFCOSE_EAT_PSA_PROTECTION_SIGN1) &&
        (token.componentCount == 1u)) {
        (void)printf("lean PSA/EAT verifier: RFC 9783 Sign1 token verified\n");
        sign1Verified = 1;
    }
    else {
        (void)printf("lean PSA/EAT verifier: Sign1 failed (%d)\n", ret);
    }

    if (sign1Verified != 0) {
        ret = hex_decode(kMac0TokenHex, rawToken, sizeof(rawToken),
            &rawTokenLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseKey_Init(&macKey);
        if (ret == WOLFCOSE_SUCCESS) {
            macKeyInitialized = 1;
        }
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseKey_SetSymmetric(&macKey, kMac0Key, sizeof(kMac0Key));
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseEatPsaToken_Verify(&macKey, rawToken, rawTokenLen,
            kExpectedNonce, sizeof(kExpectedNonce), scratch, sizeof(scratch),
            &token);
    }
    if ((ret == WOLFCOSE_SUCCESS) &&
        (token.profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT) &&
        (token.protection == WOLFCOSE_EAT_PSA_PROTECTION_MAC0) &&
        (token.componentCount == 1u)) {
        (void)printf("lean PSA/EAT verifier: RFC 9783 Mac0 token verified\n");
        mac0Verified = 1;
    }
    else {
        (void)printf("lean PSA/EAT verifier: Mac0 failed (%d)\n", ret);
    }
    if ((sign1Verified != 0) && (mac0Verified != 0)) {
        rc = 0;
    }

    if (macKeyInitialized != 0) {
        wc_CoseKey_Free(&macKey);
    }
    if (keyInitialized != 0) {
        wc_CoseKey_Free(&key);
    }
    if (eccInitialized != 0) {
        wc_ecc_free(&eccKey);
    }
    return rc;
}
