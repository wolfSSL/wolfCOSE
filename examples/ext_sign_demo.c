/* ext_sign_demo.c
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

/* Delegated signing: the private key never enters wolfCOSE.
 *
 * Mirrors wolfBoot's hardware DICE attestation, where the key lives inside a
 * secure element and the platform exposes only a sign-hash entry point. The
 * secure_element_* functions below stand in for that boundary; everything
 * above them is what an integrator writes.
 */

#include <stdio.h>
#include <string.h>
#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#if !defined(WOLFCOSE_EXT_SIGN)
int main(void)
{
    printf("Build with -DWOLFCOSE_ENABLE_EXT_SIGN to run this example.\n");
    return 0;
}
#else

/* ----- Below this line stands in for the secure element ----- */

static ecc_key se_key;
static WC_RNG  se_rng;
static int     se_ready;

static int secure_element_init(void)
{
    int ret;
    int rngUp = 0;
    int keyUp = 0;

    ret = wc_InitRng(&se_rng);
    if (ret == 0) {
        rngUp = 1;
        ret = wc_ecc_init(&se_key);
    }
    if (ret == 0) {
        keyUp = 1;
        ret = wc_ecc_make_key(&se_rng, 32, &se_key);
    }
    if (ret == 0) {
        se_ready = 1;
    }
    else {
        /* Unwind here: se_ready stays 0, so the free path below cannot. */
        if (keyUp != 0) {
            (void)wc_ecc_free(&se_key);
        }
        if (rngUp != 0) {
            (void)wc_FreeRng(&se_rng);
        }
    }
    return ret;
}

/* The platform's only signing entry point: digest in, raw R||S out.
 *
 * COSE wants fixed-width R||S (RFC 9053 sec. 2.1), not the DER SEQUENCE
 * wc_ecc_sign_hash emits, so the conversion belongs on this side of the
 * boundary. A real secure element usually returns R||S already. */
static int secure_element_sign_hash(const uint8_t* hash, size_t hashLen,
                                    uint8_t* sig, size_t* sigLen)
{
    uint8_t derSig[ECC_MAX_SIG_SIZE];
    word32 derLen = (word32)sizeof(derSig);
    word32 rLen = 32u;
    word32 sLen = 32u;
    int ret;

    if ((se_ready == 0) || (*sigLen < 64u)) {
        return -1;
    }

    ret = wc_ecc_sign_hash(hash, (word32)hashLen, derSig, &derLen,
                           &se_rng, &se_key);
    if (ret != 0) {
        return -1;
    }

    memset(sig, 0, 64);
    ret = wc_ecc_sig_to_rs(derSig, derLen, sig, &rLen, &sig[32], &sLen);
    if ((ret != 0) || (rLen > 32u) || (sLen > 32u)) {
        return -1;
    }

    /* wc_ecc_sig_to_rs left-aligns each half; COSE needs them right-aligned
     * in a fixed 32-byte field. */
    memmove(&sig[32u - rLen], sig, rLen);
    memset(sig, 0, 32u - rLen);
    memmove(&sig[32u + (32u - sLen)], &sig[32], sLen);
    memset(&sig[32], 0, 32u - sLen);

    *sigLen = 64u;
    return 0;
}

/* The only thing that legitimately crosses the boundary: the public point. */
static int secure_element_export_public(uint8_t* qx, word32* qxLen,
                                        uint8_t* qy, word32* qyLen)
{
    if (se_ready == 0) {
        return -1;
    }
    return wc_ecc_export_public_raw(&se_key, qx, qxLen, qy, qyLen);
}

static void secure_element_free(void)
{
    if (se_ready != 0) {
        (void)wc_ecc_free(&se_key);
        (void)wc_FreeRng(&se_rng);
        se_ready = 0;
    }
}

/* ----- Above this line stands in for the secure element ----- */

/* Every pointer is freed only if its own init flag says it was created, so
 * an early failure never frees an object that was never initialised. */
static void demo_cleanup(WOLFCOSE_KEY* signKey, int signInited,
                         WOLFCOSE_KEY* verifyKey, int verifyInited,
                         ecc_key* pubKey, int pubInited)
{
    if ((signKey != NULL) && (signInited != 0)) {
        wc_CoseKey_Free(signKey);
    }
    if ((verifyKey != NULL) && (verifyInited != 0)) {
        wc_CoseKey_Free(verifyKey);
    }
    if ((pubKey != NULL) && (pubInited != 0)) {
        (void)wc_ecc_free(pubKey);
    }
    secure_element_free();
}

/* wolfCOSE pre-hashes the Sig_structure for ESP256, so tbs is the 32-byte
 * digest and must go to a sign-hash primitive, never a sign-message one. */
static int demo_sign_cb(void* cbCtx, int32_t alg,
                        const uint8_t* tbs, size_t tbsLen,
                        uint8_t* sig, size_t sigSz, size_t* sigLen)
{
    size_t outLen = sigSz;

    (void)cbCtx;

    /* The length check wolfCOSE performs cannot separate ESP256 from another
     * 64-byte algorithm, so a real signer must pin what it was built for. */
    if (alg != WOLFCOSE_ALG_ESP256) {
        return -1;
    }

    if (secure_element_sign_hash(tbs, tbsLen, sig, &outLen) != 0) {
        return -1;
    }
    *sigLen = outLen;
    return 0;
}

int main(void)
{
    WOLFCOSE_KEY signKey;
    WOLFCOSE_KEY verifyKey;
    WOLFCOSE_HDR hdr;
    ecc_key pubKey;
    uint8_t qx[32];
    uint8_t qy[32];
    word32 qxLen = (word32)sizeof(qx);
    word32 qyLen = (word32)sizeof(qy);
    int pubInited = 0;
    int signInited = 0;
    int verifyInited = 0;
    uint8_t payload[] = "DICE attestation claims";
    uint8_t kid[] = "se-attest-1";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t msg[512];
    size_t msgLen = 0;
    const uint8_t* gotPayload = NULL;
    size_t gotPayloadLen = 0;
    int ret;

    printf("=== wolfCOSE delegated signing (external key) ===\n");

    ret = secure_element_init();
    if (ret != 0) {
        printf("FAIL: secure element init: %d\n", ret);
        return 1;
    }

    ret = wc_CoseKey_Init(&signKey);
    if (ret == 0) {
        signInited = 1;
        /* ESP256 derives its signature length from alg alone, so the key
         * declares only what the algorithm needs. No private key is set. */
        signKey.kty = WOLFCOSE_KTY_EC2;
        signKey.crv = WOLFCOSE_CRV_P256;
        ret = wc_CoseKey_SetExtSigner(&signKey, demo_sign_cb, NULL);
    }
    if (ret != 0) {
        printf("FAIL: attach external signer: %d\n", ret);
        demo_cleanup(&signKey, signInited, NULL, 0, &pubKey, pubInited);
        return 1;
    }
    printf("  signer attached, local private key held: %s\n",
           (signKey.hasPrivate == 0u) ? "no" : "yes");

    /* rng is NULL: the external signer owns its own randomness. */
    ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_ESP256,
                            kid, sizeof(kid) - 1,
                            payload, sizeof(payload) - 1,
                            NULL, 0, NULL, 0,
                            scratch, sizeof(scratch),
                            msg, sizeof(msg), &msgLen, NULL);
    if (ret != 0) {
        printf("FAIL: delegated sign: %d\n", ret);
        demo_cleanup(&signKey, signInited, NULL, 0, &pubKey, pubInited);
        return 1;
    }
    printf("  signed via callback, COSE_Sign1 is %zu bytes\n", msgLen);

    /* Verification takes only the public point out of the secure element and
     * rebuilds a separate key from it, so no private scalar reaches wolfCOSE.
     * Handing it &se_key would be shorter and would defeat the whole point. */
    ret = wc_ecc_init(&pubKey);
    if (ret == 0) {
        pubInited = 1;
        ret = secure_element_export_public(qx, &qxLen, qy, &qyLen);
        if (ret != 0) {
            printf("FAIL: export public key: %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = wc_ecc_import_unsigned(&pubKey, qx, qy, NULL, ECC_SECP256R1);
        if (ret != 0) {
            printf("FAIL: import public key: %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = wc_CoseKey_Init(&verifyKey);
        verifyInited = (ret == 0) ? 1 : 0;
    }
    if (ret == 0) {
        ret = wc_CoseKey_SetEcc(&verifyKey, WOLFCOSE_CRV_P256, &pubKey);
    }
    if (ret == 0) {
        printf("  verify key holds a private scalar: %s\n",
               (verifyKey.hasPrivate == 0u) ? "no" : "yes");
        ret = wc_CoseSign1_Verify(&verifyKey, msg, msgLen, NULL, 0, NULL, 0,
                                  scratch, sizeof(scratch), &hdr,
                                  &gotPayload, &gotPayloadLen);
    }
    if (ret != 0) {
        printf("FAIL: verify chain: %d\n", ret);
        demo_cleanup(&signKey, signInited, &verifyKey, verifyInited,
                     &pubKey, pubInited);
        return 1;
    }

    if ((gotPayloadLen != sizeof(payload) - 1) || (gotPayload == NULL) ||
        (memcmp(gotPayload, payload, gotPayloadLen) != 0)) {
        printf("FAIL: payload mismatch\n");
        demo_cleanup(&signKey, signInited, &verifyKey, verifyInited,
                     &pubKey, pubInited);
        return 1;
    }
    printf("  verified, payload round-tripped intact\n");

    demo_cleanup(&signKey, signInited, &verifyKey, verifyInited,
                     &pubKey, pubInited);
    printf("PASS: delegated signing demo\n");
    return 0;
}
#endif /* WOLFCOSE_EXT_SIGN */
