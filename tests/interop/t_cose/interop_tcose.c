/* interop_tcose.c — wolfCOSE <-> t_cose wire-interop harness (test-only).
 *
 * Proves RFC 9052 interop: wolfCOSE (on wolfCrypt) and t_cose (on OpenSSL) produce
 * and consume each other's COSE messages, both directions, across every algorithm
 * both implement. The interface is the bytes on the wire; the two APIs are never
 * reconciled. wolfCrypt and OpenSSL must not meet in one TU (their headers collide
 * on SHA256 etc.), so the t_cose-side asymmetric key loading lives in
 * interop_key_ossl.c. Symmetric keys use t_cose's backend-agnostic helper.
 *
 * Copyright (C) 2026 wolfSSL Inc.  GPL-3.0-or-later (see wolfCOSE LICENSE).
 * t_cose and QCBOR are fetched at pinned SHAs by CI (BSD-3-Clause, not vendored).
 */

#include <wolfcose/eat_psa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/ed448.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_key.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/t_cose_mac_compute.h"
#include "t_cose/t_cose_mac_validate.h"
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_encrypt_dec.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose/q_useful_buf.h"

#include <stdio.h>
#include <string.h>
#include "interop_cases.h"
#include "interop_keys.h"

/* t_cose-side asymmetric key loader (interop_key_ossl.c; no wolfSSL there). */
struct t_cose_key interop_tcose_load(int key_id);
void              interop_tcose_free(struct t_cose_key key);

static int g_fail = 0;

#define OK(cond, name) do {                                                 \
    if (!(cond)) { printf("    FAIL: %s (line %d)\n", (name), __LINE__);     \
                   g_fail++; }                                              \
    else        { printf("    pass: %s\n", (name)); }                       \
} while (0)

static const unsigned char g_payload[] = "wolfCOSE<->t_cose interop payload";
static const size_t        g_payloadLen = sizeof(g_payload) - 1u;

/* A small, valid RFC 9783 current-profile payload. It is deliberately built
 * by wolfCOSE and signed by both implementations below, so this test covers
 * the profile claims as well as the COSE envelope wire format. */
static const unsigned char g_psa_nonce[32] = { 0xA1 };
static const unsigned char g_psa_ueid[33] = { 0x01, 0xA2 };
static const unsigned char g_psa_implementation_id[32] = { 0xA3 };
static const unsigned char g_psa_measurement[32] = { 0xA4 };
static const unsigned char g_psa_signer_id[32] = { 0xA5 };

static void psa_claims(WOLFCOSE_EAT_PSA_CLAIMS* claims,
                       WOLFCOSE_EAT_PSA_COMPONENT* component)
{
    static const unsigned char type[] = "PRoT";

    memset(claims, 0, sizeof(*claims));
    memset(component, 0, sizeof(*component));
    component->measurementType.data = type;
    component->measurementType.len = sizeof(type) - 1u;
    component->measurementValue.data = g_psa_measurement;
    component->measurementValue.len = sizeof(g_psa_measurement);
    component->signerId.data = g_psa_signer_id;
    component->signerId.len = sizeof(g_psa_signer_id);
    claims->nonce.data = g_psa_nonce;
    claims->nonce.len = sizeof(g_psa_nonce);
    claims->ueid.data = g_psa_ueid;
    claims->ueid.len = sizeof(g_psa_ueid);
    claims->implementationId.data = g_psa_implementation_id;
    claims->implementationId.len = sizeof(g_psa_implementation_id);
    claims->clientId = -1;
    claims->lifecycle = 0x3000u;
    claims->components = component;
    claims->componentCount = 1u;
}

/* ---- wolfCrypt key set (owns the underlying wolfCrypt key for cleanup) ---- */
typedef struct {
    WOLFCOSE_KEY ck;
    int          kind;   /* 0 ecc, 1 rsa, 2 ed25519, 3 ed448 */
    ecc_key      ec;
    RsaKey       rsa;
    ed25519_key  ed;
    ed448_key    ed4;
} wc_keyset;

static void wc_free(wc_keyset* ks)
{
    if (ks->kind == 0) wc_ecc_free(&ks->ec);
    else if (ks->kind == 1) wc_FreeRsaKey(&ks->rsa);
    else if (ks->kind == 2) wc_ed25519_free(&ks->ed);
    else if (ks->kind == 3) wc_ed448_free(&ks->ed4);
    wc_CoseKey_Free(&ks->ck);
}

/* kind stays at the sentinel -1 until the matching wolfCrypt init succeeds, so
 * wc_free() on any failure path frees exactly what was initialized. */
static int wc_load(wc_keyset* ks, int key_id)
{
    word32 idx = 0;
    int ret = 0;
    memset(ks, 0, sizeof(*ks));
    ks->kind = -1;
    if (wc_CoseKey_Init(&ks->ck) != 0) return -1;

    switch (key_id) {
    case IT_KEY_P256:
    case IT_KEY_P384:
    case IT_KEY_P521: {
        const unsigned char* der; word32 dlen; int crv;
        if (key_id == IT_KEY_P256) { der = p256_der; dlen = p256_der_len; crv = WOLFCOSE_CRV_P256; }
        else if (key_id == IT_KEY_P384) { der = p384_der; dlen = p384_der_len; crv = WOLFCOSE_CRV_P384; }
        else { der = p521_der; dlen = p521_der_len; crv = WOLFCOSE_CRV_P521; }
        if (wc_ecc_init(&ks->ec) != 0) { ret = -1; break; }
        ks->kind = 0;
        if (wc_EccPrivateKeyDecode(der, &idx, &ks->ec, dlen) != 0) { ret = -1; break; }
        ret = wc_CoseKey_SetEcc(&ks->ck, crv, &ks->ec);
        break;
    }
    case IT_KEY_RSA2048:
        if (wc_InitRsaKey(&ks->rsa, NULL) != 0) { ret = -1; break; }
        ks->kind = 1;
        if (wc_RsaPrivateKeyDecode(rsa2048_der, &idx, &ks->rsa, rsa2048_der_len) != 0) { ret = -1; break; }
        ret = wc_CoseKey_SetRsa(&ks->ck, &ks->rsa);
        break;
    case IT_KEY_ED25519: {
        /* PKCS#8 EdDSA carries only the private seed; derive the public key. */
        byte pub[ED25519_PUB_KEY_SIZE];
        if (wc_ed25519_init(&ks->ed) != 0) { ret = -1; break; }
        ks->kind = 2;
        if (wc_Ed25519PrivateKeyDecode(ed25519_der, &idx, &ks->ed, ed25519_der_len) != 0) { ret = -1; break; }
        if (wc_ed25519_make_public(&ks->ed, pub, sizeof(pub)) != 0) { ret = -1; break; }
        if (wc_ed25519_import_public(pub, sizeof(pub), &ks->ed) != 0) { ret = -1; break; }
        ret = wc_CoseKey_SetEd25519(&ks->ck, &ks->ed);
        break;
    }
    case IT_KEY_ED448: {
        byte pub[ED448_PUB_KEY_SIZE];
        if (wc_ed448_init(&ks->ed4) != 0) { ret = -1; break; }
        ks->kind = 3;
        if (wc_Ed448PrivateKeyDecode(ed448_der, &idx, &ks->ed4, ed448_der_len) != 0) { ret = -1; break; }
        if (wc_ed448_make_public(&ks->ed4, pub, sizeof(pub)) != 0) { ret = -1; break; }
        if (wc_ed448_import_public(pub, sizeof(pub), &ks->ed4) != 0) { ret = -1; break; }
        ret = wc_CoseKey_SetEd448(&ks->ck, &ks->ed4);
        break;
    }
    default:
        ret = -1;
        break;
    }

    if (ret != 0) {
        wc_free(ks);
    }
    return ret;
}

/* ---- COSE_Sign1 round-trip for one (wc_alg, tc_alg, key), both directions ---- */
static void sign1_case(const char* name, int32_t wc_alg, int32_t tc_alg,
                       int key_id, int needs_aux, int with_negative)
{
    wc_keyset ks;
    struct t_cose_key tk;
    struct t_cose_sign1_sign_ctx sctx;
    uint8_t  scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t  wbuf[2048]; size_t wlen = 0;
    uint8_t  aux[2048];
    Q_USEFUL_BUF_MAKE_STACK_UB(tbuf, 2048);
    struct q_useful_buf_c payload = { g_payload, g_payloadLen };
    struct q_useful_buf_c tmsg = { NULL, 0 };
    WOLFCOSE_HDR hdr; const uint8_t* dec = NULL; size_t decLen = 0;
    enum t_cose_err_t terr;
    WC_RNG rng;
    int rc;

    printf("  [Sign1 / %s]\n", name);
    if (wc_load(&ks, key_id) != 0) { OK(0, "wolfCrypt key load"); return; }
    tk = interop_tcose_load(key_id);
    if (tk.key.ptr == NULL)        { OK(0, "t_cose key load"); wc_free(&ks); return; }
    if (wc_InitRng(&rng) != 0)     { OK(0, "rng"); interop_tcose_free(tk); wc_free(&ks); return; }

    /* w->t */
    rc = wc_CoseSign1_Sign(&ks.ck, wc_alg, NULL, 0,
                           g_payload, g_payloadLen, NULL, 0, NULL, 0,
                           scratch, sizeof(scratch), wbuf, sizeof(wbuf), &wlen, &rng);
    OK(rc == 0 && wlen > 0, "wolfCOSE produced COSE_Sign1");
    if (rc == 0) {
        struct t_cose_sign1_verify_ctx vctx;
        struct q_useful_buf_c sign1 = { wbuf, wlen };
        struct q_useful_buf_c vp = { NULL, 0 };
        t_cose_sign1_verify_init(&vctx, 0);
        if (needs_aux) {
            struct q_useful_buf auxb = { aux, sizeof(aux) };
            t_cose_sign1_verify_set_auxiliary_buffer(&vctx, auxb);
        }
        t_cose_sign1_set_verification_key(&vctx, tk);
        terr = t_cose_sign1_verify(&vctx, sign1, &vp, NULL);
        OK(terr == T_COSE_SUCCESS, "t_cose verified wolfCOSE output (w->t)");
        OK(terr == T_COSE_SUCCESS && vp.len == g_payloadLen &&
           memcmp(vp.ptr, g_payload, g_payloadLen) == 0, "payload matches (w->t)");
    }

    /* t->w */
    t_cose_sign1_sign_init(&sctx, 0, tc_alg);
    if (needs_aux) {
        struct q_useful_buf auxb = { aux, sizeof(aux) };
        t_cose_sign1_sign_set_auxiliary_buffer(&sctx, auxb);
    }
    t_cose_sign1_set_signing_key(&sctx, tk, NULL_Q_USEFUL_BUF_C);
    terr = t_cose_sign1_sign(&sctx, payload, tbuf, &tmsg);
    OK(terr == T_COSE_SUCCESS && tmsg.len > 0, "t_cose produced COSE_Sign1");
    if (terr == T_COSE_SUCCESS) {
        rc = wc_CoseSign1_Verify(&ks.ck, tmsg.ptr, tmsg.len, NULL, 0, NULL, 0,
                                 scratch, sizeof(scratch), &hdr, &dec, &decLen);
        OK(rc == 0, "wolfCOSE verified t_cose output (t->w)");
        OK(rc == 0 && decLen == g_payloadLen &&
           memcmp(dec, g_payload, g_payloadLen) == 0, "payload matches (t->w)");
    }

    /* negative: corrupt the signature tail -> wolfCOSE must reject */
    if (with_negative && wlen > 0 && wlen <= sizeof(wbuf)) {
        uint8_t bad[2048]; memcpy(bad, wbuf, wlen);
        bad[wlen - 1u] ^= 0xFFu;
        rc = wc_CoseSign1_Verify(&ks.ck, bad, wlen, NULL, 0, NULL, 0,
                                 scratch, sizeof(scratch), &hdr, &dec, &decLen);
        OK(rc != 0, "wolfCOSE rejects tampered signature (negative)");
    }

    interop_tcose_free(tk);
    wc_free(&ks);
    wc_FreeRng(&rng);
}

/* ---- COSE_Mac0 (HMAC) round-trip, both directions. Symmetric key is
 *      backend-agnostic (t_cose_key_init_symmetric), so it lives in this TU. ---- */
static void mac0_case(const char* name, int32_t wc_alg, int32_t tc_alg, size_t keyLen)
{
    WOLFCOSE_KEY ck;
    struct t_cose_key tk;
    struct t_cose_mac_calculate_ctx cctx;
    struct q_useful_buf_c keyb = { sym_key_64, keyLen };
    struct q_useful_buf_c payload = { g_payload, g_payloadLen };
    struct q_useful_buf_c tmsg = { NULL, 0 };
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t wbuf[512]; size_t wlen = 0;
    Q_USEFUL_BUF_MAKE_STACK_UB(tbuf, 512);
    WOLFCOSE_HDR hdr; const uint8_t* dec = NULL; size_t decLen = 0;
    enum t_cose_err_t terr;
    int rc;

    printf("  [Mac0 / %s]\n", name);
    if (wc_CoseKey_Init(&ck) != 0) { OK(0, "wolfCOSE key"); return; }
    if (wc_CoseKey_SetSymmetric(&ck, sym_key_64, keyLen) != 0) {
        OK(0, "wolfCOSE key"); wc_CoseKey_Free(&ck); return; }
    if (t_cose_key_init_symmetric(tc_alg, keyb, &tk) != T_COSE_SUCCESS) {
        OK(0, "t_cose key"); wc_CoseKey_Free(&ck); return; }

    rc = wc_CoseMac0_Create(&ck, wc_alg, NULL, 0, g_payload, g_payloadLen,
                            NULL, 0, NULL, 0, scratch, sizeof(scratch),
                            wbuf, sizeof(wbuf), &wlen);
    OK(rc == 0 && wlen > 0, "wolfCOSE produced COSE_Mac0");
    if (rc == 0) {
        struct t_cose_mac_validate_ctx vctx;
        struct q_useful_buf_c msg = { wbuf, wlen };
        struct q_useful_buf_c vp = { NULL, 0 };
        uint64_t tags[T_COSE_MAX_TAGS_TO_RETURN];
        t_cose_mac_validate_init(&vctx, T_COSE_OPT_MESSAGE_TYPE_MAC0);
        t_cose_mac_set_validate_key(&vctx, tk);
        terr = t_cose_mac_validate_msg(&vctx, msg, NULL_Q_USEFUL_BUF_C, &vp, NULL, tags);
        OK(terr == T_COSE_SUCCESS, "t_cose validated wolfCOSE output (w->t)");
        OK(terr == T_COSE_SUCCESS && vp.len == g_payloadLen &&
           memcmp(vp.ptr, g_payload, g_payloadLen) == 0, "payload matches (w->t)");
    }

    /* t->w */
    t_cose_mac_compute_init(&cctx, T_COSE_OPT_MESSAGE_TYPE_MAC0, tc_alg);
    t_cose_mac_set_computing_key(&cctx, tk, NULL_Q_USEFUL_BUF_C);
    terr = t_cose_mac_compute(&cctx, NULL_Q_USEFUL_BUF_C, payload, tbuf, &tmsg);
    OK(terr == T_COSE_SUCCESS && tmsg.len > 0, "t_cose produced COSE_Mac0");
    if (terr == T_COSE_SUCCESS) {
        rc = wc_CoseMac0_Verify(&ck, tmsg.ptr, tmsg.len, NULL, 0, NULL, 0,
                                scratch, sizeof(scratch), &hdr, &dec, &decLen);
        OK(rc == 0, "wolfCOSE verified t_cose output (t->w)");
        OK(rc == 0 && decLen == g_payloadLen &&
           memcmp(dec, g_payload, g_payloadLen) == 0, "payload matches (t->w)");
    }

    /* negative: corrupt the tag tail -> wolfCOSE must reject */
    if (wlen > 0 && wlen <= sizeof(wbuf)) {
        uint8_t bad[512]; memcpy(bad, wbuf, wlen);
        bad[wlen - 1u] ^= 0xFFu;
        rc = wc_CoseMac0_Verify(&ck, bad, wlen, NULL, 0, NULL, 0,
                                scratch, sizeof(scratch), &hdr, &dec, &decLen);
        OK(rc != 0, "wolfCOSE rejects tampered tag (negative)");
    }
    t_cose_key_free_symmetric(tk);
    wc_CoseKey_Free(&ck);
}

/* ---- RFC 9783 current-profile COSE_Sign1, both directions. ---- */
static void psa_sign1_case(void)
{
    wc_keyset ks;
    struct t_cose_key tk;
    struct t_cose_sign1_sign_ctx sctx;
    WOLFCOSE_EAT_PSA_CLAIMS claims;
    WOLFCOSE_EAT_PSA_COMPONENT component;
    WOLFCOSE_EAT_PSA_TOKEN token;
    uint8_t claimsBuf[512];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t wbuf[1024];
    size_t claimsLen = 0u;
    size_t wlen = 0u;
    Q_USEFUL_BUF_MAKE_STACK_UB(tbuf, 1024);
    struct q_useful_buf_c payload;
    struct q_useful_buf_c tmsg = { NULL, 0 };
    enum t_cose_err_t terr;
    WC_RNG rng;
    int rc;

    printf("  [RFC 9783 PSA/EAT Sign1]\n");
    psa_claims(&claims, &component);
    rc = wc_EatPsaToken_EncodeClaims(&claims, claimsBuf, sizeof(claimsBuf),
        &claimsLen);
    OK(rc == 0 && claimsLen > 0, "wolfCOSE encoded RFC 9783 claims");
    if (rc != 0) return;
    payload.ptr = claimsBuf;
    payload.len = claimsLen;
    if (wc_load(&ks, IT_KEY_P256) != 0) { OK(0, "wolfCrypt key load"); return; }
    tk = interop_tcose_load(IT_KEY_P256);
    if (tk.key.ptr == NULL) {
        OK(0, "t_cose key load");
        wc_free(&ks);
        return;
    }
    if (wc_InitRng(&rng) != 0) {
        OK(0, "rng");
        interop_tcose_free(tk);
        wc_free(&ks);
        return;
    }

    /* wolfCOSE issues a PSA token, t_cose verifies the COSE envelope. */
    rc = wc_EatPsaToken_CreateSign1(&ks.ck, WOLFCOSE_ALG_ES256, &claims,
        claimsBuf, sizeof(claimsBuf), scratch, sizeof(scratch), wbuf,
        sizeof(wbuf), &wlen, &rng);
    OK(rc == 0 && wlen > 0, "wolfCOSE issued PSA COSE_Sign1 (w->t)");
    if (rc == 0) {
        struct t_cose_sign1_verify_ctx vctx;
        struct q_useful_buf_c sign1 = { wbuf, wlen };
        struct q_useful_buf_c verifiedPayload = { NULL, 0 };

        t_cose_sign1_verify_init(&vctx, 0);
        t_cose_sign1_set_verification_key(&vctx, tk);
        terr = t_cose_sign1_verify(&vctx, sign1, &verifiedPayload, NULL);
        OK(terr == T_COSE_SUCCESS,
            "t_cose verified wolfCOSE PSA token (w->t)");
        OK(terr == T_COSE_SUCCESS && verifiedPayload.len == claimsLen &&
           memcmp(verifiedPayload.ptr, claimsBuf, claimsLen) == 0,
           "PSA claim payload matches (w->t)");
    }

    /* t_cose issues the same claims, wolfCOSE verifies both layers. */
    t_cose_sign1_sign_init(&sctx, 0, T_COSE_ALGORITHM_ES256);
    t_cose_sign1_set_signing_key(&sctx, tk, NULL_Q_USEFUL_BUF_C);
    terr = t_cose_sign1_sign(&sctx, payload, tbuf, &tmsg);
    OK(terr == T_COSE_SUCCESS && tmsg.len > 0,
        "t_cose issued PSA COSE_Sign1 (t->w)");
    if (terr == T_COSE_SUCCESS) {
        rc = wc_EatPsaToken_Verify(&ks.ck, tmsg.ptr, tmsg.len, g_psa_nonce,
            sizeof(g_psa_nonce), scratch, sizeof(scratch), &token);
        OK(rc == 0 && token.profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT &&
           token.protection == WOLFCOSE_EAT_PSA_PROTECTION_SIGN1,
           "wolfCOSE verified t_cose PSA token (t->w)");
    }

    wc_FreeRng(&rng);
    interop_tcose_free(tk);
    wc_free(&ks);
}

/* ---- RFC 9783 current-profile COSE_Mac0, both directions. ---- */
static void psa_mac0_case(void)
{
    WOLFCOSE_KEY ck;
    struct t_cose_key tk;
    struct t_cose_mac_calculate_ctx cctx;
    WOLFCOSE_EAT_PSA_CLAIMS claims;
    WOLFCOSE_EAT_PSA_COMPONENT component;
    WOLFCOSE_EAT_PSA_TOKEN token;
    struct q_useful_buf_c keyb = { sym_key_64, 32 };
    struct q_useful_buf_c payload;
    struct q_useful_buf_c tmsg = { NULL, 0 };
    uint8_t claimsBuf[512];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t wbuf[1024];
    size_t claimsLen = 0u;
    size_t wlen = 0u;
    Q_USEFUL_BUF_MAKE_STACK_UB(tbuf, 1024);
    enum t_cose_err_t terr;
    int rc;

    printf("  [RFC 9783 PSA/EAT Mac0]\n");
    psa_claims(&claims, &component);
    rc = wc_EatPsaToken_EncodeClaims(&claims, claimsBuf, sizeof(claimsBuf),
        &claimsLen);
    OK(rc == 0 && claimsLen > 0, "wolfCOSE encoded RFC 9783 claims");
    if (rc != 0) return;
    payload.ptr = claimsBuf;
    payload.len = claimsLen;
    if (wc_CoseKey_Init(&ck) != 0) { OK(0, "wolfCOSE key"); return; }
    if (wc_CoseKey_SetSymmetric(&ck, sym_key_64, 32) != 0) {
        OK(0, "wolfCOSE key");
        wc_CoseKey_Free(&ck);
        return;
    }
    if (t_cose_key_init_symmetric(T_COSE_ALGORITHM_HMAC256, keyb, &tk) !=
        T_COSE_SUCCESS) {
        OK(0, "t_cose key");
        wc_CoseKey_Free(&ck);
        return;
    }

    rc = wc_EatPsaToken_CreateMac0(&ck, WOLFCOSE_ALG_HMAC_256_256,
        &claims, claimsBuf, sizeof(claimsBuf), scratch, sizeof(scratch),
        wbuf, sizeof(wbuf), &wlen);
    OK(rc == 0 && wlen > 0, "wolfCOSE issued PSA COSE_Mac0 (w->t)");
    if (rc == 0) {
        struct t_cose_mac_validate_ctx vctx;
        struct q_useful_buf_c msg = { wbuf, wlen };
        struct q_useful_buf_c verifiedPayload = { NULL, 0 };
        uint64_t tags[T_COSE_MAX_TAGS_TO_RETURN];

        t_cose_mac_validate_init(&vctx, T_COSE_OPT_MESSAGE_TYPE_MAC0);
        t_cose_mac_set_validate_key(&vctx, tk);
        terr = t_cose_mac_validate_msg(&vctx, msg, NULL_Q_USEFUL_BUF_C,
            &verifiedPayload, NULL, tags);
        OK(terr == T_COSE_SUCCESS,
            "t_cose validated wolfCOSE PSA token (w->t)");
        OK(terr == T_COSE_SUCCESS && verifiedPayload.len == claimsLen &&
           memcmp(verifiedPayload.ptr, claimsBuf, claimsLen) == 0,
           "PSA claim payload matches (w->t)");
    }

    t_cose_mac_compute_init(&cctx, T_COSE_OPT_MESSAGE_TYPE_MAC0,
        T_COSE_ALGORITHM_HMAC256);
    t_cose_mac_set_computing_key(&cctx, tk, NULL_Q_USEFUL_BUF_C);
    terr = t_cose_mac_compute(&cctx, NULL_Q_USEFUL_BUF_C, payload, tbuf,
        &tmsg);
    OK(terr == T_COSE_SUCCESS && tmsg.len > 0,
        "t_cose issued PSA COSE_Mac0 (t->w)");
    if (terr == T_COSE_SUCCESS) {
        rc = wc_EatPsaToken_Verify(&ck, tmsg.ptr, tmsg.len, g_psa_nonce,
            sizeof(g_psa_nonce), scratch, sizeof(scratch), &token);
        OK(rc == 0 && token.profile == WOLFCOSE_EAT_PSA_PROFILE_CURRENT &&
           token.protection == WOLFCOSE_EAT_PSA_PROTECTION_MAC0,
           "wolfCOSE verified t_cose PSA token (t->w)");
    }

    t_cose_key_free_symmetric(tk);
    wc_CoseKey_Free(&ck);
}

/* ---- COSE_Encrypt0 (AES-GCM) round-trip. IV travels in the message. ---- */
static void enc0_case(const char* name, int32_t wc_alg, int32_t tc_alg, size_t keyLen)
{
    WOLFCOSE_KEY ck;
    struct t_cose_key tk;
    struct t_cose_encrypt_enc ectx;
    struct q_useful_buf_c keyb = { sym_key_64, keyLen };
    struct q_useful_buf_c payload = { g_payload, g_payloadLen };
    struct q_useful_buf_c tmsg = { NULL, 0 };
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t wbuf[512]; size_t wlen = 0;
    Q_USEFUL_BUF_MAKE_STACK_UB(tbuf, 512);
    uint8_t iv[12];
    uint8_t pt[256]; size_t ptLen = 0;
    WOLFCOSE_HDR hdr;
    enum t_cose_err_t terr;
    WC_RNG rng;
    int rc;

    printf("  [Encrypt0 / %s]\n", name);
    if (wc_CoseKey_Init(&ck) != 0) { OK(0, "wolfCOSE key"); return; }
    if (wc_CoseKey_SetSymmetric(&ck, sym_key_64, keyLen) != 0) {
        OK(0, "wolfCOSE key"); wc_CoseKey_Free(&ck); return; }
    if (t_cose_key_init_symmetric(tc_alg, keyb, &tk) != T_COSE_SUCCESS) {
        OK(0, "t_cose key"); wc_CoseKey_Free(&ck); return; }
    if (wc_InitRng(&rng) != 0) {
        OK(0, "rng"); t_cose_key_free_symmetric(tk); wc_CoseKey_Free(&ck); return; }
    if (wc_RNG_GenerateBlock(&rng, iv, sizeof(iv)) != 0) {
        OK(0, "iv"); wc_FreeRng(&rng); t_cose_key_free_symmetric(tk); wc_CoseKey_Free(&ck); return; }

    rc = wc_CoseEncrypt0_Encrypt(&ck, wc_alg, iv, sizeof(iv),
                                 g_payload, g_payloadLen, NULL, 0, NULL, NULL, 0,
                                 scratch, sizeof(scratch), wbuf, sizeof(wbuf), &wlen);
    OK(rc == 0 && wlen > 0, "wolfCOSE produced COSE_Encrypt0");
    if (rc == 0) {
        struct t_cose_encrypt_dec_ctx dctx;
        struct q_useful_buf_c msg = { wbuf, wlen };
        struct q_useful_buf   ptb = { pt, sizeof(pt) };
        struct q_useful_buf_c out = { NULL, 0 };
        uint64_t tags[T_COSE_MAX_TAGS_TO_RETURN];
        t_cose_encrypt_dec_init(&dctx, T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0);
        t_cose_encrypt_dec_set_cek(&dctx, tk);
        terr = t_cose_encrypt_dec_msg(&dctx, msg, NULL_Q_USEFUL_BUF_C, ptb, &out, NULL, tags);
        OK(terr == T_COSE_SUCCESS, "t_cose decrypted wolfCOSE output (w->t)");
        OK(terr == T_COSE_SUCCESS && out.len == g_payloadLen &&
           memcmp(out.ptr, g_payload, g_payloadLen) == 0, "plaintext matches (w->t)");
    }

    /* t->w */
    t_cose_encrypt_enc_init(&ectx, T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0, tc_alg);
    t_cose_encrypt_set_cek(&ectx, tk);
    terr = t_cose_encrypt_enc(&ectx, payload, NULL_Q_USEFUL_BUF_C, tbuf, &tmsg);
    OK(terr == T_COSE_SUCCESS && tmsg.len > 0, "t_cose produced COSE_Encrypt0");
    if (terr == T_COSE_SUCCESS) {
        rc = wc_CoseEncrypt0_Decrypt(&ck, tmsg.ptr, tmsg.len, NULL, 0, NULL, 0,
                                     scratch, sizeof(scratch), &hdr,
                                     pt, sizeof(pt), &ptLen);
        OK(rc == 0, "wolfCOSE decrypted t_cose output (t->w)");
        OK(rc == 0 && ptLen == g_payloadLen &&
           memcmp(pt, g_payload, g_payloadLen) == 0, "plaintext matches (t->w)");
    }

    /* negative: corrupt the AEAD tag tail -> wolfCOSE must reject */
    if (wlen > 0 && wlen <= sizeof(wbuf)) {
        uint8_t bad[512]; memcpy(bad, wbuf, wlen);
        bad[wlen - 1u] ^= 0xFFu;
        rc = wc_CoseEncrypt0_Decrypt(&ck, bad, wlen, NULL, 0, NULL, 0,
                                     scratch, sizeof(scratch), &hdr,
                                     pt, sizeof(pt), &ptLen);
        OK(rc != 0, "wolfCOSE rejects tampered ciphertext (negative)");
    }
    t_cose_key_free_symmetric(tk);
    wc_CoseKey_Free(&ck);
    wc_FreeRng(&rng);
}

struct sign1_row {
    const char* name;
    int32_t     wc_alg;
    int32_t     tc_alg;
    int         key_id;
    int         needs_aux;   /* EdDSA needs the t_cose auxiliary buffer */
};

static const struct sign1_row SIGN1_CASES[] = {
    { "ES256",       WOLFCOSE_ALG_ES256, T_COSE_ALGORITHM_ES256, IT_KEY_P256,    0 },
    { "ES384",       WOLFCOSE_ALG_ES384, T_COSE_ALGORITHM_ES384, IT_KEY_P384,    0 },
    { "ES512",       WOLFCOSE_ALG_ES512, T_COSE_ALGORITHM_ES512, IT_KEY_P521,    0 },
    { "PS256",       WOLFCOSE_ALG_PS256, T_COSE_ALGORITHM_PS256, IT_KEY_RSA2048, 0 },
    { "PS384",       WOLFCOSE_ALG_PS384, T_COSE_ALGORITHM_PS384, IT_KEY_RSA2048, 0 },
    { "PS512",       WOLFCOSE_ALG_PS512, T_COSE_ALGORITHM_PS512, IT_KEY_RSA2048, 0 },
    { "EdDSA/Ed25519", WOLFCOSE_ALG_EDDSA, T_COSE_ALGORITHM_EDDSA, IT_KEY_ED25519, 1 },
    { "EdDSA/Ed448",   WOLFCOSE_ALG_EDDSA, T_COSE_ALGORITHM_EDDSA, IT_KEY_ED448,   1 },
};

int main(void)
{
    size_t i;
    printf("=== wolfCOSE <-> t_cose interop (t_cose backend: OpenSSL) ===\n\n");

    for (i = 0; i < sizeof(SIGN1_CASES)/sizeof(SIGN1_CASES[0]); i++) {
        const struct sign1_row* r = &SIGN1_CASES[i];
        sign1_case(r->name, r->wc_alg, r->tc_alg, r->key_id, r->needs_aux,
                   /*with_negative=*/ i == 0);
    }

    mac0_case("HMAC256", WOLFCOSE_ALG_HMAC_256_256, T_COSE_ALGORITHM_HMAC256, 32);
    mac0_case("HMAC384", WOLFCOSE_ALG_HMAC_384_384, T_COSE_ALGORITHM_HMAC384, 48);
    mac0_case("HMAC512", WOLFCOSE_ALG_HMAC_512_512, T_COSE_ALGORITHM_HMAC512, 64);

    psa_sign1_case();
    psa_mac0_case();

    enc0_case("A128GCM", WOLFCOSE_ALG_A128GCM, T_COSE_ALGORITHM_A128GCM, 16);
    enc0_case("A192GCM", WOLFCOSE_ALG_A192GCM, T_COSE_ALGORITHM_A192GCM, 24);
    enc0_case("A256GCM", WOLFCOSE_ALG_A256GCM, T_COSE_ALGORITHM_A256GCM, 32);

    printf("\n=== Results: %d failure(s) ===\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
