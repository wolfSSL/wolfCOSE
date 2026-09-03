/* interop_rust_coset.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#include <wolfcose/wolfcose.h>

#ifdef WOLFCOSE_HAVE_EDDSA
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif

#include <stdio.h>
#include <string.h>

#include "../t_cose/interop_keys.h"

#define RUST_COSET_MESSAGE_MAX_SZ 2048u

#define RUST_COSET_KEY_ECC      1
#define RUST_COSET_KEY_ED25519  2

typedef struct rust_coset_keyset {
    WOLFCOSE_KEY cose_key;
    int kind;
    int cose_key_inited;
    ecc_key ecc;
#ifdef WOLFCOSE_HAVE_EDDSA
    ed25519_key ed25519;
#endif
} RUST_COSET_KEYSET;

typedef struct rust_coset_case {
    const char* name;
    int32_t alg;
    int key_id;
    const uint8_t* ext_aad;
    size_t ext_aad_len;
    uint32_t sign_flags;
    int detached;
} RUST_COSET_CASE;

static const uint8_t g_payload[] =
    "wolfCOSE<->Rust coset COSE_Sign1 interoperability";
static const uint8_t g_external_aad[] = "wolfCOSE<->Rust coset external AAD";

static const RUST_COSET_CASE g_cases[] = {
    { "es256", WOLFCOSE_ALG_ES256, RUST_COSET_KEY_ECC, NULL, 0u, 0u, 0 },
#ifdef WOLFCOSE_HAVE_EDDSA
    { "ed25519", WOLFCOSE_ALG_EDDSA, RUST_COSET_KEY_ED25519, NULL, 0u,
      0u, 0 },
#endif
    { "es256-aad", WOLFCOSE_ALG_ES256, RUST_COSET_KEY_ECC,
      g_external_aad, sizeof(g_external_aad) - 1u, 0u, 0 },
    { "es256-untagged", WOLFCOSE_ALG_ES256, RUST_COSET_KEY_ECC, NULL, 0u,
      WOLFCOSE_SIGN1_UNTAGGED, 0 },
    { "es256-detached", WOLFCOSE_ALG_ES256, RUST_COSET_KEY_ECC, NULL, 0u,
      0u, 1 }
};

static const RUST_COSET_CASE* find_case(const char* name)
{
    size_t i;

    if (name == NULL) {
        return NULL;
    }
    for (i = 0u; i < sizeof(g_cases) / sizeof(g_cases[0]); i++) {
        if (strcmp(name, g_cases[i].name) == 0) {
            return &g_cases[i];
        }
    }

    return NULL;
}

static void free_key(RUST_COSET_KEYSET* keyset)
{
    if (keyset == NULL) {
        return;
    }

    if (keyset->kind == RUST_COSET_KEY_ECC) {
        wc_ecc_free(&keyset->ecc);
    }
#ifdef WOLFCOSE_HAVE_EDDSA
    else if (keyset->kind == RUST_COSET_KEY_ED25519) {
        wc_ed25519_free(&keyset->ed25519);
    }
#endif
    else {
        /* No initialized wolfCrypt key to free. */
    }

    if (keyset->cose_key_inited != 0) {
        wc_CoseKey_Free(&keyset->cose_key);
    }

    keyset->kind = 0;
    keyset->cose_key_inited = 0;
}

static int init_ecc_key(RUST_COSET_KEYSET* keyset)
{
    word32 index = 0u;
    int ret;

    ret = wc_ecc_init(&keyset->ecc);
    if (ret == 0) {
        keyset->kind = RUST_COSET_KEY_ECC;
        ret = wc_EccPrivateKeyDecode(p256_der, &index, &keyset->ecc,
                                     p256_der_len);
    }
    if (ret == 0) {
        ret = wc_CoseKey_SetEcc(&keyset->cose_key, WOLFCOSE_CRV_P256,
                                &keyset->ecc);
    }

    return ret;
}

static int init_key(RUST_COSET_KEYSET* keyset,
                    const RUST_COSET_CASE* test_case)
{
    int ret;

    if ((keyset == NULL) || (test_case == NULL)) {
        return -1;
    }

    (void)memset(keyset, 0, sizeof(*keyset));
    ret = wc_CoseKey_Init(&keyset->cose_key);
    if (ret != 0) {
        return ret;
    }
    keyset->cose_key_inited = 1;

    if (test_case->key_id == RUST_COSET_KEY_ECC) {
        ret = init_ecc_key(keyset);
    }
#ifdef WOLFCOSE_HAVE_EDDSA
    else if (test_case->key_id == RUST_COSET_KEY_ED25519) {
        word32 index = 0u;
        byte public_key[ED25519_PUB_KEY_SIZE];

        ret = wc_ed25519_init(&keyset->ed25519);
        if (ret == 0) {
            keyset->kind = RUST_COSET_KEY_ED25519;
            ret = wc_Ed25519PrivateKeyDecode(ed25519_der, &index,
                                              &keyset->ed25519,
                                              ed25519_der_len);
        }
        if (ret == 0) {
            ret = wc_ed25519_make_public(&keyset->ed25519, public_key,
                                         (word32)sizeof(public_key));
        }
        if (ret == 0) {
            ret = wc_ed25519_import_public(public_key,
                                           (word32)sizeof(public_key),
                                           &keyset->ed25519);
        }
        if (ret == 0) {
            ret = wc_CoseKey_SetEd25519(&keyset->cose_key,
                                         &keyset->ed25519);
        }
    }
#endif
    else {
        ret = -1;
    }

    if (ret != 0) {
        free_key(keyset);
    }
    return ret;
}

static int read_message(uint8_t* message, size_t message_sz, size_t* message_len)
{
    size_t length = 0u;

    if ((message == NULL) || (message_len == NULL) || (message_sz == 0u)) {
        return -1;
    }

    while (length < message_sz) {
        int input;

        input = fgetc(stdin);
        if (input == EOF) {
            break;
        }
        message[length++] = (uint8_t)input;
    }

    if ((ferror(stdin) != 0) || (length == 0u)) {
        return -1;
    }
    if ((length == message_sz) && (fgetc(stdin) != EOF)) {
        return -1;
    }

    *message_len = length;
    return 0;
}

static int write_message(const uint8_t* message, size_t message_len)
{
    if ((message == NULL) || (message_len == 0u)) {
        return -1;
    }
    if (fwrite(message, 1u, message_len, stdout) != message_len) {
        return -1;
    }
    if (fflush(stdout) != 0) {
        return -1;
    }

    return 0;
}

static int sign_message(const RUST_COSET_CASE* test_case)
{
    RUST_COSET_KEYSET keyset;
    WC_RNG rng;
    uint8_t message[RUST_COSET_MESSAGE_MAX_SZ];
    const uint8_t* payload = g_payload;
    const uint8_t* detached_payload = NULL;
    size_t payload_len = sizeof(g_payload) - 1u;
    size_t detached_len = 0u;
    size_t message_len = 0u;
    int rng_inited = 0;
    int ret;

    if (test_case->detached != 0) {
        payload = NULL;
        payload_len = 0u;
        detached_payload = g_payload;
        detached_len = sizeof(g_payload) - 1u;
    }

    ret = init_key(&keyset, test_case);
    if (ret == 0) {
        ret = wc_InitRng(&rng);
        if (ret == 0) {
            rng_inited = 1;
        }
    }
    if (ret == 0) {
        uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];

        ret = wc_CoseSign1_Sign_ex(&keyset.cose_key, test_case->alg, NULL,
            0u, payload, payload_len, detached_payload, detached_len,
            test_case->ext_aad, test_case->ext_aad_len, scratch,
            sizeof(scratch), message, sizeof(message), &message_len, &rng,
            test_case->sign_flags);
    }
    if (ret == 0) {
        ret = write_message(message, message_len);
    }

    if (rng_inited != 0) {
        wc_FreeRng(&rng);
    }
    free_key(&keyset);
    return ret;
}

static int verify_message(const RUST_COSET_CASE* test_case)
{
    WOLFCOSE_HDR header;
    RUST_COSET_KEYSET keyset = { 0 };
    const uint8_t* decoded = NULL;
    const uint8_t* detached_payload = NULL;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[RUST_COSET_MESSAGE_MAX_SZ];
    uint8_t tampered[RUST_COSET_MESSAGE_MAX_SZ];
    size_t decoded_len = 0u;
    size_t detached_len = 0u;
    size_t message_len = 0u;
    int ret;

    if (test_case->detached != 0) {
        detached_payload = g_payload;
        detached_len = sizeof(g_payload) - 1u;
    }

    ret = read_message(message, sizeof(message), &message_len);
    if (ret == 0) {
        ret = init_key(&keyset, test_case);
    }
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&keyset.cose_key, message, message_len,
            detached_payload, detached_len, test_case->ext_aad,
            test_case->ext_aad_len, scratch, sizeof(scratch), &header,
            &decoded, &decoded_len);
    }
    if ((ret == 0) && (header.alg != test_case->alg)) {
        ret = -1;
    }
    if ((ret == 0) && (test_case->detached != 0)) {
        if ((decoded != NULL) || (decoded_len != 0u)) {
            ret = -1;
        }
    }
    else if ((ret == 0) && ((decoded_len != sizeof(g_payload) - 1u) ||
        (memcmp(decoded, g_payload, decoded_len) != 0))) {
        ret = -1;
    }
    if (ret == 0) {
        (void)memcpy(tampered, message, message_len);
        tampered[message_len - 1u] ^= 0x01u;
        ret = wc_CoseSign1_Verify(&keyset.cose_key, tampered, message_len,
            detached_payload, detached_len, test_case->ext_aad,
            test_case->ext_aad_len, scratch, sizeof(scratch), &header,
            &decoded, &decoded_len);
        if (ret == 0) {
            ret = -1;
        }
        else {
            ret = 0;
        }
    }

    free_key(&keyset);
    return ret;
}

int main(int argc, char** argv)
{
    const RUST_COSET_CASE* test_case;
    int ret;

    if (argc != 3) {
        fprintf(stderr, "usage: interop_rust_coset sign|verify case\n");
        return 2;
    }

    test_case = find_case(argv[2]);
    if (test_case == NULL) {
        fprintf(stderr, "unknown case: %s\n", argv[2]);
        return 2;
    }

    if (strcmp(argv[1], "sign") == 0) {
        ret = sign_message(test_case);
    }
    else if (strcmp(argv[1], "verify") == 0) {
        ret = verify_message(test_case);
    }
    else {
        fprintf(stderr, "unknown mode: %s\n", argv[1]);
        return 2;
    }

    if (ret != 0) {
        fprintf(stderr, "Rust coset interop failed for %s: %d\n",
                test_case->name, ret);
    }

    return ret == 0 ? 0 : 1;
}
