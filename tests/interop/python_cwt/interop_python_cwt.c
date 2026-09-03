/* interop_python_cwt.c
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
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#include <wolfcose/wolfcose.h>

#include <stdio.h>
#include <string.h>

#define PYTHON_CWT_MESSAGE_MAX_SZ 2048u
#define PYTHON_CWT_TAMPER_OFFSET 30u

#define PYTHON_CWT_ENCRYPT_DIRECT 1
#define PYTHON_CWT_ENCRYPT_A128KW 2
#define PYTHON_CWT_ENCRYPT_ECDH   3
#define PYTHON_CWT_MAC_DIRECT     4

#if defined(WOLFCOSE_ENCRYPT_ENCRYPT) && \
    defined(WOLFCOSE_ENCRYPT_DECRYPT) && defined(WOLFCOSE_HAVE_AESGCM)
    #define PYTHON_CWT_HAVE_ENCRYPT
#endif

#if defined(WOLFCOSE_MAC_CREATE) && defined(WOLFCOSE_MAC_VERIFY) && \
    defined(WOLFCOSE_HAVE_HMAC256)
    #define PYTHON_CWT_HAVE_MAC
#endif

typedef struct python_cwt_case {
    const char* name;
    int kind;
} PYTHON_CWT_CASE;

static const uint8_t g_payload[] =
    "wolfCOSE<->python-cwt COSE recipient interoperability";
static const uint8_t g_external_aad[] = "wolfCOSE<->python-cwt external AAD";
static const uint8_t g_iv[] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u,
    0x06u, 0x07u, 0x08u, 0x09u, 0x0au, 0x0bu
};

#if defined(PYTHON_CWT_HAVE_ENCRYPT)
static const uint8_t g_direct_key[] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu
};
static const uint8_t g_direct_kid[] = "cwt-direct";

    #if defined(WOLFCOSE_KEY_WRAP)
static const uint8_t g_kw_key[] = {
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
    0x18u, 0x19u, 0x1au, 0x1bu, 0x1cu, 0x1du, 0x1eu, 0x1fu
};
static const uint8_t g_kw_kid[] = "cwt-kw";
    #endif

    #if defined(WOLFCOSE_ECDH_ES_DIRECT) && \
        defined(WOLFCOSE_HAVE_ES256) && defined(HAVE_HKDF)
static const uint8_t g_ecdh_private[] = {
    0xafu, 0xf9u, 0x07u, 0xc9u, 0x9fu, 0x9au, 0xd3u, 0xaau,
    0xe6u, 0xc4u, 0xcdu, 0xf2u, 0x11u, 0x22u, 0xbcu, 0xe2u,
    0xbdu, 0x68u, 0xb5u, 0x28u, 0x3eu, 0x69u, 0x07u, 0x15u,
    0x4au, 0xd9u, 0x11u, 0x84u, 0x0fu, 0xa2u, 0x08u, 0xcfu
};
static const uint8_t g_ecdh_public[] = {
    0x04u,
    0x65u, 0xedu, 0xa5u, 0xa1u, 0x25u, 0x77u, 0xc2u, 0xbau,
    0xe8u, 0x29u, 0x43u, 0x7fu, 0xe3u, 0x38u, 0x70u, 0x1au,
    0x10u, 0xaau, 0xa3u, 0x75u, 0xe1u, 0xbbu, 0x5bu, 0x5du,
    0xe1u, 0x08u, 0xdeu, 0x43u, 0x9cu, 0x08u, 0x55u, 0x1du,
    0x1eu, 0x52u, 0xedu, 0x75u, 0x70u, 0x11u, 0x63u, 0xf7u,
    0xf9u, 0xe4u, 0x0du, 0xdfu, 0x9fu, 0x34u, 0x1bu, 0x3du,
    0xc9u, 0xbau, 0x86u, 0x0au, 0xf7u, 0xe0u, 0xcau, 0x7cu,
    0xa7u, 0xe9u, 0xeeu, 0xcdu, 0x00u, 0x84u, 0xd1u, 0x9cu
};
static const uint8_t g_ecdh_kid[] = "cwt-ecdh";
    #endif
#endif

#if defined(PYTHON_CWT_HAVE_MAC)
static const uint8_t g_mac_key[] = {
    0x20u, 0x21u, 0x22u, 0x23u, 0x24u, 0x25u, 0x26u, 0x27u,
    0x28u, 0x29u, 0x2au, 0x2bu, 0x2cu, 0x2du, 0x2eu, 0x2fu,
    0x30u, 0x31u, 0x32u, 0x33u, 0x34u, 0x35u, 0x36u, 0x37u,
    0x38u, 0x39u, 0x3au, 0x3bu, 0x3cu, 0x3du, 0x3eu, 0x3fu
};
static const uint8_t g_mac_kid[] = "cwt-mac";
#endif

static const PYTHON_CWT_CASE g_cases[] = {
#if defined(PYTHON_CWT_HAVE_ENCRYPT)
    { "encrypt-direct", PYTHON_CWT_ENCRYPT_DIRECT },
    #if defined(WOLFCOSE_KEY_WRAP)
    { "encrypt-a128kw", PYTHON_CWT_ENCRYPT_A128KW },
    #endif
    #if defined(WOLFCOSE_ECDH_ES_DIRECT) && \
        defined(WOLFCOSE_HAVE_ES256) && defined(HAVE_HKDF)
    { "encrypt-ecdh-es", PYTHON_CWT_ENCRYPT_ECDH },
    #endif
#endif
#if defined(PYTHON_CWT_HAVE_MAC)
    { "mac-direct", PYTHON_CWT_MAC_DIRECT },
#endif
    { NULL, 0 }
};

static const PYTHON_CWT_CASE* find_case(const char* name)
{
    size_t i;

    if (name == NULL) {
        return NULL;
    }
    for (i = 0u; g_cases[i].name != NULL; i++) {
        if (strcmp(name, g_cases[i].name) == 0) {
            return &g_cases[i];
        }
    }

    return NULL;
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

#if defined(PYTHON_CWT_HAVE_ENCRYPT)
static int init_encrypt_recipient(int kind, int decrypt,
                                  WOLFCOSE_KEY* key, ecc_key* ecc,
                                  int* key_inited, int* ecc_inited,
                                  WOLFCOSE_RECIPIENT* recipient)
{
    int ret;

    if ((key == NULL) || (ecc == NULL) || (key_inited == NULL) ||
        (ecc_inited == NULL) || (recipient == NULL)) {
        return -1;
    }

    *key_inited = 0;
    *ecc_inited = 0;
    (void)decrypt;
    (void)memset(recipient, 0, sizeof(*recipient));

    ret = wc_CoseKey_Init(key);
    if (ret != 0) {
        return ret;
    }
    *key_inited = 1;

    switch (kind) {
        case PYTHON_CWT_ENCRYPT_DIRECT:
            ret = wc_CoseKey_SetSymmetric(key, g_direct_key,
                                          sizeof(g_direct_key));
            if (ret == 0) {
                key->alg = WOLFCOSE_ALG_A128GCM;
                recipient->algId = WOLFCOSE_ALG_DIRECT;
                recipient->kid = g_direct_kid;
                recipient->kidLen = sizeof(g_direct_kid) - 1u;
            }
            break;

        case PYTHON_CWT_ENCRYPT_A128KW:
#if defined(WOLFCOSE_KEY_WRAP)
            ret = wc_CoseKey_SetSymmetric(key, g_kw_key, sizeof(g_kw_key));
            if (ret == 0) {
                key->alg = WOLFCOSE_ALG_A128KW;
                recipient->algId = WOLFCOSE_ALG_A128KW;
                recipient->kid = g_kw_kid;
                recipient->kidLen = sizeof(g_kw_kid) - 1u;
            }
#else
            ret = -1;
#endif
            break;

        case PYTHON_CWT_ENCRYPT_ECDH:
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && \
    defined(WOLFCOSE_HAVE_ES256) && defined(HAVE_HKDF)
            ret = wc_ecc_init(ecc);
            if (ret == 0) {
                *ecc_inited = 1;
                ret = wc_ecc_import_private_key_ex(g_ecdh_private,
                    (word32)sizeof(g_ecdh_private), g_ecdh_public,
                    (word32)sizeof(g_ecdh_public), ecc, ECC_SECP256R1);
            }
            if (ret == 0) {
                ret = wc_CoseKey_SetEcc(key, WOLFCOSE_CRV_P256, ecc);
            }
            if (ret == 0) {
                key->hasPrivate = decrypt != 0 ? 1u : 0u;
                recipient->algId = WOLFCOSE_ALG_ECDH_ES_HKDF_256;
                recipient->kid = g_ecdh_kid;
                recipient->kidLen = sizeof(g_ecdh_kid) - 1u;
            }
#else
            ret = -1;
#endif
            break;

        default:
            ret = -1;
            break;
    }

    if (ret == 0) {
        recipient->key = key;
    }

    return ret;
}

static void free_encrypt_recipient(WOLFCOSE_KEY* key, ecc_key* ecc,
                                   int key_inited, int ecc_inited)
{
    if (key_inited != 0) {
        wc_CoseKey_Free(key);
    }
    if (ecc_inited != 0) {
        wc_ecc_free(ecc);
    }
}

static int encrypt_message(const PYTHON_CWT_CASE* test_case)
{
    WOLFCOSE_KEY key;
    WOLFCOSE_RECIPIENT recipient;
    ecc_key ecc;
    WC_RNG rng;
    uint8_t message[PYTHON_CWT_MESSAGE_MAX_SZ];
    size_t message_len = 0u;
    int key_inited = 0;
    int ecc_inited = 0;
    int rng_inited = 0;
    int ret;

    ret = init_encrypt_recipient(test_case->kind, 0, &key, &ecc,
                                 &key_inited, &ecc_inited, &recipient);
    if (ret == 0) {
        if ((test_case->kind == PYTHON_CWT_ENCRYPT_A128KW) ||
            (test_case->kind == PYTHON_CWT_ENCRYPT_ECDH)) {
            ret = wc_InitRng(&rng);
            if (ret == 0) {
                rng_inited = 1;
            }
        }
    }
    if (ret == 0) {
        uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];

        ret = wc_CoseEncrypt_Encrypt(&recipient, 1u, WOLFCOSE_ALG_A128GCM,
            g_iv, sizeof(g_iv), g_payload, sizeof(g_payload) - 1u,
            NULL, 0u, g_external_aad, sizeof(g_external_aad) - 1u,
            scratch, sizeof(scratch), message, sizeof(message), &message_len,
            rng_inited != 0 ? &rng : NULL);
    }
    if (ret == 0) {
        ret = write_message(message, message_len);
    }

    if (rng_inited != 0) {
        wc_FreeRng(&rng);
    }
    free_encrypt_recipient(&key, &ecc, key_inited, ecc_inited);
    return ret;
}

static int verify_encrypt_message(const PYTHON_CWT_CASE* test_case)
{
    WOLFCOSE_KEY key;
    WOLFCOSE_RECIPIENT recipient;
    WOLFCOSE_HDR header;
    ecc_key ecc;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[PYTHON_CWT_MESSAGE_MAX_SZ];
    uint8_t plaintext[PYTHON_CWT_MESSAGE_MAX_SZ];
    uint8_t tampered[PYTHON_CWT_MESSAGE_MAX_SZ];
    size_t message_len = 0u;
    size_t plaintext_len = 0u;
    int key_inited = 0;
    int ecc_inited = 0;
    int ret;

    ret = read_message(message, sizeof(message), &message_len);
    if (ret == 0) {
        ret = init_encrypt_recipient(test_case->kind, 1, &key, &ecc,
                                     &key_inited, &ecc_inited, &recipient);
    }
    if (ret == 0) {
        (void)memset(&header, 0, sizeof(header));
        ret = wc_CoseEncrypt_Decrypt(&recipient, 0u, message, message_len,
            NULL, 0u, g_external_aad, sizeof(g_external_aad) - 1u,
            scratch, sizeof(scratch), &header, plaintext, sizeof(plaintext),
            &plaintext_len);
    }
    if ((ret == 0) && ((header.alg != WOLFCOSE_ALG_A128GCM) ||
        (plaintext_len != sizeof(g_payload) - 1u) ||
        (memcmp(plaintext, g_payload, plaintext_len) != 0))) {
        ret = -1;
    }
    if ((ret == 0) && (message_len > PYTHON_CWT_TAMPER_OFFSET)) {
        (void)memcpy(tampered, message, message_len);
        tampered[PYTHON_CWT_TAMPER_OFFSET] ^= 0x01u;
        ret = wc_CoseEncrypt_Decrypt(&recipient, 0u, tampered, message_len,
            NULL, 0u, g_external_aad, sizeof(g_external_aad) - 1u,
            scratch, sizeof(scratch), &header, plaintext, sizeof(plaintext),
            &plaintext_len);
        if (ret == 0) {
            ret = -1;
        }
        else {
            ret = 0;
        }
    }

    free_encrypt_recipient(&key, &ecc, key_inited, ecc_inited);
    return ret;
}
#endif /* PYTHON_CWT_HAVE_ENCRYPT */

#if defined(PYTHON_CWT_HAVE_MAC)
static int init_mac_recipient(WOLFCOSE_KEY* key, int* key_inited,
                              WOLFCOSE_RECIPIENT* recipient)
{
    int ret;

    if ((key == NULL) || (key_inited == NULL) || (recipient == NULL)) {
        return -1;
    }

    *key_inited = 0;
    (void)memset(recipient, 0, sizeof(*recipient));
    ret = wc_CoseKey_Init(key);
    if (ret == 0) {
        *key_inited = 1;
        ret = wc_CoseKey_SetSymmetric(key, g_mac_key, sizeof(g_mac_key));
    }
    if (ret == 0) {
        key->alg = WOLFCOSE_ALG_HMAC_256_256;
        recipient->algId = WOLFCOSE_ALG_DIRECT;
        recipient->key = key;
        recipient->kid = g_mac_kid;
        recipient->kidLen = sizeof(g_mac_kid) - 1u;
    }

    return ret;
}

static int mac_message(void)
{
    WOLFCOSE_KEY key;
    WOLFCOSE_RECIPIENT recipient;
    uint8_t message[PYTHON_CWT_MESSAGE_MAX_SZ];
    size_t message_len = 0u;
    int key_inited = 0;
    int ret;

    ret = init_mac_recipient(&key, &key_inited, &recipient);
    if (ret == 0) {
        uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];

        ret = wc_CoseMac_Create(&recipient, 1u, WOLFCOSE_ALG_HMAC_256_256,
            g_payload, sizeof(g_payload) - 1u, NULL, 0u, g_external_aad,
            sizeof(g_external_aad) - 1u, scratch, sizeof(scratch), message,
            sizeof(message), &message_len);
    }
    if (ret == 0) {
        ret = write_message(message, message_len);
    }

    if (key_inited != 0) {
        wc_CoseKey_Free(&key);
    }
    return ret;
}

static int verify_mac_message(void)
{
    WOLFCOSE_KEY key;
    WOLFCOSE_RECIPIENT recipient;
    WOLFCOSE_HDR header;
    const uint8_t* payload = NULL;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[PYTHON_CWT_MESSAGE_MAX_SZ];
    uint8_t tampered[PYTHON_CWT_MESSAGE_MAX_SZ];
    size_t message_len = 0u;
    size_t payload_len = 0u;
    int key_inited = 0;
    int ret;

    ret = read_message(message, sizeof(message), &message_len);
    if (ret == 0) {
        ret = init_mac_recipient(&key, &key_inited, &recipient);
    }
    if (ret == 0) {
        (void)memset(&header, 0, sizeof(header));
        ret = wc_CoseMac_Verify(&recipient, 0u, message, message_len, NULL,
            0u, g_external_aad, sizeof(g_external_aad) - 1u, scratch,
            sizeof(scratch), &header, &payload, &payload_len);
    }
    if ((ret == 0) && ((header.alg != WOLFCOSE_ALG_HMAC_256_256) ||
        (payload_len != sizeof(g_payload) - 1u) ||
        (memcmp(payload, g_payload, payload_len) != 0))) {
        ret = -1;
    }
    if ((ret == 0) && (message_len > PYTHON_CWT_TAMPER_OFFSET)) {
        (void)memcpy(tampered, message, message_len);
        tampered[PYTHON_CWT_TAMPER_OFFSET] ^= 0x01u;
        ret = wc_CoseMac_Verify(&recipient, 0u, tampered, message_len, NULL,
            0u, g_external_aad, sizeof(g_external_aad) - 1u, scratch,
            sizeof(scratch), &header, &payload, &payload_len);
        if (ret == 0) {
            ret = -1;
        }
        else {
            ret = 0;
        }
    }

    if (key_inited != 0) {
        wc_CoseKey_Free(&key);
    }
    return ret;
}
#endif /* PYTHON_CWT_HAVE_MAC */

int main(int argc, char** argv)
{
    const PYTHON_CWT_CASE* test_case;
    int ret;

    if (argc != 3) {
        fprintf(stderr, "usage: interop_python_cwt sign|verify case\n");
        return 2;
    }

    test_case = find_case(argv[2]);
    if ((test_case == NULL) || (test_case->kind == 0)) {
        fprintf(stderr, "unknown case: %s\n", argv[2]);
        return 2;
    }

    if (strcmp(argv[1], "sign") == 0) {
#if defined(PYTHON_CWT_HAVE_ENCRYPT)
        if (test_case->kind != PYTHON_CWT_MAC_DIRECT) {
            ret = encrypt_message(test_case);
        }
        else
#endif
        {
#if defined(PYTHON_CWT_HAVE_MAC)
            ret = mac_message();
#else
            ret = -1;
#endif
        }
    }
    else if (strcmp(argv[1], "verify") == 0) {
#if defined(PYTHON_CWT_HAVE_ENCRYPT)
        if (test_case->kind != PYTHON_CWT_MAC_DIRECT) {
            ret = verify_encrypt_message(test_case);
        }
        else
#endif
        {
#if defined(PYTHON_CWT_HAVE_MAC)
            ret = verify_mac_message();
#else
            ret = -1;
#endif
        }
    }
    else {
        fprintf(stderr, "unknown mode: %s\n", argv[1]);
        return 2;
    }

    if (ret != 0) {
        fprintf(stderr, "python-cwt interop failed for %s: %d\n",
                test_case->name, ret);
    }

    return ret == 0 ? 0 : 1;
}
