/* wolfcose_tool.c
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

/**
 * wolfCOSE CLI tool -- Swiss Army knife for COSE operations.
 * Standalone binary, never part of core library.
 *
 * Subcommands:
 *   keygen  -a <alg> -o <keyfile>
 *   sign    -k <keyfile> -a <alg> -i <payload> -o <cose_file>
 *   verify  -k <keyfile> -i <cose_file>
 *   countersign -k <keyfile> -a <alg> -i <cose_file> -o <cose_file>
 *   counterverify -k <keyfile> -i <cose_file>
 *   enc     -k <keyfile> -a <alg> -i <plaintext> -o <cose_file>
 *   dec     -k <keyfile> -i <cose_file> -o <plaintext>
 *   info    -i <cose_file>
 *
 * Key files: raw COSE_Key CBOR format.
 * Exit codes: 0=success, 1=usage, 2=crypto failure, 3=I/O error.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/random.h>
#ifdef WOLFCOSE_HAVE_ECDSA
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef WOLFCOSE_HAVE_EDDSA
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef WOLFCOSE_HAVE_ED448
    #include <wolfssl/wolfcrypt/ed448.h>
#endif
#ifdef WOLFCOSE_HAVE_RSAPSS
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef WOLFCOSE_HAVE_MLDSA
    #include <wolfssl/wolfcrypt/wc_mldsa.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WOLFCOSE_TOOL_MAX_MSG
    #define WOLFCOSE_TOOL_MAX_MSG  8192
#endif

#ifndef WOLFCOSE_TOOL_MAX_KEY
    #ifdef WOLFCOSE_HAVE_MLDSA
        /* ML-DSA-87: pub=2592 + priv=4896 + CBOR overhead */
        #define WOLFCOSE_TOOL_MAX_KEY  8192
    #else
        /* RSA-2048 private COSE_Key: n,e,d,p,q,qInv plus export scratch */
        #define WOLFCOSE_TOOL_MAX_KEY  4096
    #endif
#endif

#define EXIT_USAGE   1
#define EXIT_CRYPTO  2
#define EXIT_IO      3

/* Portable secure-zero for sensitive key material; volatile writes are not
 * optimized away. wc_ForceZero is only public in wolfSSL >= 5.8.4, so the tool
 * carries its own to match the library's supported range. */
static void tool_force_zero(void* mem, size_t len)
{
    volatile unsigned char* p = (volatile unsigned char*)mem;
    size_t i;
    for (i = 0u; i < len; i++) {
        p[i] = 0u;
    }
}

static void usage(void)
{
    fprintf(stderr,
        "Usage: wolfcose_tool <command> [options]\n"
        "\n"
        "Commands:\n"
        "  keygen  -a <alg> -o <keyfile>\n"
        "  sign    -k <keyfile> -a <alg> -i <payload> -o <cose_file>\n"
        "  verify  -k <keyfile> -i <cose_file>\n"
        "  countersign -k <keyfile> -a <alg> -i <cose_file>"
        " -o <cose_file>\n"
        "  counterverify -k <keyfile> -i <cose_file> [--index <n>]\n"
        "  enc     -k <keyfile> -a <alg> -i <plaintext> -o <cose_file>\n"
        "  dec     -k <keyfile> -i <cose_file> -o <plaintext>\n"
        "  mac     -k <keyfile> -a <alg> -i <payload> -o <cose_file>\n"
        "  macverify -k <keyfile> -i <cose_file>\n"
        "  info    -i <cose_file>\n"
        "  test    [--all | -a <alg>]   Round-trip self-test\n"
        "\nCountersign options: -p <detached_payload> --aad <aad_file>\n"
        "\n"
        "Algorithms: ES256, EdDSA, Ed448, PS256, PS384, PS512,\n"
        "            ML-DSA-44, ML-DSA-65, ML-DSA-87,\n"
        "            A128GCM, A192GCM, A256GCM, ChaCha20, AES-CCM,\n"
        "            HMAC256, HMAC384, HMAC512\n");
}

/* Parse algorithm name to COSE algorithm ID */
static int parse_alg(const char* name, int32_t* alg)
{
    if (strcmp(name, "ES256") == 0) {
        *alg = WOLFCOSE_ALG_ES256;
    }
    else if (strcmp(name, "EdDSA") == 0) {
        *alg = WOLFCOSE_ALG_EDDSA;
    }
#ifdef WOLFCOSE_HAVE_ED448
    else if (strcmp(name, "Ed448") == 0) {
        *alg = WOLFCOSE_ALG_EDDSA;
    }
#endif
    else if (strcmp(name, "A128GCM") == 0) {
        *alg = WOLFCOSE_ALG_A128GCM;
    }
    else if (strcmp(name, "A192GCM") == 0) {
        *alg = WOLFCOSE_ALG_A192GCM;
    }
    else if (strcmp(name, "A256GCM") == 0) {
        *alg = WOLFCOSE_ALG_A256GCM;
    }
#ifdef WOLFCOSE_HAVE_RSAPSS
    else if (strcmp(name, "PS256") == 0) {
        *alg = WOLFCOSE_ALG_PS256;
    }
    else if (strcmp(name, "PS384") == 0) {
        *alg = WOLFCOSE_ALG_PS384;
    }
    else if (strcmp(name, "PS512") == 0) {
        *alg = WOLFCOSE_ALG_PS512;
    }
#endif
#ifdef WOLFCOSE_HAVE_MLDSA
    else if (strcmp(name, "ML-DSA-44") == 0) {
        *alg = WOLFCOSE_ALG_ML_DSA_44;
    }
    else if (strcmp(name, "ML-DSA-65") == 0) {
        *alg = WOLFCOSE_ALG_ML_DSA_65;
    }
    else if (strcmp(name, "ML-DSA-87") == 0) {
        *alg = WOLFCOSE_ALG_ML_DSA_87;
    }
#endif
#if defined(WOLFCOSE_HAVE_CHACHA20)
    else if (strcmp(name, "ChaCha20") == 0) {
        *alg = WOLFCOSE_ALG_CHACHA20_POLY1305;
    }
#endif
#ifdef WOLFCOSE_HAVE_AESCCM
    else if (strcmp(name, "AES-CCM") == 0) {
        *alg = WOLFCOSE_ALG_AES_CCM_16_128_128;
    }
#endif
    else if (strcmp(name, "HMAC256") == 0) {
        *alg = WOLFCOSE_ALG_HMAC256;
    }
#ifdef WOLFCOSE_HAVE_HMAC384
    else if (strcmp(name, "HMAC384") == 0) {
        *alg = WOLFCOSE_ALG_HMAC384;
    }
#endif
#ifdef WOLFCOSE_HAVE_HMAC512
    else if (strcmp(name, "HMAC512") == 0) {
        *alg = WOLFCOSE_ALG_HMAC512;
    }
#endif
    else {
        fprintf(stderr, "Unknown algorithm: %s\n", name);
        return -1;
    }
    return 0;
}

/* Read entire file into buffer, return bytes read */
static int read_file(const char* path, uint8_t* buf, size_t bufSz,
                      size_t* outLen)
{
    FILE* f;
    size_t n;

    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "Cannot open: %s\n", path);
        return EXIT_IO;
    }
    n = fread(buf, 1, bufSz, f);
    if (n == 0 && ferror(f)) {
        fclose(f);
        fprintf(stderr, "Read error: %s\n", path);
        return EXIT_IO;
    }
    fclose(f);
    *outLen = n;
    return 0;
}

/* Write buffer to file */
static int write_file(const char* path, const uint8_t* buf, size_t len)
{
    FILE* f;

    f = fopen(path, "wb");
    if (f == NULL) {
        fprintf(stderr, "Cannot create: %s\n", path);
        return EXIT_IO;
    }
    if (fwrite(buf, 1, len, f) != len) {
        fclose(f);
        fprintf(stderr, "Write error: %s\n", path);
        return EXIT_IO;
    }
    fclose(f);
    return 0;
}

/* ----- keygen: generate a COSE key and write to file ----- */
static int tool_keygen(int32_t alg, const char* algStr, const char* outPath)
{
    int ret;
    WC_RNG rng;
    WOLFCOSE_KEY coseKey;
    uint8_t keyBuf[WOLFCOSE_TOOL_MAX_KEY];
    size_t keyLen = 0;

#if !defined(WOLFCOSE_HAVE_EDDSA) && !defined(WOLFCOSE_HAVE_ED448)
    /* Only the Ed448-vs-Ed25519 disambiguation reads this. */
    (void)algStr;
#endif

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        fprintf(stderr, "RNG init failed: %d\n", ret);
        return EXIT_CRYPTO;
    }

    wc_CoseKey_Init(&coseKey);

#ifdef WOLFCOSE_HAVE_ES256
    if (alg == WOLFCOSE_ALG_ES256) {
        ecc_key ecc;
        wc_ecc_init(&ecc);
        ret = wc_ecc_make_key(&rng, 32, &ecc);
        if (ret != 0) {
            fprintf(stderr, "ECC keygen failed: %d\n", ret);
            wc_ecc_free(&ecc);
            wc_FreeRng(&rng);
            return EXIT_CRYPTO;
        }
        wc_CoseKey_SetEcc(&coseKey, WOLFCOSE_CRV_P256, &ecc);
        ret = wc_CoseKey_Encode(&coseKey, keyBuf, sizeof(keyBuf), &keyLen);
        wc_ecc_free(&ecc);
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_EDDSA
    if (alg == WOLFCOSE_ALG_EDDSA && strcmp(algStr, "Ed448") != 0) {
        ed25519_key ed;
        wc_ed25519_init(&ed);
        ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &ed);
        if (ret != 0) {
            fprintf(stderr, "Ed25519 keygen failed: %d\n", ret);
            wc_ed25519_free(&ed);
            wc_FreeRng(&rng);
            return EXIT_CRYPTO;
        }
        wc_CoseKey_SetEd25519(&coseKey, &ed);
        ret = wc_CoseKey_Encode(&coseKey, keyBuf, sizeof(keyBuf), &keyLen);
        wc_ed25519_free(&ed);
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_ED448
    if (alg == WOLFCOSE_ALG_EDDSA && strcmp(algStr, "Ed448") == 0) {
        ed448_key ed;
        wc_ed448_init(&ed);
        ret = wc_ed448_make_key(&rng, ED448_KEY_SIZE, &ed);
        if (ret != 0) {
            fprintf(stderr, "Ed448 keygen failed: %d\n", ret);
            wc_ed448_free(&ed);
            wc_FreeRng(&rng);
            return EXIT_CRYPTO;
        }
        wc_CoseKey_SetEd448(&coseKey, &ed);
        ret = wc_CoseKey_Encode(&coseKey, keyBuf, sizeof(keyBuf), &keyLen);
        wc_ed448_free(&ed);
    }
    else
#endif
#if defined(WOLFCOSE_HAVE_RSAPSS) && defined(WOLFSSL_KEY_GEN)
    if (alg == WOLFCOSE_ALG_PS256 || alg == WOLFCOSE_ALG_PS384 ||
        alg == WOLFCOSE_ALG_PS512) {
        RsaKey rsa;
        wc_InitRsaKey(&rsa, NULL);
        ret = wc_MakeRsaKey(&rsa, 2048, WC_RSA_EXPONENT, &rng);
        if (ret != 0) {
            fprintf(stderr, "RSA keygen failed: %d\n", ret);
            wc_FreeRsaKey(&rsa);
            wc_FreeRng(&rng);
            return EXIT_CRYPTO;
        }
        wc_CoseKey_SetRsa(&coseKey, &rsa);
        ret = wc_CoseKey_Encode(&coseKey, keyBuf, sizeof(keyBuf), &keyLen);
        wc_FreeRsaKey(&rsa);
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_MLDSA
    if (alg == WOLFCOSE_ALG_ML_DSA_44 || alg == WOLFCOSE_ALG_ML_DSA_65 ||
        alg == WOLFCOSE_ALG_ML_DSA_87) {
        wc_MlDsaKey dl;
        byte level;
        uint8_t seed[WOLFCOSE_MLDSA_SEED_SZ];
        if (alg == WOLFCOSE_ALG_ML_DSA_44)       level = WC_ML_DSA_44;
        else if (alg == WOLFCOSE_ALG_ML_DSA_65)  level = WC_ML_DSA_65;
        else                                      level = WC_ML_DSA_87;
        ret = wc_MlDsaKey_Init(&dl, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_MlDsaKey_SetParams(&dl, level);
        }
        if (ret == 0) {
            /* RFC 9964: derive from a seed so the conformant private key
             * (the 32-byte seed) can be written to the COSE_Key. */
            ret = wc_RNG_GenerateBlock(&rng, seed, (word32)sizeof(seed));
        }
        if (ret == 0) {
            ret = wc_MlDsaKey_MakeKeyFromSeed(&dl, seed);
        }
        if (ret != 0) {
            fprintf(stderr, "ML-DSA keygen failed: %d\n", ret);
            tool_force_zero(seed, sizeof(seed));
            wc_MlDsaKey_Free(&dl);
            wc_FreeRng(&rng);
            return EXIT_CRYPTO;
        }
        wc_CoseKey_SetMlDsa_ex(&coseKey, alg, &dl, seed, sizeof(seed));
        ret = wc_CoseKey_Encode(&coseKey, keyBuf, sizeof(keyBuf), &keyLen);
        tool_force_zero(seed, sizeof(seed));
        wc_MlDsaKey_Free(&dl);
    }
    else
#endif
    if (alg == WOLFCOSE_ALG_HMAC256 || alg == WOLFCOSE_ALG_HMAC384 ||
        alg == WOLFCOSE_ALG_HMAC512) {
        size_t kLen;
        uint8_t symKey[64];
        if (alg == WOLFCOSE_ALG_HMAC256) {
            kLen = 32;
        }
        else if (alg == WOLFCOSE_ALG_HMAC384) {
            kLen = 48;
        }
        else {
            kLen = 64;
        }
        ret = wc_RNG_GenerateBlock(&rng, symKey, (word32)kLen);
        if (ret != 0) {
            fprintf(stderr, "RNG generate failed: %d\n", ret);
            wc_FreeRng(&rng);
            return EXIT_CRYPTO;
        }
        wc_CoseKey_SetSymmetric(&coseKey, symKey, kLen);
        ret = wc_CoseKey_Encode(&coseKey, keyBuf, sizeof(keyBuf), &keyLen);
    }
    else if (alg == WOLFCOSE_ALG_A128GCM || alg == WOLFCOSE_ALG_A192GCM ||
             alg == WOLFCOSE_ALG_A256GCM ||
             alg == WOLFCOSE_ALG_CHACHA20_POLY1305 ||
             alg == WOLFCOSE_ALG_AES_CCM_16_128_128) {
        size_t kLen;
        uint8_t symKey[32];
        if (alg == WOLFCOSE_ALG_A128GCM ||
            alg == WOLFCOSE_ALG_AES_CCM_16_128_128) {
            kLen = 16;
        }
        else if (alg == WOLFCOSE_ALG_A192GCM) {
            kLen = 24;
        }
        else {
            kLen = 32;
        }
        ret = wc_RNG_GenerateBlock(&rng, symKey, (word32)kLen);
        if (ret != 0) {
            fprintf(stderr, "RNG generate failed: %d\n", ret);
            wc_FreeRng(&rng);
            return EXIT_CRYPTO;
        }
        wc_CoseKey_SetSymmetric(&coseKey, symKey, kLen);
        ret = wc_CoseKey_Encode(&coseKey, keyBuf, sizeof(keyBuf), &keyLen);
    }
    else {
        fprintf(stderr, "Unsupported algorithm for keygen\n");
        wc_FreeRng(&rng);
        return EXIT_USAGE;
    }

    wc_FreeRng(&rng);

    if (ret != 0) {
        fprintf(stderr, "Key encode failed: %d\n", ret);
        return EXIT_CRYPTO;
    }

    ret = write_file(outPath, keyBuf, keyLen);
    if (ret == 0) {
        printf("Generated key: %s (%zu bytes)\n", outPath, keyLen);
    }
    return ret;
}

/* ----- sign: COSE_Sign1 sign ----- */
static int tool_sign(const char* keyPath, int32_t alg, const char* algStr,
                      const char* inPath, const char* outPath)
{
    int ret;
    uint8_t keyBuf[WOLFCOSE_TOOL_MAX_KEY];
    size_t keyLen = 0;
    uint8_t msgBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t msgLen = 0;
    uint8_t outBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t outLen = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    WOLFCOSE_KEY coseKey;
    WC_RNG rng;

#if !defined(WOLFCOSE_HAVE_EDDSA) && !defined(WOLFCOSE_HAVE_ED448)
    /* Only the Ed448-vs-Ed25519 disambiguation reads this. */
    (void)algStr;
#endif


    ret = read_file(keyPath, keyBuf, sizeof(keyBuf), &keyLen);
    if (ret != 0) return ret;

    ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    if (ret != 0) return ret;

    wc_CoseKey_Init(&coseKey);

#ifdef WOLFCOSE_HAVE_ECDSA
    if (alg == WOLFCOSE_ALG_ES256 || alg == WOLFCOSE_ALG_ES384 ||
        alg == WOLFCOSE_ALG_ES512) {
        ecc_key ecc;
        wc_ecc_init(&ecc);
        /* Attach curve is a placeholder; decode takes crv from the key file. */
        ret = wc_CoseKey_SetEcc(&coseKey, WOLFCOSE_CRV_P256, &ecc);
        if (ret == 0) {
            ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        }
        if (ret != 0) {
            fprintf(stderr, "Key decode failed: %d\n", ret);
            wc_ecc_free(&ecc);
            return EXIT_CRYPTO;
        }

        ret = wc_InitRng(&rng);
        if (ret != 0) {
            wc_ecc_free(&ecc);
            return EXIT_CRYPTO;
        }

        ret = wc_CoseSign1_Sign(&coseKey, alg, NULL, 0,
            msgBuf, msgLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            outBuf, sizeof(outBuf), &outLen, &rng);

        wc_FreeRng(&rng);
        wc_ecc_free(&ecc);
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_EDDSA
    if (alg == WOLFCOSE_ALG_EDDSA && strcmp(algStr, "Ed448") != 0) {
        ed25519_key ed;
        wc_ed25519_init(&ed);
        ret = wc_CoseKey_SetEd25519(&coseKey, &ed);
        if (ret == 0) {
            ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        }
        if (ret != 0) {
            fprintf(stderr, "Key decode failed: %d\n", ret);
            wc_ed25519_free(&ed);
            return EXIT_CRYPTO;
        }

        ret = wc_InitRng(&rng);
        if (ret != 0) {
            wc_ed25519_free(&ed);
            return EXIT_CRYPTO;
        }

        ret = wc_CoseSign1_Sign(&coseKey, alg, NULL, 0,
            msgBuf, msgLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            outBuf, sizeof(outBuf), &outLen, &rng);

        wc_FreeRng(&rng);
        wc_ed25519_free(&ed);
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_ED448
    if (alg == WOLFCOSE_ALG_EDDSA && strcmp(algStr, "Ed448") == 0) {
        ed448_key ed;
        wc_ed448_init(&ed);
        ret = wc_CoseKey_SetEd448(&coseKey, &ed);
        if (ret == 0) {
            ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        }
        if (ret != 0) {
            fprintf(stderr, "Key decode failed: %d\n", ret);
            wc_ed448_free(&ed);
            return EXIT_CRYPTO;
        }

        ret = wc_InitRng(&rng);
        if (ret != 0) {
            wc_ed448_free(&ed);
            return EXIT_CRYPTO;
        }

        ret = wc_CoseSign1_Sign(&coseKey, alg, NULL, 0,
            msgBuf, msgLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            outBuf, sizeof(outBuf), &outLen, &rng);

        wc_FreeRng(&rng);
        wc_ed448_free(&ed);
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_RSAPSS
    if (alg == WOLFCOSE_ALG_PS256 || alg == WOLFCOSE_ALG_PS384 ||
        alg == WOLFCOSE_ALG_PS512) {
        RsaKey rsa;
        wc_InitRsaKey(&rsa, NULL);
        ret = wc_CoseKey_SetRsa(&coseKey, &rsa);
        if (ret == 0) {
            ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        }
        if (ret != 0) {
            fprintf(stderr, "Key decode failed: %d\n", ret);
            wc_FreeRsaKey(&rsa);
            return EXIT_CRYPTO;
        }

        ret = wc_InitRng(&rng);
        if (ret != 0) {
            wc_FreeRsaKey(&rsa);
            return EXIT_CRYPTO;
        }

        ret = wc_CoseSign1_Sign(&coseKey, alg, NULL, 0,
            msgBuf, msgLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            outBuf, sizeof(outBuf), &outLen, &rng);

        wc_FreeRng(&rng);
        wc_FreeRsaKey(&rsa);
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_MLDSA
    if (alg == WOLFCOSE_ALG_ML_DSA_44 || alg == WOLFCOSE_ALG_ML_DSA_65 ||
        alg == WOLFCOSE_ALG_ML_DSA_87) {
        wc_MlDsaKey dl;
        ret = wc_MlDsaKey_Init(&dl, NULL, INVALID_DEVID);
        if (ret != 0) {
            fprintf(stderr, "ML-DSA init failed: %d\n", ret);
            return EXIT_CRYPTO;
        }
        ret = wc_CoseKey_SetMlDsa(&coseKey, alg, &dl);
        if (ret == 0) {
            ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        }
        if (ret != 0) {
            fprintf(stderr, "Key decode failed: %d\n", ret);
            wc_MlDsaKey_Free(&dl);
            return EXIT_CRYPTO;
        }

        ret = wc_InitRng(&rng);
        if (ret != 0) {
            wc_MlDsaKey_Free(&dl);
            return EXIT_CRYPTO;
        }

        ret = wc_CoseSign1_Sign(&coseKey, alg, NULL, 0,
            msgBuf, msgLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            outBuf, sizeof(outBuf), &outLen, &rng);

        wc_FreeRng(&rng);
        wc_MlDsaKey_Free(&dl);
    }
    else
#endif
    {
        fprintf(stderr, "Unsupported sign algorithm\n");
        return EXIT_USAGE;
    }

    if (ret != 0) {
        fprintf(stderr, "Sign failed: %d\n", ret);
        return EXIT_CRYPTO;
    }

    ret = write_file(outPath, outBuf, outLen);
    if (ret == 0) {
        printf("Signed: %zu byte payload -> %zu byte COSE_Sign1\n",
               msgLen, outLen);
    }
    return ret;
}

/* ----- verify: COSE_Sign1 verify ----- */
static int tool_verify(const char* keyPath, const char* inPath)
{
    int ret = 0;
    uint8_t keyBuf[WOLFCOSE_TOOL_MAX_KEY];
    size_t keyLen = 0;
    uint8_t msgBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t msgLen = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    WOLFCOSE_KEY coseKey;
    WOLFCOSE_HDR hdr;
    const uint8_t* payload = NULL;
    size_t payloadLen = 0;
    int keyMatched = 0;
    int32_t kty = 0;
    int32_t crv = 0;
    int32_t keyAlg = 0;

    ret = read_file(keyPath, keyBuf, sizeof(keyBuf), &keyLen);
    if (ret == 0) {
        ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    }

    /* Peek kty/crv/alg with nothing attached so no importer runs, then
     * dispatch to exactly one correctly-typed key. */
    if (ret == 0) {
        wc_CoseKey_Init(&coseKey);
        (void)wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        kty = coseKey.kty;
        crv = coseKey.crv;
        keyAlg = coseKey.alg;
    }

#ifdef WOLFCOSE_HAVE_ECDSA
    if (ret == 0 && kty == WOLFCOSE_KTY_EC2) {
        ecc_key ecc;
        keyMatched = 1;
        wc_CoseKey_Init(&coseKey);
        wc_ecc_init(&ecc);
        ret = wc_CoseKey_SetEcc(&coseKey, crv, &ecc);
        if (ret == 0) {
            ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        }
        if (ret == 0) {
            ret = wc_CoseSign1_Verify(&coseKey, msgBuf, msgLen,
                NULL, 0, NULL, 0, scratch, sizeof(scratch),
                &hdr, &payload, &payloadLen);
        }
        wc_ecc_free(&ecc);
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_RSAPSS
    if (ret == 0 && kty == WOLFCOSE_KTY_RSA) {
        RsaKey rsa;
        keyMatched = 1;
        wc_CoseKey_Init(&coseKey);
        wc_InitRsaKey(&rsa, NULL);
        ret = wc_CoseKey_SetRsa(&coseKey, &rsa);
        if (ret == 0) {
            ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        }
        if (ret == 0) {
            ret = wc_CoseSign1_Verify(&coseKey, msgBuf, msgLen,
                NULL, 0, NULL, 0, scratch, sizeof(scratch),
                &hdr, &payload, &payloadLen);
        }
        wc_FreeRsaKey(&rsa);
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_EDDSA
    if (ret == 0 && kty == WOLFCOSE_KTY_OKP &&
        crv == WOLFCOSE_CRV_ED25519) {
        ed25519_key ed;
        keyMatched = 1;
        wc_CoseKey_Init(&coseKey);
        wc_ed25519_init(&ed);
        ret = wc_CoseKey_SetEd25519(&coseKey, &ed);
        if (ret == 0) {
            ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        }
        if (ret == 0) {
            ret = wc_CoseSign1_Verify(&coseKey, msgBuf, msgLen,
                NULL, 0, NULL, 0, scratch, sizeof(scratch),
                &hdr, &payload, &payloadLen);
        }
        wc_ed25519_free(&ed);
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_ED448
    if (ret == 0 && kty == WOLFCOSE_KTY_OKP &&
        crv == WOLFCOSE_CRV_ED448) {
        ed448_key ed;
        keyMatched = 1;
        wc_CoseKey_Init(&coseKey);
        wc_ed448_init(&ed);
        ret = wc_CoseKey_SetEd448(&coseKey, &ed);
        if (ret == 0) {
            ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        }
        if (ret == 0) {
            ret = wc_CoseSign1_Verify(&coseKey, msgBuf, msgLen,
                NULL, 0, NULL, 0, scratch, sizeof(scratch),
                &hdr, &payload, &payloadLen);
        }
        wc_ed448_free(&ed);
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_MLDSA
    if (ret == 0 && kty == WOLFCOSE_KTY_AKP) {
        wc_MlDsaKey dl;
        keyMatched = 1;
        wc_CoseKey_Init(&coseKey);
        ret = wc_MlDsaKey_Init(&dl, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_CoseKey_SetMlDsa(&coseKey, keyAlg, &dl);
            if (ret == 0) {
                ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
            }
            if (ret == 0) {
                ret = wc_CoseSign1_Verify(&coseKey, msgBuf, msgLen,
                    NULL, 0, NULL, 0, scratch, sizeof(scratch),
                    &hdr, &payload, &payloadLen);
            }
            wc_MlDsaKey_Free(&dl);
        }
    }
    else
#endif
    {
        (void)crv;
        (void)keyAlg;
        fprintf(stderr, "Unsupported key type\n");
        ret = EXIT_CRYPTO;
    }

    /* Report result */
    if (keyMatched != 0 && ret != 0) {
        fprintf(stderr, "Verification FAILED: %d\n", ret);
        ret = EXIT_CRYPTO;
    }
    else if (ret == 0) {
        printf("Verification OK. Payload: %zu bytes\n", payloadLen);
    }

    return ret;
}

#if defined(WOLFCOSE_COUNTERSIGN)
static int tool_counter_apply(WOLFCOSE_KEY* key, int32_t alg,
    int verify, size_t counterIndex,
    const uint8_t* msg, size_t msgLen,
    const uint8_t* detached, size_t detachedLen,
    const uint8_t* aad, size_t aadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen)
{
    int ret;

    if (verify != 0) {
#if defined(WOLFCOSE_COUNTERSIGN_VERIFY)
        WOLFCOSE_HDR hdr;

        ret = wc_Cose_VerifyCounterSignature(key, counterIndex,
            msg, msgLen, detached, detachedLen, aad, aadLen,
            scratch, scratchSz, &hdr);
        if (ret == 0) {
            printf("Countersignature %zu verification OK", counterIndex);
            if (hdr.kidLen != 0u) {
                printf(". KID: %.*s", (int)hdr.kidLen,
                       (const char*)hdr.kid);
            }
            printf("\n");
        }
#else
        (void)key;
        (void)counterIndex;
        (void)msg;
        (void)msgLen;
        (void)detached;
        (void)detachedLen;
        (void)aad;
        (void)aadLen;
        (void)scratch;
        (void)scratchSz;
        ret = WOLFCOSE_E_UNSUPPORTED;
#endif
    }
    else {
#if defined(WOLFCOSE_COUNTERSIGN_SIGN)
        WOLFCOSE_COUNTERSIGNATURE counterSigner;
        WC_RNG rng;

        ret = wc_InitRng(&rng);
        if (ret == 0) {
            counterSigner.algId = alg;
            counterSigner.key = key;
            counterSigner.kid = key->kid;
            counterSigner.kidLen = key->kidLen;
            ret = wc_Cose_AddCounterSignature(&counterSigner,
                msg, msgLen, detached, detachedLen, aad, aadLen,
                scratch, scratchSz, out, outSz, outLen, &rng);
            wc_FreeRng(&rng);
        }
#else
        (void)key;
        (void)alg;
        (void)msg;
        (void)msgLen;
        (void)detached;
        (void)detachedLen;
        (void)aad;
        (void)aadLen;
        (void)scratch;
        (void)scratchSz;
        (void)out;
        (void)outSz;
        (void)outLen;
        ret = WOLFCOSE_E_UNSUPPORTED;
#endif
    }
    return ret;
}

static int tool_counter(const char* keyPath, int32_t alg,
    int verify, size_t counterIndex,
    const char* inPath, const char* outPath,
    const char* detachedPath, const char* aadPath)
{
    int ret;
    int keyMatched = 0;
    int32_t kty = 0;
    int32_t crv = 0;
    int32_t keyAlg = 0;
    uint8_t keyBuf[WOLFCOSE_TOOL_MAX_KEY];
    uint8_t msgBuf[WOLFCOSE_TOOL_MAX_MSG];
    uint8_t detachedBuf[WOLFCOSE_TOOL_MAX_MSG];
    uint8_t aadBuf[WOLFCOSE_TOOL_MAX_MSG];
    uint8_t outBuf[WOLFCOSE_TOOL_MAX_MSG + WOLFCOSE_TOOL_MAX_KEY +
                   WOLFCOSE_MAX_SIG_SZ + 128u];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    size_t keyLen = 0u;
    size_t msgLen = 0u;
    size_t detachedLen = 0u;
    size_t aadLen = 0u;
    size_t outLen = 0u;
    const uint8_t* detached = NULL;
    const uint8_t* aad = NULL;
    WOLFCOSE_KEY coseKey;

    ret = read_file(keyPath, keyBuf, sizeof(keyBuf), &keyLen);
    if (ret == 0) {
        ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    }
    if ((ret == 0) && (detachedPath != NULL)) {
        ret = read_file(detachedPath, detachedBuf,
                        sizeof(detachedBuf), &detachedLen);
        if (ret == 0) {
            detached = detachedBuf;
        }
    }
    if ((ret == 0) && (aadPath != NULL)) {
        ret = read_file(aadPath, aadBuf, sizeof(aadBuf), &aadLen);
        if (ret == 0) {
            aad = aadBuf;
        }
    }
    if (ret != 0) {
        return ret;
    }

    wc_CoseKey_Init(&coseKey);
    (void)wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
    kty = coseKey.kty;
    crv = coseKey.crv;
    keyAlg = coseKey.alg;

#ifdef WOLFCOSE_HAVE_ECDSA
    if (kty == WOLFCOSE_KTY_EC2) {
        ecc_key ecc;

        keyMatched = 1;
        wc_CoseKey_Init(&coseKey);
        wc_ecc_init(&ecc);
        ret = wc_CoseKey_SetEcc(&coseKey, crv, &ecc);
        if (ret == 0) {
            ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        }
        if (ret == 0) {
            ret = tool_counter_apply(&coseKey, alg, verify, counterIndex,
                msgBuf, msgLen, detached, detachedLen, aad, aadLen,
                scratch, sizeof(scratch), outBuf, sizeof(outBuf), &outLen);
        }
        wc_ecc_free(&ecc);
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_RSAPSS
    if (kty == WOLFCOSE_KTY_RSA) {
        RsaKey rsa;

        keyMatched = 1;
        wc_CoseKey_Init(&coseKey);
        wc_InitRsaKey(&rsa, NULL);
        ret = wc_CoseKey_SetRsa(&coseKey, &rsa);
        if (ret == 0) {
            ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        }
        if (ret == 0) {
            ret = tool_counter_apply(&coseKey, alg, verify, counterIndex,
                msgBuf, msgLen, detached, detachedLen, aad, aadLen,
                scratch, sizeof(scratch), outBuf, sizeof(outBuf), &outLen);
        }
        wc_FreeRsaKey(&rsa);
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_EDDSA
    if ((kty == WOLFCOSE_KTY_OKP) &&
        (crv == WOLFCOSE_CRV_ED25519)) {
        ed25519_key ed;

        keyMatched = 1;
        wc_CoseKey_Init(&coseKey);
        wc_ed25519_init(&ed);
        ret = wc_CoseKey_SetEd25519(&coseKey, &ed);
        if (ret == 0) {
            ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        }
        if (ret == 0) {
            ret = tool_counter_apply(&coseKey, alg, verify, counterIndex,
                msgBuf, msgLen, detached, detachedLen, aad, aadLen,
                scratch, sizeof(scratch), outBuf, sizeof(outBuf), &outLen);
        }
        wc_ed25519_free(&ed);
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_ED448
    if ((kty == WOLFCOSE_KTY_OKP) && (crv == WOLFCOSE_CRV_ED448)) {
        ed448_key ed;

        keyMatched = 1;
        wc_CoseKey_Init(&coseKey);
        wc_ed448_init(&ed);
        ret = wc_CoseKey_SetEd448(&coseKey, &ed);
        if (ret == 0) {
            ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        }
        if (ret == 0) {
            ret = tool_counter_apply(&coseKey, alg, verify, counterIndex,
                msgBuf, msgLen, detached, detachedLen, aad, aadLen,
                scratch, sizeof(scratch), outBuf, sizeof(outBuf), &outLen);
        }
        wc_ed448_free(&ed);
    }
    else
#endif
#ifdef WOLFCOSE_HAVE_MLDSA
    if (kty == WOLFCOSE_KTY_AKP) {
        wc_MlDsaKey dl;

        keyMatched = 1;
        wc_CoseKey_Init(&coseKey);
        ret = wc_MlDsaKey_Init(&dl, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_CoseKey_SetMlDsa(&coseKey, keyAlg, &dl);
        }
        if (ret == 0) {
            ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        }
        if (ret == 0) {
            ret = tool_counter_apply(&coseKey, alg, verify, counterIndex,
                msgBuf, msgLen, detached, detachedLen, aad, aadLen,
                scratch, sizeof(scratch), outBuf, sizeof(outBuf), &outLen);
        }
        wc_MlDsaKey_Free(&dl);
    }
    else
#endif
    {
        (void)crv;
        (void)keyAlg;
    }

    if (keyMatched == 0) {
        fprintf(stderr, "Unsupported countersigning key type\n");
        return EXIT_USAGE;
    }
    if (ret != 0) {
        fprintf(stderr, "%s failed: %d\n",
                (verify != 0) ? "Counter verification" : "Countersign",
                ret);
        return EXIT_CRYPTO;
    }
    if (verify == 0) {
        ret = write_file(outPath, outBuf, outLen);
        if (ret == 0) {
            printf("Countersigned: %zu byte COSE object -> %zu bytes\n",
                   msgLen, outLen);
        }
    }
    return ret;
}
#endif /* WOLFCOSE_COUNTERSIGN */

/* ----- enc: COSE_Encrypt0 encrypt ----- */
#if defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM) || \
    (defined(WOLFCOSE_HAVE_CHACHA20))
static int tool_enc(const char* keyPath, int32_t alg,
                     const char* inPath, const char* outPath)
{
    int ret;
    uint8_t keyBuf[WOLFCOSE_TOOL_MAX_KEY];
    size_t keyLen = 0;
    uint8_t msgBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t msgLen = 0;
    uint8_t outBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t outLen = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t iv[13]; /* max nonce: 13 for AES-CCM-16, 12 for GCM/ChaCha20 */
    size_t ivLen;
    WOLFCOSE_KEY coseKey;
    WC_RNG rng;

    ret = read_file(keyPath, keyBuf, sizeof(keyBuf), &keyLen);
    if (ret != 0) return ret;

    ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    if (ret != 0) return ret;

    wc_CoseKey_Init(&coseKey);
    coseKey.kty = WOLFCOSE_KTY_SYMMETRIC;
    ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
    if (ret != 0) {
        fprintf(stderr, "Key decode failed: %d\n", ret);
        return EXIT_CRYPTO;
    }

    /* Determine nonce length for algorithm */
    if (alg == WOLFCOSE_ALG_AES_CCM_16_64_128  ||
        alg == WOLFCOSE_ALG_AES_CCM_16_64_256  ||
        alg == WOLFCOSE_ALG_AES_CCM_16_128_128 ||
        alg == WOLFCOSE_ALG_AES_CCM_16_128_256) {
        ivLen = 13; /* CCM-16: L=2, nonce=13 */
    }
    else if (alg == WOLFCOSE_ALG_AES_CCM_64_64_128  ||
             alg == WOLFCOSE_ALG_AES_CCM_64_64_256  ||
             alg == WOLFCOSE_ALG_AES_CCM_64_128_128 ||
             alg == WOLFCOSE_ALG_AES_CCM_64_128_256) {
        ivLen = 7;  /* CCM-64: L=8, nonce=7 */
    }
    else {
        ivLen = 12; /* GCM and ChaCha20 */
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) return EXIT_CRYPTO;

    ret = wc_RNG_GenerateBlock(&rng, iv, (word32)ivLen);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return EXIT_CRYPTO;
    }

    ret = wc_CoseEncrypt0_Encrypt(&coseKey, alg,
        iv, ivLen,
        msgBuf, msgLen, NULL, 0, NULL,
        NULL, 0, scratch, sizeof(scratch),
        outBuf, sizeof(outBuf), &outLen);

    wc_FreeRng(&rng);

    if (ret != 0) {
        fprintf(stderr, "Encrypt failed: %d\n", ret);
        return EXIT_CRYPTO;
    }

    ret = write_file(outPath, outBuf, outLen);
    if (ret == 0) {
        printf("Encrypted: %zu byte plaintext -> %zu byte COSE_Encrypt0\n",
               msgLen, outLen);
    }
    return ret;
}

/* ----- dec: COSE_Encrypt0 decrypt ----- */
static int tool_dec(const char* keyPath, const char* inPath,
                     const char* outPath)
{
    int ret;
    uint8_t keyBuf[WOLFCOSE_TOOL_MAX_KEY];
    size_t keyLen = 0;
    uint8_t msgBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t msgLen = 0;
    uint8_t plainBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t plainLen = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    WOLFCOSE_KEY coseKey;
    WOLFCOSE_HDR hdr;

    ret = read_file(keyPath, keyBuf, sizeof(keyBuf), &keyLen);
    if (ret != 0) return ret;

    ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    if (ret != 0) return ret;

    wc_CoseKey_Init(&coseKey);
    coseKey.kty = WOLFCOSE_KTY_SYMMETRIC;
    ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
    if (ret != 0) {
        fprintf(stderr, "Key decode failed: %d\n", ret);
        return EXIT_CRYPTO;
    }

    ret = wc_CoseEncrypt0_Decrypt(&coseKey, msgBuf, msgLen,
        NULL, 0, NULL, 0, scratch, sizeof(scratch), &hdr,
        plainBuf, sizeof(plainBuf), &plainLen);
    if (ret != 0) {
        fprintf(stderr, "Decrypt FAILED: %d\n", ret);
        return EXIT_CRYPTO;
    }

    ret = write_file(outPath, plainBuf, plainLen);
    if (ret == 0) {
        printf("Decrypted: %zu byte COSE_Encrypt0 -> %zu byte plaintext\n",
               msgLen, plainLen);
    }
    return ret;
}
#endif /* WOLFCOSE_HAVE_AESGCM || WOLFCOSE_HAVE_AESCCM || (WOLFCOSE_HAVE_CHACHA20) */

/* ----- mac: COSE_Mac0 create ----- */
#if defined(WOLFCOSE_HAVE_HMAC)
static int tool_mac(const char* keyPath, int32_t alg,
                     const char* inPath, const char* outPath)
{
    int ret;
    uint8_t keyBuf[WOLFCOSE_TOOL_MAX_KEY];
    size_t keyLen = 0;
    uint8_t msgBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t msgLen = 0;
    uint8_t outBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t outLen = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    WOLFCOSE_KEY coseKey;

    ret = read_file(keyPath, keyBuf, sizeof(keyBuf), &keyLen);
    if (ret != 0) return ret;

    ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    if (ret != 0) return ret;

    wc_CoseKey_Init(&coseKey);
    coseKey.kty = WOLFCOSE_KTY_SYMMETRIC;
    ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
    if (ret != 0) {
        fprintf(stderr, "Key decode failed: %d\n", ret);
        return EXIT_CRYPTO;
    }

    ret = wc_CoseMac0_Create(&coseKey, alg, NULL, 0,
        msgBuf, msgLen, NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        outBuf, sizeof(outBuf), &outLen);
    if (ret != 0) {
        fprintf(stderr, "MAC create failed: %d\n", ret);
        return EXIT_CRYPTO;
    }

    ret = write_file(outPath, outBuf, outLen);
    if (ret == 0) {
        printf("MAC: %zu byte payload -> %zu byte COSE_Mac0\n",
               msgLen, outLen);
    }
    return ret;
}

/* ----- macverify: COSE_Mac0 verify ----- */
static int tool_macverify(const char* keyPath, const char* inPath)
{
    int ret;
    uint8_t keyBuf[WOLFCOSE_TOOL_MAX_KEY];
    size_t keyLen = 0;
    uint8_t msgBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t msgLen = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    WOLFCOSE_KEY coseKey;
    WOLFCOSE_HDR hdr;
    const uint8_t* payload = NULL;
    size_t payloadLen = 0;

    ret = read_file(keyPath, keyBuf, sizeof(keyBuf), &keyLen);
    if (ret != 0) return ret;

    ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    if (ret != 0) return ret;

    wc_CoseKey_Init(&coseKey);
    coseKey.kty = WOLFCOSE_KTY_SYMMETRIC;
    ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
    if (ret != 0) {
        fprintf(stderr, "Key decode failed: %d\n", ret);
        return EXIT_CRYPTO;
    }

    ret = wc_CoseMac0_Verify(&coseKey, msgBuf, msgLen,
        NULL, 0, NULL, 0, scratch, sizeof(scratch),
        &hdr, &payload, &payloadLen);
    if (ret != 0) {
        fprintf(stderr, "MAC verification FAILED: %d\n", ret);
        return EXIT_CRYPTO;
    }

    printf("MAC verification OK. Payload: %zu bytes\n", payloadLen);
    return 0;
}
#endif /* WOLFCOSE_HAVE_HMAC */

/* ----- info: dump CBOR structure of a COSE message ----- */
static int tool_info(const char* inPath)
{
    int ret;
    uint8_t msgBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t msgLen = 0;
    WOLFCOSE_CBOR_CTX ctx;
    WOLFCOSE_CBOR_ITEM item;
    size_t i;
    int indent = 0;

    ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    if (ret != 0) return ret;

    printf("COSE message: %zu bytes\n", msgLen);

    ctx.buf = msgBuf;
    ctx.bufSz = msgLen;
    ctx.idx = 0;

    while (ctx.idx < ctx.bufSz) {
        size_t pos = ctx.idx;
        ret = wc_CBOR_DecodeHead(&ctx, &item);
        if (ret != 0) {
            printf("  [decode error at offset %zu: %d]\n", pos, ret);
            break;
        }

        for (i = 0; i < (size_t)indent; i++) printf("  ");

        switch (item.majorType) {
            case WOLFCOSE_CBOR_UINT:
                printf("[%zu] uint: %llu\n", pos,
                       (unsigned long long)item.val);
                break;
            case WOLFCOSE_CBOR_NEGINT:
                printf("[%zu] negint: -%llu\n", pos,
                       (unsigned long long)(item.val + 1));
                break;
            case WOLFCOSE_CBOR_BSTR:
                printf("[%zu] bstr(%zu): ", pos, item.dataLen);
                for (i = 0; i < item.dataLen && i < 32; i++)
                    printf("%02X", item.data[i]);
                if (item.dataLen > 32) printf("...");
                printf("\n");
                break;
            case WOLFCOSE_CBOR_TSTR:
                printf("[%zu] tstr(%zu): \"%.*s\"\n", pos, item.dataLen,
                       (int)item.dataLen, item.data);
                break;
            case WOLFCOSE_CBOR_ARRAY:
                printf("[%zu] array(%llu)\n", pos,
                       (unsigned long long)item.val);
                break;
            case WOLFCOSE_CBOR_MAP:
                printf("[%zu] map(%llu)\n", pos,
                       (unsigned long long)item.val);
                break;
            case WOLFCOSE_CBOR_TAG:
                printf("[%zu] tag(%llu)\n", pos,
                       (unsigned long long)item.val);
                break;
            case WOLFCOSE_CBOR_SIMPLE:
                if (item.val == 20) printf("[%zu] false\n", pos);
                else if (item.val == 21) printf("[%zu] true\n", pos);
                else if (item.val == 22) printf("[%zu] null\n", pos);
                else printf("[%zu] simple(%llu)\n", pos,
                            (unsigned long long)item.val);
                break;
            default:
                printf("[%zu] unknown(%u, %llu)\n", pos, item.majorType,
                       (unsigned long long)item.val);
                break;
        }
    }

    return 0;
}

/* ----- test: in-memory round-trip self-tests for all algorithms ----- */

/* Sign round-trip: keygen -> sign -> verify -> check payload */
#ifdef WOLFCOSE_HAVE_ES256
static int test_sign_es256(void)
{
    int ret = 0;
    WC_RNG rng;
    ecc_key ecc;
    WOLFCOSE_KEY key;
    uint8_t payload[] = "wolfCOSE roundtrip";
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;
    WOLFCOSE_HDR hdr;
    const uint8_t* decoded;
    size_t decodedLen;
    int rngInit = 0, eccInit = 0;

    printf("  %-12s sign/verify ... ", "ES256");

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wc_ecc_init(&ecc);
    }
    if (ret == 0) {
        eccInit = 1;
        ret = wc_ecc_make_key(&rng, 32, &ecc);
    }
    if (ret == 0) {
        wc_CoseKey_Init(&key);
        wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &ecc);

        ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0,
            payload, sizeof(payload) - 1, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
    }
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&key, out, outLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decoded, &decodedLen);
    }
    if (ret == 0) {
        if (decodedLen != sizeof(payload) - 1 ||
            memcmp(decoded, payload, decodedLen) != 0) {
            ret = -1;
        }
    }

    /* Cleanup */
    if (eccInit != 0) {
        wc_ecc_free(&ecc);
    }
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    printf("%s\n", ret == 0 ? "PASS" : "FAIL");
    return ret;
}
#endif

#ifdef WOLFCOSE_HAVE_EDDSA
static int test_sign_eddsa(void)
{
    int ret = 0;
    WC_RNG rng;
    ed25519_key ed;
    WOLFCOSE_KEY key;
    uint8_t payload[] = "wolfCOSE roundtrip";
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;
    WOLFCOSE_HDR hdr;
    const uint8_t* decoded;
    size_t decodedLen;
    int rngInit = 0, edInit = 0;

    printf("  %-12s sign/verify ... ", "EdDSA");

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wc_ed25519_init(&ed);
    }
    if (ret == 0) {
        edInit = 1;
        ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &ed);
    }
    if (ret == 0) {
        wc_CoseKey_Init(&key);
        wc_CoseKey_SetEd25519(&key, &ed);

        ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_EDDSA, NULL, 0,
            payload, sizeof(payload) - 1, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
    }
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&key, out, outLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decoded, &decodedLen);
    }
    if (ret == 0) {
        if (decodedLen != sizeof(payload) - 1 ||
            memcmp(decoded, payload, decodedLen) != 0) {
            ret = -1;
        }
    }

    /* Cleanup */
    if (edInit != 0) {
        wc_ed25519_free(&ed);
    }
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    printf("%s\n", ret == 0 ? "PASS" : "FAIL");
    return ret;
}
#endif

#ifdef WOLFCOSE_HAVE_ED448
static int test_sign_ed448(void)
{
    int ret = 0;
    WC_RNG rng;
    ed448_key ed;
    WOLFCOSE_KEY key;
    uint8_t payload[] = "wolfCOSE roundtrip";
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;
    WOLFCOSE_HDR hdr;
    const uint8_t* decoded;
    size_t decodedLen;
    int rngInit = 0, edInit = 0;

    printf("  %-12s sign/verify ... ", "Ed448");

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wc_ed448_init(&ed);
    }
    if (ret == 0) {
        edInit = 1;
        ret = wc_ed448_make_key(&rng, ED448_KEY_SIZE, &ed);
    }
    if (ret == 0) {
        wc_CoseKey_Init(&key);
        wc_CoseKey_SetEd448(&key, &ed);

        ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_EDDSA, NULL, 0,
            payload, sizeof(payload) - 1, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
    }
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&key, out, outLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decoded, &decodedLen);
    }
    if (ret == 0) {
        if (decodedLen != sizeof(payload) - 1 ||
            memcmp(decoded, payload, decodedLen) != 0) {
            ret = -1;
        }
    }

    /* Cleanup */
    if (edInit != 0) {
        wc_ed448_free(&ed);
    }
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    printf("%s\n", ret == 0 ? "PASS" : "FAIL");
    return ret;
}
#endif

#if defined(WOLFCOSE_HAVE_RSAPSS) && defined(WOLFSSL_KEY_GEN)
static int test_sign_pss(const char* name, int32_t alg)
{
    int ret = 0;
    WC_RNG rng;
    RsaKey rsa;
    WOLFCOSE_KEY key;
    uint8_t payload[] = "wolfCOSE roundtrip";
    uint8_t scratch[2048];
    uint8_t out[2048];
    size_t outLen = 0;
    WOLFCOSE_HDR hdr;
    const uint8_t* decoded;
    size_t decodedLen;
    int rngInit = 0, rsaInit = 0;

    printf("  %-12s sign/verify ... ", name);

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wc_InitRsaKey(&rsa, NULL);
    }
    if (ret == 0) {
        rsaInit = 1;
        ret = wc_MakeRsaKey(&rsa, 2048, WC_RSA_EXPONENT, &rng);
    }
    if (ret == 0) {
        wc_CoseKey_Init(&key);
        wc_CoseKey_SetRsa(&key, &rsa);

        ret = wc_CoseSign1_Sign(&key, alg, NULL, 0,
            payload, sizeof(payload) - 1, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
    }
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&key, out, outLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decoded, &decodedLen);
    }
    if (ret == 0) {
        if (decodedLen != sizeof(payload) - 1 ||
            memcmp(decoded, payload, decodedLen) != 0) {
            ret = -1;
        }
    }

    /* Cleanup */
    if (rsaInit != 0) {
        wc_FreeRsaKey(&rsa);
    }
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    printf("%s\n", ret == 0 ? "PASS" : "FAIL");
    return ret;
}
#endif

#ifdef WOLFCOSE_HAVE_MLDSA
static int test_sign_mldsa(const char* name, int32_t alg, byte level)
{
    int ret = 0;
    WC_RNG rng;
    wc_MlDsaKey dl;
    WOLFCOSE_KEY key;
    uint8_t payload[] = "wolfCOSE roundtrip";
    uint8_t scratch[8192];
    uint8_t out[8192];
    size_t outLen = 0;
    WOLFCOSE_HDR hdr;
    const uint8_t* decoded;
    size_t decodedLen;
    int rngInit = 0, dlInit = 0;

    printf("  %-12s sign/verify ... ", name);

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wc_MlDsaKey_Init(&dl, NULL, INVALID_DEVID);
    }
    if (ret == 0) {
        dlInit = 1;
        ret = wc_MlDsaKey_SetParams(&dl, level);
    }
    if (ret == 0) {
        ret = wc_MlDsaKey_MakeKey(&dl, &rng);
    }
    if (ret == 0) {
        wc_CoseKey_Init(&key);
        wc_CoseKey_SetMlDsa(&key, alg, &dl);

        ret = wc_CoseSign1_Sign(&key, alg, NULL, 0,
            payload, sizeof(payload) - 1, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
    }
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&key, out, outLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decoded, &decodedLen);
    }
    if (ret == 0) {
        if (decodedLen != sizeof(payload) - 1 ||
            memcmp(decoded, payload, decodedLen) != 0) {
            ret = -1;
        }
    }

    /* Cleanup */
    if (dlInit != 0) {
        wc_MlDsaKey_Free(&dl);
    }
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    printf("%s\n", ret == 0 ? "PASS" : "FAIL");
    return ret;
}
#endif

/* Encrypt round-trip: keygen -> encrypt -> decrypt -> check payload */
#if defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM) || \
    (defined(WOLFCOSE_HAVE_CHACHA20))
static int test_enc_roundtrip(const char* name, int32_t alg,
                               size_t keyLen, size_t nonceLen)
{
    int ret = 0;
    WC_RNG rng;
    WOLFCOSE_KEY key;
    uint8_t keyData[32];
    uint8_t iv[13];
    uint8_t payload[] = "wolfCOSE roundtrip";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plain[256];
    size_t plainLen = 0;
    WOLFCOSE_HDR hdr;
    int rngInit = 0;

    printf("  %-12s enc/dec   ... ", name);

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wc_RNG_GenerateBlock(&rng, keyData, (word32)keyLen);
    }
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(&rng, iv, (word32)nonceLen);
    }
    if (ret == 0) {
        wc_CoseKey_Init(&key);
        wc_CoseKey_SetSymmetric(&key, keyData, keyLen);

        ret = wc_CoseEncrypt0_Encrypt(&key, alg, iv, nonceLen,
            payload, sizeof(payload) - 1, NULL, 0, NULL,
            NULL, 0, scratch, sizeof(scratch),
            out, sizeof(out), &outLen);
    }
    if (ret == 0) {
        ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch), &hdr,
            plain, sizeof(plain), &plainLen);
    }
    if (ret == 0) {
        if (plainLen != sizeof(payload) - 1 ||
            memcmp(plain, payload, plainLen) != 0) {
            ret = -1;
        }
    }

    /* Cleanup */
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    printf("%s\n", ret == 0 ? "PASS" : "FAIL");
    return ret;
}
#endif

/* MAC round-trip: keygen -> mac -> macverify -> check payload */
#if defined(WOLFCOSE_HAVE_HMAC)
static int test_mac_roundtrip(const char* name, int32_t alg, size_t keyLen)
{
    int ret = 0;
    WC_RNG rng;
    WOLFCOSE_KEY key;
    uint8_t keyData[64];
    uint8_t payload[] = "wolfCOSE roundtrip";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    WOLFCOSE_HDR hdr;
    const uint8_t* decoded;
    size_t decodedLen;
    int rngInit = 0;

    printf("  %-12s mac/verify ... ", name);

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wc_RNG_GenerateBlock(&rng, keyData, (word32)keyLen);
    }
    if (ret == 0) {
        wc_CoseKey_Init(&key);
        wc_CoseKey_SetSymmetric(&key, keyData, keyLen);

        ret = wc_CoseMac0_Create(&key, alg, NULL, 0,
            payload, sizeof(payload) - 1, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen);
    }
    if (ret == 0) {
        ret = wc_CoseMac0_Verify(&key, out, outLen, NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decoded, &decodedLen);
    }
    if (ret == 0) {
        if (decodedLen != sizeof(payload) - 1 ||
            memcmp(decoded, payload, decodedLen) != 0) {
            ret = -1;
        }
    }

    /* Cleanup */
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    printf("%s\n", ret == 0 ? "PASS" : "FAIL");
    return ret;
}
#endif

/* Run all or filtered round-trip tests */
static int tool_test(const char* filter)
{
    int failures = 0, tests = 0;
    int all = (filter == NULL || strcmp(filter, "all") == 0);

    printf("=== wolfCOSE Round-Trip Tests ===\n\n");

    /* --- COSE_Sign1 --- */
#ifdef WOLFCOSE_HAVE_ES256
    if (all || strcmp(filter, "ES256") == 0) {
        tests++; if (test_sign_es256() != 0) failures++;
    }
#endif
#ifdef WOLFCOSE_HAVE_EDDSA
    if (all || strcmp(filter, "EdDSA") == 0) {
        tests++; if (test_sign_eddsa() != 0) failures++;
    }
#endif
#ifdef WOLFCOSE_HAVE_ED448
    if (all || strcmp(filter, "Ed448") == 0) {
        tests++; if (test_sign_ed448() != 0) failures++;
    }
#endif
#if defined(WOLFCOSE_HAVE_RSAPSS) && defined(WOLFSSL_KEY_GEN)
    if (all || strcmp(filter, "PS256") == 0) {
        tests++;
        if (test_sign_pss("PS256", WOLFCOSE_ALG_PS256) != 0) failures++;
    }
    if (all || strcmp(filter, "PS384") == 0) {
        tests++;
        if (test_sign_pss("PS384", WOLFCOSE_ALG_PS384) != 0) failures++;
    }
    if (all || strcmp(filter, "PS512") == 0) {
        tests++;
        if (test_sign_pss("PS512", WOLFCOSE_ALG_PS512) != 0) failures++;
    }
#endif
#ifdef WOLFCOSE_HAVE_MLDSA
    if (all || strcmp(filter, "ML-DSA-44") == 0) {
        tests++;
        if (test_sign_mldsa("ML-DSA-44", WOLFCOSE_ALG_ML_DSA_44, WC_ML_DSA_44) != 0)
            failures++;
    }
    if (all || strcmp(filter, "ML-DSA-65") == 0) {
        tests++;
        if (test_sign_mldsa("ML-DSA-65", WOLFCOSE_ALG_ML_DSA_65, WC_ML_DSA_65) != 0)
            failures++;
    }
    if (all || strcmp(filter, "ML-DSA-87") == 0) {
        tests++;
        if (test_sign_mldsa("ML-DSA-87", WOLFCOSE_ALG_ML_DSA_87, WC_ML_DSA_87) != 0)
            failures++;
    }
#endif

    /* --- COSE_Encrypt0 --- */
#ifdef WOLFCOSE_HAVE_AESGCM
    if (all || strcmp(filter, "A128GCM") == 0) {
        tests++;
        if (test_enc_roundtrip("A128GCM", WOLFCOSE_ALG_A128GCM, 16, 12) != 0)
            failures++;
    }
    if (all || strcmp(filter, "A192GCM") == 0) {
        tests++;
        if (test_enc_roundtrip("A192GCM", WOLFCOSE_ALG_A192GCM, 24, 12) != 0)
            failures++;
    }
    if (all || strcmp(filter, "A256GCM") == 0) {
        tests++;
        if (test_enc_roundtrip("A256GCM", WOLFCOSE_ALG_A256GCM, 32, 12) != 0)
            failures++;
    }
#endif
#if defined(WOLFCOSE_HAVE_CHACHA20)
    if (all || strcmp(filter, "ChaCha20") == 0) {
        tests++;
        if (test_enc_roundtrip("ChaCha20",
                WOLFCOSE_ALG_CHACHA20_POLY1305, 32, 12) != 0)
            failures++;
    }
#endif
#ifdef WOLFCOSE_HAVE_AESCCM
    if (all || strcmp(filter, "AES-CCM") == 0) {
        tests++;
        if (test_enc_roundtrip("AES-CCM",
                WOLFCOSE_ALG_AES_CCM_16_128_128, 16, 13) != 0)
            failures++;
    }
#endif

    /* --- COSE_Mac0 --- */
#if defined(WOLFCOSE_HAVE_HMAC)
#ifdef WOLFCOSE_HAVE_HMAC256
    if (all || strcmp(filter, "HMAC256") == 0) {
        tests++;
        if (test_mac_roundtrip("HMAC256", WOLFCOSE_ALG_HMAC256, 32) != 0)
            failures++;
    }
#endif
#ifdef WOLFCOSE_HAVE_HMAC384
    if (all || strcmp(filter, "HMAC384") == 0) {
        tests++;
        if (test_mac_roundtrip("HMAC384", WOLFCOSE_ALG_HMAC384, 48) != 0)
            failures++;
    }
#endif
#ifdef WOLFCOSE_HAVE_HMAC512
    if (all || strcmp(filter, "HMAC512") == 0) {
        tests++;
        if (test_mac_roundtrip("HMAC512", WOLFCOSE_ALG_HMAC512, 64) != 0)
            failures++;
    }
#endif
#endif /* WOLFCOSE_HAVE_HMAC */

    if (tests == 0) {
        printf("  No matching algorithm: %s\n", filter ? filter : "(none)");
        return EXIT_USAGE;
    }

    printf("\n=== Results: %d/%d passed", tests - failures, tests);
    if (failures > 0) {
        printf(" (%d FAILED)", failures);
    }
    printf(" ===\n");
    return failures > 0 ? EXIT_CRYPTO : 0;
}

/* ----- main ----- */
int main(int argc, char* argv[])
{
    const char* cmd;
    const char* algStr = NULL;
    const char* keyPath = NULL;
    const char* inPath = NULL;
    const char* outPath = NULL;
    const char* detachedPath = NULL;
    const char* aadPath = NULL;
    size_t counterIndex = 0u;
    int32_t alg = 0;
    int i;

    if (argc < 2) {
        usage();
        return EXIT_USAGE;
    }

    cmd = argv[1];

    /* Parse options */
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--all") == 0) {
            algStr = "all";
        }
        else if (i + 1 < argc) {
            if (strcmp(argv[i], "-a") == 0) {
                algStr = argv[++i];
            }
            else if (strcmp(argv[i], "-k") == 0) {
                keyPath = argv[++i];
            }
            else if (strcmp(argv[i], "-i") == 0) {
                inPath = argv[++i];
            }
            else if (strcmp(argv[i], "-o") == 0) {
                outPath = argv[++i];
            }
            else if (strcmp(argv[i], "-p") == 0) {
                detachedPath = argv[++i];
            }
            else if (strcmp(argv[i], "--aad") == 0) {
                aadPath = argv[++i];
            }
            else if (strcmp(argv[i], "--index") == 0) {
                char extra;

                if (sscanf(argv[++i], "%zu%c", &counterIndex, &extra) != 1) {
                    fprintf(stderr, "Invalid countersignature index\n");
                    return EXIT_USAGE;
                }
            }
            else {
                fprintf(stderr, "Unknown option: %s\n", argv[i]);
                usage();
                return EXIT_USAGE;
            }
        }
        else {
            fprintf(stderr, "Missing value for: %s\n", argv[i]);
            usage();
            return EXIT_USAGE;
        }
    }

    if (algStr != NULL && strcmp(cmd, "test") != 0) {
        if (parse_alg(algStr, &alg) != 0) {
            return EXIT_USAGE;
        }
    }

    /* Dispatch */
    if (strcmp(cmd, "test") == 0) {
        return tool_test(algStr);
    }
    else if (strcmp(cmd, "keygen") == 0) {
        if (algStr == NULL || outPath == NULL) {
            fprintf(stderr, "keygen requires -a <alg> -o <keyfile>\n");
            return EXIT_USAGE;
        }
        return tool_keygen(alg, algStr, outPath);
    }
    else if (strcmp(cmd, "sign") == 0) {
        if (keyPath == NULL || algStr == NULL || inPath == NULL ||
            outPath == NULL) {
            fprintf(stderr,
                    "sign requires -k <key> -a <alg> -i <input> -o <output>\n");
            return EXIT_USAGE;
        }
        return tool_sign(keyPath, alg, algStr, inPath, outPath);
    }
    else if (strcmp(cmd, "verify") == 0) {
        if (keyPath == NULL || inPath == NULL) {
            fprintf(stderr, "verify requires -k <key> -i <input>\n");
            return EXIT_USAGE;
        }
        return tool_verify(keyPath, inPath);
    }
#if defined(WOLFCOSE_COUNTERSIGN)
    else if (strcmp(cmd, "countersign") == 0) {
        if (keyPath == NULL || algStr == NULL || inPath == NULL ||
            outPath == NULL) {
            fprintf(stderr, "countersign requires -k <key> -a <alg>"
                    " -i <input> -o <output>\n");
            return EXIT_USAGE;
        }
        return tool_counter(keyPath, alg, 0, 0u, inPath, outPath,
                            detachedPath, aadPath);
    }
    else if (strcmp(cmd, "counterverify") == 0) {
        if (keyPath == NULL || inPath == NULL) {
            fprintf(stderr,
                    "counterverify requires -k <key> -i <input>\n");
            return EXIT_USAGE;
        }
        return tool_counter(keyPath, alg, 1, counterIndex, inPath, NULL,
                            detachedPath, aadPath);
    }
#endif
#if defined(WOLFCOSE_HAVE_HMAC)
    else if (strcmp(cmd, "mac") == 0) {
        if (keyPath == NULL || algStr == NULL || inPath == NULL ||
            outPath == NULL) {
            fprintf(stderr,
                    "mac requires -k <key> -a <alg> -i <input> -o <output>\n");
            return EXIT_USAGE;
        }
        return tool_mac(keyPath, alg, inPath, outPath);
    }
    else if (strcmp(cmd, "macverify") == 0) {
        if (keyPath == NULL || inPath == NULL) {
            fprintf(stderr, "macverify requires -k <key> -i <input>\n");
            return EXIT_USAGE;
        }
        return tool_macverify(keyPath, inPath);
    }
#endif
#if defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_AESCCM) || \
    (defined(WOLFCOSE_HAVE_CHACHA20))
    else if (strcmp(cmd, "enc") == 0) {
        if (keyPath == NULL || algStr == NULL || inPath == NULL ||
            outPath == NULL) {
            fprintf(stderr,
                    "enc requires -k <key> -a <alg> -i <input> -o <output>\n");
            return EXIT_USAGE;
        }
        return tool_enc(keyPath, alg, inPath, outPath);
    }
    else if (strcmp(cmd, "dec") == 0) {
        if (keyPath == NULL || inPath == NULL || outPath == NULL) {
            fprintf(stderr,
                    "dec requires -k <key> -i <input> -o <output>\n");
            return EXIT_USAGE;
        }
        return tool_dec(keyPath, inPath, outPath);
    }
#endif /* WOLFCOSE_HAVE_AESGCM || WOLFCOSE_HAVE_AESCCM || (WOLFCOSE_HAVE_CHACHA20) */
    else if (strcmp(cmd, "info") == 0) {
        if (inPath == NULL) {
            fprintf(stderr, "info requires -i <input>\n");
            return EXIT_USAGE;
        }
        return tool_info(inPath);
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage();
        return EXIT_USAGE;
    }
}
