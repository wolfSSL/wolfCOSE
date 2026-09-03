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
 *   enc     -k <keyfile> -a <alg> -i <plaintext> -o <cose_file>
 *   dec     -k <keyfile> -i <cose_file> -o <plaintext>
 *   hpke0-enc -k <public-key> -i <plaintext> -o <cose_file>
 *   hpke0-dec -k <private-key> -i <cose_file> -o <plaintext>
 *   hpke-ke-enc -a <alg> -k <public-key> [-k <public-key> ...] -i <plaintext> -o <cose_file>
 *   hpke-ke-dec -k <private-key> [-r <recipient-index>] -i <cose_file> -o <plaintext>
 *   info    -i <cose_file>
 *
 * Key files: raw COSE_Key CBOR format.
 * Exit codes: 0=success, 1=usage, 2=crypto failure, 3=I/O error.
 */

/* Request the POSIX interfaces used by the optional HPKE key-output guard
 * before any system header on POSIX hosts. */
#if (defined(__unix__) || defined(__APPLE__) || defined(__MACH__) || \
     defined(__CYGWIN__)) && !defined(_XOPEN_SOURCE)
    #define _XOPEN_SOURCE 700
#endif

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfcose/wolfcose.h>

#if !defined(WOLFCOSE_TOOL_HAVE_POSIX_FS)
    #if defined(__unix__) || defined(__APPLE__) || defined(__MACH__) || \
        defined(__CYGWIN__)
        #define WOLFCOSE_TOOL_HAVE_POSIX_FS 1
    #else
        #define WOLFCOSE_TOOL_HAVE_POSIX_FS 0
    #endif
#endif

#include <wolfssl/wolfcrypt/random.h>
#if defined(WOLFCOSE_HAVE_ECDSA) || defined(WOLFCOSE_HAVE_HPKE_0)
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
#if defined(WOLFCOSE_HAVE_HPKE_0)
    #include <errno.h>
    #if (WOLFCOSE_TOOL_HAVE_POSIX_FS == 1)
        #include <fcntl.h>
        #include <limits.h>
        #include <sys/stat.h>
        #include <unistd.h>
    #endif
#endif

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

#if defined(WOLFCOSE_HAVE_HPKE_0) && \
    (WOLFCOSE_TOOL_HAVE_POSIX_FS == 1)
/* PATH_MAX is optional in POSIX headers. This fallback matches the minimum
 * practical path size supported by the command-line tool. */
    #ifndef PATH_MAX
        #define WOLFCOSE_TOOL_PATH_MAX 4096u
    #else
        #define WOLFCOSE_TOOL_PATH_MAX PATH_MAX
    #endif
#endif

/* Bounds the command-line multi-recipient HPKE helper without limiting the
 * library API. Integrators can reduce this for constrained tools. */
#if defined(WOLFCOSE_HAVE_HPKE_0)
#ifndef WOLFCOSE_TOOL_MAX_HPKE_RECIPIENTS
    #define WOLFCOSE_TOOL_MAX_HPKE_RECIPIENTS 4u
#endif
#if (WOLFCOSE_TOOL_MAX_HPKE_RECIPIENTS < 1u)
    #error "WOLFCOSE_TOOL_MAX_HPKE_RECIPIENTS must be at least one"
#endif
#endif

#if defined(WOLFCOSE_HPKE_0_ENCRYPT) || defined(WOLFCOSE_HPKE_0_DECRYPT)
/* Direct HPKE-0 adds protected and unprotected headers, a P-256 enc value,
 * an AEAD tag, and CBOR framing. */
#define WOLFCOSE_TOOL_HPKE_0_ENCODED_MAX \
    ((size_t)WOLFCOSE_TOOL_MAX_MSG + 128u)
#endif

#if defined(WOLFCOSE_HPKE_0_KE_ENCRYPT) || \
    defined(WOLFCOSE_HPKE_0_KE_DECRYPT)
/* Each HPKE-0-KE recipient carries a fixed P-256 enc value and wrapped CEK. */
#define WOLFCOSE_TOOL_HPKE_0_KE_ENCODED_MAX \
    ((size_t)WOLFCOSE_TOOL_MAX_MSG + 64u + \
     (128u * (size_t)WOLFCOSE_TOOL_MAX_HPKE_RECIPIENTS))
#endif

#if defined(WOLFCOSE_HPKE_0_KE_ENCRYPT) || \
    defined(WOLFCOSE_HPKE_0_KE_DECRYPT)
    #define WOLFCOSE_TOOL_MAX_COSE_MSG WOLFCOSE_TOOL_HPKE_0_KE_ENCODED_MAX
#elif defined(WOLFCOSE_HPKE_0_ENCRYPT) || defined(WOLFCOSE_HPKE_0_DECRYPT)
    #define WOLFCOSE_TOOL_MAX_COSE_MSG WOLFCOSE_TOOL_HPKE_0_ENCODED_MAX
#else
    #define WOLFCOSE_TOOL_MAX_COSE_MSG WOLFCOSE_TOOL_MAX_MSG
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
#if defined(WOLFCOSE_HAVE_HPKE_0)
        "  keygen  -a <alg> -o <keyfile> [-p <public-keyfile>]\n"
#else
        "  keygen  -a <alg> -o <keyfile>\n"
#endif
        "  sign    -k <keyfile> -a <alg> -i <payload> -o <cose_file>\n"
        "  verify  -k <keyfile> -i <cose_file>\n"
        "  enc     -k <keyfile> -a <alg> -i <plaintext> -o <cose_file>\n"
        "  dec     -k <keyfile> -i <cose_file> -o <plaintext>\n"
#if defined(WOLFCOSE_HPKE_0_ENCRYPT)
        "  hpke0-enc -k <public-key> -i <plaintext> -o <cose_file>\n"
#endif
#if defined(WOLFCOSE_HPKE_0_DECRYPT)
        "  hpke0-dec -k <private-key> -i <cose_file> -o <plaintext>\n"
#endif
#if defined(WOLFCOSE_HPKE_0_KE_ENCRYPT)
        "  hpke-ke-enc -a <alg> -k <public-key> [-k <public-key> ...]"
        " -i <plaintext> -o <cose_file>\n"
#endif
#if defined(WOLFCOSE_HPKE_0_KE_DECRYPT)
        "  hpke-ke-dec -k <private-key> [-r <recipient-index>]"
        " -i <cose_file> -o <plaintext>\n"
#endif
        "  mac     -k <keyfile> -a <alg> -i <payload> -o <cose_file>\n"
        "  macverify -k <keyfile> -i <cose_file>\n"
        "  info    -i <cose_file>\n"
        "  test    [--all | -a <alg>]   Round-trip self-test\n"
        "\n"
        "Algorithms: ES256, EdDSA, Ed448, PS256, PS384, PS512,\n"
        "            ML-DSA-44, ML-DSA-65, ML-DSA-87,\n"
        "            A128GCM, A192GCM, A256GCM, ChaCha20, AES-CCM,\n"
#if defined(WOLFCOSE_HAVE_HPKE_0)
        "            HPKE-0, HPKE-0-KE,\n"
#endif
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
#if defined(WOLFCOSE_HPKE_0_ENCRYPT) || defined(WOLFCOSE_HPKE_0_DECRYPT)
    else if (strcmp(name, "HPKE-0") == 0) {
        *alg = WOLFCOSE_ALG_HPKE_0;
    }
#endif
#if defined(WOLFCOSE_HPKE_0_KE_ENCRYPT) || \
    defined(WOLFCOSE_HPKE_0_KE_DECRYPT)
    else if (strcmp(name, "HPKE-0-KE") == 0) {
        *alg = WOLFCOSE_ALG_HPKE_0_KE;
    }
#endif
    else {
        fprintf(stderr, "Unknown algorithm: %s\n", name);
        return -1;
    }
    return 0;
}

/* Read an entire file into buffer, rejecting data beyond the caller's bound. */
static int read_file(const char* path, uint8_t* buf, size_t bufSz,
                      size_t* outLen)
{
    FILE* f;
    size_t n;
    int extra = EOF;

    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "Cannot open: %s\n", path);
        return EXIT_IO;
    }
    n = fread(buf, 1, bufSz, f);
    if (n == bufSz) {
        extra = fgetc(f);
    }
    if (ferror(f)) {
        fclose(f);
        fprintf(stderr, "Read error: %s\n", path);
        return EXIT_IO;
    }
    if (extra != EOF) {
        fclose(f);
        fprintf(stderr, "Input too large: %s\n", path);
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

#if defined(WOLFCOSE_HAVE_HPKE_0)
#if (WOLFCOSE_TOOL_HAVE_POSIX_FS == 1)
/* Resolve an output path without allowing a final symlink. Existing paths
 * resolve fully; a new leaf is made canonical by resolving its parent. This
 * lets the key generator reject aliases before either destination is created. */
static int tool_hpke_canonical_output_path(const char* path,
    char* canonical, size_t canonicalSz)
{
    char parent[WOLFCOSE_TOOL_PATH_MAX];
    char resolvedParent[WOLFCOSE_TOOL_PATH_MAX];
    const char* leaf;
    const char* slash;
    size_t parentLen;
    size_t resolvedParentLen;
    size_t leafLen;
    struct stat pathStat;
    int ret = 0;

    if ((path == NULL) || (path[0] == '\0') || (canonical == NULL) ||
        (canonicalSz == 0u)) {
        ret = -1;
    }
    else if ((lstat(path, &pathStat) == 0) && S_ISLNK(pathStat.st_mode)) {
        fprintf(stderr, "Refusing HPKE key output symlink: %s\n", path);
        ret = -1;
    }
    else if (realpath(path, canonical) != NULL) {
        /* Existing non-symlink path resolved successfully. */
    }
    else {
        slash = strrchr(path, '/');
        if (slash == NULL) {
            parent[0] = '.';
            parent[1] = '\0';
            leaf = path;
        }
        else if (slash == path) {
            parent[0] = '/';
            parent[1] = '\0';
            leaf = slash + 1;
        }
        else {
            parentLen = (size_t)(slash - path);
            if (parentLen >= sizeof(parent)) {
                ret = -1;
            }
            else {
                (void)XMEMCPY(parent, path, parentLen);
                parent[parentLen] = '\0';
                leaf = slash + 1;
            }
        }

        if ((ret == 0) && (leaf[0] == '\0')) {
            ret = -1;
        }
        if ((ret == 0) && (realpath(parent, resolvedParent) == NULL)) {
            ret = -1;
        }
        if (ret == 0) {
            resolvedParentLen = strlen(resolvedParent);
            leafLen = strlen(leaf);
            if ((resolvedParentLen > (SIZE_MAX - leafLen - 2u)) ||
                ((resolvedParentLen + leafLen + 2u) > canonicalSz)) {
                ret = -1;
            }
            else if ((resolvedParentLen == 1u) &&
                     (resolvedParent[0] == '/')) {
                (void)XMEMCPY(canonical, resolvedParent,
                              resolvedParentLen);
                (void)XMEMCPY(&canonical[resolvedParentLen], leaf, leafLen);
                canonical[resolvedParentLen + leafLen] = '\0';
            }
            else {
                (void)XMEMCPY(canonical, resolvedParent,
                              resolvedParentLen);
                canonical[resolvedParentLen] = '/';
                (void)XMEMCPY(&canonical[resolvedParentLen + 1u], leaf,
                              leafLen);
                canonical[resolvedParentLen + leafLen + 1u] = '\0';
            }
        }
    }

    if (ret != 0) {
        fprintf(stderr, "Invalid HPKE key output path: %s\n", path);
    }
    return ret;
}

/* Return one when paths name distinct, new outputs, zero when they collide,
 * and negative when either path cannot be resolved safely. For two absent
 * leaves, create a temporary zero-length reservation and ask the filesystem
 * whether the second spelling resolves to it. */
static int tool_hpke_key_paths_distinct(const char* privatePath,
    const char* publicPath)
{
    char privateCanonical[WOLFCOSE_TOOL_PATH_MAX];
    char publicCanonical[WOLFCOSE_TOOL_PATH_MAX];
    struct stat privateStat;
    struct stat publicStat;
    int privateExists;
    int publicExists;
    int reservationFd = -1;
    int ret;

    ret = tool_hpke_canonical_output_path(privatePath, privateCanonical,
                                          sizeof(privateCanonical));
    if ((ret == 0) && (publicPath != NULL)) {
        ret = tool_hpke_canonical_output_path(publicPath, publicCanonical,
                                              sizeof(publicCanonical));
    }
    if (ret != 0) {
        return -1;
    }
    if ((publicPath != NULL) &&
        (strcmp(privateCanonical, publicCanonical) == 0)) {
        return 0;
    }
    privateExists = (stat(privateCanonical, &privateStat) == 0) ? 1 : 0;
    if ((privateExists == 0) && (errno != ENOENT)) {
        return -1;
    }
    if (privateExists != 0) {
        return -1;
    }
    if (publicPath == NULL) {
        return 1;
    }
    publicExists = (stat(publicCanonical, &publicStat) == 0) ? 1 : 0;
    if ((publicExists == 0) && (errno != ENOENT)) {
        return -1;
    }
    if (publicExists != 0) {
        return -1;
    }

    reservationFd = open(privateCanonical, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (reservationFd < 0) {
        return -1;
    }
    if (close(reservationFd) != 0) {
        (void)unlink(privateCanonical);
        return -1;
    }
    if (stat(publicCanonical, &publicStat) == 0) {
        ret = ((stat(privateCanonical, &privateStat) == 0) &&
               (privateStat.st_dev == publicStat.st_dev) &&
               (privateStat.st_ino == publicStat.st_ino)) ? 0 : -1;
    }
    else if (errno == ENOENT) {
        ret = 1;
    }
    else {
        ret = -1;
    }
    if (unlink(privateCanonical) != 0) {
        ret = -1;
    }
    if (ret == 0) {
        return 0;
    }
    if (ret < 0) {
        return -1;
    }
    return 1;
}

static int tool_hpke_write_all(int fd, const uint8_t* buf, size_t len)
{
    size_t offset = 0u;

    while (offset < len) {
        ssize_t written = write(fd, &buf[offset], len - offset);

        if (written > 0) {
            offset += (size_t)written;
        }
        else if ((written < 0) && (errno == EINTR)) {
            continue;
        }
        else {
            return -1;
        }
    }
    return 0;
}

/* Stage a key in the target directory so a link creates only a complete file. */
static int tool_hpke_stage_key(const char* outputPath, const uint8_t* buf,
    size_t len, char* temporaryPath, size_t temporaryPathSz)
{
    static const char suffix[] = ".wolfcose-tmp.XXXXXX";
    size_t outputPathLen;
    int fd;
    int ret;

    if ((outputPath == NULL) || (temporaryPath == NULL) ||
        (temporaryPathSz < sizeof(suffix))) {
        return -1;
    }
    temporaryPath[0] = '\0';
    outputPathLen = strlen(outputPath);
    if (outputPathLen > (temporaryPathSz - sizeof(suffix))) {
        return -1;
    }
    (void)XMEMCPY(temporaryPath, outputPath, outputPathLen);
    (void)XMEMCPY(&temporaryPath[outputPathLen], suffix, sizeof(suffix));

    fd = mkstemp(temporaryPath);
    if (fd < 0) {
        temporaryPath[0] = '\0';
        return -1;
    }
    ret = tool_hpke_write_all(fd, buf, len);
    if ((ret == 0) && (fsync(fd) != 0)) {
        ret = -1;
    }
    if (close(fd) != 0) {
        ret = -1;
    }
    if (ret != 0) {
        (void)unlink(temporaryPath);
        temporaryPath[0] = '\0';
    }
    return ret;
}

/* Publish complete new key files without truncating any existing destination. */
static int tool_hpke_write_key_pair(const char* privatePath,
    const uint8_t* privateBuf, size_t privateLen, const char* publicPath,
    const uint8_t* publicBuf, size_t publicLen)
{
    char privateCanonical[WOLFCOSE_TOOL_PATH_MAX];
    char publicCanonical[WOLFCOSE_TOOL_PATH_MAX];
    char privateTemporary[WOLFCOSE_TOOL_PATH_MAX];
    char publicTemporary[WOLFCOSE_TOOL_PATH_MAX];
    int privateInstalled = 0;
    int publicInstalled = 0;
    int ret = EXIT_IO;

    privateTemporary[0] = '\0';
    publicTemporary[0] = '\0';
    if (tool_hpke_canonical_output_path(privatePath, privateCanonical,
                                        sizeof(privateCanonical)) != 0) {
        goto exit;
    }
    if ((publicPath != NULL) &&
        (tool_hpke_canonical_output_path(publicPath, publicCanonical,
                                         sizeof(publicCanonical)) != 0)) {
        goto exit;
    }
    if (tool_hpke_stage_key(privateCanonical, privateBuf, privateLen,
                            privateTemporary, sizeof(privateTemporary)) != 0) {
        goto exit;
    }
    if ((publicPath != NULL) &&
        (tool_hpke_stage_key(publicCanonical, publicBuf, publicLen,
                             publicTemporary, sizeof(publicTemporary)) != 0)) {
        goto exit;
    }
    if (link(privateTemporary, privateCanonical) != 0) {
        goto exit;
    }
    privateInstalled = 1;
    if ((publicPath != NULL) &&
        (link(publicTemporary, publicCanonical) != 0)) {
        goto exit;
    }
    if (publicPath != NULL) {
        publicInstalled = 1;
    }
    ret = 0;

exit:
    if ((ret != 0) && (publicInstalled != 0)) {
        (void)unlink(publicCanonical);
    }
    if ((ret != 0) && (privateInstalled != 0)) {
        (void)unlink(privateCanonical);
    }
    if (privateTemporary[0] != '\0') {
        (void)unlink(privateTemporary);
    }
    if (publicTemporary[0] != '\0') {
        (void)unlink(publicTemporary);
    }
    return ret;
}
#else
static int tool_hpke_key_paths_distinct(const char* privatePath,
    const char* publicPath)
{
    if (privatePath == NULL) {
        return -1;
    }
    if ((publicPath != NULL) && (strcmp(privatePath, publicPath) == 0)) {
        return 0;
    }
    return 1;
}

static int tool_hpke_write_key_pair(const char* privatePath,
    const uint8_t* privateBuf, size_t privateLen, const char* publicPath,
    const uint8_t* publicBuf, size_t publicLen)
{
    (void)publicBuf;
    (void)publicLen;
    if (publicPath != NULL) {
        fprintf(stderr, "HPKE public key export requires POSIX filesystem support\n");
        return EXIT_USAGE;
    }
    return write_file(privatePath, privateBuf, privateLen);
}
#endif /* WOLFCOSE_TOOL_HAVE_POSIX_FS */

/* Generate a P-256 HPKE key pair and optionally export its public half. */
static int tool_hpke_keygen(int32_t alg, const char* outPath,
                            const char* publicPath)
{
    WC_RNG rng;
    ecc_key ecc;
    WOLFCOSE_KEY coseKey;
    uint8_t privateBuf[WOLFCOSE_TOOL_MAX_KEY];
    uint8_t publicBuf[WOLFCOSE_TOOL_MAX_KEY];
    size_t privateLen = 0u;
    size_t publicLen = 0u;
    int rngInit = 0;
    int eccInit = 0;
    int ret;

    if (outPath == NULL) {
        fprintf(stderr, "HPKE key generation requires a private output path\n");
        return EXIT_USAGE;
    }
#if (WOLFCOSE_TOOL_HAVE_POSIX_FS == 0)
    if (publicPath != NULL) {
        fprintf(stderr, "HPKE public key export requires POSIX filesystem support\n");
        return EXIT_USAGE;
    }
#endif

    ret = tool_hpke_key_paths_distinct(outPath, publicPath);
    if (ret <= 0) {
        if (ret == 0) {
            fprintf(stderr, "HPKE private and public key paths must differ\n");
            return EXIT_USAGE;
        }
        fprintf(stderr, "HPKE key output paths must be new and non-symlinked\n");
        return EXIT_IO;
    }

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
        wc_CoseKey_Init(&coseKey);
        ret = wc_CoseKey_SetEcc(&coseKey, WOLFCOSE_CRV_P256, &ecc);
        coseKey.alg = alg;
    }
    if (ret == 0) {
        ret = wc_CoseKey_Encode(&coseKey, privateBuf, sizeof(privateBuf),
                                &privateLen);
    }
    if ((ret == 0) && (publicPath != NULL)) {
        ret = wc_CoseKey_Encode_ex(&coseKey, publicBuf, sizeof(publicBuf),
                                   &publicLen, WOLFCOSE_KEY_PUBLIC_ONLY);
    }

    if (eccInit != 0) {
        wc_ecc_free(&ecc);
    }
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    if (ret != 0) {
        fprintf(stderr, "HPKE key generation failed: %d\n", ret);
        tool_force_zero(privateBuf, sizeof(privateBuf));
        tool_force_zero(publicBuf, sizeof(publicBuf));
        return EXIT_CRYPTO;
    }

    ret = tool_hpke_write_key_pair(outPath, privateBuf, privateLen,
                                   publicPath, publicBuf, publicLen);
    tool_force_zero(privateBuf, sizeof(privateBuf));
    tool_force_zero(publicBuf, sizeof(publicBuf));
    if (ret == 0) {
        printf("Generated HPKE private key: %s (%zu bytes)\n", outPath,
               privateLen);
        if (publicPath != NULL) {
            printf("Generated HPKE public key: %s (%zu bytes)\n", publicPath,
                   publicLen);
        }
    }
    return ret;
}

/* Decode an EC2 P-256 COSE_Key and enforce its HPKE algorithm binding. */
static int tool_hpke_load_key(const char* path, int32_t alg,
                              WOLFCOSE_KEY* coseKey, ecc_key* ecc)
{
    uint8_t keyBuf[WOLFCOSE_TOOL_MAX_KEY];
    size_t keyLen = 0u;
    int eccInit = 0;
    int ret;

    ret = read_file(path, keyBuf, sizeof(keyBuf), &keyLen);
    if (ret != 0) {
        return ret;
    }
    wc_CoseKey_Init(coseKey);
    ret = wc_ecc_init(ecc);
    if (ret == 0) {
        eccInit = 1;
        ret = wc_CoseKey_SetEcc(coseKey, WOLFCOSE_CRV_P256, ecc);
    }
    if (ret == 0) {
        ret = wc_CoseKey_Decode(coseKey, keyBuf, keyLen);
    }
    tool_force_zero(keyBuf, sizeof(keyBuf));
    if ((ret == 0) && (coseKey->alg != alg)) {
        fprintf(stderr, "HPKE key has an unexpected algorithm binding\n");
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    if (ret != 0) {
        fprintf(stderr, "HPKE key decode failed: %d\n", ret);
        if (eccInit != 0) {
            wc_ecc_free(ecc);
        }
        return EXIT_CRYPTO;
    }
    return 0;
}

/* Return the nonce size required by the selected content encryption suite. */
#if defined(WOLFCOSE_HPKE_0_KE_ENCRYPT)
static int tool_content_nonce_len(int32_t alg, size_t* nonceLen)
{
    if ((alg == WOLFCOSE_ALG_AES_CCM_16_64_128) ||
        (alg == WOLFCOSE_ALG_AES_CCM_16_64_256) ||
        (alg == WOLFCOSE_ALG_AES_CCM_16_128_128) ||
        (alg == WOLFCOSE_ALG_AES_CCM_16_128_256)) {
        *nonceLen = 13u;
    }
    else if ((alg == WOLFCOSE_ALG_AES_CCM_64_64_128) ||
             (alg == WOLFCOSE_ALG_AES_CCM_64_64_256) ||
             (alg == WOLFCOSE_ALG_AES_CCM_64_128_128) ||
             (alg == WOLFCOSE_ALG_AES_CCM_64_128_256)) {
        *nonceLen = 7u;
    }
    else if ((alg == WOLFCOSE_ALG_A128GCM) ||
             (alg == WOLFCOSE_ALG_A192GCM) ||
             (alg == WOLFCOSE_ALG_A256GCM) ||
             (alg == WOLFCOSE_ALG_CHACHA20_POLY1305)) {
        *nonceLen = 12u;
    }
    else {
        return EXIT_USAGE;
    }
    return 0;
}
#endif /* WOLFCOSE_HPKE_0_KE_ENCRYPT */
#endif /* WOLFCOSE_HAVE_HPKE_0 */

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

/* ----- hpke0-enc: COSE HPKE-0 integrated encryption ----- */
#if defined(WOLFCOSE_HPKE_0_ENCRYPT)
static int tool_hpke0_enc(const char* keyPath, const char* inPath,
                          const char* outPath)
{
    WOLFCOSE_KEY recipientKey;
    ecc_key recipientEcc;
    WC_RNG rng;
    uint8_t msgBuf[WOLFCOSE_TOOL_MAX_MSG];
    uint8_t outBuf[WOLFCOSE_TOOL_HPKE_0_ENCODED_MAX];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    size_t msgLen = 0u;
    size_t outLen = 0u;
    int eccLoaded = 0;
    int rngInit = 0;
    int ret;

    ret = tool_hpke_load_key(keyPath, WOLFCOSE_ALG_HPKE_0, &recipientKey,
                             &recipientEcc);
    if (ret != 0) {
        return ret;
    }
    eccLoaded = 1;
    ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    if (ret != 0) {
        goto exit;
    }
    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wc_CoseHpkeEncrypt0_Encrypt(&recipientKey, NULL, 0u, msgBuf,
            msgLen, NULL, 0u, NULL, NULL, 0u, scratch, sizeof(scratch),
            outBuf, sizeof(outBuf), &outLen, &rng);
    }
    if (ret != 0) {
        fprintf(stderr, "HPKE-0 encrypt failed: %d\n", ret);
        ret = EXIT_CRYPTO;
        goto exit;
    }
    ret = write_file(outPath, outBuf, outLen);
    if (ret == 0) {
        printf("HPKE-0 encrypted: %zu byte plaintext -> %zu byte "
               "COSE_Encrypt0\n", msgLen, outLen);
    }

exit:
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    if (eccLoaded != 0) {
        wc_ecc_free(&recipientEcc);
    }
    return ret;
}
#endif /* WOLFCOSE_HPKE_0_ENCRYPT */

/* ----- hpke0-dec: COSE HPKE-0 integrated decryption ----- */
#if defined(WOLFCOSE_HPKE_0_DECRYPT)
static int tool_hpke0_dec(const char* keyPath, const char* inPath,
                          const char* outPath)
{
    WOLFCOSE_KEY recipientKey;
    ecc_key recipientEcc;
    WOLFCOSE_HDR hdr;
    uint8_t msgBuf[WOLFCOSE_TOOL_HPKE_0_ENCODED_MAX];
    uint8_t plainBuf[WOLFCOSE_TOOL_MAX_MSG];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    size_t msgLen = 0u;
    size_t plainLen = 0u;
    int eccLoaded = 0;
    int ret;

    ret = tool_hpke_load_key(keyPath, WOLFCOSE_ALG_HPKE_0, &recipientKey,
                             &recipientEcc);
    if (ret != 0) {
        return ret;
    }
    eccLoaded = 1;
    ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    if (ret != 0) {
        goto exit;
    }
    ret = wc_CoseHpkeEncrypt0_Decrypt(&recipientKey, msgBuf, msgLen, NULL,
        0u, NULL, 0u, scratch, sizeof(scratch), &hdr, plainBuf,
        sizeof(plainBuf), &plainLen);
    if (ret != 0) {
        fprintf(stderr, "HPKE-0 decrypt failed: %d\n", ret);
        ret = EXIT_CRYPTO;
        goto exit;
    }
    ret = write_file(outPath, plainBuf, plainLen);
    if (ret == 0) {
        printf("HPKE-0 decrypted: %zu byte COSE_Encrypt0 -> %zu byte "
               "plaintext\n", msgLen, plainLen);
    }

exit:
    if (eccLoaded != 0) {
        wc_ecc_free(&recipientEcc);
    }
    return ret;
}
#endif /* WOLFCOSE_HPKE_0_DECRYPT */

/* ----- hpke-ke-enc: HPKE-0-KE multi-recipient COSE_Encrypt ----- */
#if defined(WOLFCOSE_HPKE_0_KE_ENCRYPT)
static int tool_hpke_ke_enc(const char* const* keyPaths, size_t keyCount,
                            int32_t contentAlg, const char* inPath,
                            const char* outPath)
{
    WOLFCOSE_KEY recipientKey[WOLFCOSE_TOOL_MAX_HPKE_RECIPIENTS];
    WOLFCOSE_RECIPIENT recipients[WOLFCOSE_TOOL_MAX_HPKE_RECIPIENTS];
    ecc_key recipientEcc[WOLFCOSE_TOOL_MAX_HPKE_RECIPIENTS];
    WC_RNG rng;
    uint8_t msgBuf[WOLFCOSE_TOOL_MAX_MSG];
    uint8_t outBuf[WOLFCOSE_TOOL_HPKE_0_KE_ENCODED_MAX];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t iv[13];
    size_t msgLen = 0u;
    size_t outLen = 0u;
    size_t ivLen = 0u;
    size_t eccCount = 0u;
    size_t i;
    int rngInit = 0;
    int ret;

    if ((keyCount == 0u) || (keyCount > WOLFCOSE_TOOL_MAX_HPKE_RECIPIENTS)) {
        fprintf(stderr, "HPKE-0-KE supports 1 to %u recipient keys\n",
                (unsigned int)WOLFCOSE_TOOL_MAX_HPKE_RECIPIENTS);
        return EXIT_USAGE;
    }
    ret = tool_content_nonce_len(contentAlg, &ivLen);
    if (ret != 0) {
        fprintf(stderr, "Unsupported HPKE-0-KE content algorithm\n");
        return ret;
    }
    ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    if (ret != 0) {
        return ret;
    }
    (void)memset(recipients, 0, sizeof(recipients));
    for (i = 0u; (ret == 0) && (i < keyCount); i++) {
        ret = tool_hpke_load_key(keyPaths[i], WOLFCOSE_ALG_HPKE_0_KE,
                                 &recipientKey[i], &recipientEcc[i]);
        if (ret == 0) {
            eccCount++;
            recipients[i].algId = WOLFCOSE_ALG_HPKE_0_KE;
            recipients[i].key = &recipientKey[i];
        }
    }
    if (ret == 0) {
        ret = wc_InitRng(&rng);
        if (ret == 0) {
            rngInit = 1;
            ret = wc_RNG_GenerateBlock(&rng, iv, (word32)ivLen);
        }
    }
    if (ret == 0) {
        ret = wc_CoseEncrypt_Encrypt(recipients, keyCount, contentAlg, iv,
            ivLen, msgBuf, msgLen, NULL, 0u, NULL, 0u, scratch,
            sizeof(scratch), outBuf, sizeof(outBuf), &outLen, &rng);
    }
    if (ret != 0) {
        fprintf(stderr, "HPKE-0-KE encrypt failed: %d\n", ret);
        ret = EXIT_CRYPTO;
        goto exit;
    }
    ret = write_file(outPath, outBuf, outLen);
    if (ret == 0) {
        printf("HPKE-0-KE encrypted: %zu byte plaintext -> %zu byte "
               "COSE_Encrypt (%zu recipients)\n", msgLen, outLen, keyCount);
    }

exit:
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    while (eccCount > 0u) {
        eccCount--;
        wc_ecc_free(&recipientEcc[eccCount]);
    }
    return ret;
}
#endif /* WOLFCOSE_HPKE_0_KE_ENCRYPT */

/* ----- hpke-ke-dec: HPKE-0-KE multi-recipient COSE_Encrypt decryption ----- */
#if defined(WOLFCOSE_HPKE_0_KE_DECRYPT)
static int tool_hpke_ke_dec(const char* keyPath, size_t recipientIndex,
                            const char* inPath, const char* outPath)
{
    WOLFCOSE_KEY recipientKey;
    WOLFCOSE_RECIPIENT recipient;
    WOLFCOSE_HDR hdr;
    ecc_key recipientEcc;
    uint8_t msgBuf[WOLFCOSE_TOOL_HPKE_0_KE_ENCODED_MAX];
    uint8_t plainBuf[WOLFCOSE_TOOL_MAX_MSG];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    size_t msgLen = 0u;
    size_t plainLen = 0u;
    int eccLoaded = 0;
    int ret;

    ret = tool_hpke_load_key(keyPath, WOLFCOSE_ALG_HPKE_0_KE, &recipientKey,
                             &recipientEcc);
    if (ret != 0) {
        return ret;
    }
    eccLoaded = 1;
    ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    if (ret != 0) {
        goto exit;
    }
    (void)memset(&recipient, 0, sizeof(recipient));
    recipient.algId = WOLFCOSE_ALG_HPKE_0_KE;
    recipient.key = &recipientKey;
    ret = wc_CoseEncrypt_Decrypt(&recipient, recipientIndex, msgBuf, msgLen,
        NULL, 0u, NULL, 0u, scratch, sizeof(scratch), &hdr, plainBuf,
        sizeof(plainBuf), &plainLen);
    if (ret != 0) {
        fprintf(stderr, "HPKE-0-KE decrypt failed: %d\n", ret);
        ret = EXIT_CRYPTO;
        goto exit;
    }
    ret = write_file(outPath, plainBuf, plainLen);
    if (ret == 0) {
        printf("HPKE-0-KE decrypted recipient %zu: %zu byte COSE_Encrypt -> "
               "%zu byte plaintext\n", recipientIndex, msgLen, plainLen);
    }

exit:
    if (eccLoaded != 0) {
        wc_ecc_free(&recipientEcc);
    }
    return ret;
}
#endif /* WOLFCOSE_HPKE_0_KE_DECRYPT */

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
    uint8_t msgBuf[WOLFCOSE_TOOL_MAX_COSE_MSG];
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

/* HPKE-0 integrated-encryption round trip. */
#if defined(WOLFCOSE_HPKE_0_ENCRYPT) && defined(WOLFCOSE_HPKE_0_DECRYPT)
static int test_hpke0_roundtrip(void)
{
    static const uint8_t payload[] = "wolfCOSE HPKE-0 roundtrip";
    WC_RNG rng;
    ecc_key recipientEcc;
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

    printf("  %-12s enc/dec   ... ", "HPKE-0");
    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wc_ecc_init(&recipientEcc);
    }
    if (ret == 0) {
        eccInit = 1;
        ret = wc_ecc_make_key(&rng, 32, &recipientEcc);
    }
    if (ret == 0) {
        wc_CoseKey_Init(&recipientKey);
        ret = wc_CoseKey_SetEcc(&recipientKey, WOLFCOSE_CRV_P256,
                                &recipientEcc);
        recipientKey.alg = WOLFCOSE_ALG_HPKE_0;
        recipientKey.hasPrivate = 0u;
    }
    if (ret == 0) {
        ret = wc_CoseHpkeEncrypt0_Encrypt(&recipientKey, NULL, 0u, payload,
            sizeof(payload) - 1u, NULL, 0u, NULL, NULL, 0u, scratch,
            sizeof(scratch), cose, sizeof(cose), &coseLen, &rng);
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
        wc_ecc_free(&recipientEcc);
    }
    if (rngInit != 0) {
        wc_FreeRng(&rng);
    }
    printf("%s\n", ret == 0 ? "PASS" : "FAIL");
    return ret;
}
#endif /* WOLFCOSE_HPKE_0_ENCRYPT && WOLFCOSE_HPKE_0_DECRYPT */

/* HPKE-0-KE uses one independently protected CEK for each recipient. */
#if defined(WOLFCOSE_HPKE_0_KE_ENCRYPT) && \
    defined(WOLFCOSE_HPKE_0_KE_DECRYPT)
static int test_hpke_ke_roundtrip(void)
{
    enum { HPKE_TEST_RECIPIENTS = 2 };
    static const uint8_t payload[] = "wolfCOSE HPKE-0-KE roundtrip";
    WC_RNG rng;
    ecc_key recipientEcc[HPKE_TEST_RECIPIENTS];
    WOLFCOSE_KEY recipientKey[HPKE_TEST_RECIPIENTS];
    WOLFCOSE_RECIPIENT recipients[HPKE_TEST_RECIPIENTS];
    WOLFCOSE_HDR hdr;
    uint8_t iv[12];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t cose[1024];
    uint8_t plaintext[sizeof(payload)];
    size_t coseLen = 0u;
    size_t plaintextLen = 0u;
    size_t eccCount = 0u;
    size_t i;
    int rngInit = 0;
    int ret;

    printf("  %-12s enc/dec   ... ", "HPKE-0-KE");
    (void)memset(recipients, 0, sizeof(recipients));
    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
    }
    for (i = 0u; (ret == 0) && (i < HPKE_TEST_RECIPIENTS); i++) {
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
        }
    }
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(&rng, iv, (word32)sizeof(iv));
    }
    if (ret == 0) {
        ret = wc_CoseEncrypt_Encrypt(recipients, HPKE_TEST_RECIPIENTS,
            WOLFCOSE_ALG_A128GCM, iv, sizeof(iv), payload,
            sizeof(payload) - 1u, NULL, 0u, NULL, 0u, scratch,
            sizeof(scratch), cose, sizeof(cose), &coseLen, &rng);
    }
    if (ret == 0) {
        for (i = 0u; i < HPKE_TEST_RECIPIENTS; i++) {
            recipientKey[i].hasPrivate = 1u;
        }
    }
    for (i = 0u; (ret == 0) && (i < HPKE_TEST_RECIPIENTS); i++) {
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
    printf("%s\n", ret == 0 ? "PASS" : "FAIL");
    return ret;
}
#endif /* WOLFCOSE_HPKE_0_KE_ENCRYPT && WOLFCOSE_HPKE_0_KE_DECRYPT */

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

    /* --- Experimental COSE-HPKE --- */
#if defined(WOLFCOSE_HPKE_0_ENCRYPT) && defined(WOLFCOSE_HPKE_0_DECRYPT)
    if (all || strcmp(filter, "HPKE-0") == 0) {
        tests++;
        if (test_hpke0_roundtrip() != 0) {
            failures++;
        }
    }
#endif
#if defined(WOLFCOSE_HPKE_0_KE_ENCRYPT) && \
    defined(WOLFCOSE_HPKE_0_KE_DECRYPT)
    if (all || strcmp(filter, "HPKE-0-KE") == 0) {
        tests++;
        if (test_hpke_ke_roundtrip() != 0) {
            failures++;
        }
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
#if defined(WOLFCOSE_HAVE_HPKE_0)
    const char* publicPath = NULL;
#endif
    const char* inPath = NULL;
    const char* outPath = NULL;
#if defined(WOLFCOSE_HPKE_0_KE_ENCRYPT)
    const char* keyPaths[WOLFCOSE_TOOL_MAX_HPKE_RECIPIENTS];
#endif
#if defined(WOLFCOSE_HAVE_HPKE_0)
    size_t keyPathCount = 0u;
#endif
#if defined(WOLFCOSE_HPKE_0_KE_DECRYPT)
    size_t recipientIndex = 0u;
#endif
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
#if defined(WOLFCOSE_HAVE_HPKE_0)
                if (keyPathCount >= WOLFCOSE_TOOL_MAX_HPKE_RECIPIENTS) {
                    fprintf(stderr, "Too many -k recipient keys\n");
                    return EXIT_USAGE;
                }
#if defined(WOLFCOSE_HPKE_0_KE_ENCRYPT)
                keyPaths[keyPathCount] = keyPath;
#endif
                keyPathCount++;
#endif
            }
#if defined(WOLFCOSE_HAVE_HPKE_0)
            else if (strcmp(argv[i], "-p") == 0) {
                publicPath = argv[++i];
            }
#endif
            else if (strcmp(argv[i], "-r") == 0) {
#if defined(WOLFCOSE_HPKE_0_KE_DECRYPT)
                char* end = NULL;
                unsigned long value;

                errno = 0;
                value = strtoul(argv[++i], &end, 10);
                if ((errno != 0) || (end == argv[i]) || (*end != '\0') ||
                    (value >= WOLFCOSE_TOOL_MAX_HPKE_RECIPIENTS)) {
                    fprintf(stderr, "Invalid recipient index: %s\n", argv[i]);
                    return EXIT_USAGE;
                }
                recipientIndex = (size_t)value;
#else
                fprintf(stderr, "HPKE recipient selection is not built in\n");
                return EXIT_USAGE;
#endif
            }
            else if (strcmp(argv[i], "-i") == 0) {
                inPath = argv[++i];
            }
            else if (strcmp(argv[i], "-o") == 0) {
                outPath = argv[++i];
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
#if defined(WOLFCOSE_HAVE_HPKE_0)
        if ((alg == WOLFCOSE_ALG_HPKE_0) ||
            (alg == WOLFCOSE_ALG_HPKE_0_KE)) {
            return tool_hpke_keygen(alg, outPath, publicPath);
        }
        if (publicPath != NULL) {
            fprintf(stderr, "-p is only valid for HPKE key generation\n");
            return EXIT_USAGE;
        }
#endif
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
#if defined(WOLFCOSE_HPKE_0_ENCRYPT)
    else if (strcmp(cmd, "hpke0-enc") == 0) {
        if ((keyPath == NULL) || (keyPathCount != 1u) || (inPath == NULL) ||
            (outPath == NULL)) {
            fprintf(stderr,
                    "hpke0-enc requires -k <public-key> -i <input> -o <output>\n");
            return EXIT_USAGE;
        }
        return tool_hpke0_enc(keyPath, inPath, outPath);
    }
#endif
#if defined(WOLFCOSE_HPKE_0_DECRYPT)
    else if (strcmp(cmd, "hpke0-dec") == 0) {
        if ((keyPath == NULL) || (keyPathCount != 1u) || (inPath == NULL) ||
            (outPath == NULL)) {
            fprintf(stderr,
                    "hpke0-dec requires -k <private-key> -i <input> -o <output>\n");
            return EXIT_USAGE;
        }
        return tool_hpke0_dec(keyPath, inPath, outPath);
    }
#endif
#if defined(WOLFCOSE_HPKE_0_KE_ENCRYPT)
    else if (strcmp(cmd, "hpke-ke-enc") == 0) {
        if ((keyPathCount == 0u) || (algStr == NULL) || (inPath == NULL) ||
            (outPath == NULL)) {
            fprintf(stderr,
                    "hpke-ke-enc requires -a <alg> -k <public-key> "
                    "-i <input> -o <output>\n");
            return EXIT_USAGE;
        }
        return tool_hpke_ke_enc(keyPaths, keyPathCount, alg, inPath, outPath);
    }
#endif
#if defined(WOLFCOSE_HPKE_0_KE_DECRYPT)
    else if (strcmp(cmd, "hpke-ke-dec") == 0) {
        if ((keyPath == NULL) || (keyPathCount != 1u) || (inPath == NULL) ||
            (outPath == NULL)) {
            fprintf(stderr,
                    "hpke-ke-dec requires -k <private-key> -i <input> "
                    "-o <output>\n");
            return EXIT_USAGE;
        }
        return tool_hpke_ke_dec(keyPath, recipientIndex, inPath, outPath);
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
