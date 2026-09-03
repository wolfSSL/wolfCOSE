# Getting Started

This guide covers prerequisites, building wolfCOSE, and basic usage examples.

## Prerequisites

### wolfSSL Installation

wolfCOSE requires wolfSSL 5.8.0 or later with the appropriate algorithms
enabled. AES Key Wrap requires wolfSSL 5.9.0 or later because that release
uses a constant-time integrity comparison during unwrap. ML-DSA requires a
wolfSSL release newer than 5.9.1.

Here is a full-featured build using a release that meets those feature floors:

```bash
cd wolfssl
./autogen.sh
./configure --enable-ecc --enable-ed25519 --enable-ed448 \
            --enable-curve25519 --enable-aesgcm --enable-aesccm \
            --enable-sha384 --enable-sha512 --enable-keygen \
            --enable-rsapss --enable-chacha --enable-poly1305 \
            --enable-mldsa --enable-hkdf --enable-aeskeywrap
make && sudo make install
sudo ldconfig
```

### Minimal Builds

You can enable only the algorithms you need:

**ECC + AES-GCM only:**
```bash
./configure --enable-ecc --enable-aesgcm --enable-sha384 \
            --enable-sha512 --enable-keygen
```

**Post-quantum only (ML-DSA):**
```bash
./configure --enable-mldsa --enable-sha512
```

**ECDH-ES + Key Wrap (multi-recipient encryption):**
```bash
./configure --enable-ecc --enable-aesgcm --enable-sha384 \
            --enable-sha512 --enable-keygen --enable-hkdf --enable-aeskeywrap
```

### Feature to wolfSSL Flag Mapping

| Feature | wolfSSL Configure Flags |
|---------|------------------------|
| ECC signing (ES256/384/512) | `--enable-ecc --enable-keygen` |
| EdDSA (Ed25519) | `--enable-ed25519 --enable-curve25519` |
| EdDSA (Ed448) | `--enable-ed448` |
| AES-GCM encryption | `--enable-aesgcm` |
| AES-CCM encryption | `--enable-aesccm` |
| ChaCha20-Poly1305 | `--enable-chacha --enable-poly1305` |
| ECDH-ES key agreement | `--enable-ecc --enable-hkdf` |
| AES Key Wrap | `--enable-aeskeywrap` (wolfSSL 5.9.0+) |
| RSA-PSS signing | `--enable-rsapss --enable-keygen` |
| ML-DSA (post-quantum) | `--enable-mldsa` |
| AES-MAC | `--enable-aescbc` |

## Building wolfCOSE

```bash
git clone https://github.com/wolfSSL/wolfCOSE.git
cd wolfCOSE
make
```

### wolfSSL Discovery

The Makefile uses `pkg-config` for system-installed wolfSSL when its metadata
is available. This works with Homebrew installations on either supported macOS
architecture:

```bash
brew install wolfssl pkgconf
make
```

If the package metadata is outside the default search path, set
`PKG_CONFIG_PATH` before building:

```bash
PKG_CONFIG_PATH="$(brew --prefix wolfssl)/lib/pkgconfig" make
```

For a custom prefix without a `.pc` file, use `WOLFSSL_PREFIX`. For
cross-builds or other custom installations, override the flags explicitly:

```bash
make WOLFSSL_PREFIX=/path/to/wolfssl
make WOLFSSL_CFLAGS="-isystem /path/to/wolfssl/include" \
     WOLFSSL_LIBS="-L/path/to/wolfssl/lib -lwolfssl"
```

Set `WOLFSSL_PACKAGE` for a non-default package name, or `PKG_CONFIG` to use a
different metadata tool. Run `make pkg-config-test` to verify these discovery
paths without a wolfSSL installation.

### Build Targets

| Target | Description |
|--------|-------------|
| `make all` | Build `libwolfcose.a` (static library) |
| `make shared` | Build `libwolfcose.so` (shared library) |
| `make test` | Build and run CBOR and COSE unit tests |
| `make pkg-config-test` | Verify wolfSSL package discovery and overrides |
| `make tool` | Build CLI tool (`tools/wolfcose_tool`) |
| `make tool-test` | Round-trip self-test for all 17 algorithms |
| `make demo` | Build and run lifecycle demo (11 algorithms) |
| `make demos` | Build and run all basic demos |
| `make comprehensive` | Build and run comprehensive algorithm tests (~240 tests) |
| `make scenarios` | Build and run real-world scenario examples |
| `make coverage` | Run tests with gcov coverage |
| `make clean` | Remove all build artifacts |

## Quick Start: Sign and Verify

```c
#include <wolfcose/wolfcose.h>
#include <stdio.h>

int main(void)
{
    ecc_key eccKey;
    WOLFCOSE_KEY coseKey;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[256];
    size_t outLen;
    WC_RNG rng;

    const uint8_t payload[] = "Hello, COSE!";
    const uint8_t kid[] = "key-1";

    /* Initialize RNG */
    wc_InitRng(&rng);

    /* Generate ECC key */
    wc_ecc_init(&eccKey);
    wc_ecc_make_key(&rng, 32, &eccKey);

    /* Wrap in COSE key structure */
    wc_CoseKey_Init(&coseKey);
    wc_CoseKey_SetEcc(&coseKey, WOLFCOSE_CRV_P256, &eccKey);

    /* Sign */
    wc_CoseSign1_Sign(&coseKey, WOLFCOSE_ALG_ES256,
        kid, sizeof(kid) - 1,
        payload, sizeof(payload) - 1,
        NULL, 0,  /* no detached payload */
        NULL, 0,  /* no external AAD */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);

    /* Verify */
    WOLFCOSE_HDR hdr;
    const uint8_t* decoded;
    size_t decodedLen;

    int ret = wc_CoseSign1_Verify(&coseKey,
        out, outLen,
        NULL, 0,  /* no detached payload */
        NULL, 0,  /* no external AAD */
        scratch, sizeof(scratch),
        &hdr, &decoded, &decodedLen);

    if (ret == WOLFCOSE_SUCCESS) {
        printf("Verified! Payload: %.*s\n", (int)decodedLen, decoded);
    }

    /* Cleanup */
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);

    return 0;
}
```

## Quick Start: Encrypt and Decrypt

```c
#include <wolfcose/wolfcose.h>
#include <stdio.h>

int main(void)
{
    WOLFCOSE_KEY coseKey;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[256];
    uint8_t plaintext[256];
    size_t outLen, plaintextLen;

    /* 128-bit symmetric key */
    uint8_t symKey[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    /* 12-byte IV for AES-GCM */
    uint8_t iv[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
    };

    const uint8_t data[] = "Secret message";

    /* Setup symmetric key */
    wc_CoseKey_Init(&coseKey);
    wc_CoseKey_SetSymmetric(&coseKey, symKey, sizeof(symKey));

    /* Encrypt */
    wc_CoseEncrypt0_Encrypt(&coseKey, WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        data, sizeof(data) - 1,
        NULL, 0, NULL,  /* no detached ciphertext */
        NULL, 0,        /* no external AAD */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);

    /* Decrypt */
    WOLFCOSE_HDR hdr;

    int ret = wc_CoseEncrypt0_Decrypt(&coseKey,
        out, outLen,
        NULL, 0,  /* no detached ciphertext */
        NULL, 0,  /* no external AAD */
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);

    if (ret == WOLFCOSE_SUCCESS) {
        printf("Decrypted: %.*s\n", (int)plaintextLen, plaintext);
    }

    return 0;
}
```

## Quick Start: Post-Quantum Signing (ML-DSA)

```c
#include <wolfcose/wolfcose.h>
#include <stdio.h>

int main(void)
{
    wc_MlDsaKey mlDsaKey;
    WOLFCOSE_KEY coseKey;
    uint8_t scratch[8192];  /* PQC needs larger scratch */
    uint8_t out[8192];
    size_t outLen;
    WC_RNG rng;

    const uint8_t payload[] = "Quantum-safe message";

    wc_InitRng(&rng);

    /* Generate ML-DSA-44 key (Level 2) */
    wc_MlDsaKey_Init(&mlDsaKey, NULL, INVALID_DEVID);
    wc_MlDsaKey_SetParams(&mlDsaKey, WC_ML_DSA_44);
    wc_MlDsaKey_MakeKey(&mlDsaKey, &rng);

    /* Wrap in COSE key. ML-DSA uses the RFC 9964 AKP key type; this is all
     * that is needed for sign/verify. To export a *private* COSE_Key, create
     * the key with wc_MlDsaKey_MakeKeyFromSeed and pass the 32-byte seed via
     * wc_CoseKey_SetMlDsa_ex (RFC 9964 private keys are the seed). */
    wc_CoseKey_Init(&coseKey);
    wc_CoseKey_SetMlDsa(&coseKey, WOLFCOSE_ALG_ML_DSA_44, &mlDsaKey);

    /* Sign */
    wc_CoseSign1_Sign(&coseKey, WOLFCOSE_ALG_ML_DSA_44,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);

    /* Verify */
    WOLFCOSE_HDR hdr;
    const uint8_t* decoded;
    size_t decodedLen;

    wc_CoseSign1_Verify(&coseKey,
        out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decoded, &decodedLen);

    wc_MlDsaKey_Free(&mlDsaKey);
    wc_FreeRng(&rng);

    return 0;
}
```

## CLI Tool

The `wolfcose_tool` provides command-line access to all wolfCOSE operations:

```bash
# Build the tool
make tool

# Generate keys
./tools/wolfcose_tool keygen -a ES256 -o ec.key
./tools/wolfcose_tool keygen -a ML-DSA-44 -o pqc.key
./tools/wolfcose_tool keygen -a A128GCM -o sym.key

# Sign and verify
./tools/wolfcose_tool sign -k ec.key -a ES256 -i data.bin -o data.cose
./tools/wolfcose_tool verify -k ec.key -i data.cose

# Encrypt and decrypt
./tools/wolfcose_tool enc -k sym.key -a A128GCM -i secret.bin -o secret.cose
./tools/wolfcose_tool dec -k sym.key -i secret.cose -o recovered.bin

# MAC operations
./tools/wolfcose_tool keygen -a HMAC256 -o hmac.key
./tools/wolfcose_tool mac -k hmac.key -a HMAC256 -i data.bin -o data.mac
./tools/wolfcose_tool macverify -k hmac.key -i data.mac

# Inspect COSE structure
./tools/wolfcose_tool info -i data.cose

# Self-test all algorithms
./tools/wolfcose_tool test --all
```

## Examples Directory

The `examples/` directory contains complete working examples:

| File | Description |
|------|-------------|
| `sign1_demo.c` | All COSE_Sign1 algorithms |
| `encrypt0_demo.c` | All COSE_Encrypt0 algorithms |
| `mac0_demo.c` | All COSE_Mac0 algorithms |
| `lifecycle_demo.c` | Full edge-to-cloud workflow |
| `psa_eat_demo.c` | RFC 9783 device onboarding and component appraisal |
| `psa_eat_verify_lean.c` | Verify a fixed RFC 9783 token in a lean receiver |

Run the complete PSA/EAT onboarding flow with:

```bash
make psa-eat-demo
```

The demo hashes a sample secure-partition firmware image, creates a current
profile COSE_Sign1 token, selects a provisioned public IAK by UEID, proves that
a wrong challenge is rejected, verifies the correct challenge, and appraises
the authenticated lifecycle, device IDs, software measurement, signer ID, and
version against trusted reference values.

### Comprehensive Tests (`examples/comprehensive/`)

| File | Description |
|------|-------------|
| `sign_all.c` | Sign1 and multi-signer matrix tests (~61 tests) |
| `encrypt_all.c` | Encrypt0 and multi-recipient matrix tests (~23 tests) |
| `mac_all.c` | Mac0 and multi-recipient matrix tests (~32 tests) |
| `errors_all.c` | Error handling and edge cases (~19 tests) |

### Real-World Scenarios (`examples/scenarios/`)

| File | Description |
|------|-------------|
| `firmware_update.c` | Post-quantum ML-DSA firmware signing with detached payload |
| `multi_party_approval.c` | Dual-control firmware approval (ES256 + ES384) |
| `iot_fleet_config.c` | Encrypted config push to IoT device fleet |
| `sensor_attestation.c` | EAT-style attestation with replay protection via AAD |
| `group_broadcast_mac.c` | Authenticated broadcast to multiple subscribers |

## Strict Decoding (RFC 8949 Preferred Serialization)

**Read this before filing an interop bug.** wolfCOSE's ordinary decoder APIs
accept only *deterministically encoded* CBOR. This is required by COSE
(RFC 9052) and by CTAP2 canonical CBOR, but it is stricter than most
general-purpose CBOR parsers, so on a device the symptom is usually "my
authenticator rejects requests from client X" rather than an obvious parse
bug. The optional RFC 9783 PSA/EAT verifier is a definite-length
variation-tolerant exception; that profile behavior is not exposed through the
ordinary COSE API.

The following two rules apply to `wc_CBOR_Decode*()`, `wc_CoseKey_Decode()`,
and the ordinary `_Verify` / `_Decrypt` functions:

| Rule | Example rejected input | Error |
|------|------------------------|-------|
| Arguments must use the **shortest** additional-information form (RFC 8949 Section 4.2.1) | `0x18 0x17` for 23 (must be `0x17`); `0x19 0x00 0x64` for 100 (must be `0x18 0x64`) | `WOLFCOSE_E_CBOR_MALFORMED` |
| **Indefinite lengths** are not accepted (additional information 31) | `0x5F ... 0xFF` (chunked bstr), `0x9F ... 0xFF` (open array) | `WOLFCOSE_E_UNSUPPORTED` |

Related strictness that surprises integrators for the same reason:

- Trailing bytes after the encoded object are rejected. `inSz` must be exactly
  the object length, not the capacity of the buffer holding it. Use
  [`wc_CBOR_SkipItem()`](API-Reference.md#wc_cbor_skipitem) to carve out the
  exact byte range of an embedded item.
- Two-byte simple values below 32 are malformed, per RFC 8949.
- All encountered CBOR text strings are validated as UTF-8. This also applies
  to `wc_CBOR_DecodeHead()`, `wc_CBOR_DecodeLabel()`, `wc_CBOR_Skip()`, and
  `wc_CBOR_SkipItem()` when they only inspect or traverse the string; invalid
  text returns `WOLFCOSE_E_CBOR_MALFORMED`.
- EC2 coordinates must be exactly the curve size, with leading zeros preserved
  (RFC 9053 Section 7.1.1) - a 31-byte P-256 `x` is rejected, not left-padded.
- A duplicate label in a header or `COSE_Key` map is rejected.
- With `WOLFCOSE_ENABLE_COSE_TEXT_LABELS`, `COSE_Key` and COSE header maps
  accept unknown text labels and reject their duplicates. Registered COSE
  parameters remain numeric; `"alg"` is not an alias for integer label 1.
  The option is off by default and is implied by PSA/EAT verification.

The strict decoding rules are not configurable for the ordinary API: relaxing
them would let a signature or MAC be recomputed over a re-encoding of the same
data. The text-label option expands accepted label types without relaxing CBOR
encoding rules. The optional PSA/EAT verifier's variation-tolerant path still
rejects indefinite CBOR.

## Cross-Compilation

For embedded targets:

```bash
make CC=arm-none-eabi-gcc \
     CFLAGS="-std=c99 -Os -mcpu=cortex-m4 -mthumb \
             -I./include -I/path/to/wolfssl/include \
             -DWOLFSSL_USER_SETTINGS"
```

Provide a `user_settings.h` with your wolfSSL configuration instead of `wolfssl/options.h`.

## Stack Budget

Per-function stack usage (from `-fstack-usage`, GCC, `-Os`, aarch64):

| Function | Stack (bytes) |
|----------|--------------|
| `wc_CoseSign1_Sign` | 464 |
| `wc_CoseSign1_Verify` | 288 |
| `wc_CoseEncrypt0_Encrypt` | 1120 |
| `wc_CoseEncrypt0_Decrypt` | 1072 |
| `wc_CoseMac0_Create` | 1104 |
| `wc_CoseMac0_Verify` | 1072 |
| `wc_CoseKey_Encode` | 352 |
| `wc_CoseKey_Decode` | 224 |
| `wc_CBOR_Skip` | 112 |
| CBOR encode/decode | 0-48 |

## Next Steps

- [[Algorithms]]: See all supported algorithms
- [[API Reference]]: Complete function documentation
- [[Macros]]: Configure compile-time options
- [[Testing]]: Run tests and measure coverage
