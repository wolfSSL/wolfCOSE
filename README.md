# wolfCOSE

wolfCOSE is a lightweight C library implementing [CBOR (RFC 8949)](https://www.rfc-editor.org/rfc/rfc8949), [COSE (RFC 9052/9053)](https://www.rfc-editor.org/rfc/rfc9052), and post-quantum [ML-DSA for COSE (RFC 9964)](https://www.rfc-editor.org/rfc/rfc9964) using [wolfSSL](https://www.wolfssl.com/) as the crypto backend.

## Main Features

- **Complete RFC 9052 message set**: all six COSE message types, including multi-signer 
  `COSE_Sign` and multi-recipient `COSE_Encrypt` / `COSE_Mac`
- **Post-quantum signing**: ML-DSA (FIPS 204) at all three security levels, with RFC 9964 `COSE_Key` (AKP key type, seed-based private keys)
- **40 algorithms** across signing, encryption, MAC, and key distribution
- **Zero dynamic allocation**: heap-allocation-free and non-recursive. Every operation runs on caller-provided buffers 
   within a bounded, target-customizable stack ceiling (nothing on the heap, zero `.data`/`.bss`)
- **Tiny footprint**: ES256 `COSE_Sign1` wolfCOSE (COSE + CBOR engine) **~5.1 KB** verify-only and **~6.8 KB** sign + verify.
   Total flash including wolfCrypt is **~26.2 KB** verify-only (`WOLFCOSE_LEAN_VERIFY`) and **~34.6 KB** sign + verify
- **Fast**: (ES256 `COSE_Sign1`, x86_64, wolfCrypt `sp_256` asm): **66,538** sign/s, **26,437** verify/s
- **Post-quantum at the same cost**: ML-DSA-44 `COSE_Sign1` total flash including wolfCrypt is **~20.8 KB** verify-only
  (`WOLFCOSE_LEAN_VERIFY_MLDSA`) and **~35.8 KB** sign + verify, within about 1 KB of classical ES256. The wolfCOSE portion
  alone is **4.6 KB** and **~6.6 KB** respectively. See [Footprint](https://github.com/wolfSSL/wolfCOSE/wiki/Footprint)
- **Path to FIPS 140-3**: via wolfCrypt **FIPS Certificate #4718** (sole crypto dependency)
- **STM32Cube ready**: available as a drop-in STM32Cube pack (`I-CUBE-wolfCOSE`) for STM32CubeMX and STM32CubeIDE, so STM32 devices get COSE and CBOR out of the box (see [STM32Cube](https://github.com/wolfSSL/wolfCOSE/wiki/STM32Cube))

## Supported Algorithms

**Signing:** `ES256, ES384, ES512, EdDSA (Ed25519/Ed448), PS256/384/512, ML-DSA-44/65/87`

**Encryption:** `AES-GCM (128/192/256), ChaCha20-Poly1305, AES-CCM variants`

**MAC:** `HMAC-SHA256/384/512, AES-MAC`

**Key Distribution:** `Direct, AES Key Wrap, ECDH-ES+HKDF`

## COSE Message Types (RFC 9052)

wolfCOSE has implemented all RFC 9052 messages both single-actor and multi-actor variants:

| Message | RFC 9052 | API | Purpose |
|---|---|---|---|
| `COSE_Sign1` | Sec. 4.2 | `wc_CoseSign1_Sign` / `wc_CoseSign1_Verify` | Single-signer signature |
| `COSE_Sign` | Sec. 4.1 | `wc_CoseSign_Sign` / `wc_CoseSign_Verify` | **Multi-signer** (independent signatures over the same payload) |
| `COSE_Encrypt0` | Sec. 5.2 | `wc_CoseEncrypt0_Encrypt` / `wc_CoseEncrypt0_Decrypt` | Single-recipient AEAD |
| `COSE_Encrypt` | Sec. 5.1 | `wc_CoseEncrypt_Encrypt` / `wc_CoseEncrypt_Decrypt` | **Multi-recipient** (one ciphertext, many recipients via Direct / AES-KW / ECDH-ES) |
| `COSE_Mac0` | Sec. 6.2 | `wc_CoseMac0_Create` / `wc_CoseMac0_Verify` | Single-recipient MAC |
| `COSE_Mac` | Sec. 6.1 | `wc_CoseMac_Create` / `wc_CoseMac_Verify` | **Multi-recipient** MAC (shared MAC key, distributed to recipients) |
| `COSE_Key` / `COSE_KeySet` | Sec. 7 | `wc_CoseKey_Encode` / `wc_CoseKey_Decode` | Key serialization for all key types |

## Prerequisites (wolfSSL)

wolfCOSE requires [wolfSSL](https://www.wolfssl.com/) as its crypto backend.
**Minimum supported version: v5.8.0-stable**. Some optional algorithms require
newer releases; see [Getting Started](docs/Getting-Started.md#prerequisites) for
feature-specific dependency floors.

### System-installed wolfSSL

The Makefile uses `pkg-config` to obtain wolfSSL compiler and linker flags when
the metadata is available. This avoids assuming `/usr/local`, so a Homebrew
installation works on both supported macOS architectures:

```bash
brew install wolfssl pkgconf
make
```

If `wolfssl.pc` is outside the default search path, set `PKG_CONFIG_PATH`:

```bash
PKG_CONFIG_PATH="$(brew --prefix wolfssl)/lib/pkgconfig" make
```

For cross-compilation or an installation without a `.pc` file, override the
flags explicitly:

```bash
make WOLFSSL_CFLAGS="-isystem /path/to/wolfssl/include" \
     WOLFSSL_LIBS="-L/path/to/wolfssl/lib -lwolfssl"
```

`PKG_CONFIG` selects the metadata tool, and `WOLFSSL_PACKAGE` selects its
module name. When metadata is unavailable, `WOLFSSL_PREFIX` controls the
compatible include and library fallback:

```bash
make WOLFSSL_PACKAGE=wolfssl-custom
make WOLFSSL_PREFIX=/path/to/wolfssl
```

Choose a build configuration based on the algorithms you need.

### Minimal Build (ECC + AES-GCM)

This gives you COSE Sign1 (ES256/384/512) and Encrypt0 (AES-GCM):

```bash
cd wolfssl
./autogen.sh
./configure --enable-ecc --enable-aesgcm \
            --enable-sha384 --enable-sha512 --enable-keygen
make && sudo make install
sudo ldconfig
```

**Algorithms enabled:** ES256, ES384, ES512, AES-GCM-128/192/256

For a smaller wolfCrypt footprint, add `--enable-cryptonly` to drop the TLS
stack and disable the algorithms a Sign1 + Encrypt0 build never uses:

```bash
./configure --enable-cryptonly --enable-ecc --enable-aesgcm \
            --enable-sha384 --enable-sha512 --enable-keygen \
            --enable-lowresource \
            --disable-dh --disable-rsa --disable-aescbc \
            --disable-sha --disable-md5 --disable-chacha --disable-poly1305 \
            --disable-errorstrings
```

See [Tuning for Size](docs/Macros.md#tuning-for-size) and [Tuning for Speed](docs/Macros.md#tuning-for-speed)
for squeezing wolfCOSE and wolfCrypt further on MCUs.

### Minimal Build (Post-Quantum / ML-DSA only)

For pure post-quantum signing with ML-DSA-44/65/87:

```bash
cd wolfssl
./autogen.sh
./configure --enable-cryptonly --enable-mldsa
make && sudo make install
sudo ldconfig
```

**Algorithms enabled:** ML-DSA-44, ML-DSA-65, ML-DSA-87
(SHAKE-128/256 are pulled in automatically by `--enable-mldsa`. The
`wc_MlDsaKey` API requires wolfSSL newer than v5.9.1-stable.)

### Full Build (All Algorithms)

```bash
cd wolfssl
./autogen.sh
./configure --enable-ecc --enable-ed25519 --enable-ed448 \
            --enable-curve25519 --enable-aesgcm --enable-aesccm \
            --enable-sha384 --enable-sha512 --enable-keygen \
            --enable-rsapss --enable-chacha --enable-poly1305 \
            --enable-mldsa \
            --enable-hkdf --enable-aeskeywrap
make && sudo make install
sudo ldconfig
```

## Build

```bash
# Core library (libwolfcose.a)
make

# Run unit tests
make test

# Build and run CLI tool round-trip tests (all algorithms)
make tool-test

# Run lifecycle demo (11 algorithms)
make demo
```

### Build Targets

| Target | Description |
|--------|-------------|
| `make all` | Build `libwolfcose.a` (core library only) |
| `make shared` | Build `libwolfcose.so` |
| `make test` | Build + run CBOR and COSE unit tests |
| `make pkg-config-test` | Verify wolfSSL package discovery and overrides |
| `make tool` | Build CLI tool (`tools/wolfcose_tool`) |
| `make tool-test` | Round-trip self-test for all 17 algorithms |
| `make demo` | Build + run lifecycle demo (11 algorithms) |
| `make clean` | Remove all build artifacts |

## Quick Start

### Examples

See `examples/` for complete working code:
- `sign1_demo.c`, `encrypt0_demo.c`, `mac0_demo.c`: algorithm demos
- `lifecycle_demo.c`: full edge-to-cloud workflow
- `comprehensive/`: algorithm matrix tests
- `scenarios/`: firmware signing, attestation, fleet config

## CI / Testing

Runs on every push and PR:

- **Build + Test**: Ubuntu, macOS, GCC 10-14, Clang 14-18
- **Comprehensive Tests**: ~240 algorithm combination tests
- **Static Analysis**: cppcheck, Clang analyzer, GCC `-fanalyzer`
- **MISRA C 2012**: cppcheck `--addon=misra` checking all wolfCOSE code paths
- **MISRA C 2023**: strict GCC warnings and clang-tidy (`bugprone-*`, `cert-*`, `clang-analyzer-*`, `misc-*`)
- **Coverity Scan**: nightly defect analysis
- **Advanced Internal Static Analysis:** Fenrir wolfssl advanced static analysis tools
- **Code Coverage**: 100% line coverage enforced for every wolfCOSE source file

```bash
make coverage                  # Run tests with gcov
make coverage-force-failure    # Include crypto failure path testing
```

<a href="https://scan.coverity.com/projects/wolfcose">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/32918/badge.svg"/>
</a>
<a href="https://github.com/wolfSSL/wolfCOSE/actions">
  <img alt="CI Status"
       src="https://img.shields.io/github/actions/workflow/status/wolfSSL/wolfCOSE/build-test.yml?label=CI&logo=github"/>
</a>
<a href="https://github.com/wolfssl/skoll">                                                                                                              <img alt="Skoll Review" src="https://img.shields.io/badge/skoll-passed-blue"/>                                                                     
</a>                                                                                                                                                 
<a href="https://github.com/wolfssl/fenrir">                                                                                                         
  <img alt="Fenrir Review" src="https://img.shields.io/badge/fenrir-passed-blueviolet"/>
</a>


## Documentation

Full documentation is available in the [Wiki](https://github.com/wolfSSL/wolfCOSE/wiki):

- [Getting Started](https://github.com/wolfSSL/wolfCOSE/wiki/Getting-Started): Build instructions and first steps
- [Message Types](https://github.com/wolfSSL/wolfCOSE/wiki/Message-Types): All six RFC 9052 messages (Sign1, Sign, Encrypt0, Encrypt, Mac0, Mac) with code samples
- [Algorithms](https://github.com/wolfSSL/wolfCOSE/wiki/Algorithms): Complete list of 40 supported algorithms with COSE IDs
- [API Reference](https://github.com/wolfSSL/wolfCOSE/wiki/API-Reference): Function signatures, data structures, error codes
- [Macros](https://github.com/wolfSSL/wolfCOSE/wiki/Macros): Compile-time configuration, size tuning, and ECDSA nonce policy
- [Footprint](https://github.com/wolfSSL/wolfCOSE/wiki/Footprint): Size and speed numbers, desktop and on-device
- [Testing](https://github.com/wolfSSL/wolfCOSE/wiki/Testing): Test infrastructure, coverage, and failure injection
- [MISRA Compliance](https://github.com/wolfSSL/wolfCOSE/wiki/MISRA-Compliance): MISRA C:2012 and C:2023 compliance status and deviation rationale
- [Project Structure](https://github.com/wolfSSL/wolfCOSE/wiki/Project-Structure): Source file layout
- [STM32Cube](https://github.com/wolfSSL/wolfCOSE/wiki/STM32Cube): Install and run wolfCOSE as an STM32Cube pack on device

## Release Notes

The current release is **1.0.0**, the first stable release: the complete RFC 9052 COSE message set (all six message types, single- and multi-actor), 40 algorithms, and standardized post-quantum ML-DSA (RFC 9964), all with zero dynamic allocation. See [ChangeLog.md](ChangeLog.md) for the full release notes.

wolfCOSE 1.0.0 has been developed according to wolfSSL's development and QA process (see https://www.wolfssl.com/about/wolfssl-software-development-process-quality-assurance) and successfully passed the quality criteria.

## License

wolfCOSE is free software licensed under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html); see [LICENSE](LICENSE) for the full text.

Copyright (C) 2026 wolfSSL Inc.

## Support

For commercial licensing, professional support contracts, or to discuss moving wolfCOSE into your production environment, contact [wolfSSL](https://www.wolfssl.com/contact/).
