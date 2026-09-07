# wolfCOSE

wolfCOSE is a lightweight and fast C library implementing core CBOR and COSE standards, backed by [wolfSSL](https://github.com/wolfSSL/wolfssl) for cryptography.

## Supported Standards & RFCs

* **Core Specifications:**
  * [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) - Concise Binary Object Representation (CBOR)
  * [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) - CBOR Object Signing and Encryption (COSE)
  * [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053) - COSE algorithms
  * [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864) - Fully-Specified Algorithms for JOSE and COSE
  * [RFC 9338](https://www.rfc-editor.org/rfc/rfc9338) - COSE Countersignatures
* **Post-Quantum Cryptography:**
  * [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964) - ML-DSA for COSE
  * [RFC 8778](https://www.rfc-editor.org/rfc/rfc8778) - HSS/LMS for COSE
* **Attestation:**
  * [RFC 9783](https://www.rfc-editor.org/rfc/rfc9783) - PSA Attestation Token Profile of EAT

## Main Features

* **Complete COSE Suite (RFC 9052):** Full support for all six message types, including `COSE_Sign1`, `COSE_Encrypt0`, and `COSE_Mac0`.
* **V2 Countersignatures (RFC 9338):** Full and abbreviated in-place countersignatures across all six tagged COSE message types.
* **Post-Quantum Cryptography:**
  * ML-DSA (FIPS 204 / RFC 9964) at all security levels.
  * HSS/LMS stateful hash-based signing (RFC 8778 / CNSA 2.0).
* **Fast Performance:** On an Intel i9-11950H, end-to-end `COSE_Sign1` reaches 66,538 sign/s and 26,437 verify/s with ES256, and 21,986 sign/s and 53,686 verify/s with ML-DSA-44. See the [performance and footprint details](https://github.com/wolfSSL/wolfCOSE/wiki/Footprint) and [wolfCOSE vs. The Field](https://www.wolfssl.com/wolfcose-vs-the-field-the-smallest-and-fastest-cose-library-now-with-post-quantum-ml-dsa-at-the-same-cost/).
* **PSA Attestation:** EAT / PSA Token issuance and verification with delegated HSM signing support.
* **41 Cryptographic Algorithms:** Broad algorithm coverage across signing, encryption, MAC, and key distribution.
* **Embedded-First Design:** Zero dynamic memory allocation (no heap, zero `.data`/`.bss`). Operates on caller-supplied buffers with bounded stack usage.
* **FIPS 140-3 Path:** Uses wolfCrypt (FIPS Certificate #4718) as its sole cryptographic dependency.
* **STM32 Integrated:** Drop-in STM32Cube pack (`I-CUBE-wolfCOSE`) available for STM32CubeMX / IDE ([Details](https://github.com/wolfSSL/wolfCOSE/wiki/STM32Cube)).

## Supported Algorithms

* **Digital Signatures:**
  * **Classical:** `ESP256`, `ESP384`, `ESP512`, `Ed25519`, `Ed448`, `PS256`, `PS384`, `PS512`
  * **Post-Quantum:** `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`
  * **Stateful Hash-Based:** `HSS-LMS`
* **Encryption (AEAD):**
  * `AES-GCM` (128 / 192 / 256)
  * `AES-CCM` (variants)
  * `ChaCha20-Poly1305`
* **Message Authentication (MAC):**
  * `HMAC-SHA256`, `HMAC-SHA384`, `HMAC-SHA512`
  * `AES-MAC`
* **Key Distribution:**
  * `Direct`
  * `AES Key Wrap`
  * `ECDH-ES + HKDF`

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

RFC 9338 countersignatures can be attached to any tagged message in this
table. Use `wc_Cose_AddCounterSignature()` or
`wc_Cose_AddCounterSignature0()` to add one, then verify it independently with
the corresponding `wc_Cose_VerifyCounterSignature*()` API.

## Dependencies (wolfSSL)

wolfCOSE requires [wolfSSL](https://www.wolfssl.com/) as its crypto backend.
**Minimum supported version: v5.8.0-stable**. Some optional algorithms require
newer releases; see [Getting Started](docs/Getting-Started.md#prerequisites) for
feature-specific dependency floors and build instructions. HSS/LMS (RFC 8778)
requires v5.9.2-stable or later.

Choose a build configuration based on the algorithms you need.

### Minimal Build (ECC + AES-GCM)

This gives you COSE Sign1 (ESP256/384/512) and Encrypt0 (AES-GCM):

```bash
cd wolfssl
./autogen.sh
./configure --enable-ecc --enable-aesgcm \
            --enable-sha384 --enable-sha512 --enable-keygen
make && sudo make install
sudo ldconfig
```

**Algorithms enabled:** ESP256, ESP384, ESP512, AES-GCM-128/192/256

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
            --enable-mldsa --enable-lms \
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
| `make eat-psa-test` | Build + run the explicit full RFC 9783 PSA/EAT conformance suite |
| `make eat-psa-min-buffers-test` | Run the full PSA/EAT suite with `WOLFCOSE_MIN_BUFFERS` constrained-target limits |
| `make eat-psa-config-check` | Verify PSA/EAT is absent by default and validate feature-gate combinations |
| `make psa-eat-lean-verify` | Build + run the full `#tfm` verify-only PSA/EAT RFC vector example |
| `make psa-eat-demo` | Issue, verify, and appraise a current RFC 9783 device-onboarding token |
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
- `psa_eat_demo.c`: RFC 9783 device onboarding with measurement appraisal
- `psa_eat_verify_lean.c`: RFC 9783 current-profile Sign1 verification in a lean build

## CI / Testing

Runs on every push and PR:

- **Build + Test**: Ubuntu, macOS, GCC 10-14, Clang 14-18
- **Comprehensive Tests**: ~240 algorithm combination tests
- **Static Analysis**: cppcheck, Clang analyzer, GCC `-fanalyzer`
- **MISRA C 2012**: cppcheck `--addon=misra` checking all wolfCOSE code paths
- **MISRA C 2023**: strict GCC warnings and clang-tidy (`bugprone-*`, `cert-*`, `clang-analyzer-*`, `misc-*`)
- **Coverity Scan**: nightly defect analysis
- **Internal Static Analysis:** Fenrir wolfssl advanced static analysis tools
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

## Documentation

Full documentation is available in the [Wiki](https://github.com/wolfSSL/wolfCOSE/wiki):

- [Getting Started](https://github.com/wolfSSL/wolfCOSE/wiki/Getting-Started): Build instructions and first steps
- [Message Types](https://github.com/wolfSSL/wolfCOSE/wiki/Message-Types): All six RFC 9052 messages (Sign1, Sign, Encrypt0, Encrypt, Mac0, Mac) and RFC 9338 countersignatures with code samples
- [Algorithms](https://github.com/wolfSSL/wolfCOSE/wiki/Algorithms): Complete list of 41 supported algorithms with COSE IDs
- [API Reference](https://github.com/wolfSSL/wolfCOSE/wiki/API-Reference): Function signatures, data structures, error codes
- [Macros](https://github.com/wolfSSL/wolfCOSE/wiki/Macros): Compile-time configuration, size tuning, and ECDSA nonce policy
- [PSA-EAT](https://github.com/wolfSSL/wolfCOSE/wiki/PSA-EAT): RFC 9783 PSA token profiles, APIs, macros, and security guidance
- [Footprint](https://github.com/wolfSSL/wolfCOSE/wiki/Footprint): Size and speed numbers, desktop and on-device
- [Testing](https://github.com/wolfSSL/wolfCOSE/wiki/Testing): Test infrastructure, coverage, and failure injection
- [MISRA Compliance](https://github.com/wolfSSL/wolfCOSE/wiki/MISRA-Compliance): MISRA C:2012 and C:2023 compliance status and deviation rationale
- [Project Structure](https://github.com/wolfSSL/wolfCOSE/wiki/Project-Structure): Source file layout
- [STM32Cube](https://github.com/wolfSSL/wolfCOSE/wiki/STM32Cube): Install and run wolfCOSE as an STM32Cube pack on device

## Release Notes

The current release is **2.0.0**. It adds standardized HSS/LMS signatures (RFC 8778), COSE countersignatures (RFC 9338), PSA/EAT attestation (RFC 9783), RFC 9864 signature IDs, delegated signing, expanded key and CBOR APIs, experimental COSE-HPKE, and extensive hardening, all with zero dynamic allocation. See [ChangeLog.md](ChangeLog.md) for the full release notes.

wolfCOSE 2.0.0 has been developed according to wolfSSL's development and QA process (see https://www.wolfssl.com/about/wolfssl-software-development-process-quality-assurance) and successfully passed the quality criteria.

## License

wolfCOSE is free software licensed under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html); see [LICENSE](LICENSE) for the full text.

Copyright (C) 2026 wolfSSL Inc.

## Support

For commercial licensing, professional support contracts, or to discuss moving wolfCOSE into your production environment, contact [wolfSSL](https://www.wolfssl.com/contact/).
