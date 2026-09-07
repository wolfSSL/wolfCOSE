# Release Notes

## wolfCOSE 2.0.0 (September 17, 2026)

Release 2.0.0 adds standardized HSS/LMS signatures, COSE
countersignatures, PSA/EAT attestation, RFC 9864 fully specified signature
algorithms, experimental COSE-HPKE, delegated signing, expanded key and CBOR
APIs, and extensive parser and key-handling hardening. wolfCOSE remains a
zero-allocation C implementation of CBOR and COSE backed solely by wolfCrypt.

This is a major release because `WOLFCOSE_KEY` gained fields since 1.0.0.
Applications must be recompiled against the 2.0.0 headers. Code that
initializes keys with `wc_CoseKey_Init()` and attaches keys through the
`wc_CoseKey_Set*()` APIs does not need source changes.

### Vulnerabilities

- No CVEs were assigned for this release.

### New Feature Additions

- Added delegated signing for `COSE_Sign1` and multi-signer `COSE_Sign`.
  `WOLFCOSE_ENABLE_EXT_SIGN` lets an HSM, secure element, PSA Crypto service,
  or remote KMS produce signatures without exposing the private key to
  wolfCOSE. ([#59](https://github.com/wolfSSL/wolfCOSE/pull/59))
- Added `wc_CoseSign1_Sign_ex()` for tagged or untagged output and
  `wc_CoseSign1_SignSize_ex()` for exact sizing without signing, consuming an
  RNG, or advancing an external signer.
  ([#65](https://github.com/wolfSSL/wolfCOSE/pull/65))
- Expanded the COSE_Key API with public-only encoding, exact encoded-size
  queries, raw ECC coordinate encoding, and metadata inspection before key
  import. Added CBOR context initializers, int-or-text label decoding, and
  zero-copy skipped-item capture helpers.
  ([#66](https://github.com/wolfSSL/wolfCOSE/pull/66))
- Added RFC 8778 HSS/LMS signatures and COSE_Key support for `COSE_Sign1`,
  multi-signer `COSE_Sign`, delegated signing, and lean sign/verify profiles.
  Signing state remains owned and persisted by the caller.
  ([#72](https://github.com/wolfSSL/wolfCOSE/pull/72))
- Added RFC 9338 full and abbreviated countersignatures across all six tagged
  COSE message types, including in-place creation, independent verification,
  CLI support, and RFC interoperability vectors.
  ([#74](https://github.com/wolfSSL/wolfCOSE/pull/74))
- Added RFC 9783 PSA/EAT token issuance, verification, UEID-selected key
  resolution, software-component iteration, delegated signing, current and
  legacy profile handling, and Sign1 and Mac0 envelopes. PSA/EAT remains
  explicitly enabled by application-selected compile-time gates.
  ([#75](https://github.com/wolfSSL/wolfCOSE/pull/75))
- Added RFC 9864 fully specified signature algorithms `ESP256`, `ESP384`,
  `ESP512`, `Ed25519`, and `Ed448` as the default IDs. The deprecated RFC 9053
  polymorphic IDs remain available with
  `WOLFCOSE_ENABLE_DEPRECATED_ALGS`.
  ([#85](https://github.com/wolfSSL/wolfCOSE/pull/85))
- Added a two-step compile-time gate for draft features. A draft feature must
  select its own operation gate and acknowledge unstable specifications with
  `WOLFCOSE_EXPERIMENTAL`.
  ([#68](https://github.com/wolfSSL/wolfCOSE/pull/68))
- Added experimental COSE-HPKE P0 support for `COSE_Encrypt0` and
  multi-recipient `COSE_Encrypt`, including CLI commands and tests. It is off
  by default and requires `WOLFCOSE_EXPERIMENTAL` plus the selected HPKE
  operation gates while the specification remains an Internet-Draft.
  ([#70](https://github.com/wolfSSL/wolfCOSE/pull/70))
- Added the I-CUBE-wolfCOSE STM32Cube pack, STM32CubeMX/IDE integration
  documentation, and an on-device test.
  ([#61](https://github.com/wolfSSL/wolfCOSE/pull/61))

### Fixes

- Rejected COSE_Key decoding into an attached wolfCrypt key object of a
  different type before any import occurs. Thanks to Omoikane Labs for the
  report. ([#64](https://github.com/wolfSSL/wolfCOSE/pull/64))
- Hardened CBOR and COSE parsing, cryptographic dispatch, length handling,
  strict serialization checks, key encoding and decoding, and cleanup on
  error paths. ([#67](https://github.com/wolfSSL/wolfCOSE/pull/67))
- Rejected invalid protected and skipped recipient structures, including
  nested Direct recipients and conflicting recipient metadata.
  ([#77](https://github.com/wolfSSL/wolfCOSE/pull/77))
- Tightened COSE_Key metadata validation, public/private material checks,
  constant-time ML-DSA public-key comparison, and attached-key type and curve
  validation across signing, verification, and ECDH operations.
  ([#78](https://github.com/wolfSSL/wolfCOSE/pull/78),
  [#80](https://github.com/wolfSSL/wolfCOSE/pull/80))
- Hardened detached input checks, critical-header handling, ECDSA signing
  prerequisites, protected-header pointers, AES cleanup, CBOR state tracking,
  public API contracts, and recipient depth accounting.
  ([#81](https://github.com/wolfSSL/wolfCOSE/pull/81),
  [#82](https://github.com/wolfSSL/wolfCOSE/pull/82))
- Hardened RSA COSE_Key import and export by validating component presence and
  widths, bounding output by RSA capacity, fully initializing modulus buffers,
  and requiring hardened private-key import behavior.
  ([#83](https://github.com/wolfSSL/wolfCOSE/pull/83))
- Guarded COSE header label conversion against values outside the supported
  signed range. ([#86](https://github.com/wolfSSL/wolfCOSE/pull/86))

### Improvements/Optimizations

- Split the former monolithic implementation into per-area source modules for
  smaller selective builds and easier analysis.
  ([#73](https://github.com/wolfSSL/wolfCOSE/pull/73))
- Added `pkg-config` discovery while retaining explicit wolfSSL include and
  library overrides. ([#69](https://github.com/wolfSSL/wolfCOSE/pull/69))
- Expanded interoperability testing against t_cose/QCBOR, go-cose,
  python-cwt, Rust coset, OpenSSL, COSE WG examples, and RFC vectors.
  ([#71](https://github.com/wolfSSL/wolfCOSE/pull/71))
- Tightened internal integer and size types for MISRA C analysis and fixed
  static-analysis stability in the test suite.
  ([#62](https://github.com/wolfSSL/wolfCOSE/pull/62),
  [#79](https://github.com/wolfSSL/wolfCOSE/pull/79))
- Added optional RFC 6979 deterministic ECDSA signing through
  `WOLFCOSE_ENABLE_DETERMINISTIC_ECDSA`.
  ([#67](https://github.com/wolfSSL/wolfCOSE/pull/67))
- Refreshed the README, algorithm documentation, build guidance, and measured
  ES256 and ML-DSA-44 performance and footprint references.
  ([#87](https://github.com/wolfSSL/wolfCOSE/pull/87),
  [#88](https://github.com/wolfSSL/wolfCOSE/pull/88))
- Added release-only qualification targets for advanced feature scenarios,
  C++ compilation, Valgrind, merged coverage profiles, metadata validation,
  and reproducible smoke-tested source archives.
  ([#89](https://github.com/wolfSSL/wolfCOSE/pull/89))

### Compatibility / Migration

- `WOLFCOSE_KEY` gained delegated-signing and internal key-type tracking
  fields. Recompile applications against the 2.0.0 headers.
- New messages use the RFC 9864 fully specified signature IDs. Existing
  messages using `ES256`, `ES384`, `ES512`, or `EdDSA` require
  `WOLFCOSE_ENABLE_DEPRECATED_ALGS`; changing a protected algorithm ID also
  requires re-signing the message. See
  [[Algorithms#Migrating from RFC 9053 Signature IDs]].
- COSE-HPKE is experimental. Its wire format and API may change until the IETF
  specification is finalized.
- `LIBWOLFCOSE_VERSION_STRING` is now `"2.0.0"` and
  `LIBWOLFCOSE_VERSION_HEX` is `0x02000000`.

## wolfCOSE 1.0.0 (June 25, 2026)

Release 1.0.0 is the first stable release of wolfCOSE, a complete,
zero-allocation C implementation of CBOR (RFC 8949) and COSE (RFC 9052/9053)
on top of wolfCrypt. It provides all six COSE message types in both
single-actor and multi-actor forms, 40 algorithms across signing, encryption,
MAC, and key distribution, and standardized post-quantum ML-DSA signatures
(RFC 9964), all heap-allocation-free and within a tiny footprint.

### Vulnerabilities

- None. This is the initial release.

### New Feature Additions

- CBOR engine implementing RFC 8949 encode/decode with no external dependency,
  enforcing deterministic/preferred-encoding rules and rejecting non-preferred
  or trailing input on decode.
- All six COSE message types (RFC 9052): `COSE_Sign1`, `COSE_Sign`,
  `COSE_Encrypt0`, `COSE_Encrypt`, `COSE_Mac0`, and `COSE_Mac`, including the
  multi-signer and multi-recipient variants. See [[Message Types]].
- 40 algorithms across signing, encryption, MAC, and key distribution
  (RFC 9053): ES256/384/512, EdDSA (Ed25519/Ed448), PS256/384/512,
  ML-DSA-44/65/87, AES-GCM (128/192/256), ChaCha20-Poly1305, AES-CCM variants,
  HMAC-SHA256/384/512, AES-MAC, Direct, AES Key Wrap, and ECDH-ES+HKDF. See
  [[Algorithms]].
- Standardized post-quantum signatures: ML-DSA (FIPS 204) at all three security
  levels, conformant to RFC 9964 ("ML-DSA for JOSE and COSE"). COSE keys use the
  RFC 9964 AKP key type (`kty` 7) with a required `alg`, the public key in `pub`
  (-1), and the 32-byte seed private key in `priv` (-2).
- `COSE_Key` / `COSE_KeySet` serialization for all supported key types,
  including full RFC 8230 RSA private keys (n, e, d, p, q, dP, dQ, qInv).
- Zero dynamic allocation: every operation uses caller-provided buffers, with no
  heap, `.data`, or `.bss` usage.
- Path to FIPS 140-3 through wolfCrypt FIPS Certificate #4718 (sole crypto
  dependency).
- `WOLFCOSE_LEAN` configuration layer with `WOLFCOSE_HAVE_*` feature gates,
  `WOLFCOSE_LEAN_VERIFY` / ML-DSA lean profiles for verify-only targets, and a
  `WOLFCOSE_MIN_BUFFERS` bounded-stack profile. Verify-only ECC builds link
  against sign-disabled wolfCrypt (`NO_ECC_SIGN`, `NO_ASN`, no `mp_int`); the
  ECC signing helpers are gated out so a verify-only image never pulls in sign
  code, enforced in CI without `-ffunction-sections` garbage collection. See
  [[Macros]].
- `LIBWOLFCOSE_VERSION_STRING` / `LIBWOLFCOSE_VERSION_HEX` in
  `wolfcose/version.h` for compile-time version checks.

### Fixes

- RSA private `COSE_Key` encode/decode now emits the RFC 8230 MUST-present `dP`
  (-6) and `dQ` (-7) CRT exponents and encodes `d` at full modulus width, so a
  private RSA key round-trips reliably against strict RSA decoders.
- `COSE_Mac` emits an empty protected header for direct-key recipients, matching
  the COSE structure other implementations expect on the wire.
- `COSE_Key` emits preferred (shortest) CBOR length for the RSA `n` and `d` byte
  strings, keeping serialized keys deterministic.

### Improvements/Optimizations

- Minimal footprint: an ES256 `COSE_Sign1` build is ~5.1 KB verify-only and
  ~6.8 KB sign + verify for the wolfCOSE COSE + CBOR engine. See [[Footprint]].
- MISRA C:2012 and C:2023 checked. See [[MISRA Compliance]].
- API hardening: `COSE_Encrypt` and `wc_CoseMac_Create` direct mode now require
  an explicit `WOLFCOSE_ALG_DIRECT` and reject a zero-initialized algorithm id;
  `wc_CoseMac_Verify` classifies the recipient algorithm and enforces the algId
  policy; the CBOR `wc_CBOR_PeekType` peek is guarded against NULL and
  end-of-buffer reads with a single-exit sentinel return; the
  `wc_CoseSign1_Verify` and symmetric `COSE_Encrypt0` key parameters are
  `const`-qualified; and ephemeral `COSE_Key` curve ids are range-checked before
  any narrowing cast.
- Coverity DEADCODE findings in the COSE MAC and CBOR decode paths resolved;
  static analysis (cppcheck, Clang analyzer, GCC `-fanalyzer`, Coverity) is
  clean.
- CI matrix covering Ubuntu/macOS, GCC 10-14 and Clang 14-18, ~240 algorithm
  combination tests, static analysis (cppcheck, Clang analyzer, GCC
  `-fanalyzer`, Coverity), security scanning (CodeQL, Semgrep) and house-style
  gates, sanitizers (ASan/UBSan), a wolfCOSE <-> t_cose wire-interop conformance
  suite, and a wolfSSL version matrix with explicit ML-DSA/PQC rows. See
  [[Testing]].
- Expanded negative and boundary coverage: 4 KB large-payload round-trips for
  `COSE_Encrypt0`/`COSE_Mac0`, empty-payload round-trips across
  AES-GCM/AES-CCM/ChaCha20-Poly1305, CBOR integer argument-width boundaries
  through the 8-byte and `INT64_MIN` extremes with pinned encoded lengths,
  HMAC-384/512 short-key rejection, and pinned MAC tag lengths (including an
  AES-CBC-MAC block-boundary known-answer test) with IV-chaining tamper checks.

---

wolfCOSE 1.0.0 has been developed according to wolfSSL's development and QA
process (see the [wolfSSL Software Development Process and Quality
Assurance](https://www.wolfssl.com/about/wolfssl-software-development-process-quality-assurance)
page) and successfully passed the quality criteria.

Requires wolfSSL 5.8.0 or later as the crypto backend; ML-DSA support requires
wolfSSL 5.9.2 or later. See [[Getting Started]] for build instructions.
