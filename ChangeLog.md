# wolfCOSE Release 2.0.0 (September 2026)

Release 2.0.0 builds on the first stable wolfCOSE release with a delegated
(external) signing seam, expanded COSE_Key and CBOR helper APIs, exact
encoded-size queries, a broad parsing and key-handling hardening pass, and
initial experimental support for several additional COSE specifications. It
remains a zero-allocation C implementation of CBOR (RFC 8949) and COSE
(RFC 9052/9053) on top of wolfCrypt, with a path to FIPS 140-3 through
wolfCrypt.

This is a major release because `WOLFCOSE_KEY` gained fields since 1.0.0 (see
Compatibility below). Applications must be recompiled against the 2.0.0
headers; no source changes are needed for code that attaches keys through the
`wc_CoseKey_Set*()` APIs and initializes with `wc_CoseKey_Init()`.

## Vulnerabilities

* No CVEs were assigned for this release.

## New Feature Additions

* Delegated (external) signing seam: `WOLFCOSE_ENABLE_EXT_SIGN` adds a signing
  callback (`signCb` / `signCtx` on `WOLFCOSE_KEY`) so COSE_Sign1 and COSE_Sign
  signatures can be produced by an external signer (HSM, secure element, remote
  KMS) instead of a local wolfCrypt key.
  ([#59](https://github.com/wolfSSL/wolfCOSE/pull/59))
* `wc_CoseSign1_Sign_ex()` and `wc_CoseSign1_SignSize_ex()` add an untagged
  COSE_Sign1 output option and an exact encoded-size query that reports the
  size without signing.
  ([#65](https://github.com/wolfSSL/wolfCOSE/pull/65))
* Expanded COSE_Key API: `wc_CoseKey_Encode_ex()` with a
  `WOLFCOSE_KEY_PUBLIC_ONLY` flag that never serialises private material, exact
  `wc_CoseKey_EncodeSize()` / `wc_CoseKey_EncodeSize_ex()` size queries,
  `wc_CoseKey_EncodeEccRaw()` for raw affine coordinates, and
  `wc_CoseKey_PeekInfo()` to read key metadata before decoding.
  ([#66](https://github.com/wolfSSL/wolfCOSE/pull/66))
* New CBOR helpers for parsing maps wolfCOSE does not itself define:
  `wc_CBOR_EncoderInit` / `wc_CBOR_DecoderInit`, `wc_CBOR_DecodeLabel` for
  int-or-text map labels, and `wc_CBOR_SkipItem` to capture a skipped item's
  raw bytes.
  ([#66](https://github.com/wolfSSL/wolfCOSE/pull/66))
* Experimental-feature acknowledgment gate: draft, pre-RFC COSE features are
  held behind `WOLFCOSE_EXPERIMENTAL` plus a per-feature `WOLFCOSE_ENABLE_<X>`;
  selecting a draft feature without the master acknowledgment is a hard compile
  error.
  ([#68](https://github.com/wolfSSL/wolfCOSE/pull/68))

### Experimental additions (opt-in, off by default)

New, opt-in implementations gated behind their own `WOLFCOSE_ENABLE_<X>` build
flags while they mature; see `docs/Macros.md`.

* RFC 8778 HSS/LMS signature and COSE_Key support.
  ([#72](https://github.com/wolfSSL/wolfCOSE/pull/72))
* RFC 9338 countersignature support.
  ([#74](https://github.com/wolfSSL/wolfCOSE/pull/74))
* RFC 9783 PSA/EAT support.
  ([#75](https://github.com/wolfSSL/wolfCOSE/pull/75))
* COSE-HPKE support. This tracks an IETF Internet-Draft that is not yet a
  finalized RFC, so it additionally requires the `WOLFCOSE_EXPERIMENTAL`
  acknowledgment and its wire format and API may still change.
  ([#70](https://github.com/wolfSSL/wolfCOSE/pull/70))

## Fixes

* Hardened COSE_Key decoding so an attached key is only ever imported as its
  actual type: a decode whose key type does not match the attached key object
  is now rejected before any import runs. Thanks to Omoikane Labs for reporting.
  ([#64](https://github.com/wolfSSL/wolfCOSE/pull/64))
* Broad hardening pass across COSE parsing, key handling, and cryptographic
  operations, adding input validation and robustness throughout the decode and
  key paths.
  ([#67](https://github.com/wolfSSL/wolfCOSE/pull/67))

## Improvements/Optimizations

* Split the monolithic `wolfcose.c` into per-area source modules for
  maintainability and finer-grained builds.
  ([#73](https://github.com/wolfSSL/wolfCOSE/pull/73))
* Build discovery now uses `pkg-config` for system-installed wolfSSL.
  ([#69](https://github.com/wolfSSL/wolfCOSE/pull/69))
* Expanded COSE interoperability coverage against external COSE
  implementations.
  ([#71](https://github.com/wolfSSL/wolfCOSE/pull/71))
* STM32Cube pack support: I-CUBE-wolfCOSE pack files, an on-device test, and
  documentation.
  ([#61](https://github.com/wolfSSL/wolfCOSE/pull/61))
* Stabilized the nightly cppcheck static-analysis job on `test_cose.c`.
  ([#62](https://github.com/wolfSSL/wolfCOSE/pull/62))

## Compatibility / Migration

* ABI: `WOLFCOSE_KEY` gained tail fields since 1.0.0 (the delegated-signing
  callback and context, and internal key-type tracking), so
  `sizeof(WOLFCOSE_KEY)` differs from 1.0.0. Recompile applications against the
  2.0.0 headers. Code that attaches keys through `wc_CoseKey_Set*()` and
  initializes with `wc_CoseKey_Init()` needs no source changes.
* `LIBWOLFCOSE_VERSION_STRING` is now `"2.0.0"`
  (`LIBWOLFCOSE_VERSION_HEX 0x02000000`).

# wolfCOSE Release 1.0.0 (June 25, 2026)

Release 1.0.0 is the first stable release of wolfCOSE, a complete,
zero-allocation C implementation of CBOR (RFC 8949) and COSE (RFC 9052/9053)
on top of wolfCrypt. It provides all six COSE message types in both
single-actor and multi-actor forms, 40 algorithms across signing, encryption,
MAC, and key distribution, and standardized post-quantum ML-DSA signatures
(RFC 9964), all heap-allocation-free and within a tiny footprint.

## Vulnerabilities

* None. This is the initial release.

## New Feature Additions

* `wc_CoseSign1_Sign_ex()` can emit untagged COSE_Sign1 messages, and
  `wc_CoseSign1_SignSize_ex()` reports their exact encoded size without
  signing or invoking an external signer.
* CBOR engine implementing RFC 8949 encode/decode with no external dependency,
  enforcing deterministic/preferred-encoding rules and rejecting non-preferred
  or trailing input on decode.
* All six COSE message types (RFC 9052): `COSE_Sign1`, `COSE_Sign`,
  `COSE_Encrypt0`, `COSE_Encrypt`, `COSE_Mac0`, and `COSE_Mac`, including the
  multi-signer and multi-recipient variants.
* 40 algorithms across signing, encryption, MAC, and key distribution
  (RFC 9053): ES256/384/512, EdDSA (Ed25519/Ed448), PS256/384/512,
  ML-DSA-44/65/87, AES-GCM (128/192/256), ChaCha20-Poly1305, AES-CCM variants,
  HMAC-SHA256/384/512, AES-MAC, Direct, AES Key Wrap, and ECDH-ES+HKDF.
* Standardized post-quantum signatures: ML-DSA (FIPS 204) at all three security
  levels, conformant to RFC 9964 ("ML-DSA for JOSE and COSE"). COSE keys use the
  RFC 9964 AKP key type (`kty` 7) with a required `alg`, the public key in `pub`
  (-1), and the 32-byte seed private key in `priv` (-2).
* `COSE_Key` / `COSE_KeySet` serialization for all supported key types,
  including full RFC 8230 RSA private keys (n, e, d, p, q, dP, dQ, qInv).
* Zero dynamic allocation: every operation uses caller-provided buffers, with no
  heap, `.data`, or `.bss` usage.
* Path to FIPS 140-3 through wolfCrypt FIPS Certificate #4718 (sole crypto
  dependency).
* `WOLFCOSE_LEAN` configuration layer with `WOLFCOSE_HAVE_*` feature gates,
  `WOLFCOSE_LEAN_VERIFY` / ML-DSA lean profiles for verify-only targets, and a
  `WOLFCOSE_MIN_BUFFERS` bounded-stack profile. Verify-only ECC builds link
  against sign-disabled wolfCrypt (`NO_ECC_SIGN`, `NO_ASN`, no `mp_int`); the
  ECC signing helpers are gated out so a verify-only image never pulls in sign
  code, enforced in CI without `-ffunction-sections` garbage collection.
* `LIBWOLFCOSE_VERSION_STRING` / `LIBWOLFCOSE_VERSION_HEX` in
  `wolfcose/version.h` for compile-time version checks.

## Fixes

* RSA private `COSE_Key` encode/decode now emits the RFC 8230 MUST-present `dP`
  (-6) and `dQ` (-7) CRT exponents and encodes `d` at full modulus width, so a
  private RSA key round-trips reliably against strict RSA decoders.
* `COSE_Mac` emits an empty protected header for direct-key recipients, matching
  the COSE structure other implementations expect on the wire.
* `COSE_Key` emits preferred (shortest) CBOR length for the RSA `n` and `d` byte
  strings, keeping serialized keys deterministic.

## Improvements/Optimizations

* Build discovery uses `pkg-config` for system-installed wolfSSL and supports
  explicit flags for custom and cross builds.
* Minimal footprint: an ES256 `COSE_Sign1` build is ~5.1 KB verify-only and
  ~6.8 KB sign + verify for the wolfCOSE COSE + CBOR engine; see the
  [Footprint](https://github.com/wolfSSL/wolfCOSE/wiki/Footprint) page for
  total-flash numbers including wolfCrypt.
* MISRA C:2012 and C:2023 checked.
* API hardening: `COSE_Encrypt` and `wc_CoseMac_Create` direct mode now require
  an explicit `WOLFCOSE_ALG_DIRECT` and reject a zero-initialized algorithm id;
  `wc_CoseMac_Verify` classifies the recipient algorithm and enforces the algId
  policy; the CBOR `wc_CBOR_PeekType` peek is guarded against NULL and
  end-of-buffer reads with a single-exit sentinel return; the
  `wc_CoseSign1_Verify` and symmetric `COSE_Encrypt0` key parameters are
  `const`-qualified; and ephemeral `COSE_Key` curve ids are range-checked before
  any narrowing cast.
* Coverity DEADCODE findings in the COSE MAC and CBOR decode paths resolved;
  static analysis (cppcheck, Clang analyzer, GCC `-fanalyzer`, Coverity) is
  clean.
* CI matrix covering Ubuntu/macOS, GCC 10-14 and Clang 14-18, ~240 algorithm
  combination tests, static analysis (cppcheck, Clang analyzer, GCC
  `-fanalyzer`, Coverity), security scanning (CodeQL, Semgrep) and house-style
  gates, sanitizers (ASan/UBSan), a wolfCOSE <-> t_cose wire-interop conformance
  suite, and a wolfSSL version matrix with explicit ML-DSA/PQC rows.
* Expanded negative and boundary coverage: 4 KB large-payload round-trips for
  `COSE_Encrypt0`/`COSE_Mac0`, empty-payload round-trips across
  AES-GCM/AES-CCM/ChaCha20-Poly1305, CBOR integer argument-width boundaries
  through the 8-byte and `INT64_MIN` extremes with pinned encoded lengths,
  HMAC-384/512 short-key rejection, and pinned MAC tag lengths (including an
  AES-CBC-MAC block-boundary known-answer test) with IV-chaining tamper checks.

---

wolfCOSE 1.0.0 has been developed according to wolfSSL's development and QA
process (see
https://www.wolfssl.com/about/wolfssl-software-development-process-quality-assurance)
and successfully passed the quality criteria.

For additional vulnerability information visit the vulnerability page at
https://www.wolfssl.com/docs/security-vulnerabilities/

Requires wolfSSL 5.8.0 or later as the crypto backend; ML-DSA support requires
wolfSSL 5.9.2 or later. See README.md for build instructions.
