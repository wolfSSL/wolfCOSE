# Configuration Macros

wolfCOSE has two configuration modes. The default is an opt-out full build: every algorithm wolfSSL provides is enabled, and you strip what you don't need with `WOLFCOSE_NO_*` defines. Alternatively, `WOLFCOSE_LEAN` switches to an opt-in core build and you add extensions with `WOLFCOSE_ENABLE_*`. See [Lean Configuration Layer](#lean-configuration-layer).

Draft, pre-RFC features are held behind a separate acknowledgement,
`WOLFCOSE_EXPERIMENTAL`; see [Experimental Features](Experimental.md).

## Experimental Features

Some COSE work is standardized in an IETF **Internet-Draft that is not yet a finalized RFC** (for example COSE-HPKE and ML-KEM key encapsulation). While a spec is a draft, its wire format and API may still change, so wolfCOSE keeps that code off in every normal build and requires you to opt in twice — once for the master acknowledgement, once for the specific feature.

| Define | Role |
|--------|------|
| `WOLFCOSE_EXPERIMENTAL` | Master acknowledgement. Enables **no** functionality on its own; it only *permits* the individually selected experimental features below. |
| `WOLFCOSE_ENABLE_<X>` | Opt in one experimental feature (each keeps its own fine-grained gate). |

An experimental feature is compiled in only when **both** its own `WOLFCOSE_ENABLE_<X>` and `WOLFCOSE_EXPERIMENTAL` are defined. Selecting the feature without the acknowledgement is a hard compile error:

```c
#if defined(WOLFCOSE_ENABLE_<X>) && !defined(WOLFCOSE_EXPERIMENTAL)
    #error "WOLFCOSE_ENABLE_<X> selects experimental draft code (spec not yet a finalized RFC); also define WOLFCOSE_EXPERIMENTAL to acknowledge"
#endif
```

`WOLFCOSE_ENABLE_EXPERIMENTAL_EXAMPLE` is a permanent reference exemplar that enables no functionality; it documents the pattern above and is the target the `make experimental-check` gate exercises. Compile examples:

```bash
# Normal build: zero experimental code, no acknowledgement needed.
cc ... src/*.c

# Enable an experimental feature (requires both defines):
cc -DWOLFCOSE_EXPERIMENTAL -DWOLFCOSE_ENABLE_EXPERIMENTAL_EXAMPLE ...

# Feature without acknowledgement -> compile error, by design.
cc -DWOLFCOSE_ENABLE_EXPERIMENTAL_EXAMPLE ...
```

> **Warning:** experimental features track drafts still in flux. Their message wire format, header parameters, and public API may change or be removed between wolfCOSE releases with no compatibility guarantee. Do not depend on them in a stable deployment.

**Graduation policy.** When a draft is published as an RFC, its `WOLFCOSE_EXPERIMENTAL` requirement is removed in a focused follow-up and the feature becomes an ordinary gate (default-on full build, `WOLFCOSE_ENABLE_<X>` under `WOLFCOSE_LEAN`, `WOLFCOSE_NO_<X>` to strip), following the [Algorithm Gates](#algorithm-gates) convention.

COSE-HPKE is currently an experimental feature. It stays off in every build and
requires the master acknowledgement plus the relevant operation gate. See
[Experimental Features](Experimental.md) for its current draft status, scope,
and graduation plan.

## Lean Configuration Layer

Defining `WOLFCOSE_LEAN` keeps only the core (`COSE_Sign1`/`Encrypt0`/`Mac0` with ESP256, AES-GCM, and HMAC-SHA256) and turns every other algorithm into an opt-in. This is the recommended starting point for constrained targets.

| Define | Description |
|--------|-------------|
| `WOLFCOSE_LEAN` | Core-only base; all extensions become opt-in |
| `WOLFCOSE_ENABLE_<X>` | Opt in a single extension (see list below) |

Extension names for `WOLFCOSE_ENABLE_<X>`: `ES384`, `ES512`, `EDDSA`, `ED448`, `RSAPSS`, `MLDSA`, `LMS`, `HMAC384`, `HMAC512`, `AESCCM`, `CHACHA20`, `AESMAC`, `AESWRAP`, `ECDH_ES`, `SIGN` (multi-signer), `ENCRYPT` (multi-recipient), `MAC` (multi-recipient), and `COUNTERSIGN` (RFC 9338 countersignatures).

COSE-HPKE uses its own explicit gates rather than this generic extension rule,
so it never becomes enabled merely because wolfSSL provides HPKE.

An extension is compiled in when it is explicitly enabled (`WOLFCOSE_ENABLE_<X>`), or — in a non-lean build — when wolfSSL provides the primitive and it is not opted out with `WOLFCOSE_NO_<X>`. Enabling an extension wolfSSL cannot provide is a compile error. The resolved state is exposed internally as read-only `WOLFCOSE_HAVE_<X>` gates (e.g. `WOLFCOSE_HAVE_MLDSA`); sources, tests, and examples compile against those, so you set `WOLFCOSE_ENABLE_*`/`WOLFCOSE_NO_*`, not `WOLFCOSE_HAVE_*`.

## PSA/EAT Attestation Gates

PSA/EAT support is off in every build, including a non-lean full build. The
default archive does not contain `wc_CoseEatPsaToken_*` symbols or the PSA/EAT
parser. Define the common switch, one or more profiles, and one or more COSE
envelope families deliberately. The component-count limit applies to issuers
and verifiers. The two claim-map limits exist only in verifier builds.

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_ENABLE_EAT_PSA` | Common PSA/EAT API and types | off |
| `WOLFCOSE_ENABLE_EAT_PSA_CURRENT` | RFC 9783 TF-M current profile | off |
| `WOLFCOSE_ENABLE_EAT_PSA_SIGN1` | Tagged Sign1 consumption | off |
| `WOLFCOSE_ENABLE_EAT_PSA_MAC0` | Tagged Mac0 consumption | off |
| `WOLFCOSE_ENABLE_EAT_PSA_ISSUE` | Current-profile claim encoding | off |
| `WOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE` | Tagged Sign1 token issuance | off |
| `WOLFCOSE_ENABLE_EAT_PSA_MAC0_ISSUE` | Tagged Mac0 token issuance | off |
| `WOLFCOSE_ENABLE_EAT_PSA_LEGACY` | Legacy `PSA_IOT_PROFILE_1` consumption | off |
| `WOLFCOSE_ENABLE_EAT_PSA_UEID_RESOLVER` | UEID-selected key lookup helper | off |
| `WOLFCOSE_ENABLE_EAT_PSA_COMPONENT_ITERATOR` | Zero-copy component callback helper | off |
| `WOLFCOSE_EAT_PSA_TFM_FULL` | Derived: all RFC 9783 `#tfm` receiver algorithms/envelopes and the deprecated RFC 9053 ECDSA IDs are enabled; do not define manually | derived |
| `WOLFCOSE_EAT_PSA_MAX_COMPONENTS` | Maximum accepted software-component maps | 32 |
| `WOLFCOSE_EAT_PSA_MAX_CLAIMS` | Verifier-only maximum claim-map entries, including extensions | 64 |
| `WOLFCOSE_EAT_PSA_MAX_COMPONENT_CLAIMS` | Verifier-only maximum entries in each component map | 16 |

`WOLFCOSE_ENABLE_EAT_PSA_ISSUE` enables the claim encoder and requires the
current profile. Add `WOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE` and/or
`WOLFCOSE_ENABLE_EAT_PSA_MAC0_ISSUE` for a protected token creator. These
issuer gates are independent of the Sign1 and Mac0 consumption gates, so an
attester-only build does not export `wc_CoseEatPsaToken_Verify()`.
It may also disable all generic verify/decrypt operations, key decoding, and
`WOLFCOSE_CBOR_DECODE`; `make eat-psa-config-check` compiles both issuer
envelopes in exactly that encode-only configuration.

The generic operation and algorithm gates remain authoritative:

| PSA/EAT path | Required generic operation | Algorithm selection |
|--------------|----------------------------|---------------------|
| Sign1 consume | `WOLFCOSE_SIGN1_VERIFY` | `WOLFCOSE_ENABLE_DEPRECATED_ALGS` plus ES256, ES384, and/or ES512 |
| Sign1 issue | `WOLFCOSE_SIGN1_SIGN` | `WOLFCOSE_ENABLE_DEPRECATED_ALGS` plus ES256, ES384, and/or ES512 |
| Mac0 consume | `WOLFCOSE_MAC0_VERIFY` | HMAC256, HMAC384, and/or HMAC512 |
| Mac0 issue | `WOLFCOSE_MAC0_CREATE` | HMAC256, HMAC384, and/or HMAC512 |

Use `WOLFCOSE_NO_SIGN1_SIGN`, `WOLFCOSE_NO_SIGN1_VERIFY`,
`WOLFCOSE_NO_MAC0_CREATE`, or `WOLFCOSE_NO_MAC0_VERIFY` to remove a generic
operation. ES256 and HMAC256 are lean-core algorithms and can be removed with
`WOLFCOSE_NO_ES256` and `WOLFCOSE_NO_HMAC256`. Select ES384, ES512, HMAC384,
and HMAC512 in a lean build with `WOLFCOSE_ENABLE_ES384`,
`WOLFCOSE_ENABLE_ES512`, `WOLFCOSE_ENABLE_HMAC384`, and
`WOLFCOSE_ENABLE_HMAC512`; use the corresponding `WOLFCOSE_NO_*` macros in a
full build. A selected PSA/EAT path that has no compatible generic operation
or algorithm is a compile-time configuration error.

RFC 9783 Section 5.2 requires a receiver advertising the standardized
`tag:psacertified.org,2023:psa#tfm` profile to accept tagged Sign1 and Mac0
tokens with ES256/384/512 and HMAC 256/256, 384/384, and 512/512. wolfCOSE
derives `WOLFCOSE_EAT_PSA_TFM_FULL` only when that complete set is enabled.
That is a receiver-conformance gate only. An attester that enables issuance
and one RFC 9783 Sign1 or Mac0 creation path can issue a correctly labelled
`#tfm` token. A selective current-profile verifier still rejects `#tfm` with
`WOLFCOSE_E_EAT_PSA_PROFILE` and must not advertise full receiver conformance.

See [[PSA-EAT]] for examples, profile boundaries, and security guidance.

## Algorithm Gates

Per-algorithm opt-outs for the default (non-lean) build. Each also has a `WOLFCOSE_ENABLE_<X>` form for lean opt-in. `ES256`, `AESGCM`, and `HMAC256` form the lean core and stay on unless explicitly opted out.

| Opt-out | Algorithm | wolfSSL requirement |
|---------|-----------|---------------------|
| `WOLFCOSE_NO_ES256` | ECDSA P-256 (ESP256, and ES256 with deprecated IDs enabled) | `HAVE_ECC`, SHA-256, P-256 not disabled by `NO_ECC256`, and `ECC_MIN_KEY_SZ <= 256` |
| `WOLFCOSE_NO_ES384` | ECDSA P-384 (ESP384, and ES384 with deprecated IDs enabled) | `HAVE_ECC`, `WOLFSSL_SHA384`, `HAVE_ECC384` or `HAVE_ALL_CURVES`, and `ECC_MIN_KEY_SZ <= 384` |
| `WOLFCOSE_NO_ES512` | ECDSA P-521 (ESP512, and ES512 with deprecated IDs enabled) | `HAVE_ECC`, `WOLFSSL_SHA512`, `HAVE_ECC521` or `HAVE_ALL_CURVES`, and `ECC_MIN_KEY_SZ <= 521` |
| `WOLFCOSE_NO_EDDSA` | Ed25519 (and deprecated EdDSA with an Ed25519 key) | `HAVE_ED25519` |
| `WOLFCOSE_NO_ED448` | Ed448 (and deprecated EdDSA with an Ed448 key) | `HAVE_ED448` |
| `WOLFCOSE_NO_RSAPSS` | RSA-PSS (PS256/384/512) | `WC_RSA_PSS` |
| `WOLFCOSE_NO_MLDSA` | ML-DSA (FIPS 204) | `WOLFSSL_HAVE_MLDSA` (wolfSSL newer than 5.9.1) |
| `WOLFCOSE_NO_LMS` | HSS/LMS (RFC 8778) | `WOLFSSL_HAVE_LMS` (wolfSSL 5.9.2+) |
| `WOLFCOSE_NO_AESGCM` | AES-GCM | `HAVE_AESGCM` |
| `WOLFCOSE_NO_AESCCM` | AES-CCM | `HAVE_AESCCM` |
| `WOLFCOSE_NO_CHACHA20` | ChaCha20-Poly1305 | `HAVE_CHACHA` + `HAVE_POLY1305` |
| `WOLFCOSE_NO_HMAC256` | HMAC-SHA256 | HMAC and SHA-256 (`NO_HMAC` and `NO_SHA256` unset) |
| `WOLFCOSE_NO_HMAC384` | HMAC-SHA384 | `WOLFSSL_SHA384` |
| `WOLFCOSE_NO_HMAC512` | HMAC-SHA512 | `WOLFSSL_SHA512` |
| `WOLFCOSE_NO_AESMAC` | AES-CBC-MAC | `HAVE_AES_CBC` |

### Deprecated Algorithm IDs (RFC 9864)

RFC 9864 deprecates the polymorphic RFC 9053 signature IDs `ES256` (-7), `ES384` (-35), `ES512` (-36), and `EdDSA` (-8) in favour of the fully-specified `ESP256` (-9), `ESP384` (-51), `ESP512` (-52), `Ed25519` (-19), and `Ed448` (-53). The key format and signature encoding are unchanged, but the protected `alg` value is part of the signed `Sig_structure`, so relabelling an existing message to a replacement ID requires re-signing it. The new IDs bind the curve, so `Ed25519` with an Ed448 key (or `ESP256` with a P-384 key) is rejected with `WOLFCOSE_E_COSE_BAD_ALG`.

| Define | Description |
|--------|-------------|
| `WOLFCOSE_ENABLE_DEPRECATED_ALGS` | Also accept the deprecated `ES256`/`ES384`/`ES512`/`EdDSA` IDs on sign and verify. Off by default in both full and lean builds. |

Without it the deprecated IDs fail with `WOLFCOSE_E_COSE_BAD_ALG`. Enable it to verify messages from peers that still emit the RFC 9053 IDs, including the pinned t_cose, go-cose, coset, and python-cwt interop peers, the COSE WG example vectors, and the RFC 9783 PSA attestation tokens (`ES256`). The CLI tool accepts the `ES256` and `EdDSA` names only in such a build; `Ed448` on the CLI always means -53.

RSA-PSS operations enforce RFC 8230's minimum 2048-bit modulus. A minimal
wolfSSL RSA verify-only build must define `WOLFSSL_EXPORT_INT` so wolfCOSE can
inspect the exact modulus width; builds that also enable ECC already expose
the required wolfSSL integer-export API.

### ECDSA Nonce Policy

Local ES256, ES384, and ES512 signing uses wolfSSL's configured nonce policy by
default. Deterministic ECDSA is an optional hardening feature because its RFC
6979 and HMAC support increases the linked footprint and requires a specially
built wolfSSL. When enabled, wolfCOSE selects SHA-256, SHA-384, or SHA-512 to
match the COSE algorithm before every signature, then restores the caller's
deterministic-mode and hash settings.

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_ENABLE_DETERMINISTIC_ECDSA` | Require RFC 6979 deterministic local ECDSA signing | off |

The feature requires wolfSSL built with `WOLFSSL_ECDSA_DETERMINISTIC_K` or
`WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT`. wolfSSL has no dedicated configure
switch for these defines, so enable one in wolfSSL's `CPPFLAGS`, then enable the
wolfCOSE feature when building:

```bash
cd wolfssl
CPPFLAGS="-DWOLFSSL_ECDSA_DETERMINISTIC_K -DWOLFSSL_NO_MALLOC" \
    ./configure <options>
make && sudo make install

cd ../wolfcose
make EXTRA_CFLAGS="-DWOLFCOSE_ENABLE_DETERMINISTIC_ECDSA"
```

`WOLFSSL_NO_MALLOC` keeps the wolfCrypt deterministic-nonce helper on its
preallocated path. It is not required to enable deterministic signing, but it
preserves zero-heap operation across the wolfCOSE and wolfCrypt layers.

Verification-only builds do not need the option. A delegated signing callback
chooses its own nonce policy. For a `WOLFSSL_USER_SETTINGS` test build, override
the policy probe include, for example with
`ECDSA_POLICY_OPTS='-DWOLFSSL_USER_SETTINGS -Ipath/to/settings'`.

wolfCOSE also rejects local signing through wolfSSL dispatchers that do not
consume the key's deterministic nonce state: crypto callbacks that always
search or require callback-only ECC, STM32 PKA signing, ATECC508A/608A,
Microchip TA100, Pluton, CryptoCell, Silicon Labs SE acceleration, KCAPI,
SE050, and Cavium/Intel async ECC when the feature is enabled. A plain
crypto-callback build may use the software fallback, but a device-bound key is
rejected at runtime. The Xilinx Versal path remains permitted because wolfSSL
passes its RFC 6979-derived nonce to that hardware signer.

Without `WOLFSSL_NO_MALLOC`, wolfSSL may allocate a temporary deterministic
nonce object per signature. In an ES256-only x86_64 macOS link, deterministic
support increased text and constants by approximately 7.1 KB. The exact cost
is platform and wolfSSL-configuration dependent, which is why the feature is
off by default.

## Message Type Gates

### COSE Countersignatures

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_COUNTERSIGN` | Enable RFC 9338 countersignatures | Enabled |
| `WOLFCOSE_ENABLE_COUNTERSIGN` | Opt in under `WOLFCOSE_LEAN` | - |
| `WOLFCOSE_NO_COUNTERSIGN` | Disable countersignatures entirely | - |
| `WOLFCOSE_COUNTERSIGN_SIGN` | Enable countersignature creation | Enabled |
| `WOLFCOSE_NO_COUNTERSIGN_SIGN` | Disable countersignature creation | - |
| `WOLFCOSE_COUNTERSIGN_VERIFY` | Enable countersignature verification | Enabled |
| `WOLFCOSE_NO_COUNTERSIGN_VERIFY` | Disable countersignature verification | - |

The default full build includes countersignatures. `WOLFCOSE_LEAN` excludes
them unless `WOLFCOSE_ENABLE_COUNTERSIGN` is defined. Creation and verification
both require CBOR encoding and decoding because each operation decodes the
target message and encodes its `Countersign_structure`. Creation also requires
a signing algorithm, and verification requires a verification algorithm.

### COSE_Sign1 (Single Signer)

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_SIGN1` | Enable COSE_Sign1 message type | Enabled |
| `WOLFCOSE_NO_SIGN1` | Disable COSE_Sign1 entirely | - |
| `WOLFCOSE_SIGN1_SIGN` | Enable Sign1 creation | Enabled |
| `WOLFCOSE_NO_SIGN1_SIGN` | Disable Sign1 creation | - |
| `WOLFCOSE_SIGN1_VERIFY` | Enable Sign1 verification | Enabled |
| `WOLFCOSE_NO_SIGN1_VERIFY` | Disable Sign1 verification | - |

### COSE_Encrypt0 (Symmetric Encryption)

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_ENCRYPT0` | Enable COSE_Encrypt0 message type | Enabled |
| `WOLFCOSE_NO_ENCRYPT0` | Disable COSE_Encrypt0 entirely | - |
| `WOLFCOSE_ENCRYPT0_ENCRYPT` | Enable Encrypt0 creation | Enabled |
| `WOLFCOSE_NO_ENCRYPT0_ENCRYPT` | Disable Encrypt0 creation | - |
| `WOLFCOSE_ENCRYPT0_DECRYPT` | Enable Encrypt0 decryption | Enabled |
| `WOLFCOSE_NO_ENCRYPT0_DECRYPT` | Disable Encrypt0 decryption | - |

### COSE_Mac0 (Symmetric MAC)

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_MAC0` | Enable COSE_Mac0 message type | Enabled |
| `WOLFCOSE_NO_MAC0` | Disable COSE_Mac0 entirely | - |
| `WOLFCOSE_MAC0_CREATE` | Enable Mac0 creation | Enabled |
| `WOLFCOSE_NO_MAC0_CREATE` | Disable Mac0 creation | - |
| `WOLFCOSE_MAC0_VERIFY` | Enable Mac0 verification | Enabled |
| `WOLFCOSE_NO_MAC0_VERIFY` | Disable Mac0 verification | - |

### COSE_Sign (Multi-Signer)

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_SIGN` | Enable COSE_Sign (multi-signer) | Enabled |
| `WOLFCOSE_NO_SIGN` | Disable COSE_Sign entirely | - |
| `WOLFCOSE_SIGN_SIGN` | Enable Sign creation | Enabled |
| `WOLFCOSE_NO_SIGN_SIGN` | Disable Sign creation | - |
| `WOLFCOSE_SIGN_VERIFY` | Enable Sign verification | Enabled |
| `WOLFCOSE_NO_SIGN_VERIFY` | Disable Sign verification | - |

### COSE_Encrypt (Multi-Recipient)

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_ENCRYPT` | Enable COSE_Encrypt (multi-recipient) | Enabled |
| `WOLFCOSE_NO_ENCRYPT` | Disable COSE_Encrypt entirely | - |
| `WOLFCOSE_ENCRYPT_ENCRYPT` | Enable Encrypt creation | Enabled |
| `WOLFCOSE_NO_ENCRYPT_ENCRYPT` | Disable Encrypt creation | - |
| `WOLFCOSE_ENCRYPT_DECRYPT` | Enable Encrypt decryption | Enabled |
| `WOLFCOSE_NO_ENCRYPT_DECRYPT` | Disable Encrypt decryption | - |

### COSE_Mac (Multi-Recipient)

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_MAC` | Enable COSE_Mac (multi-recipient) | Enabled |
| `WOLFCOSE_NO_MAC` | Disable COSE_Mac entirely | - |
| `WOLFCOSE_MAC_CREATE` | Enable Mac creation | Enabled |
| `WOLFCOSE_NO_MAC_CREATE` | Disable Mac creation | - |
| `WOLFCOSE_MAC_VERIFY` | Enable Mac verification | Enabled |
| `WOLFCOSE_NO_MAC_VERIFY` | Disable Mac verification | - |

---

## Key Distribution Gates

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_NO_RECIPIENTS` | Disable all multi-recipient support (COSE_Encrypt/COSE_Mac) | - |
| `WOLFCOSE_NO_AESWRAP` | Disable AES Key Wrap (A128KW, A192KW, A256KW) | - |
| `WOLFCOSE_NO_ECDH_ES` | Disable ECDH-ES key agreement | - |
| `WOLFCOSE_ENABLE_AESWRAP` | Opt in AES Key Wrap under `WOLFCOSE_LEAN` | - |
| `WOLFCOSE_ENABLE_ECDH_ES` | Opt in ECDH-ES under `WOLFCOSE_LEAN` | - |

Resolved internally as read-only `WOLFCOSE_KEY_WRAP`, `WOLFCOSE_ECDH`, and `WOLFCOSE_ECDH_WRAP` gates. Requires the matching wolfSSL feature (`HAVE_AES_KEYWRAP`; `HAVE_ECC` + `HAVE_HKDF` for ECDH-ES) and at least one multi-recipient message type enabled. AES Key Wrap also requires wolfSSL 5.9.0 or later; older releases used a comparison whose timing behavior depended on the compiler and `XMEMCMP` configuration. Define `WOLFCOSE_NO_AESWRAP` when building the otherwise supported wolfSSL 5.8.x series.

---

## COSE-HPKE (experimental)

COSE-HPKE implements the P0 subset of
[draft-ietf-cose-hpke-26](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/).
It is deliberately disabled by default in both full and lean builds because the
COSE binding and its IANA values are still an Internet-Draft. HPKE itself is
standardized by RFC 9180, but the COSE profile is not yet an RFC.

P0 fixes every cryptographic choice: `DHKEM(P-256, HKDF-SHA256)`,
`HKDF-SHA256`, and `AES-128-GCM`, in HPKE base mode only. There are no hidden
P-384, P-521, X25519, PSK, authenticated, or alternate-AEAD paths to enable.
That keeps each enabled wire operation auditable and lets targets compile out
all unsupported suites.

P0 is intended for confidential provisioning, configuration, and credential
delivery. It can encrypt a payload directly to one recipient, or encrypt the
content once and independently protect its content-encryption key for multiple
recipients. Base mode provides recipient-only confidentiality; pair the result
with a COSE signature or MAC when the sender must be authenticated.

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_EXPERIMENTAL` | Required acknowledgement for every COSE-HPKE enable; alone enables no HPKE code | off |
| `WOLFCOSE_ENABLE_HPKE_0` | Enable both send and receive for single-recipient integrated `COSE_Encrypt0` HPKE-0 | off |
| `WOLFCOSE_ENABLE_HPKE_0_ENCRYPT` | Enable only integrated Encrypt0 send | off |
| `WOLFCOSE_ENABLE_HPKE_0_DECRYPT` | Enable only integrated Encrypt0 receive | off |
| `WOLFCOSE_ENABLE_HPKE_0_KE` | Enable both send and receive for multi-recipient `COSE_Encrypt` HPKE-0-KE | off |
| `WOLFCOSE_ENABLE_HPKE_0_KE_ENCRYPT` | Enable only multi-recipient HPKE key-encryption send | off |
| `WOLFCOSE_ENABLE_HPKE_0_KE_DECRYPT` | Enable only multi-recipient HPKE key-encryption receive | off |
| `WOLFCOSE_NO_HPKE_0` | Prohibit all HPKE-0 enables; conflicts with any HPKE-0 enable | off |
| `WOLFCOSE_NO_HPKE_0_ENCRYPT` / `WOLFCOSE_NO_HPKE_0_DECRYPT` | Compile out the corresponding integrated Encrypt0 direction | off |
| `WOLFCOSE_NO_HPKE_0_KE_ENCRYPT` / `WOLFCOSE_NO_HPKE_0_KE_DECRYPT` | Compile out the corresponding multi-recipient key-encryption direction | off |

Every HPKE `ENABLE_*` macro requires `WOLFCOSE_EXPERIMENTAL`; selecting an HPKE
operation without the acknowledgement is a compile error. The convenience
gates respect their per-direction `NO_*` gates. Defining an individual
`ENABLE_*` and its matching `NO_*` is a compile error; defining
`WOLFCOSE_NO_HPKE_0` with any enable is also a compile error.

An enabled HPKE operation requires wolfSSL `HAVE_HPKE`, `HAVE_ECC` with P-256,
SHA-256, and `HAVE_AESGCM`. Integrated mode also needs the matching
`COSE_Encrypt0` direction. Key-encryption mode additionally needs the matching
`COSE_Encrypt` direction and recipient support; under `WOLFCOSE_LEAN`, add
`WOLFCOSE_ENABLE_ENCRYPT` before enabling an HPKE-0-KE operation.

Build the wolfSSL backend with HPKE, ECC P-256, AES-GCM, SHA-256, and key
generation. For example, a cryptography-only backend can use:

```bash
./configure --enable-cryptonly --enable-hpke --enable-ecc --enable-aesgcm \
    --enable-keygen
```

The public identifiers are provisional draft values: `HPKE-0` is algorithm 35,
`HPKE-0-KE` is algorithm 46, and `ek` is header label -4. Applications must
treat them as draft values and update when the COSE-HPKE RFC or IANA registry
changes. P0 accepts only base mode: `psk_id`, a PSK, and external HPKE `info`
are intentionally not exposed. Application external AAD is still bound through
the normal COSE `Enc_structure` API argument.

For integrated mode, call `wc_CoseHpkeEncrypt0_Encrypt()` and
`wc_CoseHpkeEncrypt0_Decrypt()`. It encrypts payloads directly for one
recipient. For key-encryption mode, use `wc_CoseEncrypt_Encrypt()` and
`wc_CoseEncrypt_Decrypt()` with every `WOLFCOSE_RECIPIENT.algId` set to
`WOLFCOSE_ALG_HPKE_0_KE`; wolfCOSE generates one CEK, encrypts the content
once, and HPKE-wraps that CEK separately for every recipient. HPKE base mode
does not authenticate the sender, so add a COSE signature or MAC when sender
authentication is required.

Draft P0 permits the HPKE `alg` header parameter to be absent. The integrated
decrypt API is already pinned to HPKE-0; for key-encryption decrypt, set the
selected `WOLFCOSE_RECIPIENT.algId` to `WOLFCOSE_ALG_HPKE_0_KE` so wolfCOSE can
pin the omitted value safely. When an integrated or recipient HPKE `alg` is
present, it must be in the protected header. wolfCOSE rejects an unprotected
HPKE `alg` rather than accepting an unauthenticated key-management choice. For
HPKE-0-KE, the outer `COSE_Encrypt` content algorithm may be unprotected: the
HPKE Recipient_structure binds it as `next_layer_alg`, so a modification makes
HPKE CEK recovery fail. P0 requires the 65-byte P-256 `ek` in the unprotected
header, rejects it in the protected header, and rejects `psk_id` because PSK
mode is not implemented.

```bash
# Single-recipient integrated HPKE: send and receive.
make EXTRA_CFLAGS="-DWOLFCOSE_EXPERIMENTAL -DWOLFCOSE_ENABLE_HPKE_0"

# Receive-only provisioning target: no HPKE sender code.
make EXTRA_CFLAGS="-DWOLFCOSE_EXPERIMENTAL -DWOLFCOSE_ENABLE_HPKE_0_DECRYPT"

# Multi-recipient provisioning server, including the lean COSE_Encrypt gate.
make EXTRA_CFLAGS="-DWOLFCOSE_LEAN -DWOLFCOSE_EXPERIMENTAL -DWOLFCOSE_ENABLE_ENCRYPT \
    -DWOLFCOSE_ENABLE_HPKE_0_KE_ENCRYPT"
```

Draft -26's published Section 5.2 key-encryption sample encodes a 16-byte
`A128GCM` IV. RFC 9053 fixes the COSE AES-GCM nonce at 12 bytes, so wolfCOSE
rejects that malformed sample and requires a 12-byte IV for all COSE content
encryption.

---

## Delegated Signing

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_ENABLE_EXT_SIGN` | Opt in `wc_CoseKey_SetExtSigner()`, which delegates signing to a caller-supplied callback | off |

Off in every build unless explicitly enabled, lean or not. Resolved internally as the read-only `WOLFCOSE_EXT_SIGN` gate.

Intended for keys held outside wolfCOSE — an HSM, a secure element, or a TrustZone secure partition.

What the callback receives depends on the algorithm, and getting this wrong produces a well-formed message no verifier accepts:

| Algorithm | `tbs` holds |
|---|---|
| ES256/384/512 | the **digest** of the `Sig_structure` — sign with a sign-hash primitive (`psa_sign_hash`, `CKM_ECDSA`) and return fixed-width `r \|\| s` (RFC 9053 sec. 2.1), **not** a DER `SEQUENCE` |
| PS256/384/512 | the **digest** — sign with RSASSA-PSS, MGF1 over the same SHA-2 as the algorithm, salt length equal to the digest length (RFC 8230 sec. 2) |
| EdDSA, Ed448, ML-DSA, HSS-LMS | the **`Sig_structure` itself** — sign it with a sign-message primitive |

It returns the raw COSE signature; wolfCOSE checks the returned length against the algorithm but performs no key operation itself. No RNG is needed. HSS-LMS is stateful: the callback's own signing operation advances one-time-signature state, and the caller owns its persistence.

A delegated key needs no local *private* key, but it must declare enough for wolfCOSE to know the expected signature length: ES* and ML-DSA need nothing beyond `alg`; EdDSA needs `kty`/`crv`; PS* needs `kty` plus a local `RsaKey` attached via `wc_CoseKey_SetRsa()` for its modulus size; HSS-LMS needs an initialized `LmsKey` attached via `wc_CoseKey_SetLms()`, because its length follows the key's parameter set.

Pass a NULL callback to detach. Attaching local key material with `wc_CoseKey_SetEcc()` and friends detaches implicitly, so always call `wc_CoseKey_SetExtSigner()` last. `wc_CoseKey_Decode()` is rejected on a key that has a signer attached, rather than silently importing private material and signing locally with it.

For a key that has no local wolfCrypt object at all, set `kty` (and `crv` for EdDSA) on the `WOLFCOSE_KEY` directly before attaching the signer — there is no setter for declaring a key type without attaching one.

Two limits worth knowing before designing around this:

- It does not remove the local algorithm. `WOLFCOSE_ENABLE_EXT_SIGN` still requires an enabled wolfCOSE signing operation plus enough algorithm metadata to size the signature, so the verify-only profiles (`WOLFCOSE_LEAN_VERIFY`, `WOLFCOSE_LEAN_VERIFY_MLDSA`, `WOLFCOSE_LEAN_VERIFY_LMS`) cannot be combined with it. The wolfCrypt backend itself may lack the signing primitive: delegated HSS-LMS works against a `WOLFSSL_LMS_VERIFY_ONLY` wolfSSL, because the attached public `LmsKey` supplies the length and the callback signs. Delegating ML-DSA likewise needs local ML-DSA compiled in, which raises the `WOLFCOSE_MAX_SCRATCH_SZ` default to 8192 bytes and enforces a 4096-byte minimum.
- Scratch must hold the `Sig_structure`, which embeds the payload, and delegated signing needs at least as much again for the signature:
  - **ES\*, PS\*** pre-hash, so the signature reuses the `Sig_structure` space: `scratchSz >= max(Sig_structure, signature)`. Local ECDSA signs into a stack buffer and needs only the `Sig_structure`, so a small-payload ES256 case can need more scratch delegated than local.
  - **EdDSA, Ed448, ML-DSA, HSS-LMS** sign the structure in place, so the signature goes after it: `scratchSz >= Sig_structure + signature`. Delegated Ed25519 needs 64 bytes more than the local path, Ed448 114; HSS-LMS needs its parameter-set signature length (up to 10204 bytes for the W4 predefined sets).

---

## CBOR Layer Gates

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_CBOR_ENCODE` | Enable CBOR encoding | Enabled |
| `WOLFCOSE_NO_CBOR_ENCODE` | Disable CBOR encoding | - |
| `WOLFCOSE_CBOR_DECODE` | Enable CBOR decoding | Enabled |
| `WOLFCOSE_NO_CBOR_DECODE` | Disable CBOR decoding | - |

---

## COSE_Key Gates

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_KEY_ENCODE` | Enable COSE_Key encoding | Enabled |
| `WOLFCOSE_NO_KEY_ENCODE` | Disable COSE_Key encoding | - |
| `WOLFCOSE_KEY_DECODE` | Enable COSE_Key decoding | Enabled |
| `WOLFCOSE_NO_KEY_DECODE` | Disable COSE_Key decoding | - |

Private RSA `COSE_Key` serialization requires wolfSSL 5.9.2 or later. Define
`WOLFCOSE_RSA_PUBLIC_ONLY` to retain RSA-PSS and public-key encoding on an older
wolfSSL release.

---

## Size Configuration

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_MAX_SCRATCH_SZ` | Scratch buffer size for Sig_structure/Enc_structure | 512 (1024 with RSA-PSS countersigning) |
| `WOLFCOSE_PROTECTED_HDR_MAX` | Max protected header size | 64 |
| `WOLFCOSE_CBOR_MAX_DEPTH` | Max CBOR nesting depth | 8 |
| `WOLFCOSE_MIN_BUFFERS` | Trim the working set to the minimum that fits the enabled algorithms | - |

### `WOLFCOSE_MIN_BUFFERS`

One define that trims the caller working set to the minimum that still fits the enabled algorithms. It tightens the CBOR parsing limits (`WOLFCOSE_CBOR_MAX_DEPTH` 8→6, `WOLFCOSE_MAX_MAP_ITEMS` 16→8) and keeps the algorithm-driven signature/scratch floors, which track the largest enabled signature algorithm:

| Enabled signature algorithm | `WOLFCOSE_MAX_SIG_SZ` | `WOLFCOSE_MAX_SCRATCH_SZ` |
|---|---|---|
| ES256/384/512, EdDSA (Ed25519/Ed448) | 132 | 512 |
| RSA-PSS (PS256/384/512) | 512 | 512 (1024 with countersigning) |
| ML-DSA-44/65/87 | 4627 | 8192 |
| HSS-LMS | 10240 | 11264 |

Because the floor follows the algorithm, `WOLFCOSE_MIN_BUFFERS` stays valid with any algorithm — ML-DSA, HSS-LMS, and RSA-PSS simply use that algorithm's floor rather than the ECC floor. HSS-LMS uses the largest default floors because its signature size follows the key's parameter set rather than a fixed constant: the `WOLFCOSE_MAX_SIG_SZ` default of 10240 and `WOLFCOSE_MAX_SCRATCH_SZ` default of 11264 (scratch also holds the `Sig_structure`) cover every W4 and W8 predefined set, the largest being L4_H10_W4 at 10204 bytes. The low-Winternitz (W1/W2) multi-level sets reach 18012 bytes and need a `-D` override; a key whose signature exceeds these buffers is rejected via `wc_LmsKey_GetSigLen()` before any signing, so no one-time state is consumed. It stays zero-heap and shrinks buffers, not stack frames. An explicit `-D` override of any individual limit takes precedence.

**Countersignature sizing.** Countersigning builds the `Countersign_structure` and then keeps the signature after it in scratch, so `WOLFCOSE_MAX_SCRATCH_SZ` must be at least `WOLFCOSE_MAX_SIG_SZ` + 256. The RSA-PSS default therefore rises to 1024 (a 4096-bit signature is 512 bytes) only when countersignature creation is enabled; RSA-PSS builds without it keep 512. An override below the floor is a build error.

---

## Tuning for Size

Four levers, smallest impact last. See the [[Footprint]] page for the resulting numbers.

1. **Pick a build profile.** `WOLFCOSE_LEAN` is the lean ES256 core (6.8 KB glue); `WOLFCOSE_LEAN_VERIFY` is verify-only (5.1 KB); the ML-DSA profiles are post-quantum (see [Build Profiles](#build-profiles)). One define selects a curated gate set.
2. **Drop individual features** with `WOLFCOSE_NO_<X>` (e.g. `WOLFCOSE_NO_ENCRYPT0`, `WOLFCOSE_NO_SIGN`, `WOLFCOSE_NO_RECIPIENTS`), or in a lean build add only what you need with `WOLFCOSE_ENABLE_<X>`.
3. **`WOLFCOSE_MIN_BUFFERS`** trims the caller working set to the floor for the enabled algorithms (see above).
4. **Override individual limits** if you know your payload bounds:

```c
/* In your user_settings.h or build flags: */
#define WOLFCOSE_MAX_SCRATCH_SZ     256   /* default 512 */
#define WOLFCOSE_PROTECTED_HDR_MAX  32    /* default 64  */
#define WOLFCOSE_CBOR_MAX_DEPTH     4     /* default 8   */
```

**Post-quantum sizing.** The post-quantum signatures drive the largest floors; they auto-scale (ML-DSA-87: `WOLFCOSE_MAX_SIG_SZ` 4627, `WOLFCOSE_MAX_SCRATCH_SZ` 8192; HSS-LMS: `WOLFCOSE_MAX_SIG_SZ` 10240, `WOLFCOSE_MAX_SCRATCH_SZ` 11264, since its size follows the key's parameter set). `WOLFCOSE_LEAN_VERIFY_MLDSA` is the smallest secure PQ build at 20.8 KB total, smaller than classical ES256 verify-only. Always build the application with `-ffunction-sections -fdata-sections -Wl,--gc-sections` so only the COSE functions you call are linked.

## Tuning for Speed

The wolfCOSE layer is thin and allocation-free; end-to-end `COSE_Sign1` time is dominated by the wolfCrypt backend. Tuning speed (and the backend's own size) is a wolfSSL build concern; see the
[wolfSSL Tuning Guide](https://www.wolfssl.com/documentation/manuals/wolfssl-tuning-guide/index.html)
and the [wolfSSL Manual](https://www.wolfssl.com/documentation/manuals/wolfssl/)
for the assembly and math options that drive throughput (e.g. `--enable-sp-asm` / `WOLFSSL_SP_ARM_CORTEX_M_ASM` for P-256, `--enable-aesni`) and for size (`WOLFSSL_SP_SMALL`, `WOLFSSL_AES_SMALL_TABLES`).

---

## Build Profiles

Convenience macros that select a curated set of feature gates for a common deployment, so you do not list each `WOLFCOSE_NO_*` by hand. Each builds on `WOLFCOSE_LEAN` (core-only base) and sets each gate only if you have not already chosen it.

### Footprint

What each profile costs (code + rodata, ES256/ML-DSA-44 `COSE_Sign1`, built from source with dead-code elimination). *Glue* is the wolfCOSE COSE + CBOR engine alone; *total* adds the minimal wolfCrypt backend. Full cross-library and on-device numbers are on the [[Footprint]] page.

| Profile | Algorithm | wolfCOSE glue | Total + wolfCrypt |
|---------|-----------|---------------|-------------------|
| `WOLFCOSE_LEAN` | ES256 sign + verify | 6.8 KB | 34.6 KB |
| `WOLFCOSE_LEAN_VERIFY` | ES256 verify-only | 5.1 KB | 26.2 KB |
| `WOLFCOSE_LEAN_MLDSA` | ML-DSA-44 sign + verify | 6.6 KB | 35.8 KB |
| `WOLFCOSE_LEAN_VERIFY_MLDSA` | ML-DSA-44 verify-only | 4.6 KB | 20.8 KB |

Post-quantum sign + verify is within ~1 KB of classical ES256 (35.8 vs 34.6 KB), and PQ verify-only is actually *smaller* than classical ES256 verify-only (20.8 vs 26.2 KB): ML-DSA skips the DER signature conversion ECDSA needs. Full numbers (desktop, on-device, and speed) are on the [[Footprint]] page.

### `WOLFCOSE_LEAN_VERIFY` — minimal verify-only

The smallest secure on-device profile: COSE_Sign1 verification only, the common case where a device verifies signed firmware or attestation while signing happens off-device on a server or HSM. It implies `WOLFCOSE_LEAN` plus `WOLFCOSE_NO_SIGN1_SIGN` (removing signing and, transitively, the RNG), `WOLFCOSE_NO_ENCRYPT0`, `WOLFCOSE_NO_MAC0`, `WOLFCOSE_NO_MAC0_CREATE`, `WOLFCOSE_NO_KEY_ENCODE`, and `WOLFCOSE_NO_KEY_DECODE`. An explicit `WOLFCOSE_ENABLE_EAT_PSA_MAC0` selection retains Mac0 verification but not creation, so a verify-only full RFC 9783 `#tfm` receiver can opt in. Full RFC 9052 verification stays: header decode, crit enforcement, duplicate-label detection, and the Sig_structure rebuild. Sign1 verify must stay enabled; the build errors out if it is also disabled.

```bash
make lean-verify     # builds + runs examples/sign1_verify_lean.c with the profile
# or directly:
cc -DWOLFCOSE_LEAN_VERIFY ... src/*.c
```

### `WOLFCOSE_LEAN_MLDSA` — lean post-quantum sign + verify

A lean ML-DSA-only (FIPS 204) COSE_Sign1 **sign and verify** profile. It implies `WOLFCOSE_LEAN` plus `WOLFCOSE_ENABLE_MLDSA` (ML-DSA is an extension, off under `WOLFCOSE_LEAN`), `WOLFCOSE_NO_ES256` (PQ-only, so the ECDSA path compiles out), `WOLFCOSE_NO_ENCRYPT0`, `WOLFCOSE_NO_MAC0`, `WOLFCOSE_NO_KEY_ENCODE`, and `WOLFCOSE_NO_KEY_DECODE`, keeping **both** Sign1 sign and verify. Pair it with a wolfCrypt backend built with ML-DSA (`--enable-dilithium`).

```bash
make mldsa-demo      # builds + runs examples/sign1_mldsa.c (sign + verify)
# or directly:
cc -DWOLFCOSE_LEAN_MLDSA ... src/*.c
```

### `WOLFCOSE_LEAN_VERIFY_MLDSA` — minimal post-quantum verify-only

The smallest secure on-device PQ build: ML-DSA COSE_Sign1 **verify only**. It implies `WOLFCOSE_LEAN_MLDSA` plus `WOLFCOSE_NO_SIGN1_SIGN`, so signing and the RNG it needs are not compiled in, while full RFC 9052 verification stays intact. Pair with a wolfCrypt build that enables ML-DSA **verify** only (e.g. `WOLFSSL_DILITHIUM_VERIFY_ONLY`).

```bash
make mldsa-verify    # builds + runs examples/sign1_verify_mldsa.c with the profile
# or directly:
cc -DWOLFCOSE_LEAN_VERIFY_MLDSA ... src/*.c
```

### `WOLFCOSE_LEAN_LMS` — lean stateful hash-based sign + verify

A lean HSS/LMS-only (RFC 8778, SP 800-208) COSE_Sign1 **sign and verify** profile with the same implied gate set as `WOLFCOSE_LEAN_MLDSA` (`WOLFCOSE_LEAN`, `WOLFCOSE_ENABLE_LMS`, `WOLFCOSE_NO_ES256`, no Encrypt0/Mac0/key codec). LMS signing is stateful: signing advances one-time-signature state inside wolfCrypt, and the caller installs the wolfCrypt private-key read/write callbacks that persist it. wolfCOSE stores no state itself and defines no persistence policy. Pair with a wolfCrypt backend built with LMS (`--enable-lms`).

```bash
make lms-demo        # builds + runs examples/sign1_lms.c with the profile
```

### `WOLFCOSE_LEAN_VERIFY_LMS` — minimal hash-based verify-only

HSS/LMS COSE_Sign1 **verify only**: implies `WOLFCOSE_LEAN_LMS` plus `WOLFCOSE_NO_SIGN1_SIGN`. Verification is hash operations only (no big-integer or lattice math), so this pairs naturally with a wolfCrypt LMS verify-only build (`WOLFSSL_LMS_VERIFY_ONLY`), the CNSA 2.0 firmware-verification shape. The signature length follows the key's levels/height/Winternitz parameter set, so the `WOLFCOSE_MAX_SIG_SZ` default rises to 10240 and `WOLFCOSE_MAX_SCRATCH_SZ` to 11264, covering every W4/W8 predefined set; the low-Winternitz (W1/W2) multi-level sets need a `-D` override.

```bash
make lms-verify      # builds + runs examples/sign1_verify_lms.c with the profile
```

## Example Build Configurations

### Sign-Only Build (Minimal)

```bash
make CFLAGS="-DWOLFCOSE_NO_ENCRYPT0 -DWOLFCOSE_NO_MAC0 -DWOLFCOSE_NO_ENCRYPT -DWOLFCOSE_NO_MAC"
```

### Verify-Only Build

```bash
make CFLAGS="-DWOLFCOSE_NO_SIGN1_SIGN -DWOLFCOSE_NO_ENCRYPT0_ENCRYPT -DWOLFCOSE_NO_MAC0_CREATE"
```

### Sign1-Only Build (Smallest)

```bash
make CFLAGS="-DWOLFCOSE_NO_ENCRYPT0 -DWOLFCOSE_NO_MAC0 -DWOLFCOSE_NO_SIGN -DWOLFCOSE_NO_ENCRYPT -DWOLFCOSE_NO_MAC"
```

### No Multi-Recipient Support

```bash
make CFLAGS="-DWOLFCOSE_NO_RECIPIENTS"
```

---

## wolfSSL Dependencies

wolfCOSE requires these wolfSSL features for full functionality:

| wolfSSL Define | wolfCOSE Feature |
|----------------|------------------|
| `HAVE_ECC` | ECDSA signing (ES256/ES384/ES512), ECDH key agreement |
| `WOLFSSL_ECDSA_DETERMINISTIC_K` or `WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT` | Optional deterministic local ECDSA signing |
| `HAVE_ED25519` | EdDSA signing (Ed25519) |
| `HAVE_ED448` | EdDSA signing (Ed448) |
| `WOLFSSL_HAVE_MLDSA` | ML-DSA post-quantum signing |
| `WC_RSA_PSS` | RSA-PSS signing (PS256/PS384/PS512) |
| `HAVE_AESGCM` | AES-GCM encryption |
| `HAVE_AESCCM` | AES-CCM encryption |
| `HAVE_CHACHA && HAVE_POLY1305` | ChaCha20-Poly1305 encryption |
| `HAVE_AES_CBC` | AES-CBC-MAC |
| `NO_HMAC` (NOT defined) | HMAC algorithms |
| `WOLFSSL_SHA384` | SHA-384 for ES384, HMAC-384 |
| `WOLFSSL_SHA512` | SHA-512 for ES512, HMAC-512 |
| `HAVE_AES_KEYWRAP` | AES Key Wrap distribution |
| `HAVE_HKDF` | ECDH-ES key derivation |
| `HAVE_HPKE` + `HAVE_ECC` P-256 + SHA-256 + `HAVE_AESGCM` | Experimental COSE-HPKE P0 |

---

## Test and Example Gates

### Comprehensive Test Gates

Each comprehensive test file can be disabled:

| Define | Description |
|--------|-------------|
| `WOLFCOSE_NO_EXAMPLE_SIGN_ALL` | Disable sign_all.c |
| `WOLFCOSE_NO_EXAMPLE_ENCRYPT_ALL` | Disable encrypt_all.c |
| `WOLFCOSE_NO_EXAMPLE_MAC_ALL` | Disable mac_all.c |
| `WOLFCOSE_NO_EXAMPLE_ERRORS_ALL` | Disable errors_all.c |

Sub-gates within tests:

| Define | Description |
|--------|-------------|
| `WOLFCOSE_NO_SIGN_ALL_ES256` | Skip ES256 tests in sign_all |
| `WOLFCOSE_NO_SIGN_ALL_MULTI` | Skip multi-signer tests |
| `WOLFCOSE_NO_ENCRYPT_ALL_A128GCM` | Skip A128GCM tests |
| `WOLFCOSE_NO_MAC_ALL_HMAC256` | Skip HMAC-256 tests |

### Scenario Example Gates

| Define | Description |
|--------|-------------|
| `WOLFCOSE_NO_EXAMPLE_FIRMWARE_UPDATE` | Disable firmware_update.c |
| `WOLFCOSE_NO_EXAMPLE_MULTI_PARTY` | Disable multi_party_approval.c |
| `WOLFCOSE_NO_EXAMPLE_IOT_FLEET` | Disable iot_fleet_config.c |
| `WOLFCOSE_NO_EXAMPLE_SENSOR_ATTEST` | Disable sensor_attestation.c |
| `WOLFCOSE_NO_EXAMPLE_GROUP_BROADCAST` | Disable group_broadcast_mac.c |

---

## See Also

- [[Getting Started]]: Build instructions
- [[Algorithms]]: Supported algorithms with guards
- [[Testing]]: Test configuration
