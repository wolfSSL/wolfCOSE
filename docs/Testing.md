# Testing

wolfCOSE includes comprehensive testing infrastructure for unit tests, algorithm coverage, code coverage, and failure injection testing. Code coverage is enforced by CI: `wolfcose.c` requires 99% minimum and `wolfcose_cbor.c` requires 100%. These thresholds are validated on every push and PR to ensure coverage doesn't regress. 

## Running Tests

### Basic Unit Tests

```bash
make test
```

This runs the full test suite including:
- CBOR encoding/decoding tests (RFC 8949 Appendix A vectors)
- COSE Sign1/Encrypt0/Mac0 tests
- COSE Sign/Encrypt/Mac multi-party tests
- Interoperability tests with COSE Working Group vectors

### CLI Tool Tests

```bash
make tool-test
```

Round-trip self-tests for all 17 supported CLI algorithms. Each algorithm is tested with key generation, operation, and verification.

### Comprehensive Algorithm Tests

```bash
make comprehensive
```

Runs ~240 algorithm combination tests covering:
- All signature algorithms with various payloads
- All encryption algorithms with various key sizes
- All MAC algorithms
- Multi-signer and multi-recipient combinations
- Error handling and edge cases

### Scenario Examples

```bash
make scenarios
```

Runs real-world scenario examples:
- Firmware signing with ML-DSA
- Multi-party approval workflows
- IoT fleet configuration
- Sensor attestation
- Group broadcast MAC

### Interoperability (t_cose)

```bash
make interop-tcose \
  TCOSE_DIR=/path/to/t_cose QCBOR_DIR=/path/to/QCBOR \
  TCOSE_CRYPTO_LIB="-lcrypto"
```

Proves RFC 9052 wire interoperability between wolfCOSE (on wolfCrypt) and
[t_cose](https://github.com/laurencelundblade/t_cose) (on OpenSSL): each library
produces COSE messages the other consumes, both directions, across every
algorithm both implement — ES256/384/512, PS256/384/512, EdDSA (Ed25519, Ed448),
HMAC 256/384/512, and AES-GCM 128/192/256. The bytes on the wire are the only
interface; the two APIs are never reconciled. Each primitive class also exercises
a tamper case that wolfCOSE must reject.

t_cose and QCBOR are BSD-3-Clause and are not vendored; the
[Interop CI job](../.github/workflows/interop.yml) fetches them at pinned
SHAs. See `tests/interop/t_cose/README.md` for the fixed test-key provenance.

### Complete upstream t_cose suite

```bash
make tcose-upstream \
  TCOSE_DIR=/path/to/t_cose QCBOR_DIR=/path/to/QCBOR
```

This runs the entire pinned upstream t_cose suite, including its API-level and
QCBOR-adapter tests. At the current pinned revision it runs 43 tests. It is a
dependency-health gate, not wolfCOSE API coverage: t_cose's internal API tests
cannot be redirected to wolfCOSE. Use `interop-tcose` for wolfCOSE wire-format
compatibility.

### Interoperability (go-cose)

```bash
make interop-go-cose
```

This runs live, bidirectional `COSE_Sign1` interop against
[Veraison go-cose](https://github.com/veraison/go-cose), pinned at v1.3.0 in
`tests/interop/go_cose/go.mod`. The matrix covers ES256, ES384, ES512, PS256,
PS384, PS512, Ed25519, ES256 with external AAD, and untagged ES256. Each
implementation signs a message the other verifies, validates the payload, and
rejects a modified signature. Go 1.21 or later is required. go-cose requires
an embedded payload for Sign1 verification, so detached Sign1 remains covered
by the wolfCOSE tests and `interop-tcose`. go-cose's scope makes it a Sign and
Sign1 oracle; `interop-tcose` remains the broader Mac0 and Encrypt0 wire
suite. The target also verifies RFC 9783's ES256 PSA token and decodes its
standard EAT claims with Go CBOR.

### Interoperability (python-cwt)

```bash
python3 -m pip install -r tests/interop/python_cwt/requirements.txt
make interop-python-cwt
```

This runs live recipient-message interop against
[python-cwt](https://github.com/ritou/cwt), pinned at 3.3.0 with all Python
dependencies locked in `requirements.txt`. It exchanges A128GCM direct
`COSE_Encrypt`, ECDH-ES plus HKDF-SHA-256 `COSE_Encrypt`, and HMAC-256 direct
`COSE_Mac` messages in both directions. Each message carries external AAD,
checks its payload, and must reject a modified authenticated byte. The target
also verifies RFC 9783's ES256 PSA token and decodes selected EAT claims with
python-cwt and `cbor2`.

python-cwt's A128KW producer is verified by wolfCOSE. Its 3.3.0 decoder rejects
the standards-compliant protected recipient algorithm that wolfCOSE emits for
A128KW, so the reverse direction is deliberately kept in the fixed COSE WG
Examples vector suite instead of changing wolfCOSE's output.

### Interoperability (Rust coset)

```bash
make interop-rust-coset
```

This runs live, bidirectional `COSE_Sign1` interop against
[Google coset](https://github.com/google/coset), pinned at 0.4.2 in
`tests/interop/rust_coset/Cargo.lock`, using RustCrypto for signature
operations. It covers ES256, Ed25519, ES256 with external AAD, untagged ES256,
and detached ES256. Both peers validate the protected algorithm and payload
semantics, then reject a modified signature. Rust 1.81 or later is required.

### COSE WG Examples vectors

`make test` includes a curated, fixed subset from the
[COSE WG Examples repository](https://github.com/cose-wg/Examples), pinned at
commit `53c9d634333bb4f529d78f5980fffa2667ee2c12`. It verifies ES256
`COSE_Sign1` and `COSE_Sign`, HMAC-256 `COSE_Mac0`, A128GCM `COSE_Encrypt0`,
and multi-recipient A128GCM direct, A128KW, and ECDH-ES `COSE_Encrypt` vectors.
Every selected vector checks its cleartext and rejects a modified authentication
value. The selected Mac0 vectors carry `alg` only in an unprotected header, so
the test pins the expected algorithm on the local key instead of accepting an
unconstrained algorithm from the message.

### PSA attestation-token acceptance

`make test` includes fixed acceptance vectors from RFC 9783 Appendix A. The
tests verify ES256 `COSE_Sign1` and HMAC-256 `COSE_Mac0` PSA attestation tokens,
reject a modified authentication value, and decode the EAT/PSA claim payload
with wolfCOSE CBOR APIs.

---

## Code Coverage

### Running Coverage

```bash
make coverage
```

This compiles with gcov instrumentation and runs tests, producing coverage reports.

### Coverage Targets

| Component | Target |
|-----------|--------|
| `wolfcose.c` | 99% minimum |
| `wolfcose_cbor.c` | 100% minimum |

### Coverage with Failure Injection

```bash
make coverage-force-failure
```

This enables additional coverage by testing error paths that normally require wolfCrypt internal failures.

---

## Force Failure Testing

wolfCOSE includes a failure injection system for testing error paths that are difficult to reach through normal testing.

The `WOLFCOSE_FORCE_FAILURE` build flag enables controlled injection of failures at specific points in the code. This allows testing of:

- Crypto operation failures (signature, encryption, decryption, MAC)
- Key operation failures
- Memory/buffer errors
- Internal state errors

### Production Builds

The force failure system compiles out completely in production builds. When `WOLFCOSE_FORCE_FAILURE` is not defined:

- All failure injection code is excluded
- `wolfForceFailure_Check()` always returns 0
- No runtime overhead

---

## CI Pipeline

wolfCOSE runs the following CI checks on every push and pull request:

### Build and Test Matrix

| Environment | Compilers |
|-------------|-----------|
| Ubuntu (latest + 22.04) | GCC 10, 11, 12, 13, 14 |
| Ubuntu (latest + 22.04) | Clang 14, 15, 16, 17, 18 |
| macOS | Xcode default |

### Test Stages

1. **Build**: Compile library and tests
2. **Unit Tests**: Run CBOR and COSE test suites
3. **Comprehensive Tests**: ~240 algorithm combination tests
4. **Scenario Examples**: Real-world workflow tests
5. **Tool Tests**: CLI round-trip tests (17 algorithms)

The Interop workflow intentionally keeps t_cose, go-cose, python-cwt, Rust
coset, and the complete upstream t_cose suite in one matrix job per wolfSSL
version. They share the same wolfSSL build; separate jobs would only duplicate
that setup without providing useful parallelism.

### Memory and Stack Bounds

wolfCOSE is zero-heap (no `malloc`/`XMALLOC` on any path) and bounded-stack, both enforced in CI:

- **Bounded stack**: built with `-fstack-usage`, then `scripts/check_stack_usage.sh` fails the build if any wolfCOSE frame exceeds 6144 bytes or is `dynamic` (unbounded); `-Werror=vla` bans VLAs/`alloca`.
- **Zero heap**: sources, tests, tools, and examples are grepped for allocator calls.
- **`WOLFCOSE_MIN_BUFFERS`**: constrained-target profile that shrinks the caller working buffers (not the library frames) — see [[Macros]].
- **Minimal Build matrix**: builds and tests against single-purpose minimal wolfCrypt configs (ECC-only, EdDSA-only, AEAD-only, MAC-only, …) plus a `WOLFCOSE_LEAN` core build.

### Lean and Post-Quantum Builds

The Lean Build workflow (`.github/workflows/lean-build.yml`) exercises the minimal
on-device build profiles:

| Job | What it checks |
|-----|----------------|
| Lean verify-only | Builds + runs `examples/sign1_verify_lean.c` with `WOLFCOSE_LEAN_VERIFY` against a minimal ECC-only wolfSSL; asserts the signing API is not linked. |
| Lean configs compile clean | Strict `-Werror` compile of the full, `WOLFCOSE_LEAN_VERIFY`, sign-only, `WOLFCOSE_LEAN_MLDSA`, and `WOLFCOSE_LEAN_VERIFY_MLDSA` configurations. |
| Post-quantum ML-DSA | Builds wolfSSL with ML-DSA and runs `make mldsa-demo` (sign+verify) and `make mldsa-verify` (verify-only); asserts the verify-only build links no signing API. |

### Static Analysis

| Tool | Purpose |
|------|---------|
| cppcheck | Static code analysis |
| Clang Static Analyzer | Data flow analysis |
| GCC `-fanalyzer` | GCC's built-in analyzer |
| Advanced Internal Static Analysis | Security Audit |
| In PR Opus 4.6 Diff review with wolfSSL internal review bot | Security Audit |

### Coverity Scan

Nightly defect analysis via [Coverity Scan](https://scan.coverity.com/projects/wolfcose).

[![Coverity Scan Build Status](https://scan.coverity.com/projects/32918/badge.svg)](https://scan.coverity.com/projects/wolfcose)

---

## Test File Structure

```
tests/
  test_cbor.c        # CBOR vectors (RFC 8949 Appendix A) + round-trip
  test_cose.c        # COSE Sign1/Encrypt0/Mac0/Sign/Encrypt/Mac tests
  test_interop.c     # Interoperability tests with RFC vectors
  test_main.c        # Test harness (CI exit codes)
  force_failure.c    # Failure injection implementation
  force_failure.h    # Failure injection API
  vectors/           # Test vectors from COSE Working Group
```

### Test Categories in test_cose.c

| Category | Description |
|----------|-------------|
| Sign1 Tests | Single-signer signature creation and verification |
| Encrypt0 Tests | Symmetric encryption and decryption |
| Mac0 Tests | Symmetric MAC creation and verification |
| Sign Tests | Multi-signer messages |
| Encrypt Tests | Multi-recipient encryption |
| Mac Tests | Multi-recipient MAC |
| Key Tests | COSE_Key encoding and decoding |
| Error Tests | Invalid inputs, tampered messages |
| Detached Payload Tests | Messages with external payloads |
| External AAD Tests | Additional authenticated data |

---

## Test Vectors

The `tests/vectors/` directory contains test vectors from:
- COSE Working Group examples
- RFC 9052 examples
- Custom edge case vectors

Vector format is typically CBOR diagnostic notation or hex dumps with expected outputs.

---

## See Also

- [[Getting Started]]: Build instructions
- [[Macros]]: Test configuration macros
- [[Project Structure]]: Source file layout
