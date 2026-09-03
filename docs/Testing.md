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

### Experimental COSE-HPKE Tests

COSE-HPKE P0 is off by default and therefore has a dedicated opt-in test path.
Build against a wolfSSL configured with `--enable-hpke --enable-ecc
--enable-aesgcm --enable-keygen`, then acknowledge experimental draft support
and enable the four operation macros:

```bash
HPKE_FLAGS="-DWOLFCOSE_EXPERIMENTAL \
  -DWOLFCOSE_ENABLE_HPKE_0_ENCRYPT \
  -DWOLFCOSE_ENABLE_HPKE_0_DECRYPT \
  -DWOLFCOSE_ENABLE_HPKE_0_KE_ENCRYPT \
  -DWOLFCOSE_ENABLE_HPKE_0_KE_DECRYPT"

make test EXTRA_CFLAGS="$HPKE_FLAGS"
make hpke-demo EXTRA_CFLAGS="$HPKE_FLAGS"
make c99-hpke-check WOLFSSL_INC=/path/to/hpke-enabled-wolfssl/include
EXPECT_HPKE=true make cmdline-test EXTRA_CFLAGS="$HPKE_FLAGS"
```

The command-line test performs public/private key export, rejects identical,
normalized-alias, case-alias (where the filesystem supports it), and
symlink-alias key destinations, preserves existing POSIX destinations, and
rejects a failed paired key export without leaving a private-key file. It
rejects a plaintext one byte above the configured maximum for both
constructions, exercises HPKE-0 integrated
encryption, two-recipient HPKE-0-KE encryption and decryption at both
recipient indices, maximum-message round trips for both constructions, and a
focused `test -a` round trip for each construction. The dedicated strict C99
target compiles every HPKE-gated library, test, tool, and example path under
each one-way operation gate, both convenience gates, the complete P0
configuration, and wolfSSL's `NO_ECC256` plus `HAVE_ALL_CURVES` configuration.
Every enabled configuration also supplies `WOLFCOSE_EXPERIMENTAL`; the regular
`make experimental-check` target verifies that an HPKE operation selected
without that acknowledgement is rejected at compile time.
The unit suite validates draft messages that omit the optional HPKE `alg`
(including a second selected recipient), rejects an HPKE `alg` in an
unprotected header, accepts an unprotected HPKE-0-KE content algorithm only
when its authenticated Recipient_structure binds it, and rejects a modified
content algorithm. The CI backend enables Koblitz curves to prove that a
32-byte secp256k1 key cannot masquerade as P-256 at the HPKE API boundary. It
also covers missing, duplicate, wrong-type, wrong-length, and wrongly placed
`ek`, prohibited `psk_id`, detached ciphertext, and cleared outputs on failed
decrypts and encrypts.
GitHub Actions runs the same coverage in
[Experimental COSE-HPKE](../.github/workflows/cose-hpke.yml).

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
6. **Experimental COSE-HPKE**: Opt-in P0 unit tests, example, CLI commands,
   and both construction-specific self-tests

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
