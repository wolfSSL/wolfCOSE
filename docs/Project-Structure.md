# Project Structure

This page describes the source code layout and file organization of wolfCOSE.

## Directory Layout

```
wolfCOSE/
├── include/
│   └── wolfcose/
│       ├── wolfcose.h         # Public API (types, constants, all functions)
│       └── visibility.h       # WOLFCOSE_API export macros
├── src/
│   ├── wolfcose_cbor.c        # CBOR encoder/decoder (no wolfCrypt dependency)
│   ├── wolfcose_util.c        # Zeroization, rollback, constant-time compare
│   ├── wolfcose_alg.c         # Algorithm dispatch (hash/AEAD/HMAC/RSA-PSS)
│   ├── wolfcose_ecc.c         # ECC DER <-> raw r||s conversion
│   ├── wolfcose_hdr.c         # Protected/unprotected header codec
│   ├── wolfcose_key.c         # COSE_Key encode/decode + key attachment
│   ├── wolfcose_struct.c      # Sig/MAC/Enc structure builders
│   ├── wolfcose_recipient.c   # Key wrap + ECDH-ES key agreement
│   ├── wolfcose_sign1.c       # COSE_Sign1
│   ├── wolfcose_sign.c        # COSE_Sign (multi-signer)
│   ├── wolfcose_encrypt0.c    # COSE_Encrypt0
│   ├── wolfcose_mac0.c        # COSE_Mac0
│   ├── wolfcose_encrypt.c     # COSE_Encrypt (multi-recipient)
│   ├── wolfcose_mac.c         # COSE_Mac (multi-recipient)
│   └── wolfcose_internal.h    # Internal shared declarations
├── tests/
│   ├── test_cbor.c            # CBOR unit tests
│   ├── test_cose.c            # COSE unit tests
│   ├── test_interop.c         # Interoperability tests
│   ├── test_main.c            # Test harness
│   ├── force_failure.c        # Failure injection
│   ├── force_failure.h        # Failure injection API
│   └── vectors/               # Test vectors
├── tools/
│   └── wolfcose_tool.c        # CLI tool
├── examples/
│   ├── sign1_demo.c           # Sign1 algorithm demo
│   ├── encrypt0_demo.c        # Encrypt0 algorithm demo
│   ├── mac0_demo.c            # Mac0 algorithm demo
│   ├── lifecycle_demo.c       # Edge-to-cloud demo
│   ├── comprehensive/         # Algorithm matrix tests
│   │   ├── sign_all.c
│   │   ├── encrypt_all.c
│   │   ├── mac_all.c
│   │   └── errors_all.c
│   └── scenarios/             # Real-world scenarios
│       ├── firmware_update.c
│       ├── multi_party_approval.c
│       ├── iot_fleet_config.c
│       ├── sensor_attestation.c
│       └── group_broadcast_mac.c
├── Makefile
└── README.md
```

---

## Core Library Files

### include/wolfcose/wolfcose.h

The public API header. Contains:
- All type definitions (`WOLFCOSE_KEY`, `WOLFCOSE_HDR`, etc.)
- Algorithm constants (`WOLFCOSE_ALG_ES256`, etc.)
- Key type and curve constants
- COSE tag values
- Error codes
- All function declarations

### include/wolfcose/visibility.h

Export macros for shared library builds:
- `WOLFCOSE_API` for public functions
- Platform-specific visibility attributes

### COSE message modules (src/wolfcose_*.c)

The COSE implementation (RFC 9052/9053) is split into cohesive modules, one
per functional area:

| File | Contents |
|------|----------|
| `wolfcose_util.c` | Secure zeroization, key-import rollback, constant-time compare, RFC 9052 context strings |
| `wolfcose_alg.c` | Algorithm dispatch: hash/signature/curve mapping, AEAD and HMAC parameters, RSA-PSS key checks |
| `wolfcose_ecc.c` | ECC DER <-> raw r||s signature conversion |
| `wolfcose_hdr.c` | Protected/unprotected header encode and decode |
| `wolfcose_key.c` | COSE_Key encode/decode and wolfCrypt key attachment |
| `wolfcose_struct.c` | Unified Sig_structure/MAC_structure/Enc_structure builders |
| `wolfcose_recipient.c` | AES key wrap and ECDH-ES key agreement for multi-recipient messages |
| `wolfcose_sign1.c` | COSE_Sign1 sign and verify |
| `wolfcose_sign.c` | COSE_Sign multi-signer sign and verify |
| `wolfcose_encrypt0.c` | COSE_Encrypt0 encrypt and decrypt |
| `wolfcose_mac0.c` | COSE_Mac0 create and verify |
| `wolfcose_encrypt.c` | COSE_Encrypt multi-recipient encrypt and decrypt |
| `wolfcose_mac.c` | COSE_Mac multi-recipient create and verify |

These files depend on wolfCrypt for all cryptographic operations.

### src/wolfcose_cbor.c

CBOR encoder/decoder (RFC 8949). Contains:
- Major type encoding/decoding
- Integer, byte string, text string handling
- Array and map handling
- Tag encoding/decoding
- Skip functionality for unknown items
- Zero-copy decoding (pointers into input buffer)

This file has no wolfCrypt dependency. CBOR-only projects can link just `wolfcose_cbor.o`.

### src/wolfcose_internal.h

Internal helpers not exposed in public API:
- Big-endian macros for CBOR encoding
- Protected header codec
- AEAD algorithm dispatch tables
- Internal constants

---

## Build Outputs

| File | Description |
|------|-------------|
| `libwolfcose.a` | Static library |
| `libwolfcose.so` | Shared library (with `make shared`) |
| `tests/test_wolfcose` | Test executable |
| `tools/wolfcose_tool` | CLI tool executable |

The core library is one object file per source module. `wolfcose_cbor.o` is
the only object with no wolfCrypt dependency; with `-ffunction-sections` and
`--gc-sections` the linker keeps only what the application uses.

---

## Test Files

### tests/test_cbor.c

CBOR unit tests covering:
- RFC 8949 Appendix A encoding vectors
- Decoding tests for all major types
- Round-trip encode/decode tests
- Nested structure tests
- Skip functionality tests
- Error case handling

### tests/test_cose.c

COSE unit tests covering:
- All six message types (Sign1, Sign, Encrypt0, Encrypt, Mac0, Mac)
- All supported algorithms
- Detached payload mode
- External AAD
- Multi-signer and multi-recipient messages
- Error handling (tampered messages, wrong keys, etc.)

### tests/test_interop.c

Interoperability tests with:
- COSE Working Group test vectors
- RFC examples
- Cross-implementation compatibility

### tests/test_main.c

Test harness that:
- Initializes wolfCrypt
- Runs all test suites
- Reports pass/fail with CI-compatible exit codes

### tests/force_failure.c / force_failure.h

Failure injection system for coverage testing. See [[Testing]] for details.

---

## CLI Tool

### tools/wolfcose_tool.c

Command-line interface providing:
- Key generation for all algorithm types
- Sign and verify operations
- Encrypt and decrypt operations
- MAC create and verify operations
- COSE message inspection (info command)
- Self-test functionality

Supported commands:
```
keygen   - Generate a new key
sign     - Create COSE_Sign1 message
verify   - Verify COSE_Sign1 message
enc      - Create COSE_Encrypt0 message
dec      - Decrypt COSE_Encrypt0 message
mac      - Create COSE_Mac0 message
macverify - Verify COSE_Mac0 message
info     - Display COSE message structure
test     - Run self-tests
```

---

## Examples

### Basic Demos

| File | Description |
|------|-------------|
| `sign1_demo.c` | Demonstrates all Sign1 algorithms (ES256, ES384, ES512, EdDSA, PS256/384/512, ML-DSA) |
| `encrypt0_demo.c` | Demonstrates all Encrypt0 algorithms (AES-GCM, ChaCha20, AES-CCM) |
| `mac0_demo.c` | Demonstrates all Mac0 algorithms (HMAC, AES-MAC) |
| `lifecycle_demo.c` | Full edge-to-cloud workflow with 11 algorithms |

### Comprehensive Tests (examples/comprehensive/)

| File | Tests |
|------|-------|
| `sign_all.c` | Sign1 + multi-signer matrix (~61 tests) |
| `encrypt_all.c` | Encrypt0 + multi-recipient matrix (~23 tests) |
| `mac_all.c` | Mac0 + multi-recipient matrix (~32 tests) |
| `errors_all.c` | Error handling and edge cases (~19 tests) |

### Scenario Examples (examples/scenarios/)

| File | Scenario |
|------|----------|
| `firmware_update.c` | Post-quantum ML-DSA firmware signing with detached payload |
| `multi_party_approval.c` | Dual-control firmware approval (ES256 + ES384) |
| `iot_fleet_config.c` | Encrypted config push to IoT device fleet with multiple recipients |
| `sensor_attestation.c` | EAT-style attestation with replay protection via external AAD |
| `group_broadcast_mac.c` | Authenticated broadcast to multiple subscribers |

---

## Integration Notes

### Minimal Integration

For a minimal COSE integration, you need:
1. `include/wolfcose/wolfcose.h`
2. `include/wolfcose/visibility.h`
3. Every `src/*.c` file
4. `src/wolfcose_internal.h`

Unused message types compile out via the `WOLFCOSE_NO_*` feature macros, and
`-ffunction-sections`/`--gc-sections` discards unreferenced code at link time.

### CBOR-Only Integration

If you only need CBOR (no COSE):
1. `include/wolfcose/wolfcose.h` (for CBOR types)
2. `src/wolfcose_cbor.c`

No wolfCrypt dependency required for CBOR-only.

### Production Builds

Do NOT include in production firmware:
- `tools/` directory
- `examples/` directory
- `tests/` directory

---

## See Also

- [[Getting Started]]: Build instructions
- [[API Reference]]: Function documentation
- [[Testing]]: Test organization
