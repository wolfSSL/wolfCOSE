# wolfCOSE

wolfCOSE is a lightweight CBOR and COSE library for embedded systems. It implements:

- **CBOR** (RFC 8949): Concise Binary Object Representation
- **COSE** (RFC 9052/9053): CBOR Object Signing and Encryption

It uses [wolfSSL](https://www.wolfssl.com/) as the cryptographic backend and is designed for constrained IoT devices, FIPS-bounded deployments, and anywhere you need authenticated CBOR payloads in minimal RAM.

## Standards

**Core specifications**

- [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949): Concise Binary Object Representation (CBOR)
- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052): CBOR Object Signing and Encryption (COSE) structures
- [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053): COSE initial algorithms
- [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864): Fully-specified algorithms for JOSE and COSE
- [RFC 9338](https://www.rfc-editor.org/rfc/rfc9338): COSE countersignatures

**Post-quantum cryptography**

- [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964): ML-DSA for COSE
- [RFC 8778](https://www.rfc-editor.org/rfc/rfc8778): HSS/LMS hash-based signatures for COSE

**Attestation**

- [RFC 9783](https://www.rfc-editor.org/rfc/rfc9783): PSA attestation token profile of EAT

## Key Features

| Feature | Description |
|---------|-------------|
| Complete RFC 9052 | All six COSE message types — Sign1, Sign, Encrypt0, Encrypt, Mac0, Mac |
| Multi-signer / multi-recipient | Full `COSE_Sign`, `COSE_Encrypt`, and `COSE_Mac` support |
| Post-quantum signing | ML-DSA (FIPS 204) at all three security levels — first COSE library to ship native PQC |
| PSA attestation | Optional RFC 9783 EAT / PSA token verifier and issuer, including Sign1, Mac0, legacy consumption, and PSA/HSM delegated signing |
| Zero dynamic allocation | Heap-allocation-free, non-recursive; caller-provided buffers within a bounded, target-customizable stack ceiling — zero `.data`/`.bss` |
| Tiny footprint | 3.5–5.1 KB COSE engine, 5.1–6.8 KB with the built-in CBOR engine (verify-only -> sign + verify); 26.2 KB -> 34.6 KB total with wolfCrypt — ES256 `COSE_Sign1`, dead-code-eliminated |
| 41 algorithms | Signing, encryption, MAC, and key distribution — classical and post-quantum |
| FIPS 140-3 path | Sole crypto dependency is wolfCrypt FIPS Certificate #4718 |
| CNSA 2.0 ready | ML-DSA-44/65/87 for quantum-resistant signatures |
| MISRA-C:2023 | compliance striving, Single-exit pattern, no recursion, deviation-logged |

## Documentation

| Page | Description |
|------|-------------|
| [Getting Started](Getting-Started.md) | Prerequisites, building, and quick start examples |
| [Message Types](Message-Types.md) | All six RFC 9052 messages (Sign1/Sign, Encrypt0/Encrypt, Mac0/Mac) with code samples |
| [Algorithms](Algorithms.md) | Complete list of supported algorithms with COSE IDs |
| [API Reference](API-Reference.md) | Full API documentation for all functions |
| [Macros](Macros.md) | Configuration macros and compile-time options |
| [Experimental](Experimental.md) | Draft feature status, supported scope, and graduation plan |
| [PSA and EAT](PSA-EAT.md) | RFC 9783 PSA attestation profiles, APIs, and integration guidance |
| [Footprint](Footprint.md) | Size and speed numbers, desktop and on-device |
| [Testing](Testing.md) | Unit tests, coverage, and failure injection |
| [MISRA Compliance](MISRA-Compliance.md) | MISRA C:2012 and C:2023 compliance status and deviation rationale |
| [Project Structure](Project-Structure.md) | Source code layout and file descriptions |
| [STM32Cube](STM32Cube.md) | Install and run wolfCOSE as an STM32Cube pack on device |
| [Release Notes](Release-Notes.md) | Per-version changelog and release highlights |

## Supported Message Types

wolfCOSE implements all six COSE message types from RFC 9052:

| Message Type | Tag | Description |
|--------------|-----|-------------|
| COSE_Sign1 | 18 | Single signer digital signature |
| COSE_Sign | 98 | Multiple signers |
| COSE_Encrypt0 | 16 | Symmetric encryption (single key) |
| COSE_Encrypt | 96 | Multi-recipient encryption |
| COSE_Mac0 | 17 | Symmetric MAC (single key) |
| COSE_Mac | 97 | Multi-recipient MAC |

## Quick Links

- [GitHub Repository](https://github.com/wolfSSL/wolfCOSE)
- [wolfSSL Website](https://www.wolfssl.com/)

See [Standards](#standards) above for the full list of implemented RFCs.

## License

wolfCOSE is free software licensed under GPLv3. For commercial licensing and support, contact [wolfSSL](https://www.wolfssl.com/contact/).
