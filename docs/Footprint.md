# Footprint and Performance

This page reports build-profile footprint for ES256 `COSE_Sign1` and ML-DSA, end-to-end ES256 throughput, and published ML-DSA throughput whose COSE scope is unverified.

**Size method.** One fixed key and payload. Built `-ffunction-sections -fdata-sections` and linked `-Wl,--gc-sections`, so unreached functions are dropped; this is the real flash cost, not the whole-archive size. Sizes are code + rodata. Two numbers are reported: **glue** is the wolfCOSE COSE + CBOR engine alone (independent of the crypto backend); **total** is glue plus the minimal wolfCrypt build pulled in. Desktop: x86_64 Intel i9-11950H, GCC 14.2. On-device: NUCLEO-H563ZI (STM32H563ZI, Cortex-M33 @ 250 MHz). June 2026.

## Library size (glue)

The wolfCOSE COSE engine plus its built-in CBOR engine, for one ES256 `COSE_Sign1`.

| Build | COSE engine | CBOR engine | Total (glue) |
|-------|-------------|-------------|--------------|
| Sign + verify (`WOLFCOSE_LEAN`) | 5.1 KB | 1.7 KB | **6.8 KB** |
| Verify-only (`WOLFCOSE_LEAN_VERIFY`) | 3.5 KB | 1.6 KB | **5.1 KB** |

wolfCOSE uses a tiny purpose-built CBOR engine (1.6–1.7 KB) rather than a general-purpose one, which is most of why the whole library stays small. Stripping the signing path (verify-only) shrinks every part.

## Total footprint with wolfCrypt

The crypto backend dominates the binary. ES256 `COSE_Sign1`, wolfCrypt built minimal from source.

| Build | Total + wolfCrypt |
|-------|-------------------|
| Sign + verify | **34.6 KB** |
| Verify-only (`WOLFCOSE_LEAN_VERIFY`) | **26.2 KB** |

The verify-only profile is the common on-device case: a device verifies signed firmware or attestation while signing happens off-device on a server or HSM. It removes signing and the RNG entirely while keeping full RFC 9052 verification. wolfCrypt holds FIPS 140-3 certificate #4718, so this is also a direct path to a validated build.

## Build-profile footprint

The lean profiles (see [[Macros]] → Build Profiles). *Glue* is the wolfCOSE engine alone; *total* adds the minimal wolfCrypt backend.

| Profile | Algorithm | wolfCOSE glue | Total + wolfCrypt |
|---------|-----------|---------------|-------------------|
| `WOLFCOSE_LEAN` | ES256 sign + verify | 6.8 KB | 34.6 KB |
| `WOLFCOSE_LEAN_VERIFY` | ES256 verify-only | 5.1 KB | 26.2 KB |
| `WOLFCOSE_LEAN_MLDSA` | ML-DSA-44 sign + verify | 6.6 KB | 35.8 KB |
| `WOLFCOSE_LEAN_VERIFY_MLDSA` | ML-DSA-44 verify-only | 4.6 KB | 20.8 KB |

### Post-quantum at the same cost (ML-DSA-44, FIPS 204)

| ML-DSA-44 build | wolfCOSE | wolfCrypt | Total | ES256 equivalent |
|-----------------|----------|-----------|-------|------------------|
| sign + verify (`WOLFCOSE_LEAN_MLDSA`) | 6.6 KB | 29.2 KB | 35.8 KB | 34.6 KB |
| verify-only (`WOLFCOSE_LEAN_VERIFY_MLDSA`) | 4.6 KB | 16.2 KB | 20.8 KB | 26.2 KB |

Post-quantum sign + verify lands within ~1 KB of classical ES256, and verify-only is actually *smaller* (20.8 vs 26.2 KB): wolfCOSE adds just 4.6 KB on top of wolfCrypt for ML-DSA verify, less than its ES256 glue, because ML-DSA skips the DER signature conversion ECDSA needs.

## Speed (Intel i9-11950H, x86_64)

ES256 rates are end-to-end `COSE_Sign1` with wolfCrypt `sp_256` assembly. The published ML-DSA chart calls its AVX2 rates wolfCrypt throughput, but its benchmark harness is not available to establish whether COSE processing was included. Do not treat these rates as interchangeable end-to-end measurements. See the [published measurements](https://www.wolfssl.com/wolfcose-vs-the-field-the-smallest-and-fastest-cose-library-now-with-post-quantum-ml-dsa-at-the-same-cost/).

| Operation | Scope | Ops/s |
|-----------|-------|-------|
| ES256 verify | End-to-end `COSE_Sign1` | 26,437 |
| ES256 sign | End-to-end `COSE_Sign1` | 66,538 |
| ML-DSA-44 verify | Published as wolfCrypt; COSE scope unverified | 51,645 |
| ML-DSA-44 sign | Published as wolfCrypt; COSE scope unverified | 18,642 |
| ML-DSA-87 verify | Published as wolfCrypt; COSE scope unverified | 20,849 |

## On a real MCU: STM32H563 (Cortex-M33 @ 250 MHz)

ES256 `COSE_Sign1` verify on a NUCLEO-H563ZI, verify-only with no RNG, timed with the on-chip DWT cycle counter. wolfCrypt uses its Cortex-M Thumb P-256 assembly (`WOLFSSL_SP_ARM_CORTEX_M_ASM`).

| Metric | wolfCOSE + wolfCrypt |
|--------|----------------------|
| verify cycles/op | 1,510,716 |
| verify ops/s @ 250 MHz | ~165 |
| flash (verify-only) | 44.2 KB |
| peak stack | 6.7 KB |
| peak heap | **0 (zero-alloc)** |
| total RAM | ~6.7 KB |

The verify path allocates nothing, using only caller-provided buffers, so the entire RAM cost is ~6.7 KB of stack, with no heap at all, which matters where `malloc` is prohibited. The footprint is ~2% of the board's 2 MB flash and ~1% of its 640 KB RAM.

## Method and versions

Desktop: x86_64 Intel i9-11950H, GCC 14.2, June 2026. On-device: NUCLEO-H563ZI (STM32H563ZI, Cortex-M33 @ 250 MHz), arm-none-eabi-gcc 13.2, DWT cycle counter. ES256 throughput measures `COSE_Sign1`; the published ML-DSA rates lack a verifiable COSE benchmark scope. wolfCOSE 8c6209e, wolfSSL master 4c0c093.

## See Also

- [[Macros]]: build profiles and configuration
- [[Testing]]: memory and stack-bound enforcement in CI
- [[Getting Started]]: building wolfCOSE
