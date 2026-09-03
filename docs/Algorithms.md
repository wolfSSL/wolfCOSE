# Supported Algorithms

wolfCOSE supports 41 algorithms across signing, encryption, MAC, and key distribution. This page provides the complete list with COSE algorithm IDs and required wolfSSL compile-time guards. All algorithms are usable in both single-actor messages (Sign1/Encrypt0/Mac0) and multi-actor messages (Sign/Encrypt/Mac) — see [[Message Types]] for details.

## COSE_Sign1 (Digital Signatures)

| Algorithm | COSE ID | wolfCrypt Guard | Notes |
|-----------|---------|-----------------|-------|
| ES256 | -7 | `HAVE_ECC` | ECDSA with P-256 / SHA-256 |
| ES384 | -35 | `HAVE_ECC` | ECDSA with P-384 / SHA-384 |
| ES512 | -36 | `HAVE_ECC` | ECDSA with P-521 / SHA-512 |
| EdDSA (Ed25519) | -8 | `HAVE_ED25519` | Curve25519 |
| EdDSA (Ed448) | -8 | `HAVE_ED448` | Curve448 (Goldilocks) |
| PS256 | -37 | `WC_RSA_PSS` | RSA-PSS with SHA-256 |
| PS384 | -38 | `WC_RSA_PSS` | RSA-PSS with SHA-384 |
| PS512 | -39 | `WC_RSA_PSS` | RSA-PSS with SHA-512 |
| ML-DSA-44 | -48 | `WOLFSSL_HAVE_MLDSA` | Post-quantum (FIPS 204) |
| ML-DSA-65 | -49 | `WOLFSSL_HAVE_MLDSA` | Post-quantum (FIPS 204) |
| ML-DSA-87 | -50 | `WOLFSSL_HAVE_MLDSA` | Post-quantum (FIPS 204) |
| HSS-LMS | -46 | `WOLFSSL_HAVE_LMS` | Post-quantum stateful hash-based (RFC 8778, SP 800-208); COSE_Key kty 5; signature size follows the key's parameter set; signing state is caller-managed, verify-only builds pair with `WOLFSSL_LMS_VERIFY_ONLY` |

### ML-DSA Signature Sizes

| Algorithm | Signature Size | Public Key Size |
|-----------|----------------|-----------------|
| ML-DSA-44 | 2,420 bytes | 1,312 bytes |
| ML-DSA-65 | 3,293 bytes | 1,952 bytes |
| ML-DSA-87 | 4,595 bytes | 2,592 bytes |

## COSE_Encrypt0 (Authenticated Encryption)

| Algorithm | COSE ID | wolfCrypt Guard | Notes |
|-----------|---------|-----------------|-------|
| A128GCM | 1 | `HAVE_AESGCM` | AES-GCM 128-bit |
| A192GCM | 2 | `HAVE_AESGCM` | AES-GCM 192-bit |
| A256GCM | 3 | `HAVE_AESGCM` | AES-GCM 256-bit |
| ChaCha20/Poly1305 | 24 | `HAVE_CHACHA && HAVE_POLY1305` | 256-bit, software-friendly |
| AES-CCM-16-64-128 | 10 | `HAVE_AESCCM` | 128-bit key, 8-byte tag |
| AES-CCM-16-64-256 | 11 | `HAVE_AESCCM` | 256-bit key, 8-byte tag |
| AES-CCM-64-64-128 | 12 | `HAVE_AESCCM` | 128-bit key, 8-byte tag, short nonce |
| AES-CCM-64-64-256 | 13 | `HAVE_AESCCM` | 256-bit key, 8-byte tag, short nonce |
| AES-CCM-16-128-128 | 30 | `HAVE_AESCCM` | 128-bit key, 16-byte tag |
| AES-CCM-16-128-256 | 31 | `HAVE_AESCCM` | 256-bit key, 16-byte tag |
| AES-CCM-64-128-128 | 32 | `HAVE_AESCCM` | 128-bit key, 16-byte tag, short nonce |
| AES-CCM-64-128-256 | 33 | `HAVE_AESCCM` | 256-bit key, 16-byte tag, short nonce |

### AES-CCM Naming Convention

The AES-CCM algorithm names follow the pattern `AES-CCM-{L}-{T}-{K}`:
- **L**: Length field size (16 or 64 bits for nonce)
- **T**: Tag size (64 or 128 bits)
- **K**: Key size (128 or 256 bits)

## COSE_Mac0 (Message Authentication)

| Algorithm | COSE ID | wolfCrypt Guard | Notes |
|-----------|---------|-----------------|-------|
| HMAC 256/256 | 5 | `!NO_HMAC` | SHA-256, 32-byte tag |
| HMAC 384/384 | 6 | `WOLFSSL_SHA384` | SHA-384, 48-byte tag |
| HMAC 512/512 | 7 | `WOLFSSL_SHA512` | SHA-512, 64-byte tag |
| AES-MAC-128/64 | 14 | `HAVE_AES_CBC` | 128-bit key, 8-byte tag |
| AES-MAC-256/64 | 15 | `HAVE_AES_CBC` | 256-bit key, 8-byte tag |
| AES-MAC-128/128 | 25 | `HAVE_AES_CBC` | 128-bit key, 16-byte tag |
| AES-MAC-256/128 | 26 | `HAVE_AES_CBC` | 256-bit key, 16-byte tag |

## Key Distribution (Multi-Recipient)

Used with COSE_Encrypt and COSE_Mac for multi-recipient messages:

| Algorithm | COSE ID | wolfCrypt Guard | Notes |
|-----------|---------|-----------------|-------|
| Direct | -6 | always | Pre-shared symmetric key |
| A128KW | -3 | `HAVE_AES_KEYWRAP` | AES Key Wrap 128-bit |
| A192KW | -4 | `HAVE_AES_KEYWRAP` | AES Key Wrap 192-bit |
| A256KW | -5 | `HAVE_AES_KEYWRAP` | AES Key Wrap 256-bit |
| ECDH-ES+HKDF-256 | -25 | `HAVE_ECC && HAVE_HKDF` | Ephemeral-Static ECDH |
| ECDH-ES+HKDF-512 | -26 | `HAVE_ECC && HAVE_HKDF` | Ephemeral-Static ECDH |
| ECDH-SS+HKDF-256 | -27 | `HAVE_ECC && HAVE_HKDF` | Static-Static ECDH |
| ECDH-SS+HKDF-512 | -28 | `HAVE_ECC && HAVE_HKDF` | Static-Static ECDH |
| ECDH-ES+A128KW | -29 | `HAVE_ECC && HAVE_HKDF && HAVE_AES_KEYWRAP` | ECDH + Key Wrap |
| ECDH-ES+A192KW | -30 | `HAVE_ECC && HAVE_HKDF && HAVE_AES_KEYWRAP` | ECDH + Key Wrap |
| ECDH-ES+A256KW | -31 | `HAVE_ECC && HAVE_HKDF && HAVE_AES_KEYWRAP` | ECDH + Key Wrap |

AES Key Wrap-based algorithms also require wolfSSL 5.9.0 or later.

## Key Types

| COSE kty | Value | Guard | Algorithms |
|----------|-------|-------|------------|
| OKP | 1 | `HAVE_ED25519` / `HAVE_ED448` | EdDSA |
| EC2 | 2 | `HAVE_ECC` | ES256, ES384, ES512 |
| RSA | 3 | `WC_RSA_PSS` | PS256, PS384, PS512 |
| Symmetric | 4 | always | AES-GCM, AES-CCM, ChaCha20, HMAC |
| AKP | 7 | `WOLFSSL_HAVE_MLDSA` | ML-DSA (RFC 9964) |

ML-DSA keys use the RFC 9964 **AKP** (Algorithm Key Pair) key type: the `alg`
parameter is REQUIRED, the public key is in `pub` (-1), and the private key is
the 32-byte seed in `priv` (-2). There is no `crv` parameter.

## Curves

| COSE crv | Value | Description |
|----------|-------|-------------|
| P-256 | 1 | NIST P-256 (secp256r1) |
| P-384 | 2 | NIST P-384 (secp384r1) |
| P-521 | 3 | NIST P-521 (secp521r1) |
| Ed25519 | 6 | Ed25519 for signatures |
| Ed448 | 7 | Ed448 for signatures |

## COSE Tags

| Tag | Value | Message Type |
|-----|-------|--------------|
| COSE_Encrypt0 | 16 | Symmetric encryption (single key) |
| COSE_Mac0 | 17 | Symmetric MAC (single key) |
| COSE_Sign1 | 18 | Single signer signature |
| COSE_Encrypt | 96 | Multi-recipient encryption |
| COSE_Mac | 97 | Multi-recipient MAC |
| COSE_Sign | 98 | Multi-signer signature |

## Algorithm Constants in Code

wolfCOSE defines these constants in `wolfcose.h`:

```c
/* Signature algorithms */
#define WOLFCOSE_ALG_ES256      (-7)
#define WOLFCOSE_ALG_ES384      (-35)
#define WOLFCOSE_ALG_ES512      (-36)
#define WOLFCOSE_ALG_EDDSA      (-8)
#define WOLFCOSE_ALG_PS256      (-37)
#define WOLFCOSE_ALG_PS384      (-38)
#define WOLFCOSE_ALG_PS512      (-39)
#define WOLFCOSE_ALG_ML_DSA_44  (-48)
#define WOLFCOSE_ALG_ML_DSA_65  (-49)
#define WOLFCOSE_ALG_ML_DSA_87  (-50)

/* Encryption algorithms */
#define WOLFCOSE_ALG_A128GCM              (1)
#define WOLFCOSE_ALG_A192GCM              (2)
#define WOLFCOSE_ALG_A256GCM              (3)
#define WOLFCOSE_ALG_CHACHA20_POLY1305    (24)
#define WOLFCOSE_ALG_AES_CCM_16_64_128    (10)
#define WOLFCOSE_ALG_AES_CCM_16_64_256    (11)
/* ... and more */

/* MAC algorithms */
#define WOLFCOSE_ALG_HMAC_256_256   (5)
#define WOLFCOSE_ALG_HMAC_384_384   (6)
#define WOLFCOSE_ALG_HMAC_512_512   (7)
#define WOLFCOSE_ALG_AES_MAC_128_64 (14)
/* ... and more */

/* Key distribution */
#define WOLFCOSE_ALG_DIRECT             (-6)
#define WOLFCOSE_ALG_A128KW             (-3)
#define WOLFCOSE_ALG_A192KW             (-4)
#define WOLFCOSE_ALG_A256KW             (-5)
#define WOLFCOSE_ALG_DIRECT_HKDF_SHA_256 (-10)
#define WOLFCOSE_ALG_DIRECT_HKDF_SHA_512 (-11)
#define WOLFCOSE_ALG_DIRECT_HKDF_AES_128 (-12)
#define WOLFCOSE_ALG_DIRECT_HKDF_AES_256 (-13)
#define WOLFCOSE_ALG_ECDH_ES_HKDF_256   (-25)
#define WOLFCOSE_ALG_ECDH_ES_HKDF_512   (-26)

/* Key types */
#define WOLFCOSE_KTY_OKP       (1)
#define WOLFCOSE_KTY_EC2       (2)
#define WOLFCOSE_KTY_SYMMETRIC (4)

/* Curves */
#define WOLFCOSE_CRV_P256    (1)
#define WOLFCOSE_CRV_P384    (2)
#define WOLFCOSE_CRV_P521    (3)
#define WOLFCOSE_CRV_ED25519 (6)
#define WOLFCOSE_CRV_ED448   (7)
```

## Roadmap

Future algorithm support planned:

| Algorithm | Standard | Description |
|-----------|----------|-------------|
| ML-KEM | FIPS 203 (Kyber) | Post-quantum key encapsulation for COSE_Encrypt (IETF draft, no codepoints yet) |
| XMSS | NIST SP 800-208 | Hash-based stateful signatures (no COSE codepoints assigned yet) |
| SLH-DSA | SPHINCS+ | Stateless hash-based signatures |

## See Also

- [[Getting Started]]: Build instructions and examples
- [[API Reference]]: Function documentation
- [[Macros]]: Compile-time configuration
