# API Reference

Complete API documentation for wolfCOSE (RFC 9052/9053 COSE implementation).

## Table of Contents

- [Data Structures](#data-structures)
- [COSE_Key API](#cose_key-api)
- [COSE_Sign1 API](#cose_sign1-api)
- [COSE_Encrypt0 API](#cose_encrypt0-api)
- [COSE_Mac0 API](#cose_mac0-api)
- [COSE_Sign API (Multi-Signer)](#cose_sign-api-multi-signer)
- [COSE_Encrypt API (Multi-Recipient)](#cose_encrypt-api-multi-recipient)
- [COSE_Mac API (Multi-Recipient)](#cose_mac-api-multi-recipient)
- [CBOR API](#cbor-api)
- [Error Codes](#error-codes)

---

## Data Structures

### WOLFCOSE_KEY

```c
typedef struct WOLFCOSE_KEY {
    int32_t kty;      /* Key type: WOLFCOSE_KTY_EC2, WOLFCOSE_KTY_OKP, etc. */
    int32_t alg;      /* Algorithm hint (optional) */
    int32_t crv;      /* Curve for EC2/OKP keys */
    union {
        ecc_key* ecc;
        ed25519_key* ed25519;
        ed448_key* ed448;
        RsaKey* rsa;
        wc_MlDsaKey* mldsa;
        struct {
            const uint8_t* key;
            size_t keyLen;
        } symm;
    } key;
} WOLFCOSE_KEY;
```

Pointer-based key structure (~48 bytes). Caller owns underlying wolfCrypt keys.

---

### WOLFCOSE_HDR

```c
typedef struct WOLFCOSE_HDR {
    int32_t alg;              /* Algorithm from protected header */
    const uint8_t* kid;       /* Key ID (zero-copy pointer) */
    size_t kidLen;
    const uint8_t* iv;        /* IV from unprotected header */
    size_t ivLen;
    uint8_t flags;            /* WOLFCOSE_HDR_FLAG_* */
} WOLFCOSE_HDR;
```

Parsed COSE header information.

---

### WOLFCOSE_SIGNATURE

```c
typedef struct WOLFCOSE_SIGNATURE {
    int32_t algId;            /* Signature algorithm */
    WOLFCOSE_KEY* key;        /* Signing key */
    const uint8_t* kid;       /* Key identifier */
    size_t kidLen;
} WOLFCOSE_SIGNATURE;
```

Signer information for COSE_Sign multi-signer messages.

---

### WOLFCOSE_RECIPIENT

```c
typedef struct WOLFCOSE_RECIPIENT {
    int32_t algId;            /* Key distribution algorithm */
    WOLFCOSE_KEY* key;        /* Recipient key */
    const uint8_t* kid;       /* Key identifier */
    size_t kidLen;
} WOLFCOSE_RECIPIENT;
```

Recipient information for COSE_Encrypt and COSE_Mac multi-recipient messages.

---

### WOLFCOSE_CBOR_CTX

```c
typedef struct WOLFCOSE_CBOR_CTX {
    uint8_t* buf;             /* Buffer pointer */
    size_t bufSz;             /* Buffer size */
    size_t idx;               /* Current position */
} WOLFCOSE_CBOR_CTX;
```

CBOR encoder/decoder context.

---

## COSE_Key API

### wc_CoseKey_Init

```c
int wc_CoseKey_Init(WOLFCOSE_KEY* key);
```

Initialize a COSE key structure.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Pointer to COSE key structure to initialize |

**Returns:** `WOLFCOSE_SUCCESS` (0) or `WOLFCOSE_E_INVALID_ARG`

---

### wc_CoseKey_Free

```c
void wc_CoseKey_Free(WOLFCOSE_KEY* key);
```

Free a COSE key structure. Does NOT free the underlying wolfCrypt key (caller owns key lifecycle).

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Pointer to COSE key structure to free |

---

### wc_CoseKey_SetEcc

```c
int wc_CoseKey_SetEcc(WOLFCOSE_KEY* key, int32_t crv, ecc_key* eccKey);
```

Associate an ECC key with a COSE key structure.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Pointer to initialized COSE key |
| `crv` | Curve identifier: `WOLFCOSE_CRV_P256`, `WOLFCOSE_CRV_P384`, or `WOLFCOSE_CRV_P521` |
| `eccKey` | Pointer to initialized wolfCrypt ECC key (caller-owned) |

**Returns:** `WOLFCOSE_SUCCESS` or error code

---

### wc_CoseKey_SetEd25519

```c
int wc_CoseKey_SetEd25519(WOLFCOSE_KEY* key, ed25519_key* edKey);
```

Associate an Ed25519 key with a COSE key structure.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Pointer to initialized COSE key |
| `edKey` | Pointer to initialized wolfCrypt Ed25519 key (caller-owned) |

**Returns:** `WOLFCOSE_SUCCESS` or error code

---

### wc_CoseKey_SetEd448

```c
int wc_CoseKey_SetEd448(WOLFCOSE_KEY* key, ed448_key* edKey);
```

Associate an Ed448 key with a COSE key structure.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Pointer to initialized COSE key |
| `edKey` | Pointer to initialized wolfCrypt Ed448 key (caller-owned) |

**Returns:** `WOLFCOSE_SUCCESS` or error code

**Requires:** `HAVE_ED448`

---

### wc_CoseKey_SetMlDsa

```c
int wc_CoseKey_SetMlDsa(WOLFCOSE_KEY* key, int32_t alg, wc_MlDsaKey* mlDsaKey);
```

Associate an ML-DSA (FIPS 204) post-quantum key with a COSE key structure.
The key is encoded as an RFC 9964 **AKP** COSE_Key (`kty` = 7, REQUIRED `alg`,
public key in `pub` (-1)). Use this for public-key, sign, and verify use. To
encode a *private* COSE_Key (whose private value is the 32-byte seed), use
`wc_CoseKey_SetMlDsa_ex` and supply the seed.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Pointer to initialized COSE key |
| `alg` | Algorithm: `WOLFCOSE_ALG_ML_DSA_44`, `WOLFCOSE_ALG_ML_DSA_65`, or `WOLFCOSE_ALG_ML_DSA_87` |
| `mlDsaKey` | Pointer to initialized wolfCrypt ML-DSA key (caller-owned) |

**Returns:** `WOLFCOSE_SUCCESS` or error code

**Requires:** `WOLFSSL_HAVE_MLDSA`

---

### wc_CoseKey_SetMlDsa_ex

```c
int wc_CoseKey_SetMlDsa_ex(WOLFCOSE_KEY* key, int32_t alg,
                           wc_MlDsaKey* mlDsaKey,
                           const uint8_t* seed, size_t seedLen);
```

Like `wc_CoseKey_SetMlDsa`, but also attaches the 32-byte ML-DSA seed used to
create the key. RFC 9964 represents an ML-DSA private key as the seed, and
wolfCrypt does not retain it, so the caller (who created the key via
`wc_MlDsaKey_MakeKeyFromSeed`) must supply it here to encode a private COSE_Key.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Pointer to initialized COSE key |
| `alg` | Algorithm: `WOLFCOSE_ALG_ML_DSA_44`, `WOLFCOSE_ALG_ML_DSA_65`, or `WOLFCOSE_ALG_ML_DSA_87` |
| `mlDsaKey` | Pointer to initialized wolfCrypt ML-DSA key (caller-owned) |
| `seed` | 32-byte ML-DSA seed (caller-owned), or `NULL` for public/sign/verify use |
| `seedLen` | Seed length; must be `WOLFCOSE_MLDSA_SEED_SZ` (32) when `seed` is non-NULL |

**Returns:** `WOLFCOSE_SUCCESS` or error code

**Requires:** `WOLFSSL_HAVE_MLDSA`

---

### wc_CoseKey_SetRsa

```c
int wc_CoseKey_SetRsa(WOLFCOSE_KEY* key, RsaKey* rsaKey);
```

Associate an RSA key with a COSE key structure.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Pointer to initialized COSE key |
| `rsaKey` | Pointer to initialized wolfCrypt RSA key (caller-owned) |

**Returns:** `WOLFCOSE_SUCCESS` or error code

**Requires:** `WC_RSA_PSS`

---

### wc_CoseKey_SetSymmetric

```c
int wc_CoseKey_SetSymmetric(WOLFCOSE_KEY* key, const uint8_t* keyData, size_t keyLen);
```

Set symmetric key material in a COSE key structure.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Pointer to initialized COSE key |
| `keyData` | Pointer to symmetric key bytes (caller-owned buffer) |
| `keyLen` | Length of key in bytes (16, 24, or 32 for AES-GCM) |

**Returns:** `WOLFCOSE_SUCCESS` or error code

---

### wc_CoseKey_Encode

```c
int wc_CoseKey_Encode(const WOLFCOSE_KEY* key, uint8_t* buf, size_t bufSz, size_t* outLen);
```

Encode a COSE key to CBOR format.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Pointer to COSE key to encode |
| `buf` | Output buffer |
| `bufSz` | Size of output buffer |
| `outLen` | Receives actual encoded length |

**Returns:** `WOLFCOSE_SUCCESS` or error code

---

### wc_CoseKey_Decode

```c
int wc_CoseKey_Decode(WOLFCOSE_KEY* key, const uint8_t* buf, size_t bufSz);
```

Decode a COSE key from CBOR format.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Pointer to COSE key structure (with pre-allocated wolfCrypt key) |
| `buf` | Input CBOR buffer |
| `bufSz` | Size of input buffer |

**Returns:** `WOLFCOSE_SUCCESS` or error code

Attach the wolfCrypt key with `wc_CoseKey_SetEcc()`, `wc_CoseKey_SetEd25519()`,
`wc_CoseKey_SetEd448()`, `wc_CoseKey_SetRsa()`, `wc_CoseKey_SetMlDsa()`, or
`wc_CoseKey_SetSymmetric()`. These record which wolfCrypt object is attached;
assigning the `key.*` union directly does not, and no key material is imported.

The decoded `kty`/`crv` must name the attached key type or
`WOLFCOSE_E_COSE_KEY_TYPE` is returned before any importer runs. Decoding into a
key with nothing attached runs no importer and yields metadata only, which is
how to inspect an untrusted `COSE_Key` before choosing a key object for it.

---

## COSE_Sign1 API

### wc_CoseSign1_Sign

```c
int wc_CoseSign1_Sign(
    const WOLFCOSE_KEY* key,
    int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedPayloadLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng
);
```

Create a COSE_Sign1 message (single signer).

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Signing key (must have private key) |
| `alg` | Algorithm: `WOLFCOSE_ALG_ES256`, `WOLFCOSE_ALG_ES384`, `WOLFCOSE_ALG_ES512`, `WOLFCOSE_ALG_EDDSA`, etc. |
| `kid`, `kidLen` | Optional key identifier |
| `payload`, `payloadLen` | Payload to include in message (or NULL for detached) |
| `detachedPayload`, `detachedPayloadLen` | Payload to sign but not include |
| `extAad`, `extAadLen` | External additional authenticated data |
| `scratch`, `scratchSz` | Scratch buffer (min `WOLFCOSE_MAX_SCRATCH_SZ`) |
| `out`, `outSz`, `outLen` | Output buffer and length |
| `rng` | Random number generator for ECDSA |

**Returns:** `WOLFCOSE_SUCCESS` or error code

---

### wc_CoseSign1_Sign_ex

```c
int wc_CoseSign1_Sign_ex(
    WOLFCOSE_KEY* key,
    int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedPayloadLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng, uint32_t flags
);
```

As `wc_CoseSign1_Sign()`, plus output options. Passing `flags = 0` is
equivalent to calling `wc_CoseSign1_Sign()`.

| Flag | Effect |
|------|--------|
| `WOLFCOSE_SIGN1_UNTAGGED` | Omit the CBOR tag 18 prefix, so output starts with the four-element array (`0x84`). |

The tag is not covered by the signature. A caller emitting untagged output
must establish the message type out of band.

**Returns:** `WOLFCOSE_SUCCESS` or error code

---

### wc_CoseSign1_SignSize_ex

```c
int wc_CoseSign1_SignSize_ex(
    const WOLFCOSE_KEY* key,
    int32_t alg,
    size_t kidLen,
    size_t payloadLen,
    size_t detachedLen,
    uint32_t flags,
    size_t* outLen
);
```

Computes the exact encoded size that `wc_CoseSign1_Sign_ex()` would produce
without signing. It does not use an RNG, private key operation, or external
signer callback. The data itself is not required because only `kidLen`,
`payloadLen`, and `detachedLen` affect the framing.

`key` may be `NULL` when the algorithm fixes the signature length. It is
required for RSA-PSS and for EdDSA when both Ed25519 and Ed448 are enabled.

**Returns:** `WOLFCOSE_SUCCESS` or error code

---

### wc_CoseSign1_Verify

```c
int wc_CoseSign1_Verify(
    const WOLFCOSE_KEY* key,
    const uint8_t* coseMsg, size_t coseMsgLen,
    const uint8_t* detachedPayload, size_t detachedPayloadLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen
);
```

Verify a COSE_Sign1 message and extract payload.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Verification key (public key sufficient) |
| `coseMsg`, `coseMsgLen` | COSE_Sign1 message to verify |
| `detachedPayload`, `detachedPayloadLen` | Detached payload (if message has null payload) |
| `extAad`, `extAadLen` | External AAD (must match what was used during signing) |
| `scratch`, `scratchSz` | Scratch buffer |
| `hdr` | Receives parsed header information |
| `payload`, `payloadLen` | Receives pointer to payload (zero-copy into coseMsg) |

**Returns:** `WOLFCOSE_SUCCESS`, `WOLFCOSE_E_COSE_SIG_FAIL`, or other error

---

## COSE_Encrypt0 API

### wc_CoseEncrypt0_Encrypt

```c
int wc_CoseEncrypt0_Encrypt(
    const WOLFCOSE_KEY* key,
    int32_t alg,
    const uint8_t* iv, size_t ivLen,
    const uint8_t* payload, size_t payloadLen,
    uint8_t* detachedCt, size_t detachedCtSz, size_t* detachedCtLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen
);
```

Create a COSE_Encrypt0 message.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Symmetric encryption key |
| `alg` | Algorithm: `WOLFCOSE_ALG_A128GCM`, `WOLFCOSE_ALG_A192GCM`, `WOLFCOSE_ALG_A256GCM`, etc. |
| `iv`, `ivLen` | Initialization vector (12 bytes for AES-GCM) |
| `payload`, `payloadLen` | Plaintext to encrypt |
| `detachedCt`, `detachedCtSz`, `detachedCtLen` | Optional: receive ciphertext separately |
| `extAad`, `extAadLen` | External additional authenticated data |
| `scratch`, `scratchSz` | Scratch buffer |
| `out`, `outSz`, `outLen` | Output buffer and length |

**Returns:** `WOLFCOSE_SUCCESS` or error code

---

### wc_CoseEncrypt0_Decrypt

```c
int wc_CoseEncrypt0_Decrypt(
    const WOLFCOSE_KEY* key,
    const uint8_t* coseMsg, size_t coseMsgLen,
    const uint8_t* detachedCt, size_t detachedCtLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    uint8_t* plaintext, size_t plaintextSz, size_t* plaintextLen
);
```

Decrypt a COSE_Encrypt0 message.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Symmetric decryption key |
| `coseMsg`, `coseMsgLen` | COSE_Encrypt0 message |
| `detachedCt`, `detachedCtLen` | Detached ciphertext (if message has null ciphertext) |
| `extAad`, `extAadLen` | External AAD (must match encryption) |
| `scratch`, `scratchSz` | Scratch buffer |
| `hdr` | Receives parsed header information |
| `plaintext`, `plaintextSz`, `plaintextLen` | Output buffer for decrypted data |

**Returns:** `WOLFCOSE_SUCCESS`, `WOLFCOSE_E_COSE_DECRYPT_FAIL`, or other error

---

## COSE_Mac0 API

### wc_CoseMac0_Create

```c
int wc_CoseMac0_Create(
    WOLFCOSE_KEY* key,
    int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedPayloadLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen
);
```

Create a COSE_Mac0 message.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Symmetric MAC key |
| `alg` | Algorithm: `WOLFCOSE_ALG_HMAC_256_256`, `WOLFCOSE_ALG_AES_MAC_128_64`, etc. |
| `kid`, `kidLen` | Key identifier (can be NULL, 0) |
| `payload`, `payloadLen` | Payload to include in message |
| `detachedPayload`, `detachedPayloadLen` | Payload to MAC but not include |
| `extAad`, `extAadLen` | External AAD |
| `scratch`, `scratchSz` | Scratch buffer |
| `out`, `outSz`, `outLen` | Output buffer and length |

**Returns:** `WOLFCOSE_SUCCESS` or error code

---

### wc_CoseMac0_Verify

```c
int wc_CoseMac0_Verify(
    const WOLFCOSE_KEY* key,
    const uint8_t* coseMsg, size_t coseMsgLen,
    const uint8_t* detachedPayload, size_t detachedPayloadLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen
);
```

Verify a COSE_Mac0 message.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Symmetric MAC key |
| `coseMsg`, `coseMsgLen` | COSE_Mac0 message |
| `detachedPayload`, `detachedPayloadLen` | Detached payload if applicable |
| `extAad`, `extAadLen` | External AAD |
| `scratch`, `scratchSz` | Scratch buffer |
| `hdr` | Receives parsed header |
| `payload`, `payloadLen` | Receives payload pointer |

**Returns:** `WOLFCOSE_SUCCESS`, `WOLFCOSE_E_MAC_FAIL`, or other error

---

## COSE_Sign API (Multi-Signer)

### wc_CoseSign_Sign

```c
int wc_CoseSign_Sign(
    const WOLFCOSE_SIGNATURE* signers, size_t signerCount,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedPayloadLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng
);
```

Create a COSE_Sign message with multiple signers.

**Parameters:**
| Name | Description |
|------|-------------|
| `signers` | Array of `WOLFCOSE_SIGNATURE` structures |
| `signerCount` | Number of signers |
| Other parameters | Same as `wc_CoseSign1_Sign` |

---

### wc_CoseSign_Verify

```c
int wc_CoseSign_Verify(
    const WOLFCOSE_KEY* key,
    size_t signerIdx,
    const uint8_t* coseMsg, size_t coseMsgLen,
    const uint8_t* detachedPayload, size_t detachedPayloadLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen
);
```

Verify one signer's signature in a COSE_Sign message.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Verification key for the specific signer |
| `signerIdx` | Zero-based index of signer to verify |
| Other parameters | Same as `wc_CoseSign1_Verify` |

---

## COSE_Encrypt API (Multi-Recipient)

### wc_CoseEncrypt_Encrypt

```c
int wc_CoseEncrypt_Encrypt(
    const WOLFCOSE_RECIPIENT* recipients, size_t recipientCount,
    int32_t contentAlgId,
    const uint8_t* iv, size_t ivLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng
);
```

Create a COSE_Encrypt message for multiple recipients.

**Parameters:**
| Name | Description |
|------|-------------|
| `recipients` | Array of `WOLFCOSE_RECIPIENT` structures with keys and algorithms |
| `recipientCount` | Number of recipients |
| `contentAlgId` | Content encryption algorithm (e.g., `WOLFCOSE_ALG_A128GCM`) |
| `iv`, `ivLen` | Initialization vector (12 bytes for AES-GCM) |
| `payload`, `payloadLen` | Plaintext to encrypt (inline) |
| `detachedPayload`, `detachedLen` | Plaintext to encrypt but not include in message |
| `extAad`, `extAadLen` | External AAD |
| `scratch`, `scratchSz` | Scratch buffer |
| `out`, `outSz`, `outLen` | Output buffer |
| `rng` | Random number generator |

**Returns:** `WOLFCOSE_SUCCESS` or error code

---

### wc_CoseEncrypt_Decrypt

```c
int wc_CoseEncrypt_Decrypt(
    const WOLFCOSE_RECIPIENT* recipient,
    size_t recipientIndex,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedCt, size_t detachedCtLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    uint8_t* plaintext, size_t plaintextSz, size_t* plaintextLen
);
```

Decrypt a COSE_Encrypt message as a specific recipient.

**Parameters:**
| Name | Description |
|------|-------------|
| `recipient` | Recipient structure with key and algorithm |
| `recipientIndex` | Zero-based index of recipient in message |
| `in`, `inSz` | COSE_Encrypt message |
| `detachedCt`, `detachedCtLen` | Detached ciphertext (if applicable) |
| `extAad`, `extAadLen` | External AAD (must match encryption) |
| `scratch`, `scratchSz` | Scratch buffer |
| `hdr` | Receives parsed header |
| `plaintext`, `plaintextSz`, `plaintextLen` | Output buffer |

**Returns:** `WOLFCOSE_SUCCESS`, `WOLFCOSE_E_COSE_DECRYPT_FAIL`, or other error

---

## COSE_Mac API (Multi-Recipient)

### wc_CoseMac_Create

```c
int wc_CoseMac_Create(
    const WOLFCOSE_RECIPIENT* recipients, size_t recipientCount,
    int32_t macAlgId,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen
);
```

Create a COSE_Mac message for multiple recipients.

**Parameters:**
| Name | Description |
|------|-------------|
| `recipients` | Array of `WOLFCOSE_RECIPIENT` structures |
| `recipientCount` | Number of recipients |
| `macAlgId` | MAC algorithm (e.g., `WOLFCOSE_ALG_HMAC_256_256`) |
| `payload`, `payloadLen` | Payload to include in message |
| `detachedPayload`, `detachedLen` | Payload to MAC but not include |
| `extAad`, `extAadLen` | External AAD |
| `scratch`, `scratchSz` | Scratch buffer |
| `out`, `outSz`, `outLen` | Output buffer |

**Returns:** `WOLFCOSE_SUCCESS` or error code

---

### wc_CoseMac_Verify

```c
int wc_CoseMac_Verify(
    const WOLFCOSE_RECIPIENT* recipient,
    size_t recipientIndex,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen
);
```

Verify a COSE_Mac message as a specific recipient.

**Parameters:**
| Name | Description |
|------|-------------|
| `recipient` | Recipient structure with key and algorithm |
| `recipientIndex` | Zero-based index of recipient in message |
| `in`, `inSz` | COSE_Mac message |
| `detachedPayload`, `detachedLen` | Detached payload (if applicable) |
| `extAad`, `extAadLen` | External AAD |
| `scratch`, `scratchSz` | Scratch buffer |
| `hdr` | Receives parsed header |
| `payload`, `payloadLen` | Receives payload pointer |

**Returns:** `WOLFCOSE_SUCCESS`, `WOLFCOSE_E_MAC_FAIL`, or other error

---

## CBOR API

Basic CBOR encoding/decoding functions in `wolfcose.h`:

### Encoding Functions

| Function | Description |
|----------|-------------|
| `wc_CBOR_EncodeUint(ctx, val)` | Encode unsigned integer |
| `wc_CBOR_EncodeInt(ctx, val)` | Encode signed integer |
| `wc_CBOR_EncodeBstr(ctx, data, len)` | Encode byte string |
| `wc_CBOR_EncodeTstr(ctx, str, len)` | Encode text string |
| `wc_CBOR_EncodeArrayStart(ctx, count)` | Encode array header |
| `wc_CBOR_EncodeMapStart(ctx, count)` | Encode map header |
| `wc_CBOR_EncodeTag(ctx, tag)` | Encode CBOR tag |
| `wc_CBOR_EncodeNull(ctx)` | Encode null |
| `wc_CBOR_EncodeTrue(ctx)` / `wc_CBOR_EncodeFalse(ctx)` | Encode booleans |

### Decoding Functions

| Function | Description |
|----------|-------------|
| `wc_CBOR_DecodeUint(ctx, val)` | Decode unsigned integer |
| `wc_CBOR_DecodeInt(ctx, val)` | Decode signed integer |
| `wc_CBOR_DecodeBstr(ctx, data, len)` | Decode byte string (zero-copy) |
| `wc_CBOR_DecodeTstr(ctx, str, len)` | Decode text string (zero-copy) |
| `wc_CBOR_DecodeArrayStart(ctx, count)` | Decode array header |
| `wc_CBOR_DecodeMapStart(ctx, count)` | Decode map header |
| `wc_CBOR_DecodeTag(ctx, tag)` | Decode CBOR tag |
| `wc_CBOR_Skip(ctx)` | Skip over any CBOR item |
| `wc_CBOR_PeekType(ctx)` | Peek at next item's major type |

---

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | `WOLFCOSE_SUCCESS` | Operation completed successfully |
| -9000 | `WOLFCOSE_E_INVALID_ARG` | Invalid argument (NULL pointer, etc.) |
| -9001 | `WOLFCOSE_E_BUFFER_TOO_SMALL` | Output buffer insufficient |
| -9002 | `WOLFCOSE_E_CBOR_MALFORMED` | CBOR parsing error |
| -9003 | `WOLFCOSE_E_CBOR_TYPE` | Unexpected CBOR type |
| -9004 | `WOLFCOSE_E_CBOR_OVERFLOW` | Integer overflow in CBOR |
| -9006 | `WOLFCOSE_E_CBOR_DEPTH` | CBOR nesting too deep |
| -9010 | `WOLFCOSE_E_COSE_BAD_TAG` | Wrong COSE tag for message type |
| -9011 | `WOLFCOSE_E_COSE_BAD_ALG` | Unsupported or invalid algorithm |
| -9012 | `WOLFCOSE_E_COSE_SIG_FAIL` | Signature verification failed |
| -9013 | `WOLFCOSE_E_COSE_DECRYPT_FAIL` | Decryption/authentication failed |
| -9014 | `WOLFCOSE_E_COSE_BAD_HDR` | Invalid COSE header |
| -9015 | `WOLFCOSE_E_COSE_KEY_TYPE` | Wrong key type for operation |
| -9016 | `WOLFCOSE_E_COSE_MAC_FAIL` | COSE MAC verification failed |
| -9020 | `WOLFCOSE_E_CRYPTO` | wolfCrypt error |
| -9021 | `WOLFCOSE_E_UNSUPPORTED` | Feature not supported |
| -9022 | `WOLFCOSE_E_MAC_FAIL` | MAC verification failed |
| -9023 | `WOLFCOSE_E_DETACHED_PAYLOAD` | Detached payload required but not provided |

---

## See Also

- [[Getting Started]]: Build instructions and examples
- [[Algorithms]]: Supported algorithms
- [[Macros]]: Compile-time configuration
