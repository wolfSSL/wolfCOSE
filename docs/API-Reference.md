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
- [PSA/EAT API](#psaeat-api)
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
    int32_t alg;              /* Algorithm from either header bucket */
    const uint8_t* kid;       /* Key ID (zero-copy pointer) */
    size_t kidLen;
    const uint8_t* iv;        /* IV from unprotected header */
    size_t ivLen;
    const uint8_t* partialIv; /* Partial IV from unprotected header */
    size_t partialIvLen;
    int32_t contentType;      /* Content type from either header bucket */
    uint8_t flags;            /* WOLFCOSE_HDR_FLAG_* */
} WOLFCOSE_HDR;
```

Parsed COSE header information. `alg` and `contentType` may come from either
the protected or unprotected header bucket; `kid`, `iv`, and `partialIv` are
unprotected metadata. `WOLFCOSE_HDR_FLAG_CONTENT_TYPE_UNPROTECTED` is set when
the unprotected bucket contains the content-type label. Integer values are
stored in `contentType`; text-string values are accepted but not retained.
wolfCOSE pins an unprotected algorithm to the supplied key where cryptographic
policy requires it, but applications must not treat the other returned fields
as authenticated policy unless they independently pin them.

All message APIs require the external AAD pointer to be non-NULL when its
length is non-zero.

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
    uint8_t*       buf;         /* Encode output */
    const uint8_t* cbuf;        /* Decode input */
    size_t         bufSz;       /* Buffer size */
    size_t         idx;         /* Current position */
} WOLFCOSE_CBOR_CTX;
```

CBOR encoder/decoder context. Use the initializer appropriate to its mode;
the initializers clear the opposite pointer so encode operations cannot write
through decoder input. Variation-tolerant parsing is private to the optional
PSA/EAT verifier and is not stored in caller-owned context state.

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
int wc_CoseKey_Encode(WOLFCOSE_KEY* key, uint8_t* buf, size_t bufSz, size_t* outLen);
```

Encode a COSE key to CBOR format.

> **Warning: this serialises the private key when the key has one.**
> `wc_CoseKey_SetEcc()` sets `key->hasPrivate` whenever the attached `ecc_key`
> is a keypair, and `wc_CoseKey_Encode()` then emits the `-4: d` entry. The
> output is a perfectly valid `COSE_Key`, only longer - for P-256 with `alg`
> set, 112 bytes / `map(6)` instead of 77 bytes / `map(5)` - so nothing fails
> loudly. The same applies to RSA (`-3: d` plus the CRT factors), Ed25519 and
> Ed448 (`-4: d`), an RFC 9964 AKP key (`-2: priv` seed), and symmetric keys
> (`-1: k` is the whole key). Anything that publishes a public key derived
> from a live keypair - WebAuthn/CTAP2 attestation `authData`, ECDH key
> agreement, JWK-style publication - must use
> [`wc_CoseKey_Encode_ex()`](#wc_cosekey_encode_ex) with
> `WOLFCOSE_KEY_PUBLIC_ONLY`.

**Parameters:**
| Name | Description |
|------|-------------|
| `key` | Pointer to COSE key to encode |
| `buf` | Output buffer |
| `bufSz` | Size of output buffer |
| `outLen` | Receives actual encoded length |

**Returns:** `WOLFCOSE_SUCCESS` or error code

---

### wc_CoseKey_Encode_ex

```c
int wc_CoseKey_Encode_ex(WOLFCOSE_KEY* key, uint8_t* buf, size_t bufSz,
                         size_t* outLen, uint32_t flags);
```

As `wc_CoseKey_Encode()`, plus output options. Passing `flags = 0` is
equivalent to calling `wc_CoseKey_Encode()`.

| Flag | Effect |
|------|--------|
| `WOLFCOSE_KEY_PUBLIC_ONLY` | Emit the public half only. No `-4: d` for EC2/OKP, no `-3: d` or CRT factors for RSA, no `-2: priv` seed for an AKP key. |

Unknown flag bits are rejected with `WOLFCOSE_E_INVALID_ARG`.

A symmetric key has no public half - `-1: k` *is* the key - so
`WOLFCOSE_KEY_PUBLIC_ONLY` on `WOLFCOSE_KTY_SYMMETRIC` returns
`WOLFCOSE_E_COSE_KEY_TYPE` rather than emitting a key with no key material.

The key structure is not modified; the flag affects only this call, so the
same key can still sign afterwards.

```c
/* Publish the attestation public key without the private scalar. */
ret = wc_CoseKey_Encode_ex(&key, cose, sizeof(cose), &coseLen,
                           WOLFCOSE_KEY_PUBLIC_ONLY);
```

**Returns:** `WOLFCOSE_SUCCESS` or error code

---

### wc_CoseKey_EncodeEccRaw

```c
int wc_CoseKey_EncodeEccRaw(int32_t crv,
                            const uint8_t* x, const uint8_t* y,
                            const uint8_t* d, size_t coordLen,
                            const uint8_t* kid, size_t kidLen, int32_t alg,
                            uint8_t* out, size_t outSz, size_t* outLen);
```

Encode an EC2 `COSE_Key` straight from raw affine coordinates. For callers
that hold only the coordinates - re-emitting a stored credential record, or
echoing a peer key - this avoids `wc_ecc_import_unsigned()`, which pays a full
point import, an on-curve check, and an `ecc_key` worth of stack purely to
serialise bytes that are already in hand.

The output is byte-identical to what `wc_CoseKey_Encode_ex()` produces for the
same `crv`/`kid`/`alg` and the same coordinates.

**Parameters:**
| Name | Description |
|------|-------------|
| `crv` | `WOLFCOSE_CRV_P256` / `P384` / `P521` (EC2 curves only) |
| `x`, `y` | Coordinates, each exactly `coordLen` bytes, big-endian, zero-padded |
| `d` | Private scalar (`coordLen` bytes), or `NULL` for a public-only key |
| `coordLen` | Must equal the curve size: 32, 48, or 66 |
| `kid`, `kidLen` | Optional key identifier (`NULL`, 0 to omit) |
| `alg` | Algorithm for the `3: alg` entry, or `WOLFCOSE_ALG_UNSET` to omit |
| `out`, `outSz`, `outLen` | Output buffer and encoded length |

**Returns:** `WOLFCOSE_SUCCESS` or error code

Nothing here checks that `(x, y)` is on the curve: the bytes are copied into
the map as supplied. Encoding an unvalidated point is safe; *using* one is
not, so import it through wolfCrypt before any ECDH or verify operation.

There is deliberately no `wc_CoseKey_SetEccRaw()`. `WOLFCOSE_KEY` holds a
single pointer-sized union member for the key, which cannot carry three
independent buffers (`x`, `y`, `d`), and widening the structure would change
`sizeof(WOLFCOSE_KEY)` and break the ABI for already-compiled callers. The
free function above is the supported raw-coordinate path.

---

### wc_CoseKey_EncodeSize / wc_CoseKey_EncodeSize_ex

```c
int wc_CoseKey_EncodeSize(const WOLFCOSE_KEY* key, size_t* outLen);
int wc_CoseKey_EncodeSize_ex(const WOLFCOSE_KEY* key, size_t* outLen,
                             uint32_t flags);
```

Compute the **exact** number of bytes `wc_CoseKey_Encode()` /
`wc_CoseKey_Encode_ex()` would write, without encoding into a buffer. This is
the `COSE_Key` counterpart of
[`wc_CoseSign1_SignSize_ex()`](#wc_cosesign1_signsize_ex): nothing is written
and no key material is exported, only the component lengths of the attached
key are read. The result is exact, not an upper bound, so it can size a buffer
or reject an oversized key before committing storage.

`flags` takes the same `WOLFCOSE_KEY_*` values as `wc_CoseKey_Encode_ex()`, so
`WOLFCOSE_KEY_PUBLIC_ONLY` sizes the public-only encoding. `flags = 0` sizes
the private encoding - see the warning on `wc_CoseKey_Encode()`.

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
`WOLFCOSE_E_COSE_KEY_TYPE` is returned before any importer runs. To learn which
key type a buffer holds before attaching anything, use
[`wc_CoseKey_PeekInfo()`](#wc_cosekey_peekinfo).

Decoding is strict: preferred CBOR only, no duplicate integer labels, and
`bufSz` must be exactly the encoded length. With
`WOLFCOSE_ENABLE_COSE_TEXT_LABELS`, unknown text labels are accepted as
non-critical extensions and checked for duplicates. Registered COSE_Key
parameters remain numeric. See
[Getting Started - Strict
decoding](Getting-Started.md#strict-decoding-rfc-8949-preferred-serialization).
Keys containing the optional `key_ops` label (4) return
`WOLFCOSE_E_UNSUPPORTED` before any key material is imported because the
fixed-size `WOLFCOSE_KEY` wrapper cannot retain arbitrary operation arrays.

An attached `ecc_key` that will receive private EC2 material must be freshly
initialized, with no existing curve or key material. Reusing a populated ECC
object returns `WOLFCOSE_E_INVALID_ARG` without replacing its key. Free and
initialize the object again before decoding another private EC2 key. This
precondition lets wolfCOSE roll back a failed software import without losing
caller-owned wolfCrypt configuration. Backends or math layouts that cannot be
rolled back safely return `WOLFCOSE_E_UNSUPPORTED` before private import.

---

### wc_CoseKey_PeekInfo

```c
typedef struct WOLFCOSE_KEY_INFO {
    int32_t        kty;     /* WOLFCOSE_KTY_*, always set on success */
    int32_t        alg;     /* WOLFCOSE_ALG_*, WOLFCOSE_ALG_UNSET if absent */
    int32_t        crv;     /* WOLFCOSE_CRV_*, 0 if absent or N/A */
    const uint8_t* kid;     /* Key ID, zero-copy pointer, NULL if absent */
    size_t         kidLen;
} WOLFCOSE_KEY_INFO;

int wc_CoseKey_PeekInfo(const uint8_t* in, size_t inSz,
                        WOLFCOSE_KEY_INFO* info);
```

Read `kty`, `alg`, `crv`, and `kid` out of a `COSE_Key` buffer without
importing any key material and without needing a wolfCrypt key object.

`wc_CoseKey_Decode()` requires the caller to have attached a key of the
matching type up front and returns `WOLFCOSE_E_COSE_KEY_TYPE` otherwise, so a
parser that accepts more than one key type would have to guess and retry.
Peek first, then attach once:

```c
WOLFCOSE_KEY_INFO info;

ret = wc_CoseKey_PeekInfo(in, inSz, &info);
if (ret == WOLFCOSE_SUCCESS) {
    if (info.kty == WOLFCOSE_KTY_EC2) {
        (void)wc_ecc_init(&ecc);
        ret = wc_CoseKey_SetEcc(&key, info.crv, &ecc);
    }
    else if (info.kty == WOLFCOSE_KTY_OKP) {
        (void)wc_ed25519_init(&ed);
        ret = wc_CoseKey_SetEd25519(&key, &ed);
    }
    /* ... */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CoseKey_Decode(&key, in, inSz);
    }
}
```

`in` is not modified and nothing is consumed, so the call is repeatable. `kid`
points into `in`, so it stays valid only as long as that buffer does.

The same structural checks `wc_CoseKey_Decode()` applies are applied here:
no duplicate integer labels, `kty` required, and no trailing bytes. With
`WOLFCOSE_ENABLE_COSE_TEXT_LABELS`, unknown text labels are also accepted and
checked for duplicates. Registered COSE_Key parameters remain numeric. Label
`-1` is `crv` for
EC2/OKP but `k`/`n` for symmetric/RSA keys; the value is dispatched on its
CBOR type, so `crv` stays 0 for the latter. A `key_ops` label returns
`WOLFCOSE_E_UNSUPPORTED`, matching decode. On any error every field of `info`
is cleared.

**Returns:** `WOLFCOSE_SUCCESS` or error code

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
| `key` | Signing key with private material, or an external signing callback when enabled |
| `alg` | Algorithm: `WOLFCOSE_ALG_ES256`, `WOLFCOSE_ALG_ES384`, `WOLFCOSE_ALG_ES512`, `WOLFCOSE_ALG_EDDSA`, etc. |
| `kid`, `kidLen` | Optional key identifier |
| `payload`, `payloadLen` | Payload to include in message (or NULL for detached) |
| `detachedPayload`, `detachedPayloadLen` | Payload to sign but not include |
| `extAad`, `extAadLen` | External additional authenticated data |
| `scratch`, `scratchSz` | Scratch buffer (min `WOLFCOSE_MAX_SCRATCH_SZ`) |
| `out`, `outSz`, `outLen` | Output buffer and length |
| `rng` | Random number generator for local signing; may be NULL with an external signing callback |

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

Direct recipients are encoded with the mandatory unprotected `{1: -6}`
algorithm header and an empty bstr ciphertext item. This adds two bytes per
direct recipient compared with the former empty-map encoding; callers using
fixed output buffers must leave room for it.

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

Every recipient must declare its key-management algorithm. Direct encryption
algorithms may coexist with each other, direct key agreement requires one
recipient, and key-transport algorithms may coexist with each other. Direct
recipients must carry an empty bstr or null ciphertext item. If the body
algorithm is only in the unprotected header,
`recipient->key->alg` must pin the same algorithm.

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

Each direct recipient is encoded with the mandatory unprotected `{1: -6}`
algorithm header and an empty bstr ciphertext item. This adds two bytes per
recipient compared with the former empty-map encoding.

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

Every recipient must declare `WOLFCOSE_ALG_DIRECT`, sibling recipients must use
direct mode, and the recipient ciphertext item must be an empty bstr or null.
If the body algorithm is only in the unprotected header, `recipient->key->alg` must
pin the same algorithm.

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

## PSA/EAT API

Available only when `WOLFCOSE_ENABLE_EAT_PSA` and the selected profile and
envelope gates are defined. Include `<wolfcose/eat_psa.h>`. See [[PSA-EAT]]
for configuration and security requirements.

### wc_CoseEatPsaToken_Verify

```c
int wc_CoseEatPsaToken_Verify(const WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* expectedNonce, size_t expectedNonceLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_EAT_PSA_TOKEN* token);
```

Authenticates a tagged, attached RFC 9783 current or selected legacy token,
checks profile-required claim structure and the expected nonce, then returns
zero-copy claim spans in `token`. The input buffer must remain unchanged while
the output token is used. `expectedNonce` is required and must be 32, 48, or
64 bytes.

### Other PSA/EAT entry points

| Function | Required feature gate | Purpose |
|----------|-----------------------|---------|
| `wc_CoseEatPsaToken_EncodeClaims` | `WOLFCOSE_ENABLE_EAT_PSA_ISSUE` | Encode current-profile claims |
| `wc_CoseEatPsaToken_CreateSign1` | `WOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE` plus common issue | Encode and create a current Sign1 token |
| `wc_CoseEatPsaToken_CreateMac0` | `WOLFCOSE_ENABLE_EAT_PSA_MAC0_ISSUE` plus common issue | Encode and create a current Mac0 token |
| `wc_CoseEatPsaToken_VerifyByUeid` | `WOLFCOSE_ENABLE_EAT_PSA_UEID_RESOLVER` | Resolve a candidate key from an untrusted UEID, then authenticate the original token |
| `wc_CoseEatPsaToken_ForEachComponent` | `WOLFCOSE_ENABLE_EAT_PSA_COMPONENT_ITERATOR` | Decode authenticated software components one at a time |

The three writable buffers passed to either creation API (`claimsBuf`,
`scratch`, and `out`) must be pairwise disjoint. Exact or partial overlap is
rejected with `WOLFCOSE_E_INVALID_ARG` before claims are encoded.
`claimsBuf` must additionally be disjoint from the claims structure, component
array, and every nonempty input span. The direct `EncodeClaims` output has the
same input-disjointness requirement; in-place encoding is rejected.

The raw-key verifier rejects `x5chain`; validate certificates outside this API
before supplying a public key. Verification provides claims for caller policy
appraisal and does not itself authorize a device.

`wc_CoseEatPsaToken_ForEachComponent()` supplies a component structure that is
valid only for its callback. The structure's span data borrows from the verified
input token and remains valid while that input remains unchanged.

---

## CBOR API

Basic CBOR encoding/decoding functions in `wolfcose.h`:

### Context Setup

`WOLFCOSE_CBOR_CTX` carries a mutable `buf` for encode output and a const
`cbuf` for decode input. The initializers set the appropriate pointer, clear
the opposite pointer, set `bufSz`, and zero `idx` in a single call:

```c
int wc_CBOR_EncoderInit(WOLFCOSE_CBOR_CTX* ctx, uint8_t* buf, size_t bufSz);
int wc_CBOR_DecoderInit(WOLFCOSE_CBOR_CTX* ctx, const uint8_t* buf, size_t bufSz);
```

Use these initializers instead of assigning context fields directly.
Public CBOR decoding always requires RFC 8949 preferred serialization. The
optional PSA/EAT verifier handles RFC 9783's permitted definite-length
variation serialization privately; indefinite-length forms remain unsupported.

```c
WOLFCOSE_CBOR_CTX ctx;

(void)wc_CBOR_EncoderInit(&ctx, out, sizeof(out));
ret = wc_CBOR_EncodeMapStart(&ctx, 2);
...
(void)wc_CBOR_DecoderInit(&ctx, in, inSz);
ret = wc_CBOR_DecodeMapStart(&ctx, &count);
```

**Returns:** `WOLFCOSE_SUCCESS`, or `WOLFCOSE_E_INVALID_ARG` if `ctx` or `buf`
is `NULL`.

### Encoding Functions

| Function | Description |
|----------|-------------|
| `wc_CBOR_EncoderInit(ctx, buf, bufSz)` | Initialize an encode context |
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
| `wc_CBOR_DecoderInit(ctx, buf, bufSz)` | Initialize a decode context |
| `wc_CBOR_DecodeUint(ctx, val)` | Decode unsigned integer |
| `wc_CBOR_DecodeInt(ctx, val)` | Decode signed integer |
| `wc_CBOR_DecodeBstr(ctx, data, len)` | Decode byte string (zero-copy) |
| `wc_CBOR_DecodeTstr(ctx, str, len)` | Decode text string (zero-copy) |
| `wc_CBOR_DecodeArrayStart(ctx, count)` | Decode array header |
| `wc_CBOR_DecodeMapStart(ctx, count)` | Decode map header |
| `wc_CBOR_DecodeTag(ctx, tag)` | Decode CBOR tag |
| `wc_CBOR_DecodeLabel(ctx, label)` | Decode an int-or-text map label |
| `wc_CBOR_Skip(ctx)` | Skip over any CBOR item |
| `wc_CBOR_SkipItem(ctx, data, dataLen)` | Skip an item and capture its raw bytes |
| `wc_CBOR_PeekType(ctx)` | Peek at next item's major type |

> **Decoding is strict by default.** Ordinary decode entry points require
> RFC 8949 Section 4.2.1 preferred (shortest-form) arguments and reject
> indefinite lengths. The optional PSA/EAT verifier privately admits the
> non-preferred definite-length forms RFC 9783 requires; it never admits
> indefinite lengths. `wc_CBOR_DecodeHead()`, `wc_CBOR_DecodeLabel()`,
> `wc_CBOR_Skip()`, and `wc_CBOR_SkipItem()` validate every text string they
> encounter, even when merely traversing it, and return
> `WOLFCOSE_E_CBOR_MALFORMED` for invalid UTF-8. See [Getting Started - Strict
> decoding](Getting-Started.md#strict-decoding-rfc-8949-preferred-serialization)
> before debugging an interop failure.

### wc_CBOR_SkipItem

```c
int wc_CBOR_SkipItem(WOLFCOSE_CBOR_CTX* ctx,
                     const uint8_t** data, size_t* dataLen);
```

As `wc_CBOR_Skip()`, but also reports the raw encoded bytes of the item that
was skipped, zero-copy into the decoder input. This is the deferred/nested
parse primitive: capture a sub-item now, parse it later or with a different
decoder. It replaces the hand-rolled

```c
start = ctx.idx;
ret = wc_CBOR_Skip(&ctx);
ptr = ctx.cbuf + start;
len = ctx.idx - start;
```

that every integrator ends up writing - CTAP2 `allowList` entries, a
`COSE_Key` embedded in an extension map, `keyAgreement` in
`authenticatorClientPIN`.

```c
const uint8_t* sub;
size_t subLen;

ret = wc_CBOR_SkipItem(&ctx, &sub, &subLen);
if (ret == WOLFCOSE_SUCCESS) {
    ret = wc_CoseKey_Decode(&peerKey, sub, subLen);  /* parse it later */
}
```

`wc_CBOR_Skip()` and `wc_CBOR_SkipItem()` validate UTF-8 in every text string
they traverse. On failure the capture outputs are untouched.

**Returns:** `WOLFCOSE_SUCCESS` or error code

---

### wc_CBOR_DecodeLabel

```c
typedef struct WOLFCOSE_CBOR_LABEL {
    int64_t        val;      /* Integer label, valid when isText == 0 */
    const uint8_t* text;     /* Text label, points into the input buffer */
    size_t         textLen;
    uint8_t        isText;
} WOLFCOSE_CBOR_LABEL;

int wc_CBOR_DecodeLabel(WOLFCOSE_CBOR_CTX* ctx, WOLFCOSE_CBOR_LABEL* label);
int wc_CBOR_LabelIsInt(const WOLFCOSE_CBOR_LABEL* label, int64_t val);
int wc_CBOR_LabelIsText(const WOLFCOSE_CBOR_LABEL* label,
                        const uint8_t* text, size_t textLen);
```

RFC 9052 defines `label = int / tstr`. Applications may use either form for
their own map parameters, while registered COSE parameters retain their
specified numeric labels. `wc_CBOR_DecodeLabel()` consumes one item and reports
whichever form it found, so a parser writes the dispatch once instead of
duplicating a
`wc_CBOR_PeekType()` branch at every map.

Major types 0 and 1 fill `val` with `isText == 0`; major type 3 fills
`text`/`textLen` with `isText == 1` and no copy. Anything else returns
`WOLFCOSE_E_CBOR_TYPE`.

`wc_CBOR_LabelIsInt()` and `wc_CBOR_LabelIsText()` return 1 on match and 0
otherwise, including for a `NULL` label. Text comparison is byte-exact: no
Unicode normalization or case folding, matching how CTAP2 and COSE compare
labels.

```c
WOLFCOSE_CBOR_LABEL label;
static const uint8_t algText[] = "alg";

ret = wc_CBOR_DecodeLabel(&ctx, &label);
if (wc_CBOR_LabelIsInt(&label, 3) || wc_CBOR_LabelIsText(&label, algText, 3)) {
    ret = wc_CBOR_DecodeInt(&ctx, &alg);
}
else {
    ret = wc_CBOR_Skip(&ctx);
}
```

With `WOLFCOSE_ENABLE_COSE_TEXT_LABELS`, `wc_CoseKey_Decode()` and the COSE
header parsers accept both forms and bytewise track text-label duplicates,
including between protected and unprotected header buckets. Registered COSE
parameters remain numeric: a text label such as `"alg"` or `"kty"` is an
unknown extension, not an alias for numeric labels 1 or 3. Unknown
non-critical extensions are skipped; an unknown entry listed in numeric
`crit` is rejected. Without the gate, these generic parsers reject text labels.

**Returns:** `WOLFCOSE_SUCCESS` or error code

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
| -9030 | `WOLFCOSE_E_EAT_PSA_CLAIM` | PSA/EAT required claim is malformed, missing, or duplicated (PSA/EAT builds only) |
| -9031 | `WOLFCOSE_E_EAT_PSA_PROFILE` | Token does not match a selected PSA/EAT profile (PSA/EAT builds only) |
| -9032 | `WOLFCOSE_E_EAT_PSA_NONCE` | Authenticated token nonce does not match the expected nonce (PSA/EAT builds only) |
| -9033 | `WOLFCOSE_E_EAT_PSA_KEY` | PSA/EAT key resolution failed (PSA/EAT builds only) |

---

## See Also

- [[Getting Started]]: Build instructions and examples
- [[Algorithms]]: Supported algorithms
- [[Macros]]: Compile-time configuration
- [[PSA-EAT]]: RFC 9783 PSA attestation support
