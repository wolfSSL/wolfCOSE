# wolfCOSE ⇄ t_cose Interop

A wire-interoperability conformance suite: wolfCOSE (on wolfCrypt) and
[t_cose](https://github.com/laurencelundblade/t_cose) (on OpenSSL) each produce
COSE messages the other consumes, in both directions, for every algorithm both
implement. The COSE bytes on the wire are the only interface — the two libraries'
APIs are never reconciled. This demonstrates RFC 9052/9053 conformance, not a
performance or feature comparison.

## What is covered

| Message     | Algorithms (both directions)                         |
|-------------|------------------------------------------------------|
| COSE_Sign1  | ES256/384/512, PS256/384/512, EdDSA (Ed25519, Ed448) |
| COSE_Mac0   | HMAC 256/384/512                                      |
| COSE_Encrypt0 | AES-GCM 128/192/256                                |
| RFC 9783 PSA/EAT | Current TF-M claims in Sign1 ES256 and Mac0 HMAC256 |

Each primitive class also runs a negative case — a tampered signature, MAC tag,
or AEAD tag — that wolfCOSE must reject.

CBOR byte-for-byte equality is an explicit non-goal: CBOR permits multiple valid
encodings, so the suite verifies that each side *reconstructs and validates* the
other's output, never that the two producers emit identical bytes.

For the PSA/EAT rows, wolfCOSE builds the current profile claims and each side
authenticates the other's COSE envelope. On the t_cose to wolfCOSE direction,
wolfCOSE additionally performs the RFC 9783 claim and nonce checks. t_cose
does not implement a PSA/EAT profile parser, so its role is intentionally
limited to independent COSE wire validation.

## Dependencies (not vendored)

t_cose and QCBOR are BSD-3-Clause. They are **not** redistributed here; CI fetches
them at pinned SHAs and links them:

- t_cose `dev` @ `ff4c5f7c6fbbe27bb582214ff1878bf58ebc6c43`
- QCBOR @ `930708bb86481e88879eb1d87fd4d664f1d69503`

wolfCOSE itself stays zero-allocation; this harness is test-only.

## Building locally

Fetch the pinned SHAs (same sequence CI uses) and build, from this directory:

```bash
# QCBOR @ pinned SHA
mkdir -p QCBOR && cd QCBOR && git init -q && \
  git fetch --depth 1 -q https://github.com/laurencelundblade/QCBOR.git \
    930708bb86481e88879eb1d87fd4d664f1d69503 && \
  git checkout -q FETCH_HEAD && make libqcbor.a && cd ..

# t_cose @ pinned SHA (OpenSSL adapter)
mkdir -p t_cose && cd t_cose && git init -q && \
  git fetch --depth 1 -q https://github.com/laurencelundblade/t_cose.git \
    ff4c5f7c6fbbe27bb582214ff1878bf58ebc6c43 && \
  git checkout -q FETCH_HEAD && \
  make -f Makefile.ossl libt_cose.a \
    QCBOR_INC="-I ../QCBOR/inc" QCBOR_LIB="../QCBOR/libqcbor.a" && cd ..

# the suite (from the repo root)
make interop-tcose \
  TCOSE_DIR=$PWD/tests/interop/t_cose/t_cose \
  QCBOR_DIR=$PWD/tests/interop/t_cose/QCBOR \
  TCOSE_CRYPTO_LIB="-lcrypto"
```

## Files

| File                  | Role                                                          |
|-----------------------|---------------------------------------------------------------|
| `interop_tcose.c`     | Table-driven harness; wolfCrypt side; both directions per case |
| `interop_key_ossl.c`  | t_cose-side OpenSSL key loader (isolated TU — wolfSSL and OpenSSL headers collide on `SHA256`) |
| `interop_cases.h`     | Shared key-id enum so a key means the same on both sides       |
| `interop_keys.h`      | Fixed DER/symmetric test-key fixtures (provenance below)       |

## Test-key provenance (fixtures, not production keys)

Committed for determinism. Generated once with OpenSSL:

```bash
# EC private keys (SEC1/RFC 5915 DER)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform DER
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -outform DER
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -outform DER

# EdDSA private keys (PKCS#8 DER)
openssl genpkey -algorithm ED25519 -outform DER
openssl genpkey -algorithm ED448   -outform DER

# RSA-2048 private key (PKCS#1 DER)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | \
  openssl rsa -outform DER -traditional
```

OpenSSL loads all of these via `d2i_AutoPrivateKey`; wolfCrypt via the matching
`wc_{Ecc,Ed25519,Ed448,Rsa}PrivateKeyDecode`. Symmetric keys are fixed bytes,
loaded backend-agnostically through `t_cose_key_init_symmetric`.
