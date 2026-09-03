# PSA Attestation and EAT Tokens

wolfCOSE can consume and create the PSA Token profile of EAT specified by
[RFC 9783](https://www.rfc-editor.org/rfc/rfc9783). It is an explicit
opt-in: a normal `libwolfcose.a` has neither the PSA/EAT parser nor its public
API symbols.

The API is designed for a verifier receiving the bytes returned by
`psa_initial_attest_get_token()`, a device onboarding service, a gateway, or a
remote attestation component such as wolfTrust. All storage remains owned by
the caller. Decoded claim spans borrow the authenticated input token.

## Select only what is needed

`WOLFCOSE_ENABLE_EAT_PSA` enables the common API. Select at least one profile
and at least one consume or issue operation after it.

| Define | Effect | Default |
|---|---|---|
| `WOLFCOSE_ENABLE_EAT_PSA` | Common PSA/EAT API and types | off |
| `WOLFCOSE_ENABLE_EAT_PSA_CURRENT` | RFC 9783 TF-M profile, `tag:psacertified.org,2023:psa#tfm` | off |
| `WOLFCOSE_ENABLE_EAT_PSA_SIGN1` | Tagged `COSE_Sign1` consumption | off |
| `WOLFCOSE_ENABLE_EAT_PSA_MAC0` | Tagged `COSE_Mac0` consumption | off |
| `WOLFCOSE_ENABLE_EAT_PSA_ISSUE` | Current-profile claim encoding | off |
| `WOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE` | Tagged `COSE_Sign1` token creation | off |
| `WOLFCOSE_ENABLE_EAT_PSA_MAC0_ISSUE` | Tagged `COSE_Mac0` token creation | off |
| `WOLFCOSE_ENABLE_EAT_PSA_LEGACY` | Legacy `PSA_IOT_PROFILE_1` consumption | off |
| `WOLFCOSE_ENABLE_EAT_PSA_UEID_RESOLVER` | `wc_CoseEatPsaToken_VerifyByUeid()` key lookup helper | off |
| `WOLFCOSE_ENABLE_EAT_PSA_COMPONENT_ITERATOR` | `wc_CoseEatPsaToken_ForEachComponent()` callback helper | off |
| `WOLFCOSE_EAT_PSA_MAX_COMPONENTS` | Maximum accepted software-component maps | 32 |
| `WOLFCOSE_EAT_PSA_MAX_CLAIMS` | Verifier-only maximum current/legacy claim-map entries | 64 |
| `WOLFCOSE_EAT_PSA_MAX_COMPONENT_CLAIMS` | Verifier-only maximum entries in each component map | 16 |

The generic wolfCOSE algorithm gates remain authoritative. Select ES384,
ES512, HMAC384, and HMAC512 with their normal `WOLFCOSE_ENABLE_*` macros in a
lean build, or remove any supported algorithm with its `WOLFCOSE_NO_*` macro.
The PSA/EAT code has no algorithm fallback: a disabled algorithm is rejected
before claims are used.

The consume and issue directions are independent. An attester can select the
common issue gate and one issue envelope without selecting either consumption
gate. Such a build contains no PSA/EAT verifier symbol. A claim-encoder-only
build can omit both issue-envelope gates. Conversely, a verifier can omit the
common issue gate and every issuance API.

Minimal current Sign1 verifier:

```text
-DWOLFCOSE_LEAN_VERIFY
-DWOLFCOSE_ENABLE_EAT_PSA
-DWOLFCOSE_ENABLE_EAT_PSA_CURRENT
-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1
```

Current Mac0 verifier:

```text
-DWOLFCOSE_LEAN
-DWOLFCOSE_ENABLE_EAT_PSA
-DWOLFCOSE_ENABLE_EAT_PSA_CURRENT
-DWOLFCOSE_ENABLE_EAT_PSA_MAC0
```

Current ES256 Sign1 issuer without the PSA/EAT verifier:

```text
-DWOLFCOSE_LEAN
-DWOLFCOSE_NO_SIGN1_VERIFY
-DWOLFCOSE_NO_ENCRYPT0_DECRYPT
-DWOLFCOSE_NO_MAC0_VERIFY
-DWOLFCOSE_NO_KEY_DECODE
-DWOLFCOSE_NO_CBOR_DECODE
-DWOLFCOSE_ENABLE_EAT_PSA
-DWOLFCOSE_ENABLE_EAT_PSA_CURRENT
-DWOLFCOSE_ENABLE_EAT_PSA_ISSUE
-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE
```

Replace the last gate with `WOLFCOSE_ENABLE_EAT_PSA_MAC0_ISSUE` for an
HMAC256 Mac0 issuer. The same decode opt-outs apply. The algorithm gates can
then replace ES256 or HMAC256 independently as described in [[Macros]].

These selective examples are useful COSE building blocks, but they are not
RFC 9783 `#tfm` receivers: Section 5.2 requires a `#tfm` receiver to accept
both envelope types and ES256/384/512 plus HMAC 256/256, 384/384, and
512/512. wolfCOSE therefore derives `WOLFCOSE_EAT_PSA_TFM_FULL` only for that
complete configuration. Without it, the PSA/EAT verifier rejects the
standard `tag:psacertified.org,2023:psa#tfm` value with
`WOLFCOSE_E_EAT_PSA_PROFILE`. This receiver requirement does not constrain an
attester: RFC 9783 permits it to issue `#tfm` with one enabled Table 4 Sign1
or Mac0 protection algorithm. A reduced verifier must not advertise full
`#tfm` receiver conformance.

A feature-complete test profile is available through `make eat-psa-test`. It
also enables current issuance, legacy consumption, UEID resolution, and
component iteration. `make eat-psa-config-check` proves the default archive
contains no PSA/EAT symbols and checks minimal, partial, and invalid
configurations.

`make eat-psa-profile-test` then runs current Sign1-only, current Mac0-only,
legacy Sign1-only, and legacy Mac0-only binaries. It verifies that the two
partial current attesters can issue and generically authenticate `#tfm` with
their enabled envelope, while their incomplete PSA/EAT receivers reject it.
It also verifies that disabled standardized claim namespaces are not silently
skipped and that a disabled envelope returns `WOLFCOSE_E_UNSUPPORTED` before
cryptographic work.

The claim-map limits are intentionally separate from `WOLFCOSE_MAX_MAP_ITEMS`:
EAT receivers accept extension claims, but must still bound input work while
checking that every standardized and extension key is unique. Set either limit
larger for an expected extension-rich token; the values must be at least 10
and 5 respectively.

`make eat-psa-claim-limits-test` recompiles a dedicated test with the minimum
valid ceilings (10 top-level claims and 5 component-map claims). It accepts
the exact boundary and rejects each respective `+1` map before iterating its
entries.

`WOLFCOSE_EAT_PSA_TFM_FULL` is derived only when a build has current-profile
Sign1 and Mac0 verification plus ES256, ES384, ES512, HMAC256, HMAC384, and
HMAC512. That is the set RFC 9783 requires a TF-M profile receiver to support;
applications do not define this macro themselves; an externally supplied
definition is a configuration error.

## API

Include the API only in an enabled build:

```c
#include <wolfcose/eat_psa.h>
```

`wc_CoseEatPsaToken_Verify()` authenticates a tagged, attached COSE token with a
caller-owned `WOLFCOSE_KEY`, validates the selected PSA profile's required
claim shape, and compares the authenticated nonce. It fills a
`WOLFCOSE_EAT_PSA_TOKEN` only on success.

```c
WOLFCOSE_EAT_PSA_TOKEN token;
int ret = wc_CoseEatPsaToken_Verify(&iak_key, token_bytes, token_size,
    challenge, challenge_size, scratch, sizeof(scratch), &token);
if (ret == WOLFCOSE_SUCCESS) {
    /* Appraise token.clientId, token.lifecycle, implementationId, and claims. */
}
```

`expectedNonce` is mandatory and must be 32, 48, or 64 bytes. The output
spans, including `nonce`, `ueid`, `implementationId`, and `components`, point
into `token_bytes`; retain that buffer unchanged until appraisal is complete.

### PSA client handoff

wolfCOSE deliberately does not link against a PSA client library. A PSA
client obtains opaque bytes from the standard API, then passes them directly
to the verifier with a provisioned IAK key:

```c
#include <psa/initial_attestation.h>

uint8_t token_bytes[1024u]; /* Select a capacity for the PSA platform. */
size_t token_size = 0u;
psa_status_t psa_ret;

psa_ret = psa_initial_attest_get_token_size(sizeof(challenge), &token_size);
if ((psa_ret == PSA_SUCCESS) && (token_size <= sizeof(token_bytes))) {
    psa_ret = psa_initial_attest_get_token(challenge, sizeof(challenge),
        token_bytes, sizeof(token_bytes), &token_size);
}
if (psa_ret == PSA_SUCCESS) {
    ret = wc_CoseEatPsaToken_Verify(&provisioned_iak, token_bytes, token_size,
        challenge, sizeof(challenge), scratch, sizeof(scratch), &token);
}
```

For a fleet verifier, enable the UEID resolver and map the untrusted UEID to a
candidate provisioned IAK. The token is authenticated only after that lookup.
This keeps the wolfCOSE library portable while allowing a PSA client such as
wolfTrust to use its normal `psa_initial_attest_get_token()` API.

If the attestation key is selected by device identity, enable
`WOLFCOSE_ENABLE_EAT_PSA_UEID_RESOLVER` and use
`wc_CoseEatPsaToken_VerifyByUeid()`. The resolver sees an untrusted decoded UEID
only to choose a candidate key. wolfCOSE then verifies the original token
before returning any claims, so the resolver must not use that preliminary
UEID for authorization.

If software-component appraisal is needed, enable
`WOLFCOSE_ENABLE_EAT_PSA_COMPONENT_ITERATOR` and call
`wc_CoseEatPsaToken_ForEachComponent()` after successful verification. It decodes
one component at a time from the authenticated token, avoiding heap storage
for a component list. The callback's component structure is valid only for the
duration of that callback. Its span data borrows from the verified token input
and remains valid while that input remains unchanged.

For a current-profile Sign1 issuer, enable
`WOLFCOSE_ENABLE_EAT_PSA_ISSUE` and
`WOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE`, then use:

```c
wc_CoseEatPsaToken_CreateSign1(&issuer_key, WOLFCOSE_ALG_ES256, &claims,
    claims_buf, sizeof(claims_buf), scratch, sizeof(scratch), token,
    sizeof(token), &token_len, rng);
```

`wc_CoseEatPsaToken_CreateMac0()` is available only when the common issue and
Mac0 issue gates are selected. Issuance always emits the current RFC 9783 profile;
legacy is deliberately consume-only. An attester needs only one enabled
RFC 9783 Table 4 Sign1 or Mac0 creation path to emit the standardized `#tfm`
identifier. `WOLFCOSE_EAT_PSA_TFM_FULL` is deliberately separate: it proves a
receiver has every mandatory envelope and algorithm, so a selective verifier
continues to reject `#tfm` with `WOLFCOSE_E_EAT_PSA_PROFILE`.

The issuer's `claimsBuf`, `scratch`, and output buffer ranges must be pairwise
disjoint. Either creation function rejects exact or partial overlap with
`WOLFCOSE_E_INVALID_ARG` before encoding claims and clears the output range.
`claimsBuf` is the output of `wc_CoseEatPsaToken_EncodeClaims()`, so it must
also be disjoint from the claims structure, component array, and every
nonempty claim or component span. The direct encoder enforces the same rule
for its output buffer; in-place claim encoding is not supported.

The Sign1 issuer accepts an external signing key installed with
`wc_CoseKey_SetExtSigner()`. The callback receives the algorithm's digest of
the COSE `Sig_structure`, which maps directly to a PSA
`psa_sign_hash()` implementation. Pass `NULL` for `rng` when the external
signer owns all randomness. This is the intended wolfTrust and secure-element
integration path: wolfCOSE owns the standard claim encoding and COSE envelope,
while the IAK remains inside the PSA service, HSM, or secure partition.

For wolfTrust, the migration path is to have the Initial Attestation service
populate `WOLFCOSE_EAT_PSA_CLAIMS`, install its existing secure-partition
signing callback, and call `wc_CoseEatPsaToken_CreateSign1()`. The returned bytes
can then be consumed by `wc_CoseEatPsaToken_Verify()` or the UEID resolver without
a second private claim parser.

`make psa-eat-demo` runs the same application flow without a PSA service. It
measures a sample secure-partition image, issues a current-profile Sign1 token,
selects a provisioned public IAK by UEID, rejects a mismatched challenge,
authenticates the real challenge, and applies an onboarding policy to the
lifecycle, device IDs, signer, version, and software measurement. The example
is in `examples/psa_eat_demo.c`.

The pre-RFC profile used by older wolfTrust trees (`http://arm.com/psa/2.0.0`)
is intentionally not treated as RFC 9783. A wolfTrust migration replaces its
manual claim encoder with these current-profile claims, uses the RFC 9783
`tag:psacertified.org,2023:psa#tfm` profile value, and retains its existing
external IAK signer. That gives the PSA service a standards-conformant token
without moving private IAK material out of its secure partition.

## Profile behavior

| Capability | Current RFC 9783 TF-M | Legacy PSA IoT Profile 1 |
|---|---|---|
| Profile identifier | `tag:psacertified.org,2023:psa#tfm` | `PSA_IOT_PROFILE_1` |
| Consume | `WOLFCOSE_ENABLE_EAT_PSA_CURRENT` | `WOLFCOSE_ENABLE_EAT_PSA_LEGACY` |
| Issue | yes, with one enabled RFC 9783 Sign1 or Mac0 creation path | no |
| Required nonce | 32, 48, or 64 bytes | 32, 48, or 64 bytes |
| UEID | 33 bytes, first byte `0x01` | same |
| Boot seed | optional, 8 to 32 bytes when present | required, 32 bytes |
| Certification reference | current 13-digit plus version form | old 13-digit form |
| Components | one or more measurement components | components or explicit no-measurements form |

For the current profile, wolfCOSE requires nonce, UEID, profile, nonzero
client ID, lifecycle, 32-byte implementation ID, and at least one software
component. Each component needs a 32, 48, or 64 byte measurement value and
signer ID. Optional values and unknown EAT claims are retained or skipped as
appropriate without weakening the required-claim checks. Both standardized
current and legacy label namespaces are always recognized: a disabled or mixed
namespace is rejected as `WOLFCOSE_E_EAT_PSA_PROFILE`, not treated as an
extension.

The RFC 9783 `0x00xx` lifecycle range is structurally valid but represents an
unknown state. Verification retains it; an appraisal policy should normally
reject it for a trust decision.

## COSE and trust boundary

RFC 9783 specifies COSE tag 18 (`COSE_Sign1`) and tag 17 (`COSE_Mac0`) for
this profile. wolfCOSE accepts only an explicitly tagged, attached token and
requires its `alg` parameter in the protected header because this API does not
use externally supplied authenticated data. It rejects untagged messages, CWT
tag 61 wrappers, detached payloads, indefinite-length CBOR, unsupported PSA
algorithms, duplicate selected claims, and trailing bytes.

RFC 9783 requires variation-tolerant reception of definite-length CBOR.
PSA/EAT verification therefore accepts non-preferred but well-formed definite
encodings. Ordinary wolfCOSE decoding remains strict by default. Unknown
non-critical COSE header extensions may use integer or text labels; text labels
are tracked for duplicates across protected and unprotected buckets, but are
not aliases for registered numeric headers. A text extension listed in `crit`
is rejected because this verifier does not implement it. Verification implies
the otherwise optional `WOLFCOSE_ENABLE_COSE_TEXT_LABELS` capability.

The raw-key API rejects `x5chain` headers with `WOLFCOSE_E_UNSUPPORTED`. A
certificate chain is not proof of a trusted IAK until an application has
performed path building, trust-anchor selection, validity checking, and
revocation policy. Do that in a certificate-aware layer, then call the raw-key
API with the validated public key.

Successful verification is not complete attestation appraisal. The relying
party must apply its own policy to the client ID, lifecycle, UEID,
implementation ID, signer IDs, component measurements, version data, and any
verification-service indicator. It must also retain replay state beyond the
nonce exchange when its protocol requires it.

Mac0 is available because RFC 9783 defines it, but it uses a shared secret.
Use it only where shared-key provisioning and verifier identity fit the threat
model; Sign1 is normally the better choice for remotely provisioned device
attestation.

## Validation and interoperability

`make eat-psa-test` includes the RFC 9783 Appendix A Sign1 and Mac0 vectors,
which the RFC identifies as generated by TF-M's `iat-verifier`, plus current
ES256/384/512 and HMAC256/384/512 round trips, legacy cases, nonce checks,
and malformed-token negatives. `make eat-psa-claim-limits-test` covers exact
and plus-one configured claim limits. The verify-only, full-`#tfm` receiver is
exercised by `make psa-eat-lean-verify`.

The pinned t_cose and QCBOR CI harness covers COSE wire interoperation in both
directions for current-profile Sign1 and Mac0 payloads. t_cose validates the
envelope produced by wolfCOSE; wolfCOSE validates a t_cose envelope and then
performs the PSA/EAT claim checks. See `tests/interop/t_cose/README.md`.
