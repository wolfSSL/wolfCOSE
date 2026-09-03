# Experimental Features

This page tracks wolfCOSE features that intentionally remain outside the stable
default build while their standards are still in development.

> **Status snapshot:** 2 September 2026. Update this page when the IETF draft,
> its IANA registrations, or wolfCOSE's implementation status changes.

## Customer Summary

Experimental code is disabled by default. Enabling a feature requires both the
master acknowledgement, `WOLFCOSE_EXPERIMENTAL`, and the feature's individual
`WOLFCOSE_ENABLE_*` macro. This makes draft adoption an explicit build-time
decision and keeps ordinary deployments free of draft wire formats and APIs.

Experimental features may change or be removed before their associated RFC is
published. Customers who evaluate one should pin the wolfCOSE revision used for
testing and should not promise long-term wire compatibility until the feature
graduates.

## COSE-HPKE

### Standards Status

| Item | Current status |
|------|----------------|
| Specification | [draft-ietf-cose-hpke-26](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/26/) |
| IETF state | Active COSE working-group Internet-Draft |
| Intended RFC status | Proposed Standard |
| Published | 4 July 2026 |
| Draft expiration | 5 January 2027 |
| Stable RFC | Not published |

Draft expiration is not an RFC publication estimate. The IETF may revise,
replace, or advance the document at any time. Track the
[current Datatracker record](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/)
for the authoritative state.

### wolfCOSE Status

| Area | Status | Scope |
|------|--------|-------|
| Master acknowledgement | Complete | `WOLFCOSE_EXPERIMENTAL` is required but enables no code by itself. |
| Fine-grained build controls | Complete | Separate send and receive macros exist for integrated HPKE-0 and multi-recipient HPKE-0-KE. |
| Integrated encryption | Complete for P0 | `COSE_Encrypt0` HPKE-0 encrypt and decrypt. |
| Multi-recipient encryption | Complete for P0 | `COSE_Encrypt` HPKE-0-KE encrypt and decrypt. |
| Command-line and example coverage | Complete for P0 | HPKE commands, self-tests, and `examples/hpke_demo.c` use the same experimental gate. |
| Continuous integration | Complete for P0 | Unit, example, CLI, strict C99, malformed-input, and curve-validation coverage run in the experimental HPKE workflow. |
| Stable wire and API commitment | Pending | Deferred until the final RFC and IANA values are published. |

### Implemented P0 Scope

The current implementation is deliberately narrow and auditable:

- HPKE base mode only.
- DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM only.
- One-recipient integrated `COSE_Encrypt0` HPKE-0.
- Multi-recipient `COSE_Encrypt` HPKE-0-KE with an independently protected CEK
  for each recipient.
- External AAD bound through the normal COSE encryption structure.

The following are not implemented in P0: alternate KEM, KDF, or AEAD suites;
X25519; PSK mode; authenticated HPKE mode; and an application-controlled HPKE
`info` value. These omissions are intentional, not hidden runtime options.

### Build Selection

Build wolfSSL with HPKE, ECC P-256, AES-GCM, SHA-256, and key generation, then
select only the wolfCOSE directions the product needs:

```bash
# Integrated Encrypt0, send and receive.
make EXTRA_CFLAGS="-DWOLFCOSE_EXPERIMENTAL -DWOLFCOSE_ENABLE_HPKE_0"

# Receive-only integrated provisioning target.
make EXTRA_CFLAGS="-DWOLFCOSE_EXPERIMENTAL \
  -DWOLFCOSE_ENABLE_HPKE_0_DECRYPT"

# Multi-recipient sender in a lean build.
make EXTRA_CFLAGS="-DWOLFCOSE_LEAN -DWOLFCOSE_EXPERIMENTAL \
  -DWOLFCOSE_ENABLE_ENCRYPT -DWOLFCOSE_ENABLE_HPKE_0_KE_ENCRYPT"
```

The `make hpke-demo` target supplies the acknowledgement and all four P0
operation macros itself. See [Configuration Macros](Macros.md#cose-hpke-experimental)
for every enable and compile-out macro.

### Path to Stable Support

| Milestone | Status | Customer planning guidance |
|-----------|--------|----------------------------|
| New draft revisions | Ongoing | wolfCOSE will assess each revision for wire, identifier, and API changes. |
| Final RFC and IANA registrations | Pending IETF publication | No public RFC publication date is available. Do not use the draft expiration as a delivery date. |
| wolfCOSE compatibility update | Pending final RFC | Planned after the final RFC and registrations are available. |
| Graduation from experimental | Pending validation | The target is a compatible wolfCOSE release after final-RFC validation. The release date cannot be committed before the IETF publication date is known. |

When COSE-HPKE graduates, wolfCOSE will publish migration notes, update the
implemented identifiers and wire handling as needed, remove the
`WOLFCOSE_EXPERIMENTAL` requirement, and document the stable API and
compatibility policy. Until then, use a COSE signature or MAC with HPKE when
the sender must be authenticated, and treat HPKE-encoded artifacts as
experimental interoperability data.
