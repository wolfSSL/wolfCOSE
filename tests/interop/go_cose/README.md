# wolfCOSE ⇄ go-cose Interop

This test uses [Veraison go-cose](https://github.com/veraison/go-cose), pinned
at v1.3.0 in `go.mod`, as an independent Go oracle for `COSE_Sign1` messages.
Both directions are live: wolfCOSE signs and go-cose verifies, then go-cose
signs and wolfCOSE verifies. Each verifier also rejects a modified signature.

The matrix covers ES256, ES384, ES512, PS256, PS384, PS512, and Ed25519. It
also covers ES256 with external AAD and untagged `COSE_Sign1` framing. go-cose
requires an embedded payload for its Sign1 verification API, so detached Sign1
coverage remains in the wolfCOSE tests and the t_cose wire suite.

It also verifies the RFC 9783 Appendix A ES256 PSA token with go-cose and
uses Go's CBOR decoder to decode its standard EAT claims: UEID, nonce, profile,
and boot seed. The wolfCOSE C test covers the PSA-specific claims in the same
token.

The fixed private keys match the deterministic fixtures from the t_cose interop
suite. They are never production keys.

## Run

Go 1.21 or later is required.

```bash
make interop-go-cose
```

go-cose currently provides the Sign and Sign1 coverage used here. `Mac0` and
`Encrypt0` remain covered by the t_cose wire suite and the project tests.
