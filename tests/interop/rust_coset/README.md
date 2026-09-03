# Rust coset interop

This target uses [coset](https://github.com/google/coset) 0.4.2 and RustCrypto
primitives, resolved exactly in `Cargo.lock`. `coset` handles COSE structure and
Sig_structure encoding while RustCrypto performs the signatures.

Its fixed test-key fixtures match the existing `t_cose` and go-cose
interoperability fixtures; they are not production credentials.

The live peer exchanges COSE_Sign1 messages with wolfCOSE in both directions:
ES256, Ed25519, ES256 with external AAD, untagged ES256, and detached ES256.
Each side verifies the protected algorithm and payload semantics, then rejects
a modified signature.
