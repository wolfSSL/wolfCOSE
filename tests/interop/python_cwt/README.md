# python-cwt interop

`main.py` is a live peer for `interop_python_cwt.c`, using
[python-cwt](https://github.com/ritou/cwt) 3.3.0. The fully pinned
`requirements.txt` keeps the Python dependency set reproducible.

The target exchanges tagged `COSE_Encrypt` and `COSE_Mac` messages in both
directions for A128GCM direct use, ECDH-ES plus HKDF-SHA-256, and HMAC-256
direct MAC recipients. It also verifies python-cwt's A128KW producer output
with wolfCOSE. python-cwt 3.3.0 rejects the standards-compliant protected
recipient algorithm used by wolfCOSE's A128KW producer, so the reverse
direction is intentionally covered by the fixed COSE WG A128KW vector instead
of changing wolfCOSE's output. Every live case uses external AAD, checks the
decoded payload, and rejects a modified authenticated byte. The Python peer
also verifies and CBOR-decodes the RFC 9783 PSA attestation token,
independently exercising its EAT claims.
