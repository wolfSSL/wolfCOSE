#!/usr/bin/env python3
"""Bidirectional COSE_Encrypt and COSE_Mac test peer using python-cwt."""

import sys

import cbor2
from cwt import COSE, COSEKey, Recipient


MAX_MESSAGE_SIZE = 2048
TAMPER_OFFSET = 30
PAYLOAD = b"wolfCOSE<->python-cwt COSE recipient interoperability"
EXTERNAL_AAD = b"wolfCOSE<->python-cwt external AAD"
IV = bytes(range(12))
DIRECT_KEY = bytes(range(0x00, 0x10))
KW_KEY = bytes(range(0x10, 0x20))
MAC_KEY = bytes(range(0x20, 0x40))
DIRECT_KID = b"cwt-direct"
KW_KID = b"cwt-kw"
ECDH_KID = b"cwt-ecdh"
MAC_KID = b"cwt-mac"
ECDH_CONTEXT = {"alg": "A128GCM"}

ECDH_PUBLIC_JWK = {
    "kty": "EC",
    "kid": ECDH_KID.decode(),
    "alg": "ECDH-ES+HKDF-256",
    "crv": "P-256",
    "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
    "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
}
ECDH_PRIVATE_JWK = {
    **ECDH_PUBLIC_JWK,
    "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
}

PSA_SIGN1_HEX = (
    "d28443a10126a0590100a819010058210102020202020202020202020202"
    "0202020202020202020202020202020202020219095c5820000000000000"
    "00000000000000000000000000000000000000000000000000000a582001"
    "010101010101010101010101010101010101010101010101010101010101"
    "0119095a1a7fffffff19095b19300019010978217461673a707361636572"
    "7469666965642e6f72672c323032333a7073612374666d19010c48000000"
    "000000000019095f81a30558200404040404040404040404040404040404"
    "040404040404040404040404040404025820030303030303030303030303"
    "0303030303030303030303030303030303030303016450526f545840786e"
    "937a4c42667af3847399319ca95c7e7dbabdc9b50fdb8de3f6bff4ab82ff"
    "80c42140e2a488000219e3e10663193da69c75f52b798ea10b2f7041a90e"
    "8e5a"
)
PSA_PUBLIC_JWK = {
    "kty": "EC",
    "alg": "ES256",
    "crv": "P-256",
    "x": "Tl4iCZ47zrRbRG0TVf0dw7VFlHtv18HInYhnmMNybo8",
    "y": "gNcLhAslaqw0pi7eEEM2TwRAlfADR0uR4Bggkq-xPy4",
}


def direct_key():
    return COSEKey.from_symmetric_key(DIRECT_KEY, alg="A128GCM", kid=DIRECT_KID)


def kw_key():
    return COSEKey.from_symmetric_key(KW_KEY, alg="A128KW", kid=KW_KID)


def mac_key():
    return COSEKey.from_symmetric_key(MAC_KEY, alg="HS256", kid=MAC_KID)


def encrypt_direct():
    key = direct_key()
    recipient = Recipient.new(unprotected={1: -6, 4: DIRECT_KID})
    return COSE.new().encode(
        PAYLOAD,
        key,
        protected={1: 1},
        unprotected={5: IV},
        recipients=[recipient],
        external_aad=EXTERNAL_AAD,
    )


def encrypt_a128kw():
    kek = kw_key()
    cek = COSEKey.from_symmetric_key(bytes(range(0x40, 0x50)), alg="A128GCM")
    recipient = Recipient.new(
        unprotected={1: -3, 4: KW_KID},
        sender_key=kek,
    )
    return COSE.new().encode(
        PAYLOAD,
        cek,
        protected={1: 1},
        unprotected={5: IV},
        recipients=[recipient],
        external_aad=EXTERNAL_AAD,
    )


def encrypt_ecdh_es():
    recipient_key = COSEKey.from_jwk(ECDH_PUBLIC_JWK)
    recipient = Recipient.new(
        protected={1: -25},
        unprotected={4: ECDH_KID},
        recipient_key=recipient_key,
        context=ECDH_CONTEXT,
    )
    return COSE.new().encode(
        PAYLOAD,
        protected={1: 1},
        unprotected={5: IV},
        recipients=[recipient],
        external_aad=EXTERNAL_AAD,
    )


def mac_direct():
    key = mac_key()
    recipient = Recipient.new(unprotected={1: -6, 4: MAC_KID})
    return COSE.new().encode(
        PAYLOAD,
        key,
        protected={1: 5},
        recipients=[recipient],
        external_aad=EXTERNAL_AAD,
    )


def decode_case(name, encoded):
    if name == "encrypt-direct":
        return COSE.new().decode(encoded, direct_key(), external_aad=EXTERNAL_AAD)
    if name == "encrypt-a128kw":
        return COSE.new().decode(encoded, kw_key(), external_aad=EXTERNAL_AAD)
    if name == "encrypt-ecdh-es":
        return COSE.new().decode(
            encoded,
            COSEKey.from_jwk(ECDH_PRIVATE_JWK),
            context=ECDH_CONTEXT,
            external_aad=EXTERNAL_AAD,
        )
    if name == "mac-direct":
        return COSE.new().decode(encoded, mac_key(), external_aad=EXTERNAL_AAD)
    raise ValueError(f"unknown case {name!r}")


def encode_case(name):
    if name == "encrypt-direct":
        return encrypt_direct()
    if name == "encrypt-a128kw":
        return encrypt_a128kw()
    if name == "encrypt-ecdh-es":
        return encrypt_ecdh_es()
    if name == "mac-direct":
        return mac_direct()
    raise ValueError(f"unknown case {name!r}")


def verify_case(name, encoded):
    plaintext = decode_case(name, encoded)
    if plaintext != PAYLOAD:
        raise ValueError("payload mismatch")
    if len(encoded) <= TAMPER_OFFSET:
        raise ValueError("message is too short for the tamper check")

    tampered = bytearray(encoded)
    tampered[TAMPER_OFFSET] ^= 0x01
    try:
        decode_case(name, bytes(tampered))
    except Exception:
        return
    raise ValueError("accepted a modified authenticated message")


def verify_psa_token():
    encoded = bytes.fromhex(PSA_SIGN1_HEX)
    payload = COSE.new().decode(encoded, COSEKey.from_jwk(PSA_PUBLIC_JWK))
    claims = cbor2.loads(payload)

    if claims.get(256) != b"\x01" + b"\x02" * 32:
        raise ValueError("RFC 9783 UEID claim mismatch")
    if claims.get(10) != b"\x01" * 32:
        raise ValueError("RFC 9783 nonce claim mismatch")
    if claims.get(265) != "tag:psacertified.org,2023:psa#tfm":
        raise ValueError("RFC 9783 profile claim mismatch")
    if claims.get(268) != b"\x00" * 8:
        raise ValueError("RFC 9783 boot seed claim mismatch")


def read_message():
    encoded = sys.stdin.buffer.read(MAX_MESSAGE_SIZE + 1)
    if not encoded or len(encoded) > MAX_MESSAGE_SIZE:
        raise ValueError(f"invalid message length {len(encoded)}")
    return encoded


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "psa":
        verify_psa_token()
        return
    if len(sys.argv) != 3:
        raise ValueError("usage: main.py sign|verify case, or main.py psa")

    mode, name = sys.argv[1:]
    if mode == "sign":
        sys.stdout.buffer.write(encode_case(name))
        return
    if mode == "verify":
        verify_case(name, read_message())
        return
    raise ValueError(f"unknown mode {mode!r}")


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(f"python-cwt interop: {err}", file=sys.stderr)
        sys.exit(1)
