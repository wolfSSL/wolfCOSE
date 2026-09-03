use std::io::{self, Read, Write};

use coset::{
    iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder,
    TaggedCborSerializable,
};
use ed25519_dalek::{Signer as _, Verifier as _};


const MAX_MESSAGE_SIZE: usize = 2048;
const PAYLOAD: &[u8] = b"wolfCOSE<->Rust coset COSE_Sign1 interoperability";
const EXTERNAL_AAD: &[u8] = b"wolfCOSE<->Rust coset external AAD";
const P256_PRIVATE: [u8; 32] = [
    0x03, 0x1c, 0xec, 0x64, 0x39, 0xa3, 0x1a, 0x44,
    0xfc, 0x9a, 0xe4, 0xd9, 0x2f, 0x9f, 0xc5, 0x3e,
    0x88, 0xcd, 0xd4, 0x08, 0x54, 0x16, 0xfb, 0x7f,
    0xec, 0x21, 0xd6, 0x2e, 0xa2, 0x79, 0xff, 0x77,
];
const ED25519_PRIVATE: [u8; 32] = [
    0x35, 0x05, 0x66, 0xd8, 0xc4, 0x2a, 0x7a, 0x73,
    0x46, 0x04, 0xb0, 0x40, 0xab, 0x1b, 0x69, 0x0a,
    0xd9, 0xfe, 0x0a, 0x85, 0x19, 0x5d, 0x36, 0xa4,
    0x60, 0x15, 0x6e, 0x99, 0x23, 0xdf, 0x8a, 0x6e,
];


#[derive(Clone, Copy)]
enum KeyKind {
    Es256,
    Ed25519,
}


#[derive(Clone, Copy)]
struct InteropCase {
    name: &'static str,
    algorithm: iana::Algorithm,
    key_kind: KeyKind,
    external_aad: &'static [u8],
    untagged: bool,
    detached: bool,
}


const CASES: [InteropCase; 5] = [
    InteropCase {
        name: "es256",
        algorithm: iana::Algorithm::ES256,
        key_kind: KeyKind::Es256,
        external_aad: b"",
        untagged: false,
        detached: false,
    },
    InteropCase {
        name: "ed25519",
        algorithm: iana::Algorithm::EdDSA,
        key_kind: KeyKind::Ed25519,
        external_aad: b"",
        untagged: false,
        detached: false,
    },
    InteropCase {
        name: "es256-aad",
        algorithm: iana::Algorithm::ES256,
        key_kind: KeyKind::Es256,
        external_aad: EXTERNAL_AAD,
        untagged: false,
        detached: false,
    },
    InteropCase {
        name: "es256-untagged",
        algorithm: iana::Algorithm::ES256,
        key_kind: KeyKind::Es256,
        external_aad: b"",
        untagged: true,
        detached: false,
    },
    InteropCase {
        name: "es256-detached",
        algorithm: iana::Algorithm::ES256,
        key_kind: KeyKind::Es256,
        external_aad: b"",
        untagged: false,
        detached: true,
    },
];


fn find_case(name: &str) -> Result<InteropCase, String> {
    CASES
        .iter()
        .find(|test_case| test_case.name == name)
        .copied()
        .ok_or_else(|| format!("unknown case {name:?}"))
}


fn es256_signing_key() -> Result<p256::ecdsa::SigningKey, String> {
    let secret = p256::SecretKey::from_slice(&P256_PRIVATE)
        .map_err(|err| format!("load fixed ES256 key: {err}"))?;
    Ok(p256::ecdsa::SigningKey::from(secret))
}


fn sign_case(test_case: InteropCase, data: &[u8]) -> Result<Vec<u8>, String> {
    match test_case.key_kind {
        KeyKind::Es256 => {
            let key = es256_signing_key()?;
            let signature: p256::ecdsa::Signature = key.sign(data);
            Ok(signature.to_bytes().to_vec())
        }
        KeyKind::Ed25519 => {
            let key = ed25519_dalek::SigningKey::from_bytes(&ED25519_PRIVATE);
            Ok(key.sign(data).to_bytes().to_vec())
        }
    }
}


fn verify_case(test_case: InteropCase, signature: &[u8], data: &[u8]) -> Result<(), String> {
    match test_case.key_kind {
        KeyKind::Es256 => {
            let key = es256_signing_key()?;
            let signature = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|err| format!("parse ES256 signature: {err}"))?;
            key.verifying_key()
                .verify(data, &signature)
                .map_err(|err| format!("verify ES256 signature: {err}"))
        }
        KeyKind::Ed25519 => {
            let key = ed25519_dalek::SigningKey::from_bytes(&ED25519_PRIVATE);
            let signature = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|err| format!("parse Ed25519 signature: {err}"))?;
            key.verifying_key()
                .verify(data, &signature)
                .map_err(|err| format!("verify Ed25519 signature: {err}"))
        }
    }
}


fn encode_case(test_case: InteropCase) -> Result<Vec<u8>, String> {
    let protected = HeaderBuilder::new().algorithm(test_case.algorithm).build();
    let builder = CoseSign1Builder::new().protected(protected);
    let sign1 = if test_case.detached {
        builder
            .try_create_detached_signature(PAYLOAD, test_case.external_aad, |data| {
                sign_case(test_case, data)
            })
            .map_err(|err| format!("create detached COSE_Sign1: {err}"))?
            .build()
    } else {
        builder
            .payload(PAYLOAD.to_vec())
            .try_create_signature(test_case.external_aad, |data| sign_case(test_case, data))
            .map_err(|err| format!("create COSE_Sign1: {err}"))?
            .build()
    };

    if test_case.untagged {
        sign1
            .to_vec()
            .map_err(|err| format!("encode untagged COSE_Sign1: {err}"))
    } else {
        sign1
            .to_tagged_vec()
            .map_err(|err| format!("encode tagged COSE_Sign1: {err}"))
    }
}


fn decode_sign1(test_case: InteropCase, encoded: &[u8]) -> Result<CoseSign1, String> {
    if test_case.untagged {
        CoseSign1::from_slice(encoded).map_err(|err| format!("decode untagged COSE_Sign1: {err}"))
    } else {
        CoseSign1::from_tagged_slice(encoded)
            .map_err(|err| format!("decode tagged COSE_Sign1: {err}"))
    }
}


fn verify_sign1(test_case: InteropCase, sign1: &CoseSign1) -> Result<(), String> {
    if sign1.protected.header.alg != Some(test_case.algorithm.into()) {
        return Err("COSE_Sign1 algorithm mismatch".to_owned());
    }

    if test_case.detached {
        if sign1.payload.is_some() {
            return Err("COSE_Sign1 carried an inline detached payload".to_owned());
        }
        sign1
            .verify_detached_signature(PAYLOAD, test_case.external_aad, |signature, data| {
                verify_case(test_case, signature, data)
            })
            .map_err(|err| format!("verify detached COSE_Sign1: {err}"))
    } else {
        if sign1.payload.as_deref() != Some(PAYLOAD) {
            return Err("COSE_Sign1 payload mismatch".to_owned());
        }
        sign1
            .verify_signature(test_case.external_aad, |signature, data| {
                verify_case(test_case, signature, data)
            })
            .map_err(|err| format!("verify COSE_Sign1: {err}"))
    }
}


fn read_message() -> Result<Vec<u8>, String> {
    let mut encoded = Vec::new();
    io::stdin()
        .take((MAX_MESSAGE_SIZE + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|err| format!("read COSE_Sign1: {err}"))?;
    if encoded.is_empty() || encoded.len() > MAX_MESSAGE_SIZE {
        return Err(format!("invalid message length {}", encoded.len()));
    }
    Ok(encoded)
}


fn run_verify(test_case: InteropCase) -> Result<(), String> {
    let encoded = read_message()?;
    let sign1 = decode_sign1(test_case, &encoded)?;
    verify_sign1(test_case, &sign1)?;

    let mut tampered = encoded;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    if let Ok(invalid) = decode_sign1(test_case, &tampered) {
        if verify_sign1(test_case, &invalid).is_ok() {
            return Err("accepted a modified signature".to_owned());
        }
    }
    Ok(())
}


fn main() {
    let result = match std::env::args().collect::<Vec<_>>().as_slice() {
        [_, mode, name] => match find_case(name) {
            Ok(test_case) if mode == "sign" => encode_case(test_case).and_then(|encoded| {
                io::stdout()
                    .write_all(&encoded)
                    .map_err(|err| format!("write COSE_Sign1: {err}"))
            }),
            Ok(test_case) if mode == "verify" => run_verify(test_case),
            Ok(_) => Err(format!("unknown mode {mode:?}")),
            Err(err) => Err(err),
        },
        _ => Err("usage: coset_oracle sign|verify case".to_owned()),
    };

    if let Err(err) = result {
        eprintln!("Rust coset interop: {err}");
        std::process::exit(1);
    }
}
