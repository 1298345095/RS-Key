// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

// NIST KAS ECC CDH primitive vectors, P-256 COUNT = 0.
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/component-testing
const NIST_SK: &str = "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534";
const NIST_PK_X: &str = "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230";
const NIST_PK_Y: &str = "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141";
const NIST_PEER_X: &str = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287";
const NIST_PEER_Y: &str = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";
const NIST_SHARED: &str = "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b";

// RFC 6979 A.2.5, P-256 / SHA-256 / message "sample"; r and s encoded as DER.
// https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.5
const RFC6979_PUBLIC: &str = concat!(
    "04",
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
);
const RFC6979_SIGNATURE: &str = concat!(
    "3046022100",
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
    "022100",
    "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
);

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn bytes32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

#[test]
fn ecdh_matches_nist_known_answer_and_public_coordinates() {
    let sk = SecretKey::from_slice(&unhex(NIST_SK)).unwrap();
    let public = sk.public_key().to_sec1_point(false);
    assert_eq!(public.x().unwrap().as_slice(), unhex(NIST_PK_X));
    assert_eq!(public.y().unwrap().as_slice(), unhex(NIST_PK_Y));
    assert_eq!(
        ecdh_raw(&sk, &bytes32(NIST_PEER_X), &bytes32(NIST_PEER_Y)),
        Some(bytes32(NIST_SHARED)),
    );
}

#[test]
fn ecdh_keeps_leading_zero_bytes_in_shared_secret() {
    // Wycheproof ecdh_secp256r1_test.json tcId 3 and 5, both valid edge cases.
    // https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/ecdh_secp256r1_test.json
    let sk = SecretKey::from_slice(&unhex(
        "0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a",
    ))
    .unwrap();
    for (x, y, shared) in [
        (
            "58fd4168a87795603e2b04390285bdca6e57de6027fe211dd9d25e2212d29e62",
            "080d36bd224d7405509295eed02a17150e03b314f96da37445b0d1d29377d12c",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "1b0e7437c33d379929430d3ec10df59bed7fe2a1d950c5791e1e9ddeef1f4d70",
            "fbdb0e3bbce63a27f27838c685207f2ccaf689d25eb622744db1168ac92619e8",
            "0000000000000000000000000000000000000000000000000000000000010000",
        ),
    ] {
        assert_eq!(
            ecdh_raw(&sk, &bytes32(x), &bytes32(y)),
            Some(bytes32(shared)),
        );
    }
}

#[test]
fn ecdh_rejects_off_curve_and_out_of_field_coordinates() {
    let sk = SecretKey::from_slice(&unhex(NIST_SK)).unwrap();
    let x = bytes32(NIST_PEER_X);
    let y = bytes32(NIST_PEER_Y);
    let prime = bytes32("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    let mut wrong_y = y;
    wrong_y[31] ^= 1;
    for (px, py) in [([0; 32], [0; 32]), (prime, y), (x, prime), (x, wrong_y)] {
        assert_eq!(ecdh_raw(&sk, &px, &py), None);
    }
}

#[test]
fn generated_ecdh_public_key_keeps_uncompressed_sec1_coordinates() {
    let (sk, x, y) = ecdh_pub();
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    assert_eq!(sec1.len(), 65);
    assert_eq!(sk.public_key().to_sec1_point(false).as_bytes(), sec1);
    assert_eq!(PublicKey::from_sec1_bytes(&sec1).unwrap(), sk.public_key());
}

#[test]
fn client_pin_cose_wire_format_and_coordinate_padding_are_unchanged() {
    let key = cose_key(&bytes32(NIST_PK_X), &bytes32(NIST_PK_Y));
    assert_eq!(
        cbor(&key),
        unhex(concat!(
            "a501020338182001215820",
            "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230",
            "225820",
            "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
        )),
    );
    assert_eq!(coord(&key, -2).unwrap(), bytes32(NIST_PK_X));
    assert_eq!(coord(&key, -3).unwrap(), bytes32(NIST_PK_Y));
    let short = cose_key(&[1], &[2]);
    let mut padded = [0; 32];
    padded[31] = 1;
    assert_eq!(coord(&short, -2).unwrap(), padded);
    assert!(coord(&cose_key(&[1; 33], &[2]), -2).is_err());
}

#[test]
fn client_pin_protocol_two_hkdf_matches_fixed_sha256_bytes() {
    // Independently derived with Python hashlib/hmac using the NIST shared secret.
    assert_eq!(
        hkdf32(&[0; 32], &bytes32(NIST_SHARED), b"CTAP2 AES key"),
        bytes32("6d364545305064c054b8250f1b2c4305381e74f6039e0170f393d06e249592ac"),
    );
}

#[test]
fn mse_hkdf_matches_fixed_peer_sec1_info_bytes() {
    let aad = unhex(concat!(
        "04",
        "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
        "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
    ));
    assert_eq!(aad.len(), 65);
    assert_eq!(
        hkdf32(b"", &bytes32(NIST_SHARED), &aad),
        bytes32("2b9728cfd82f4f9e0d3de9cc5e1b7f5198cffd165913f928e8f2573f2b0b9f89"),
    );
}

#[test]
fn ecdsa_verifies_rfc6979_signature_with_both_sec1_encodings() {
    let public = unhex(RFC6979_PUBLIC);
    let signature = unhex(RFC6979_SIGNATURE);
    assert_eq!(
        verify_p256_signature(&public, &signature, b"sample"),
        Ok(())
    );
    let mut compressed = vec![0x03];
    compressed.extend_from_slice(&public[1..33]);
    assert_eq!(
        verify_p256_signature(&compressed, &signature, b"sample"),
        Ok(()),
    );
}

#[test]
fn ecdsa_rejects_wrong_message_key_and_signature() {
    let public = unhex(RFC6979_PUBLIC);
    let signature = unhex(RFC6979_SIGNATURE);
    let wrong_key = SecretKey::from_slice(&unhex(NIST_SK))
        .unwrap()
        .public_key()
        .to_sec1_point(false);
    let mut wrong_signature = signature.clone();
    wrong_signature[35] ^= 1;
    for (key, der, msg) in [
        (
            public.as_slice(),
            signature.as_slice(),
            b"samplf".as_slice(),
        ),
        (
            wrong_key.as_bytes(),
            signature.as_slice(),
            b"sample".as_slice(),
        ),
        (
            public.as_slice(),
            wrong_signature.as_slice(),
            b"sample".as_slice(),
        ),
    ] {
        assert_eq!(
            verify_p256_signature(key, der, msg).unwrap_err(),
            "SIGNATURE INVALID — this device cannot prove its identity",
        );
    }
}

#[test]
fn ecdsa_rejects_malformed_sec1_public_keys() {
    let signature = unhex(RFC6979_SIGNATURE);
    let mut off_curve = unhex(RFC6979_PUBLIC);
    off_curve[64] ^= 1;
    for key in [vec![0x00], vec![0x04; 64], off_curve] {
        assert_eq!(
            verify_p256_signature(&key, &signature, b"sample").unwrap_err(),
            "bad attestation pubkey",
        );
    }
}

#[test]
fn ecdsa_rejects_malformed_der_before_signature_verification() {
    let public = unhex(RFC6979_PUBLIC);
    let signature = unhex(RFC6979_SIGNATURE);
    let mut wrong_tag = signature.clone();
    wrong_tag[0] = 0x31;
    let mut trailing_data = signature.clone();
    trailing_data.push(0);
    for der in [
        signature[..signature.len() - 1].to_vec(),
        wrong_tag,
        trailing_data,
        unhex("3006020100020101"),
        unhex("3006020180020101"),
        unhex("300702020001020101"),
    ] {
        assert_eq!(
            verify_p256_signature(&public, &der, b"sample").unwrap_err(),
            "bad signature DER",
        );
    }
}
