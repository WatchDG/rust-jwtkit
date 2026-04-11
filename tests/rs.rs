#![cfg(any(feature = "rs256", feature = "rs384", feature = "rs512"))]

use jwtkit::{
    Algorithm, HeaderBuilder, JwtBuilder, PayloadBuilder, RsaSigner, RsaVerifier, Signer,
};
use rand::rngs::OsRng;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

fn generate_rsa_keypair(bits: usize) -> (RsaPrivateKey, RsaPublicKey) {
    let private_key = RsaPrivateKey::new(&mut OsRng, bits).expect("failed to generate RSA key");
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}

#[cfg(feature = "rs256")]
#[test]
fn test_rsa_signer_rs256() {
    let (private_key, _) = generate_rsa_keypair(2048);
    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();
    let signer = RsaSigner::new(&private_pem, Algorithm::RS256);
    let data = "test data";

    let signature = signer.sign(data);
    assert!(!signature.is_empty());
    assert_eq!(signer.algorithm(), Algorithm::RS256);
}

#[cfg(feature = "rs384")]
#[test]
fn test_rsa_signer_rs384() {
    let (private_key, _) = generate_rsa_keypair(2048);
    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();
    let signer = RsaSigner::new(&private_pem, Algorithm::RS384);
    let data = "test data";

    let signature = signer.sign(data);
    assert!(!signature.is_empty());
    assert_eq!(signer.algorithm(), Algorithm::RS384);
}

#[cfg(feature = "rs512")]
#[test]
fn test_rsa_signer_rs512() {
    let (private_key, _) = generate_rsa_keypair(2048);
    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();
    let signer = RsaSigner::new(&private_pem, Algorithm::RS512);
    let data = "test data";

    let signature = signer.sign(data);
    assert!(!signature.is_empty());
    assert_eq!(signer.algorithm(), Algorithm::RS512);
}

#[cfg(feature = "rs256")]
#[test]
fn test_jwt_with_rsa_signer_rs256() {
    let (private_key, public_key) = generate_rsa_keypair(2048);
    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();
    let public_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    let signer = RsaSigner::new(&private_pem, Algorithm::RS256);

    let jwt = JwtBuilder::new()
        .header_with_builder(HeaderBuilder::new(Algorithm::RS256))
        .payload_with_builder(PayloadBuilder::new().sub("user123").exp(9999999999))
        .signer(&signer)
        .build();

    let verifier = RsaVerifier::new(&public_pem, Algorithm::RS256);
    let header_encoded = jwt.header.encode();
    let payload_encoded = jwt.payload.encode();
    let signing_input = format!("{}.{}", header_encoded, payload_encoded);

    assert!(verifier.verify(&signing_input, &jwt.signature));
    assert_eq!(jwt.header.alg, Algorithm::RS256);
}

#[cfg(feature = "rs384")]
#[test]
fn test_jwt_with_rsa_signer_rs384() {
    let (private_key, public_key) = generate_rsa_keypair(2048);
    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();
    let public_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    let signer = RsaSigner::new(&private_pem, Algorithm::RS384);

    let jwt = JwtBuilder::new()
        .header_with_builder(HeaderBuilder::new(Algorithm::RS384))
        .payload_with_builder(PayloadBuilder::new().sub("user456").iss("issuer"))
        .signer(&signer)
        .build();

    let verifier = RsaVerifier::new(&public_pem, Algorithm::RS384);
    let header_encoded = jwt.header.encode();
    let payload_encoded = jwt.payload.encode();
    let signing_input = format!("{}.{}", header_encoded, payload_encoded);

    assert!(verifier.verify(&signing_input, &jwt.signature));
    assert_eq!(jwt.header.alg, Algorithm::RS384);
}

#[cfg(feature = "rs512")]
#[test]
fn test_jwt_with_rsa_signer_rs512() {
    let (private_key, public_key) = generate_rsa_keypair(2048);
    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();
    let public_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    let signer = RsaSigner::new(&private_pem, Algorithm::RS512);

    let jwt = JwtBuilder::new()
        .header_with_builder(HeaderBuilder::new(Algorithm::RS512))
        .payload_with_builder(PayloadBuilder::new().sub("user789").iat(1234567890))
        .signer(&signer)
        .build();

    let verifier = RsaVerifier::new(&public_pem, Algorithm::RS512);
    let header_encoded = jwt.header.encode();
    let payload_encoded = jwt.payload.encode();
    let signing_input = format!("{}.{}", header_encoded, payload_encoded);

    assert!(verifier.verify(&signing_input, &jwt.signature));
    assert_eq!(jwt.header.alg, Algorithm::RS512);
}

#[cfg(feature = "rs256")]
#[test]
fn test_rsa_verifier_wrong_signature() {
    let (_, public_key) = generate_rsa_keypair(2048);
    let public_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    let verifier = RsaVerifier::new(&public_pem, Algorithm::RS256);

    let data = "test data";
    let wrong_signature = "invalid_signature_base64url";

    assert!(!verifier.verify(data, wrong_signature));
}
