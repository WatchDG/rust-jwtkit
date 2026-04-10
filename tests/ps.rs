#![cfg(any(feature = "ps256", feature = "ps384", feature = "ps512"))]

use jwtkit::{Algorithm, PssSigner, PssVerifier, Signer};
use rand::rngs::OsRng;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

fn generate_rsa_keypair(bits: usize) -> (String, String) {
    let private_key = RsaPrivateKey::new(&mut OsRng, bits).expect("failed to generate RSA key");
    let public_key = RsaPublicKey::from(&private_key);
    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();
    let public_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();
    (private_pem, public_pem)
}

#[cfg(feature = "ps256")]
#[test]
fn test_pss_signer_ps256() {
    let (private_key, _) = generate_rsa_keypair(2048);
    let signer = PssSigner::new(&private_key, Algorithm::PS256);
    let data = "test data";

    let signature = signer.sign(data);
    assert!(!signature.is_empty());
    assert_eq!(signer.algorithm(), Algorithm::PS256);
}

#[cfg(feature = "ps384")]
#[test]
fn test_pss_signer_ps384() {
    let (private_key, _) = generate_rsa_keypair(2048);
    let signer = PssSigner::new(&private_key, Algorithm::PS384);
    let data = "test data";

    let signature = signer.sign(data);
    assert!(!signature.is_empty());
    assert_eq!(signer.algorithm(), Algorithm::PS384);
}

#[cfg(feature = "ps512")]
#[test]
fn test_pss_signer_ps512() {
    let (private_key, _) = generate_rsa_keypair(2048);
    let signer = PssSigner::new(&private_key, Algorithm::PS512);
    let data = "test data";

    let signature = signer.sign(data);
    assert!(!signature.is_empty());
    assert_eq!(signer.algorithm(), Algorithm::PS512);
}

#[cfg(feature = "ps256")]
#[test]
fn test_jwt_with_pss_signer_ps256() {
    let (private_key, public_key) = generate_rsa_keypair(2048);
    let signer = PssSigner::new(&private_key, Algorithm::PS256);
    let verifier = PssVerifier::new(&public_key, Algorithm::PS256);
    let data = "test data";

    let signature = signer.sign(data);
    assert!(verifier.verify(data, &signature));
}

#[cfg(feature = "ps384")]
#[test]
fn test_jwt_with_pss_signer_ps384() {
    let (private_key, public_key) = generate_rsa_keypair(2048);
    let signer = PssSigner::new(&private_key, Algorithm::PS384);
    let verifier = PssVerifier::new(&public_key, Algorithm::PS384);
    let data = "test data";

    let signature = signer.sign(data);
    assert!(verifier.verify(data, &signature));
}

#[cfg(feature = "ps512")]
#[test]
fn test_jwt_with_pss_signer_ps512() {
    let (private_key, public_key) = generate_rsa_keypair(2048);
    let signer = PssSigner::new(&private_key, Algorithm::PS512);
    let verifier = PssVerifier::new(&public_key, Algorithm::PS512);
    let data = "test data";

    let signature = signer.sign(data);
    assert!(verifier.verify(data, &signature));
}

#[cfg(feature = "ps256")]
#[test]
fn test_pss_verifier_wrong_signature() {
    let (_, public_key) = generate_rsa_keypair(2048);
    let verifier = PssVerifier::new(&public_key, Algorithm::PS256);
    let data = "test data";
    let wrong_signature = "invalid_signature_base64url";

    assert!(!verifier.verify(data, wrong_signature));
}
