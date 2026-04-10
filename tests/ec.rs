use ecdsa::SigningKey;
use jwtkit::{Algorithm, EcSigner, EcVerifier, Signer};
use p256::NistP256;
use p384::NistP384;
use rand::rngs::OsRng;

fn generate_p256_keypair() -> (Vec<u8>, Vec<u8>) {
    use p256::elliptic_curve::SecretKey;

    let secret_key = SecretKey::<NistP256>::random(&mut OsRng);
    let signing_key = SigningKey::from(&secret_key);
    let public_key = signing_key.verifying_key();
    let private_bytes = secret_key.to_bytes().to_vec();
    let public_bytes = public_key.to_encoded_point(true).to_bytes().to_vec();
    (private_bytes, public_bytes)
}

fn generate_p384_keypair() -> (Vec<u8>, Vec<u8>) {
    use p384::elliptic_curve::SecretKey;

    let secret_key = SecretKey::<NistP384>::random(&mut OsRng);
    let signing_key = SigningKey::from(&secret_key);
    let public_key = signing_key.verifying_key();
    let private_bytes = secret_key.to_bytes().to_vec();
    let public_bytes = public_key.to_encoded_point(true).to_bytes().to_vec();
    (private_bytes, public_bytes)
}

#[cfg(feature = "es256")]
#[test]
fn test_ec_signer_es256() {
    let (private_key, _) = generate_p256_keypair();
    let signer = EcSigner::new(&private_key, Algorithm::ES256);
    let data = "test data";

    let signature = signer.sign(data);
    assert!(!signature.is_empty());
    assert_eq!(signer.algorithm(), Algorithm::ES256);
}

#[cfg(feature = "es384")]
#[test]
fn test_ec_signer_es384() {
    let (private_key, _) = generate_p384_keypair();
    let signer = EcSigner::new(&private_key, Algorithm::ES384);
    let data = "test data";

    let signature = signer.sign(data);
    assert!(!signature.is_empty());
    assert_eq!(signer.algorithm(), Algorithm::ES384);
}

#[cfg(feature = "es256")]
#[test]
fn test_ec_verifier_es256() {
    let (private_key, public_key) = generate_p256_keypair();
    let signer = EcSigner::new(&private_key, Algorithm::ES256);
    let verifier = EcVerifier::new(&public_key, Algorithm::ES256);
    let data = "test data";

    let signature = signer.sign(data);
    assert!(verifier.verify(data, &signature));
}

#[cfg(feature = "es384")]
#[test]
fn test_ec_verifier_es384() {
    let (private_key, public_key) = generate_p384_keypair();
    let signer = EcSigner::new(&private_key, Algorithm::ES384);
    let verifier = EcVerifier::new(&public_key, Algorithm::ES384);
    let data = "test data";

    let signature = signer.sign(data);
    assert!(verifier.verify(data, &signature));
}

#[cfg(feature = "es256")]
#[test]
fn test_ec_verifier_wrong_signature() {
    let (_, public_key) = generate_p256_keypair();
    let verifier = EcVerifier::new(&public_key, Algorithm::ES256);
    let data = "test data";
    let wrong_signature = "invalid_signature_base64url";

    assert!(!verifier.verify(data, wrong_signature));
}
