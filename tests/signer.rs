use jwtkit::{Algorithm, HeaderBuilder, HmacSigner, Jwt, PayloadBuilder, Signer};

#[cfg(feature = "hs256")]
#[test]
fn test_hmac_signer_hs256() {
    let signer = HmacSigner::new(b"secret", Algorithm::HS256);
    let data = "test data";

    let signature = signer.sign(data);
    assert!(!signature.is_empty());
    assert_eq!(signer.algorithm(), Algorithm::HS256);
}

#[cfg(feature = "hs384")]
#[test]
fn test_hmac_signer_hs384() {
    let signer = HmacSigner::new(b"secret", Algorithm::HS384);
    let data = "test data";

    let signature = signer.sign(data);
    assert!(!signature.is_empty());
    assert_eq!(signer.algorithm(), Algorithm::HS384);
}

#[cfg(feature = "hs512")]
#[test]
fn test_hmac_signer_hs512() {
    let signer = HmacSigner::new(b"secret", Algorithm::HS512);
    let data = "test data";

    let signature = signer.sign(data);
    assert!(!signature.is_empty());
    assert_eq!(signer.algorithm(), Algorithm::HS512);
}

#[cfg(feature = "hs256")]
#[test]
fn test_jwt_with_signer_hs256() {
    let signer = HmacSigner::new(b"secret-key", Algorithm::HS256);
    let header = HeaderBuilder::new(Algorithm::HS256).build();
    let payload = PayloadBuilder::new().sub("user123").exp(9999999999).build();

    let jwt = Jwt::sign_with_signer(&header, &payload, &signer);

    assert!(jwt.verify_with_signer(&signer));
    assert_eq!(jwt.header.alg, Algorithm::HS256);
}

#[cfg(feature = "hs384")]
#[test]
fn test_jwt_with_signer_hs384() {
    let signer = HmacSigner::new(b"secret-key", Algorithm::HS384);
    let header = HeaderBuilder::new(Algorithm::HS384).build();
    let payload = PayloadBuilder::new().sub("user123").exp(9999999999).build();

    let jwt = Jwt::sign_with_signer(&header, &payload, &signer);

    assert!(jwt.verify_with_signer(&signer));
    assert_eq!(jwt.header.alg, Algorithm::HS384);
}

#[cfg(feature = "hs512")]
#[test]
fn test_jwt_with_signer_hs512() {
    let signer = HmacSigner::new(b"secret-key", Algorithm::HS512);
    let header = HeaderBuilder::new(Algorithm::HS512).build();
    let payload = PayloadBuilder::new().sub("user123").exp(9999999999).build();

    let jwt = Jwt::sign_with_signer(&header, &payload, &signer);

    assert!(jwt.verify_with_signer(&signer));
    assert_eq!(jwt.header.alg, Algorithm::HS512);
}

#[cfg(feature = "hs256")]
#[test]
fn test_jwt_with_signer_wrong_key() {
    let signer1 = HmacSigner::new(b"correct-key", Algorithm::HS256);
    let signer2 = HmacSigner::new(b"wrong-key", Algorithm::HS256);

    let header = HeaderBuilder::new(Algorithm::HS256).build();
    let payload = PayloadBuilder::new().sub("user").build();

    let jwt = Jwt::sign_with_signer(&header, &payload, &signer1);

    assert!(!jwt.verify_with_signer(&signer2));
}

#[cfg(feature = "hs256")]
#[test]
fn test_jwt_from_string_with_signer() {
    let signer = HmacSigner::new(b"secret", Algorithm::HS256);
    let header = HeaderBuilder::new(Algorithm::HS256).build();
    let payload = PayloadBuilder::new().iss("issuer").sub("subject").build();

    let jwt = Jwt::sign_with_signer(&header, &payload, &signer);
    let token = jwt.to_string();

    let parsed = Jwt::from_string(&token, &signer);
    assert!(parsed.is_some());

    let parsed = parsed.unwrap();
    assert_eq!(parsed.header.alg, Algorithm::HS256);
    assert_eq!(parsed.payload.iss, Some("issuer".to_string()));
}

#[cfg(feature = "hs256")]
#[test]
fn test_hmac_signer_consistency() {
    let signer1 = HmacSigner::new(b"same-secret", Algorithm::HS256);
    let signer2 = HmacSigner::new(b"same-secret", Algorithm::HS256);

    let data = "consistent data";
    let sig1 = signer1.sign(data);
    let sig2 = signer2.sign(data);

    assert_eq!(sig1, sig2);
}

#[cfg(feature = "hs256")]
#[test]
fn test_different_secrets_different_signatures() {
    let signer1 = HmacSigner::new(b"secret1", Algorithm::HS256);
    let signer2 = HmacSigner::new(b"secret2", Algorithm::HS256);

    let data = "same data";
    let sig1 = signer1.sign(data);
    let sig2 = signer2.sign(data);

    assert_ne!(sig1, sig2);
}
