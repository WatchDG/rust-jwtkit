use jwtkit::{Algorithm, HeaderBuilder, HmacSigner, Jwt, JwtBuilder, PayloadBuilder};

#[cfg(feature = "hs256")]
#[test]
fn test_jwt_sign_and_verify_hs256() {
    let header = HeaderBuilder::new(Algorithm::HS256).build();
    let payload = PayloadBuilder::new().sub("user123").exp(9999999999).build();

    let secret = b"my-secret-key";

    let jwt = Jwt::sign(&header, &payload, secret);

    assert!(jwt.verify(secret));
    assert_eq!(jwt.header.alg, Algorithm::HS256);
    assert_eq!(jwt.payload.sub, Some("user123".to_string()));
}

#[cfg(feature = "hs384")]
#[test]
fn test_jwt_sign_and_verify_hs384() {
    let header = HeaderBuilder::new(Algorithm::HS384).build();
    let payload = PayloadBuilder::new().iss("issuer").build();

    let secret = b"another-secret-key";

    let jwt = Jwt::sign(&header, &payload, secret);

    assert!(jwt.verify(secret));
    assert_eq!(jwt.header.alg, Algorithm::HS384);
}

#[cfg(feature = "hs512")]
#[test]
fn test_jwt_sign_and_verify_hs512() {
    let header = HeaderBuilder::new(Algorithm::HS512).build();
    let payload = PayloadBuilder::new().iat(1234567890).build();

    let secret = b"secure-key-512";

    let jwt = Jwt::sign(&header, &payload, secret);

    assert!(jwt.verify(secret));
    assert_eq!(jwt.header.alg, Algorithm::HS512);
}

#[cfg(feature = "hs256")]
#[test]
fn test_jwt_verify_wrong_secret() {
    let header = HeaderBuilder::new(Algorithm::HS256).build();
    let payload = PayloadBuilder::new().sub("user123").build();

    let secret = b"correct-secret";
    let wrong_secret = b"wrong-secret";

    let jwt = Jwt::sign(&header, &payload, secret);

    assert!(!jwt.verify(wrong_secret));
}

#[cfg(feature = "hs256")]
#[test]
fn test_jwt_to_string() {
    let header = HeaderBuilder::new(Algorithm::HS256).build();
    let payload = PayloadBuilder::new().sub("user123").build();

    let secret = b"secret";

    let jwt = Jwt::sign(&header, &payload, secret);
    let token = jwt.to_string();

    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
}

#[cfg(feature = "hs256")]
#[test]
fn test_jwt_from_string() {
    let header = HeaderBuilder::new(Algorithm::HS256).typ("JWT").build();
    let payload = PayloadBuilder::new()
        .sub("user456")
        .iss("test-issuer")
        .exp(9999999999)
        .build();

    let secret = b"my-secret";

    let jwt = Jwt::sign(&header, &payload, secret);
    let token = jwt.to_string();

    let parsed = Jwt::from_string_with_secret(&token, secret);
    assert!(parsed.is_some());

    let parsed = parsed.unwrap();
    assert_eq!(parsed.header.alg, Algorithm::HS256);
    assert_eq!(parsed.payload.sub, Some("user456".to_string()));
    assert_eq!(parsed.payload.iss, Some("test-issuer".to_string()));
}

#[cfg(feature = "hs256")]
#[test]
fn test_jwt_from_string_wrong_secret() {
    let header = HeaderBuilder::new(Algorithm::HS256).build();
    let payload = PayloadBuilder::new().sub("user123").build();

    let secret = b"correct";
    let wrong_secret = b"wrong";

    let jwt = Jwt::sign(&header, &payload, secret);
    let token = jwt.to_string();

    let parsed = Jwt::from_string_with_secret(&token, wrong_secret);
    assert!(parsed.is_none());
}

#[cfg(feature = "hs256")]
#[test]
fn test_jwt_from_invalid_string() {
    let invalid_token = "not.a.valid.token";
    let secret = b"secret";

    let parsed = Jwt::from_string_with_secret(invalid_token, secret);
    assert!(parsed.is_none());
}

#[cfg(feature = "hs256")]
#[test]
fn test_jwt_clone() {
    let header = HeaderBuilder::new(Algorithm::HS256).build();
    let payload = PayloadBuilder::new().build();
    let secret = b"secret";

    let jwt = Jwt::sign(&header, &payload, secret);
    let cloned = jwt.clone();

    assert_eq!(jwt.header, cloned.header);
    assert_eq!(jwt.payload, cloned.payload);
    assert_eq!(jwt.signature, cloned.signature);
}

#[cfg(feature = "hs256")]
#[test]
fn test_jwt_builder_with_header_and_payload() {
    let signer = HmacSigner::new(b"secret", Algorithm::HS256);
    let jwt = JwtBuilder::new()
        .header_with_builder(HeaderBuilder::new(Algorithm::HS256))
        .payload_with_builder(PayloadBuilder::new().sub("user").exp(9999999999))
        .signer(&signer)
        .build();

    assert!(jwt.verify(b"secret"));
    assert_eq!(jwt.header.alg, Algorithm::HS256);
    assert_eq!(jwt.payload.sub, Some("user".to_string()));
}

#[cfg(feature = "hs256")]
#[test]
fn test_jwt_builder_default_header() {
    let signer = HmacSigner::new(b"secret", Algorithm::HS256);
    let jwt = JwtBuilder::new()
        .payload_with_builder(PayloadBuilder::new().iss("issuer"))
        .signer(&signer)
        .build();

    assert!(jwt.verify(b"secret"));
    assert_eq!(jwt.header.alg, Algorithm::HS256);
    assert_eq!(jwt.payload.iss, Some("issuer".to_string()));
}

#[cfg(feature = "hs512")]
#[test]
fn test_jwt_builder_default_payload() {
    let signer = HmacSigner::new(b"secret", Algorithm::HS512);
    let jwt = JwtBuilder::new()
        .header_with_builder(HeaderBuilder::new(Algorithm::HS512))
        .signer(&signer)
        .build();

    assert!(jwt.verify(b"secret"));
    assert_eq!(jwt.header.alg, Algorithm::HS512);
    assert_eq!(jwt.payload.iss, None);
}

#[cfg(feature = "hs384")]
#[test]
fn test_jwt_builder_complete() {
    let signer = HmacSigner::new(b"secret", Algorithm::HS384);
    let jwt = JwtBuilder::new()
        .header_with_builder(HeaderBuilder::new(Algorithm::HS384).kid("key-id"))
        .payload_with_builder(
            PayloadBuilder::new()
                .iss("issuer")
                .sub("subject")
                .aud("audience")
                .exp(1234567890)
                .nbf(1234567800)
                .iat(1234560000)
                .jti("jwt-id"),
        )
        .signer(&signer)
        .build();

    assert!(jwt.verify(b"secret"));
    assert_eq!(jwt.header.alg, Algorithm::HS384);
    assert_eq!(jwt.header.kid, Some("key-id".to_string()));
    assert_eq!(jwt.payload.iss, Some("issuer".to_string()));
    assert_eq!(jwt.payload.sub, Some("subject".to_string()));
    assert_eq!(jwt.payload.aud, Some("audience".to_string()));
    assert_eq!(jwt.payload.exp, Some(1234567890));
    assert_eq!(jwt.payload.nbf, Some(1234567800));
    assert_eq!(jwt.payload.iat, Some(1234560000));
    assert_eq!(jwt.payload.jti, Some("jwt-id".to_string()));
}
