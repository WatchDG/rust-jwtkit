use jwtkit::{Payload, PayloadBuilder};

#[test]
fn test_payload_creation() {
    let payload = Payload::new();
    assert_eq!(payload.iss, None);
    assert_eq!(payload.sub, None);
    assert_eq!(payload.aud, None);
    assert_eq!(payload.exp, None);
    assert_eq!(payload.nbf, None);
    assert_eq!(payload.iat, None);
    assert_eq!(payload.jti, None);
}

#[test]
fn test_payload_builder() {
    let payload = PayloadBuilder::new()
        .iss("issuer")
        .sub("subject")
        .aud("audience")
        .exp(1234567890)
        .nbf(1234567800)
        .iat(1234560000)
        .jti("unique-id")
        .build();

    assert_eq!(payload.iss, Some("issuer".to_string()));
    assert_eq!(payload.sub, Some("subject".to_string()));
    assert_eq!(payload.aud, Some("audience".to_string()));
    assert_eq!(payload.exp, Some(1234567890));
    assert_eq!(payload.nbf, Some(1234567800));
    assert_eq!(payload.iat, Some(1234560000));
    assert_eq!(payload.jti, Some("unique-id".to_string()));
}

#[test]
fn test_payload_default() {
    let payload = Payload::default();
    assert_eq!(payload.iss, None);
}

#[test]
fn test_payload_to_json() {
    let payload = PayloadBuilder::new().sub("user123").exp(1234567890).build();

    let json = payload.to_json();
    assert!(json.contains("\"sub\":\"user123\""));
    assert!(json.contains("\"exp\":1234567890"));
}

#[test]
fn test_payload_from_json() {
    let json = r#"{"sub":"user123","exp":1234567890,"iss":"issuer"}"#;
    let payload = Payload::from_json(json).unwrap();

    assert_eq!(payload.sub, Some("user123".to_string()));
    assert_eq!(payload.exp, Some(1234567890));
    assert_eq!(payload.iss, Some("issuer".to_string()));
}

#[test]
fn test_payload_encode_decode() {
    let payload = PayloadBuilder::new()
        .iss("test-issuer")
        .sub("test-subject")
        .exp(9999999999)
        .build();

    let encoded = payload.encode();
    let decoded = Payload::decode(&encoded).unwrap();

    assert_eq!(decoded.iss, payload.iss);
    assert_eq!(decoded.sub, payload.sub);
    assert_eq!(decoded.exp, payload.exp);
}

#[test]
fn test_payload_empty_encode_decode() {
    let payload = Payload::new();
    let encoded = payload.encode();
    let decoded = Payload::decode(&encoded).unwrap();

    assert_eq!(decoded.iss, None);
    assert_eq!(decoded.sub, None);
}
