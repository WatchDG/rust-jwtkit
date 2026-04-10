use jwtkit::{Algorithm, Header, HeaderBuilder};

#[test]
fn test_header_creation() {
    let header = Header::new(Algorithm::HS256);
    assert_eq!(header.alg, Algorithm::HS256);
    assert_eq!(header.typ, Some("JWT".to_string()));
    assert_eq!(header.kid, None);
}

#[test]
fn test_header_with_options() {
    let header = HeaderBuilder::new(Algorithm::RS256)
        .typ("JWT")
        .kid("my-key-id")
        .build();

    assert_eq!(header.alg, Algorithm::RS256);
    assert_eq!(header.typ, Some("JWT".to_string()));
    assert_eq!(header.kid, Some("my-key-id".to_string()));
}

#[test]
fn test_header_default() {
    let header = Header::default();
    assert_eq!(header.alg, Algorithm::HS256);
    assert_eq!(header.typ, Some("JWT".to_string()));
}

#[test]
fn test_algorithm_name() {
    assert_eq!(Algorithm::HS256.name(), "HS256");
    assert_eq!(Algorithm::RS512.name(), "RS512");
    assert_eq!(Algorithm::EdDSA.name(), "EdDSA");
}

#[test]
fn test_algorithm_from_str() {
    assert_eq!(Algorithm::from_str("HS256"), Some(Algorithm::HS256));
    assert_eq!(Algorithm::from_str("RS512"), Some(Algorithm::RS512));
    assert_eq!(Algorithm::from_str("EdDSA"), Some(Algorithm::EdDSA));
    assert_eq!(Algorithm::from_str("INVALID"), None);
}

#[test]
fn test_header_to_json() {
    let header = Header::new(Algorithm::HS256);
    let json = header.to_json();
    assert!(json.contains("\"alg\":\"HS256\""));
    assert!(json.contains("\"typ\":\"JWT\""));
}

#[test]
fn test_header_from_json() {
    let json = r#"{"alg":"RS256","typ":"JWT","kid":"key-123"}"#;
    let header = Header::from_json(json).unwrap();
    assert_eq!(header.alg, Algorithm::RS256);
    assert_eq!(header.typ, Some("JWT".to_string()));
    assert_eq!(header.kid, Some("key-123".to_string()));
}

#[test]
fn test_header_encode_decode() {
    let header = HeaderBuilder::new(Algorithm::ES256)
        .typ("JWT")
        .kid("es256-key")
        .build();

    let encoded = header.encode();
    let decoded = Header::decode(&encoded).unwrap();

    assert_eq!(decoded.alg, header.alg);
    assert_eq!(decoded.typ, header.typ);
    assert_eq!(decoded.kid, header.kid);
}

#[test]
fn test_header_without_optional_fields() {
    let json = r#"{"alg":"HS256"}"#;
    let header = Header::from_json(json).unwrap();
    assert_eq!(header.alg, Algorithm::HS256);
    assert_eq!(header.typ, None);
    assert_eq!(header.kid, None);
}

#[test]
fn test_header_algorithm_display() {
    assert_eq!(format!("{}", Algorithm::HS384), "HS384");
    assert_eq!(format!("{}", Algorithm::ES256), "ES256");
}
