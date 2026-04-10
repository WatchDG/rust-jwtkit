use crate::enums::Algorithm;
use basekit::base64::{
    ALPHABET_BASE64_URL, Base64DecodeConfig, Base64EncodeConfig, DECODE_TABLE_BASE64_URL, decode,
    encode,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub alg: Algorithm,
    pub typ: Option<String>,
    pub kid: Option<String>,
}

impl Header {
    pub fn new(alg: Algorithm) -> Self {
        Self {
            alg,
            typ: Some("JWT".to_string()),
            kid: None,
        }
    }

    pub fn to_json(&self) -> String {
        let mut parts = Vec::new();

        parts.push(format!("\"alg\":\"{}\"", self.alg));

        if let Some(ref typ) = self.typ {
            parts.push(format!("\"typ\":\"{}\"", typ));
        }

        if let Some(ref kid) = self.kid {
            parts.push(format!("\"kid\":\"{}\"", kid));
        }

        format!("{{{}}}", parts.join(","))
    }

    pub fn from_json(json: &str) -> Option<Self> {
        let json = json.trim();
        if !json.starts_with('{') || !json.ends_with('}') {
            return None;
        }

        let content = &json[1..json.len() - 1];
        let mut alg: Option<Algorithm> = None;
        let mut typ: Option<String> = None;
        let mut kid: Option<String> = None;

        for part in content.split(',') {
            let part = part.trim();
            if let Some(colon_pos) = part.find(':') {
                let key = part[..colon_pos].trim().trim_matches('"');
                let value = part[colon_pos + 1..].trim().trim_matches('"');

                match key {
                    "alg" => {
                        alg = Algorithm::from_str(value);
                    }
                    "typ" => {
                        typ = Some(value.to_string());
                    }
                    "kid" => {
                        kid = Some(value.to_string());
                    }
                    _ => {}
                }
            }
        }

        alg.map(|a| Self { alg: a, typ, kid })
    }

    pub fn encode(&self) -> String {
        let json = self.to_json();
        let config = Base64EncodeConfig::new(ALPHABET_BASE64_URL, None);
        let output = encode(&config, json.as_bytes());
        String::try_from(output).unwrap()
    }

    pub fn decode(encoded: &str) -> Option<Self> {
        let config = Base64DecodeConfig::new(DECODE_TABLE_BASE64_URL, None);
        let output = decode(&config, encoded.as_bytes()).ok()?;
        let json = String::try_from(output).ok()?;
        Self::from_json(&json)
    }
}

impl Default for Header {
    fn default() -> Self {
        Self {
            alg: Algorithm::HS256,
            typ: Some("JWT".to_string()),
            kid: None,
        }
    }
}
