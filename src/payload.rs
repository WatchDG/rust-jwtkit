use basekit::base64::{
    ALPHABET_BASE64_URL, Base64DecodeConfig, Base64EncodeConfig, DECODE_TABLE_BASE64_URL, decode,
    encode,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<u64>,
    pub nbf: Option<u64>,
    pub iat: Option<u64>,
    pub jti: Option<String>,
}

impl Payload {
    pub fn new() -> Self {
        Self {
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
        }
    }

    pub fn to_json(&self) -> String {
        let mut parts = Vec::new();

        if let Some(ref iss) = self.iss {
            parts.push(format!("\"iss\":\"{}\"", iss));
        }

        if let Some(ref sub) = self.sub {
            parts.push(format!("\"sub\":\"{}\"", sub));
        }

        if let Some(ref aud) = self.aud {
            parts.push(format!("\"aud\":\"{}\"", aud));
        }

        if let Some(exp) = self.exp {
            parts.push(format!("\"exp\":{}", exp));
        }

        if let Some(nbf) = self.nbf {
            parts.push(format!("\"nbf\":{}", nbf));
        }

        if let Some(iat) = self.iat {
            parts.push(format!("\"iat\":{}", iat));
        }

        if let Some(ref jti) = self.jti {
            parts.push(format!("\"jti\":\"{}\"", jti));
        }

        format!("{{{}}}", parts.join(","))
    }

    pub fn from_json(json: &str) -> Option<Self> {
        let json = json.trim();
        if !json.starts_with('{') || !json.ends_with('}') {
            return None;
        }

        let content = &json[1..json.len() - 1];
        let mut iss: Option<String> = None;
        let mut sub: Option<String> = None;
        let mut aud: Option<String> = None;
        let mut exp: Option<u64> = None;
        let mut nbf: Option<u64> = None;
        let mut iat: Option<u64> = None;
        let mut jti: Option<String> = None;

        for part in content.split(',') {
            let part = part.trim();
            if let Some(colon_pos) = part.find(':') {
                let key = part[..colon_pos].trim().trim_matches('"');
                let value = part[colon_pos + 1..].trim();

                match key {
                    "iss" => {
                        iss = Some(value.trim_matches('"').to_string());
                    }
                    "sub" => {
                        sub = Some(value.trim_matches('"').to_string());
                    }
                    "aud" => {
                        aud = Some(value.trim_matches('"').to_string());
                    }
                    "exp" => {
                        exp = value.parse().ok();
                    }
                    "nbf" => {
                        nbf = value.parse().ok();
                    }
                    "iat" => {
                        iat = value.parse().ok();
                    }
                    "jti" => {
                        jti = Some(value.trim_matches('"').to_string());
                    }
                    _ => {}
                }
            }
        }

        Some(Self {
            iss,
            sub,
            aud,
            exp,
            nbf,
            iat,
            jti,
        })
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

impl Default for Payload {
    fn default() -> Self {
        Self::new()
    }
}
