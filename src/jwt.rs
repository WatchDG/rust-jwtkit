use basekit::base64::{ALPHABET_BASE64_URL, Base64EncodeConfig, encode};
use hmac::Mac;

use crate::enums::Algorithm;
use crate::header::Header;
use crate::payload::Payload;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwt {
    pub header: Header,
    pub payload: Payload,
    pub signature: String,
}

impl Jwt {
    pub fn new(header: Header, payload: Payload, signature: String) -> Self {
        Self {
            header,
            payload,
            signature,
        }
    }

    pub fn sign(header: &Header, payload: &Payload, secret: &[u8]) -> Self {
        let header_encoded = header.encode();
        let payload_encoded = payload.encode();
        let signing_input = format!("{}.{}", header_encoded, payload_encoded);

        let signature = sign_data(&signing_input, secret, header.alg);

        Self {
            header: header.clone(),
            payload: payload.clone(),
            signature,
        }
    }

    pub fn verify(&self, secret: &[u8]) -> bool {
        let header_encoded = self.header.encode();
        let payload_encoded = self.payload.encode();
        let signing_input = format!("{}.{}", header_encoded, payload_encoded);

        let expected_signature = sign_data(&signing_input, secret, self.header.alg);
        self.signature == expected_signature
    }

    pub fn to_string(&self) -> String {
        format!(
            "{}.{}.{}",
            self.header.encode(),
            self.payload.encode(),
            self.signature
        )
    }

    pub fn from_string(token: &str, secret: &[u8]) -> Option<Self> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let header = Header::decode(parts[0])?;
        let payload = Payload::decode(parts[1])?;
        let signature = parts[2].to_string();

        let jwt = Self {
            header,
            payload,
            signature,
        };

        if jwt.verify(secret) { Some(jwt) } else { None }
    }
}

fn sign_data(data: &str, secret: &[u8], algorithm: Algorithm) -> String {
    let config = Base64EncodeConfig::new(ALPHABET_BASE64_URL, None);

    let signature = match algorithm {
        Algorithm::HS256 => {
            use hmac::Hmac;
            use sha2::Sha256;
            type HmacSha256 = Hmac<Sha256>;

            let mut mac =
                HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
            mac.update(data.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::HS384 => {
            use hmac::Hmac;
            use sha2::Sha384;
            type HmacSha384 = Hmac<Sha384>;

            let mut mac =
                HmacSha384::new_from_slice(secret).expect("HMAC can take key of any size");
            mac.update(data.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::HS512 => {
            use hmac::Hmac;
            use sha2::Sha512;
            type HmacSha512 = Hmac<Sha512>;

            let mut mac =
                HmacSha512::new_from_slice(secret).expect("HMAC can take key of any size");
            mac.update(data.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        _ => {
            panic!(
                "Unsupported algorithm for HMAC signing: {}",
                algorithm.name()
            );
        }
    };

    let output = encode(&config, &signature);
    String::try_from(output).unwrap()
}
