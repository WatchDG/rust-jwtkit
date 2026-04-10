use crate::header::Header;
use crate::payload::Payload;
use crate::signer::Signer;

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

    pub fn sign_with_signer(header: &Header, payload: &Payload, signer: &dyn Signer) -> Self {
        let header_encoded = header.encode();
        let payload_encoded = payload.encode();
        let signing_input = format!("{}.{}", header_encoded, payload_encoded);
        let signature = signer.sign(&signing_input);

        Self {
            header: header.clone(),
            payload: payload.clone(),
            signature,
        }
    }

    pub fn verify_with_signer(&self, signer: &dyn Signer) -> bool {
        let header_encoded = self.header.encode();
        let payload_encoded = self.payload.encode();
        let signing_input = format!("{}.{}", header_encoded, payload_encoded);
        let expected_signature = signer.sign(&signing_input);
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

    pub fn from_string(token: &str, signer: &dyn Signer) -> Option<Self> {
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

        if jwt.verify_with_signer(signer) {
            Some(jwt)
        } else {
            None
        }
    }
}

#[cfg(any(feature = "hs256", feature = "hs384", feature = "hs512"))]
mod hmac_support {
    use super::Jwt;
    use crate::header::Header;
    use crate::payload::Payload;
    use crate::signer::HmacSigner;

    impl Jwt {
        pub fn sign(header: &Header, payload: &Payload, secret: &[u8]) -> Self {
            let signer = HmacSigner::new(secret, header.alg);
            Self::sign_with_signer(header, payload, &signer)
        }

        pub fn verify(&self, secret: &[u8]) -> bool {
            let signer = HmacSigner::new(secret, self.header.alg);
            self.verify_with_signer(&signer)
        }

        pub fn from_string_with_secret(token: &str, secret: &[u8]) -> Option<Self> {
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
}
