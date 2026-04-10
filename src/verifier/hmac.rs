use crate::enums::Algorithm;
use basekit::base64::{Base64DecodeConfig, DECODE_TABLE_BASE64_URL, decode};

pub struct HmacVerifier {
    secret: Vec<u8>,
    algorithm: Algorithm,
}

impl HmacVerifier {
    pub fn new(secret: &[u8], algorithm: Algorithm) -> Self {
        Self {
            secret: secret.to_vec(),
            algorithm,
        }
    }

    pub fn verify(&self, data: &str, signature: &str) -> bool {
        use hmac::Hmac;
        use hmac::Mac;

        let signature_bytes: Vec<u8> = match decode(
            &Base64DecodeConfig::new(DECODE_TABLE_BASE64_URL, None),
            signature.as_bytes(),
        ) {
            Ok(output) => output.into(),
            Err(_) => return false,
        };

        match self.algorithm {
            #[cfg(feature = "hs256")]
            Algorithm::HS256 => {
                use sha2::Sha256;
                type HmacSha256 = Hmac<Sha256>;

                let mut mac = match HmacSha256::new_from_slice(&self.secret) {
                    Ok(m) => m,
                    Err(_) => return false,
                };
                mac.update(data.as_bytes());
                mac.verify_slice(&signature_bytes).is_ok()
            }
            #[cfg(not(feature = "hs256"))]
            Algorithm::HS256 => false,
            #[cfg(feature = "hs384")]
            Algorithm::HS384 => {
                use sha2::Sha384;
                type HmacSha384 = Hmac<Sha384>;

                let mut mac = match HmacSha384::new_from_slice(&self.secret) {
                    Ok(m) => m,
                    Err(_) => return false,
                };
                mac.update(data.as_bytes());
                mac.verify_slice(&signature_bytes).is_ok()
            }
            #[cfg(not(feature = "hs384"))]
            Algorithm::HS384 => false,
            #[cfg(feature = "hs512")]
            Algorithm::HS512 => {
                use sha2::Sha512;
                type HmacSha512 = Hmac<Sha512>;

                let mut mac = match HmacSha512::new_from_slice(&self.secret) {
                    Ok(m) => m,
                    Err(_) => return false,
                };
                mac.update(data.as_bytes());
                mac.verify_slice(&signature_bytes).is_ok()
            }
            #[cfg(not(feature = "hs512"))]
            Algorithm::HS512 => false,
            _ => false,
        }
    }
}
