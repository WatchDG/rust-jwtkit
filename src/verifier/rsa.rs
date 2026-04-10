use crate::enums::Algorithm;
use basekit::base64::{Base64DecodeConfig, DECODE_TABLE_BASE64_URL, decode};

pub struct RsaVerifier {
    public_key_pem: String,
    algorithm: Algorithm,
}

impl RsaVerifier {
    pub fn new(public_key_pem: &str, algorithm: Algorithm) -> Self {
        Self {
            public_key_pem: public_key_pem.to_string(),
            algorithm,
        }
    }

    pub fn verify(&self, data: &str, signature: &str) -> bool {
        use rsa::RsaPublicKey;
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::pkcs1v15::VerifyingKey;
        use rsa::pkcs8::DecodePublicKey;
        use rsa::signature::Verifier;

        let signature_bytes: Vec<u8> = match decode(
            &Base64DecodeConfig::new(DECODE_TABLE_BASE64_URL, None),
            signature.as_bytes(),
        ) {
            Ok(output) => output.into(),
            Err(_) => return false,
        };

        let public_key = match RsaPublicKey::from_public_key_pem(&self.public_key_pem) {
            Ok(key) => key,
            Err(_) => match RsaPublicKey::from_pkcs1_pem(&self.public_key_pem) {
                Ok(key) => key,
                Err(_) => return false,
            },
        };

        let sig = match rsa::pkcs1v15::Signature::try_from(signature_bytes.as_slice()) {
            Ok(s) => s,
            Err(_) => return false,
        };

        match self.algorithm {
            #[cfg(feature = "rs256")]
            Algorithm::RS256 => {
                let verifying_key = VerifyingKey::<sha2::Sha256>::new_unprefixed(public_key);
                verifying_key.verify(data.as_bytes(), &sig).is_ok()
            }
            #[cfg(not(feature = "rs256"))]
            Algorithm::RS256 => false,
            #[cfg(feature = "rs384")]
            Algorithm::RS384 => {
                let verifying_key = VerifyingKey::<sha2::Sha384>::new_unprefixed(public_key);
                verifying_key.verify(data.as_bytes(), &sig).is_ok()
            }
            #[cfg(not(feature = "rs384"))]
            Algorithm::RS384 => false,
            #[cfg(feature = "rs512")]
            Algorithm::RS512 => {
                let verifying_key = VerifyingKey::<sha2::Sha512>::new_unprefixed(public_key);
                verifying_key.verify(data.as_bytes(), &sig).is_ok()
            }
            #[cfg(not(feature = "rs512"))]
            Algorithm::RS512 => false,
            _ => false,
        }
    }
}
