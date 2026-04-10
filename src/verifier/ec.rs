use crate::enums::Algorithm;
use basekit::base64::{Base64DecodeConfig, DECODE_TABLE_BASE64_URL, decode};

pub struct EcVerifier {
    public_key_bytes: Vec<u8>,
    algorithm: Algorithm,
}

impl EcVerifier {
    pub fn new(public_key_bytes: &[u8], algorithm: Algorithm) -> Self {
        Self {
            public_key_bytes: public_key_bytes.to_vec(),
            algorithm,
        }
    }

    pub fn verify(&self, data: &str, signature: &str) -> bool {
        use ecdsa::VerifyingKey;
        use ecdsa::signature::Verifier;

        let signature_bytes: Vec<u8> = match decode(
            &Base64DecodeConfig::new(DECODE_TABLE_BASE64_URL, None),
            signature.as_bytes(),
        ) {
            Ok(output) => output.into(),
            Err(_) => return false,
        };

        let result = match self.algorithm {
            #[cfg(feature = "es256")]
            Algorithm::ES256 => {
                use p256::NistP256;
                use p256::elliptic_curve::PublicKey;

                let public_key =
                    match PublicKey::<NistP256>::from_sec1_bytes(&self.public_key_bytes) {
                        Ok(pk) => pk,
                        Err(_) => return false,
                    };

                let verifying_key = VerifyingKey::<NistP256>::from(&public_key);
                let sig = match p256::ecdsa::Signature::from_slice(&signature_bytes) {
                    Ok(s) => s,
                    Err(_) => return false,
                };

                verifying_key.verify(data.as_bytes(), &sig).is_ok()
            }
            #[cfg(not(feature = "es256"))]
            Algorithm::ES256 => false,
            #[cfg(feature = "es384")]
            Algorithm::ES384 => {
                use p384::NistP384;
                use p384::elliptic_curve::PublicKey;

                let public_key =
                    match PublicKey::<NistP384>::from_sec1_bytes(&self.public_key_bytes) {
                        Ok(pk) => pk,
                        Err(_) => return false,
                    };

                let verifying_key = VerifyingKey::<NistP384>::from(&public_key);
                let sig = match p384::ecdsa::Signature::from_slice(&signature_bytes) {
                    Ok(s) => s,
                    Err(_) => return false,
                };

                verifying_key.verify(data.as_bytes(), &sig).is_ok()
            }
            #[cfg(not(feature = "es384"))]
            Algorithm::ES384 => false,
            _ => false,
        };

        result
    }
}
