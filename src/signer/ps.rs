use crate::enums::Algorithm;
use crate::signer::Signer;
use basekit::base64::{
    ALPHABET_BASE64_URL, Base64DecodeConfig, Base64EncodeConfig, DECODE_TABLE_BASE64_URL, decode,
    encode,
};

pub struct PssSigner {
    private_key_pem: String,
    algorithm: Algorithm,
}

impl PssSigner {
    pub fn new(private_key_pem: &str, algorithm: Algorithm) -> Self {
        Self {
            private_key_pem: private_key_pem.to_string(),
            algorithm,
        }
    }
}

impl Signer for PssSigner {
    fn sign(&self, data: &str) -> String {
        use rsa::RsaPrivateKey;
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs1v15::SigningKey;
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::signature::{SignatureEncoding, Signer as RsaSignerTrait};

        let private_key = RsaPrivateKey::from_pkcs8_pem(&self.private_key_pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&self.private_key_pem))
            .expect("Failed to parse RSA private key");

        let signature = match self.algorithm {
            #[cfg(feature = "ps256")]
            Algorithm::PS256 => {
                let signing_key = SigningKey::<sha2::Sha256>::new_unprefixed(private_key);
                let sig = signing_key.sign(data.as_bytes());
                sig.to_vec()
            }
            #[cfg(not(feature = "ps256"))]
            Algorithm::PS256 => {
                panic!("PS256 requires the \"ps256\" feature");
            }
            #[cfg(feature = "ps384")]
            Algorithm::PS384 => {
                let signing_key = SigningKey::<sha2::Sha384>::new_unprefixed(private_key);
                let sig = signing_key.sign(data.as_bytes());
                sig.to_vec()
            }
            #[cfg(not(feature = "ps384"))]
            Algorithm::PS384 => {
                panic!("PS384 requires the \"ps384\" feature");
            }
            #[cfg(feature = "ps512")]
            Algorithm::PS512 => {
                let signing_key = SigningKey::<sha2::Sha512>::new_unprefixed(private_key);
                let sig = signing_key.sign(data.as_bytes());
                sig.to_vec()
            }
            #[cfg(not(feature = "ps512"))]
            Algorithm::PS512 => {
                panic!("PS512 requires the \"ps512\" feature");
            }
            _ => {
                panic!(
                    "PssSigner does not support algorithm: {}",
                    self.algorithm.name()
                );
            }
        };

        let config = Base64EncodeConfig::new(ALPHABET_BASE64_URL, None);
        let output = encode(&config, &signature);
        String::try_from(output).unwrap()
    }

    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

pub struct PssVerifier {
    public_key_pem: String,
    algorithm: Algorithm,
}

impl PssVerifier {
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
            #[cfg(feature = "ps256")]
            Algorithm::PS256 => {
                let verifying_key = VerifyingKey::<sha2::Sha256>::new_unprefixed(public_key);
                verifying_key.verify(data.as_bytes(), &sig).is_ok()
            }
            #[cfg(not(feature = "ps256"))]
            Algorithm::PS256 => false,
            #[cfg(feature = "ps384")]
            Algorithm::PS384 => {
                let verifying_key = VerifyingKey::<sha2::Sha384>::new_unprefixed(public_key);
                verifying_key.verify(data.as_bytes(), &sig).is_ok()
            }
            #[cfg(not(feature = "ps384"))]
            Algorithm::PS384 => false,
            #[cfg(feature = "ps512")]
            Algorithm::PS512 => {
                let verifying_key = VerifyingKey::<sha2::Sha512>::new_unprefixed(public_key);
                verifying_key.verify(data.as_bytes(), &sig).is_ok()
            }
            #[cfg(not(feature = "ps512"))]
            Algorithm::PS512 => false,
            _ => false,
        }
    }
}
