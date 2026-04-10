use crate::enums::Algorithm;
use crate::signer::Signer;
use basekit::base64::{ALPHABET_BASE64_URL, Base64EncodeConfig, encode};

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
