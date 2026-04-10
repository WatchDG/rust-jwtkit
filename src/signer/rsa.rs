use crate::enums::Algorithm;
use crate::signer::Signer;
use basekit::base64::{ALPHABET_BASE64_URL, Base64EncodeConfig, encode};

pub struct RsaSigner {
    private_key_pem: String,
    algorithm: Algorithm,
}

impl RsaSigner {
    pub fn new(private_key_pem: &str, algorithm: Algorithm) -> Self {
        Self {
            private_key_pem: private_key_pem.to_string(),
            algorithm,
        }
    }
}

impl Signer for RsaSigner {
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
            #[cfg(feature = "rs256")]
            Algorithm::RS256 => {
                let signing_key = SigningKey::<sha2::Sha256>::new_unprefixed(private_key);
                let sig = signing_key.sign(data.as_bytes());
                sig.to_vec()
            }
            #[cfg(not(feature = "rs256"))]
            Algorithm::RS256 => {
                panic!("RS256 requires the \"rs256\" feature");
            }
            #[cfg(feature = "rs384")]
            Algorithm::RS384 => {
                let signing_key = SigningKey::<sha2::Sha384>::new_unprefixed(private_key);
                let sig = signing_key.sign(data.as_bytes());
                sig.to_vec()
            }
            #[cfg(not(feature = "rs384"))]
            Algorithm::RS384 => {
                panic!("RS384 requires the \"rs384\" feature");
            }
            #[cfg(feature = "rs512")]
            Algorithm::RS512 => {
                let signing_key = SigningKey::<sha2::Sha512>::new_unprefixed(private_key);
                let sig = signing_key.sign(data.as_bytes());
                sig.to_vec()
            }
            #[cfg(not(feature = "rs512"))]
            Algorithm::RS512 => {
                panic!("RS512 requires the \"rs512\" feature");
            }
            _ => {
                panic!(
                    "RsaSigner does not support algorithm: {}",
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
