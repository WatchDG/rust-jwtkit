use crate::enums::Algorithm;
use basekit::base64::{ALPHABET_BASE64_URL, Base64EncodeConfig, encode};

pub trait Signer {
    fn sign(&self, data: &str) -> String;
    fn algorithm(&self) -> Algorithm;
}

pub struct HmacSigner {
    secret: Vec<u8>,
    algorithm: Algorithm,
}

impl HmacSigner {
    pub fn new(secret: &[u8], algorithm: Algorithm) -> Self {
        Self {
            secret: secret.to_vec(),
            algorithm,
        }
    }
}

impl Signer for HmacSigner {
    fn sign(&self, data: &str) -> String {
        let config = Base64EncodeConfig::new(ALPHABET_BASE64_URL, None);
        let signature = match self.algorithm {
            #[cfg(feature = "hs256")]
            Algorithm::HS256 => {
                use hmac::Hmac;
                use hmac::Mac;
                use sha2::Sha256;
                type HmacSha256 = Hmac<Sha256>;

                let mut mac = HmacSha256::new_from_slice(&self.secret)
                    .expect("HMAC can take key of any size");
                mac.update(data.as_bytes());
                mac.finalize().into_bytes().to_vec()
            }
            #[cfg(not(feature = "hs256"))]
            Algorithm::HS256 => {
                panic!("HS256 requires the \"hs256\" feature");
            }
            #[cfg(feature = "hs384")]
            Algorithm::HS384 => {
                use hmac::Hmac;
                use hmac::Mac;
                use sha2::Sha384;
                type HmacSha384 = Hmac<Sha384>;

                let mut mac = HmacSha384::new_from_slice(&self.secret)
                    .expect("HMAC can take key of any size");
                mac.update(data.as_bytes());
                mac.finalize().into_bytes().to_vec()
            }
            #[cfg(not(feature = "hs384"))]
            Algorithm::HS384 => {
                panic!("HS384 requires the \"hs384\" feature");
            }
            #[cfg(feature = "hs512")]
            Algorithm::HS512 => {
                use hmac::Hmac;
                use hmac::Mac;
                use sha2::Sha512;
                type HmacSha512 = Hmac<Sha512>;

                let mut mac = HmacSha512::new_from_slice(&self.secret)
                    .expect("HMAC can take key of any size");
                mac.update(data.as_bytes());
                mac.finalize().into_bytes().to_vec()
            }
            #[cfg(not(feature = "hs512"))]
            Algorithm::HS512 => {
                panic!("HS512 requires the \"hs512\" feature");
            }
            _ => {
                panic!(
                    "HmacSigner does not support algorithm: {}",
                    self.algorithm.name()
                );
            }
        };

        let output = encode(&config, &signature);
        String::try_from(output).unwrap()
    }

    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

#[cfg(feature = "rsa")]
pub mod rsa_signer {
    use super::*;
    use basekit::base64::{Base64DecodeConfig, DECODE_TABLE_BASE64_URL, decode};

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
            use rsa::pkcs1v15::SigningKey;
            use rsa::signature::{SignatureEncoding, Signer as RsaSignerTrait};
            use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};

            let private_key = RsaPrivateKey::from_pkcs8_pem(&self.private_key_pem)
                .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&self.private_key_pem))
                .expect("Failed to parse RSA private key");

            let signature = match self.algorithm {
                Algorithm::RS256 => {
                    let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
                    let sig = signing_key.sign(data.as_bytes());
                    sig.to_vec()
                }
                Algorithm::RS384 => {
                    let signing_key = SigningKey::<sha2::Sha384>::new(private_key);
                    let sig = signing_key.sign(data.as_bytes());
                    sig.to_vec()
                }
                Algorithm::RS512 => {
                    let signing_key = SigningKey::<sha2::Sha512>::new(private_key);
                    let sig = signing_key.sign(data.as_bytes());
                    sig.to_vec()
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
            use rsa::pkcs1v15::VerifyingKey;
            use rsa::signature::Verifier;
            use rsa::{RsaPublicKey, pkcs8::DecodePublicKey};

            let signature_bytes = match decode(
                &Base64DecodeConfig::new(DECODE_TABLE_BASE64_URL, None),
                signature.as_bytes(),
            ) {
                Ok(output) => String::try_from(output).unwrap(),
                Err(_) => return false,
            };

            let public_key = match RsaPublicKey::from_public_key_pem(&self.public_key_pem) {
                Ok(key) => key,
                Err(_) => match RsaPublicKey::from_pkcs1_pem(&self.public_key_pem) {
                    Ok(key) => key,
                    Err(_) => return false,
                },
            };

            match self.algorithm {
                Algorithm::RS256 => {
                    let verifying_key = VerifyingKey::<sha2::Sha256>::new(public_key);
                    verifying_key
                        .verify(data.as_bytes(), &signature_bytes.as_str().parse().unwrap())
                        .is_ok()
                }
                Algorithm::RS384 => {
                    let verifying_key = VerifyingKey::<sha2::Sha384>::new(public_key);
                    verifying_key
                        .verify(data.as_bytes(), &signature_bytes.as_str().parse().unwrap())
                        .is_ok()
                }
                Algorithm::RS512 => {
                    let verifying_key = VerifyingKey::<sha2::Sha512>::new(public_key);
                    verifying_key
                        .verify(data.as_bytes(), &signature_bytes.as_str().parse().unwrap())
                        .is_ok()
                }
                _ => false,
            }
        }
    }
}
