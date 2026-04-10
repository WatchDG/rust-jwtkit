use crate::enums::Algorithm;
use crate::signer::Signer;
use basekit::base64::{ALPHABET_BASE64_URL, Base64EncodeConfig, encode};

pub struct EcSigner {
    private_key_der: Vec<u8>,
    algorithm: Algorithm,
}

impl EcSigner {
    pub fn new(private_key_der: &[u8], algorithm: Algorithm) -> Self {
        Self {
            private_key_der: private_key_der.to_vec(),
            algorithm,
        }
    }
}

impl Signer for EcSigner {
    fn sign(&self, data: &str) -> String {
        let signature = match self.algorithm {
            #[cfg(feature = "es256")]
            Algorithm::ES256 => {
                use ecdsa::SigningKey;
                use ecdsa::signature::Signer as EcSignerTrait;
                use p256::NistP256;
                use p256::elliptic_curve::SecretKey;

                let secret_key = SecretKey::<NistP256>::from_slice(&self.private_key_der)
                    .expect("Failed to parse P-256 private key");
                let signing_key = SigningKey::<NistP256>::from(secret_key);
                let sig: p256::ecdsa::Signature = signing_key.sign(data.as_bytes());
                sig.to_bytes().to_vec()
            }
            #[cfg(not(feature = "es256"))]
            Algorithm::ES256 => {
                panic!("ES256 requires the \"es256\" feature");
            }
            #[cfg(feature = "es384")]
            Algorithm::ES384 => {
                use ecdsa::SigningKey;
                use ecdsa::signature::Signer as EcSignerTrait;
                use p384::NistP384;
                use p384::elliptic_curve::SecretKey;

                let secret_key = SecretKey::<NistP384>::from_slice(&self.private_key_der)
                    .expect("Failed to parse P-384 private key");
                let signing_key = SigningKey::<NistP384>::from(secret_key);
                let sig: p384::ecdsa::Signature = signing_key.sign(data.as_bytes());
                sig.to_bytes().to_vec()
            }
            #[cfg(not(feature = "es384"))]
            Algorithm::ES384 => {
                panic!("ES384 requires the \"es384\" feature");
            }
            _ => {
                panic!(
                    "EcSigner does not support algorithm: {}",
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
