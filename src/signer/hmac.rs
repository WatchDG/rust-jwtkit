use crate::enums::Algorithm;
use crate::signer::Signer;
use basekit::base64::{ALPHABET_BASE64_URL, Base64EncodeConfig, encode};

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
