use crate::enums::Algorithm;

pub trait Signer {
    fn sign(&self, data: &str) -> String;
    fn algorithm(&self) -> Algorithm;
}

#[cfg(any(feature = "hs256", feature = "hs384", feature = "hs512"))]
pub mod hmac;

#[cfg(any(feature = "rs256", feature = "rs384", feature = "rs512"))]
pub mod rsa;

#[cfg(any(feature = "es256", feature = "es384"))]
pub mod ec;

#[cfg(any(feature = "hs256", feature = "hs384", feature = "hs512"))]
pub use hmac::HmacSigner;

#[cfg(any(feature = "rs256", feature = "rs384", feature = "rs512"))]
pub use rsa::{RsaSigner, RsaVerifier};

#[cfg(any(feature = "es256", feature = "es384"))]
pub use ec::{EcSigner, EcVerifier};
