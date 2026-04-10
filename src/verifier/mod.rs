#[cfg(any(feature = "hs256", feature = "hs384", feature = "hs512"))]
pub mod hmac;

#[cfg(any(feature = "rs256", feature = "rs384", feature = "rs512"))]
pub mod rsa;

#[cfg(any(feature = "ps256", feature = "ps384", feature = "ps512"))]
pub mod ps;

#[cfg(any(feature = "es256", feature = "es384"))]
pub mod ec;

#[cfg(any(feature = "hs256", feature = "hs384", feature = "hs512"))]
pub use hmac::HmacVerifier;

#[cfg(any(feature = "rs256", feature = "rs384", feature = "rs512"))]
pub use rsa::RsaVerifier;

#[cfg(any(feature = "ps256", feature = "ps384", feature = "ps512"))]
pub use ps::PssVerifier;

#[cfg(any(feature = "es256", feature = "es384"))]
pub use ec::EcVerifier;
