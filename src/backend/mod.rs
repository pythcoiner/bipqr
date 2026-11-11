//! The conversions between the codec's wire types and a `bitcoin` release. Each
//! backend implements [`Backend`] over one release; the orphan rule rules out
//! `From` impls between `bipqr-ll` types and `bitcoin` ones in this crate.

use crate::ll::types::{DerivationPath, ExtendedKey, Fingerprint, PublicKey, SecretKey};

#[cfg(feature = "bitcoin_0_32")]
pub use bitcoin_0_32 as bitcoin;

pub mod rust_bitcoin;

pub type Active = crate::backend::rust_bitcoin::RustBitcoin;

pub trait Backend {
    type DerivationPath;
    type Xpub;
    type Xpriv;
    type Fingerprint;
    type PublicKey;
    type SecretKey;
    type Error;

    fn to_ll_path(path: &Self::DerivationPath) -> DerivationPath;
    fn from_ll_path(path: &DerivationPath) -> Self::DerivationPath;
    fn to_ll_xpub(xpub: &Self::Xpub) -> ExtendedKey;
    fn from_ll_xpub(key: &ExtendedKey) -> Result<Self::Xpub, Self::Error>;
    fn to_ll_xpriv(xpriv: &Self::Xpriv) -> ExtendedKey;
    fn from_ll_xpriv(key: &ExtendedKey) -> Result<Self::Xpriv, Self::Error>;
    fn to_ll_fingerprint(fingerprint: &Self::Fingerprint) -> Fingerprint;
    fn from_ll_fingerprint(fingerprint: &Fingerprint) -> Self::Fingerprint;
    /// The wire carries compressed keys only, so an uncompressed one is an error.
    fn to_ll_public_key(key: &Self::PublicKey) -> Result<PublicKey, Self::Error>;
    fn from_ll_public_key(key: &PublicKey) -> Result<Self::PublicKey, Self::Error>;
    fn to_ll_secret_key(key: &Self::SecretKey) -> SecretKey;
    fn from_ll_secret_key(key: &SecretKey) -> Result<Self::SecretKey, Self::Error>;
}
