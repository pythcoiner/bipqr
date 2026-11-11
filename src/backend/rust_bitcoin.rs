//! [`Backend`] over rust-bitcoin, shared by every supported release.

use core::fmt;

use crate::{
    backend::{
        Backend,
        bitcoin::{
            self,
            bip32::{self, ChildNumber, Xpriv, Xpub},
            key::FromSliceError,
            secp256k1,
        },
    },
    ll::types::{DerivationPath, ExtendedKey, Fingerprint, PublicKey, SecretKey},
};

pub enum RustBitcoin {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    ExtendedKey(bip32::Error),
    PublicKey(FromSliceError),
    UncompressedPublicKey,
    SecretKey(secp256k1::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExtendedKey(e) => write!(f, "invalid extended key: {e}"),
            Self::PublicKey(e) => write!(f, "invalid public key: {e}"),
            Self::UncompressedPublicKey => f.write_str("public key is not compressed"),
            Self::SecretKey(e) => write!(f, "invalid secret key: {e}"),
        }
    }
}

impl core::error::Error for Error {}

impl Backend for RustBitcoin {
    type DerivationPath = bip32::DerivationPath;
    type Xpub = Xpub;
    type Xpriv = Xpriv;
    type Fingerprint = bip32::Fingerprint;
    type PublicKey = bitcoin::PublicKey;
    type SecretKey = secp256k1::SecretKey;
    type Error = Error;

    fn to_ll_path(path: &bip32::DerivationPath) -> DerivationPath {
        DerivationPath(path.into_iter().copied().map(u32::from).collect())
    }

    fn from_ll_path(path: &DerivationPath) -> bip32::DerivationPath {
        path.0.iter().copied().map(ChildNumber::from).collect()
    }

    fn to_ll_xpub(xpub: &Xpub) -> ExtendedKey {
        ExtendedKey(xpub.encode())
    }

    fn from_ll_xpub(key: &ExtendedKey) -> Result<Xpub, Error> {
        Xpub::decode(&key.0).map_err(Error::ExtendedKey)
    }

    fn to_ll_xpriv(xpriv: &Xpriv) -> ExtendedKey {
        ExtendedKey(xpriv.encode())
    }

    fn from_ll_xpriv(key: &ExtendedKey) -> Result<Xpriv, Error> {
        Xpriv::decode(&key.0).map_err(Error::ExtendedKey)
    }

    fn to_ll_fingerprint(fingerprint: &bip32::Fingerprint) -> Fingerprint {
        Fingerprint(fingerprint.to_bytes())
    }

    fn from_ll_fingerprint(fingerprint: &Fingerprint) -> bip32::Fingerprint {
        bip32::Fingerprint::from(fingerprint.0)
    }

    fn to_ll_public_key(key: &bitcoin::PublicKey) -> Result<PublicKey, Error> {
        if !key.compressed {
            return Err(Error::UncompressedPublicKey);
        }
        Ok(PublicKey(key.inner.serialize()))
    }

    fn from_ll_public_key(key: &PublicKey) -> Result<bitcoin::PublicKey, Error> {
        bitcoin::PublicKey::from_slice(&key.0).map_err(Error::PublicKey)
    }

    fn to_ll_secret_key(key: &secp256k1::SecretKey) -> SecretKey {
        SecretKey(key.secret_bytes())
    }

    fn from_ll_secret_key(key: &SecretKey) -> Result<secp256k1::SecretKey, Error> {
        secp256k1::SecretKey::from_slice(&key.0).map_err(Error::SecretKey)
    }
}
