#![cfg(feature = "bitcoin_0_32")]

#[path = "../bipqr-ll/tests/common/mod.rs"]
mod common;

use bipqr::{
    backend::{Active, Backend, rust_bitcoin::Error},
    bitcoin::{
        self,
        bip32::{self, Xpriv, Xpub},
        secp256k1::{self, Secp256k1},
    },
    ll::types::{Fingerprint, PublicKey, SecretKey},
};

use common::{FOREIGN_SCAN_KEY, path, xpriv, xpub, xpub_key};

const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
// the private key of XPUB, BIP-32 test vector 1's master key
const XPRIV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

fn bitcoin_xpub() -> Xpub {
    XPUB.parse().unwrap()
}

fn bitcoin_xpriv() -> Xpriv {
    XPRIV.parse().unwrap()
}

#[test]
fn the_xpriv_fixture_is_the_xpub_fixtures_private_key() {
    assert_eq!(
        Xpub::from_priv(&Secp256k1::new(), &bitcoin_xpriv()),
        bitcoin_xpub()
    );
}

#[test]
fn xpub_round_trips() {
    let key = Active::to_ll_xpub(&bitcoin_xpub());
    assert_eq!(key, xpub());
    assert_eq!(Active::from_ll_xpub(&key), Ok(bitcoin_xpub()));
}

#[test]
fn xpriv_round_trips() {
    let key = Active::to_ll_xpriv(&bitcoin_xpriv());
    assert_eq!(key, xpriv());
    assert_eq!(Active::from_ll_xpriv(&key), Ok(bitcoin_xpriv()));
}

#[test]
fn an_xpriv_is_not_read_as_an_xpub() {
    assert_eq!(
        Active::from_ll_xpub(&xpriv()),
        Err(Error::ExtendedKey(bip32::Error::UnknownVersion([
            0x04, 0x88, 0xad, 0xe4
        ])))
    );
}

#[test]
fn an_xpub_is_not_read_as_an_xpriv() {
    assert_eq!(
        Active::from_ll_xpriv(&xpub()),
        Err(Error::ExtendedKey(bip32::Error::UnknownVersion([
            0x04, 0x88, 0xb2, 0x1e
        ])))
    );
}

#[test]
fn a_path_round_trips() {
    for text in ["m", "m/2", "m/84'/1'/0'/0/7", "m/352'/1'/0'/1'/0"] {
        let bitcoin_path: bip32::DerivationPath = text.parse().unwrap();
        let wire = Active::to_ll_path(&bitcoin_path);
        assert_eq!(wire, path(text));
        assert_eq!(Active::from_ll_path(&wire), bitcoin_path);
    }
}

#[test]
fn a_fingerprint_round_trips() {
    let fingerprint = bitcoin_xpub().fingerprint();
    let wire = Active::to_ll_fingerprint(&fingerprint);
    assert_eq!(wire, Fingerprint([0x34, 0x42, 0x19, 0x3e]));
    assert_eq!(Active::from_ll_fingerprint(&wire), fingerprint);
}

#[test]
fn a_public_key_round_trips() {
    let key = bitcoin::PublicKey::new(bitcoin_xpub().public_key);
    let wire = Active::to_ll_public_key(&key).unwrap();
    assert_eq!(wire, xpub_key());
    assert_eq!(Active::from_ll_public_key(&wire), Ok(key));
}

#[test]
fn an_uncompressed_public_key_is_refused() {
    let key = bitcoin::PublicKey::new_uncompressed(bitcoin_xpub().public_key);
    assert_eq!(
        Active::to_ll_public_key(&key),
        Err(Error::UncompressedPublicKey)
    );
}

#[test]
fn a_public_key_of_an_unknown_prefix_is_refused() {
    let wire = PublicKey([0x05; 33]);
    assert!(matches!(
        Active::from_ll_public_key(&wire),
        Err(Error::PublicKey(_))
    ));
}

#[test]
fn a_scan_key_round_trips() {
    let key = secp256k1::SecretKey::from_slice(&FOREIGN_SCAN_KEY).unwrap();
    let wire = Active::to_ll_secret_key(&key);
    assert_eq!(wire, SecretKey(FOREIGN_SCAN_KEY));
    assert_eq!(Active::from_ll_secret_key(&wire), Ok(key));
}

#[test]
fn a_zero_secret_key_is_refused() {
    assert_eq!(
        Active::from_ll_secret_key(&SecretKey([0; 32])),
        Err(Error::SecretKey(secp256k1::Error::InvalidSecretKey))
    );
}
