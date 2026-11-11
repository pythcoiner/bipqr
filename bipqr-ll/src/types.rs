use alloc::vec::Vec;

pub const EXTENDED_KEY_LEN: usize = 78;
pub const FINGERPRINT_LEN: usize = 4;
pub const PUBLIC_KEY_LEN: usize = 33;
pub const SECRET_KEY_LEN: usize = 32;
pub const MUSIG_PUB_NONCE_LEN: usize = 66;
pub const MUSIG_PARTIAL_SIG_LEN: usize = 32;
pub const TAP_LEAF_HASH_LEN: usize = 32;
/// A BIP-374 DLEQ proof, `e || s`.
pub const DLEQ_PROOF_LEN: usize = 64;
/// A BIP-340 signature, which a sighash type byte may follow.
pub const SCHNORR_SIGNATURE_LEN: usize = 64;

/// BIP-32 child numbers with the hardened bit set, exactly as they sit on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DerivationPath(pub Vec<u32>);

/// The 78-byte BIP-32 serialization of an extended public or private key, the form
/// BIP-32 base58-encodes. A private one carries `0x00 || 32-byte key` in place of the
/// 33-byte public key, and its own version bytes, so both have the same length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedKey(pub [u8; EXTENDED_KEY_LEN]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint(pub [u8; FINGERPRINT_LEN]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_LEN]);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretKey(pub [u8; SECRET_KEY_LEN]);

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SecretKey").field(&"[redacted]").finish()
    }
}
