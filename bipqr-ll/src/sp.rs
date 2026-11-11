use alloc::collections::BTreeSet;

use crate::{
    Invalid,
    response::{SignatureEntry, SpScope},
    types::PUBLIC_KEY_LEN,
};

/// The `INPUT_INDEX` a global entry carries on the wire.
pub const GLOBAL_INPUT_INDEX: u32 = 0;

/// Each scope and scan key carries exactly one share and one proof, as BIP-375 pairs
/// every ECDH share with the DLEQ proof that lets the wallet verify it. Whether every
/// scan key and eligible input is covered depends on the PSBT, so the wallet checks it.
pub(crate) fn validate_entries(entries: &[SignatureEntry]) -> Result<(), Invalid> {
    let mut shares = BTreeSet::<(SpScope, [u8; PUBLIC_KEY_LEN])>::new();
    let mut proofs = BTreeSet::new();
    for entry in entries {
        match entry {
            SignatureEntry::SpEcdhShare {
                scope, scan_key, ..
            } => {
                if !shares.insert((*scope, scan_key.0)) {
                    return Err(Invalid::DuplicateSpShare);
                }
            }
            SignatureEntry::SpDleqProof {
                scope, scan_key, ..
            } => {
                if !proofs.insert((*scope, scan_key.0)) {
                    return Err(Invalid::DuplicateSpProof);
                }
            }
            _ => {}
        }
    }
    if shares.difference(&proofs).next().is_some() {
        return Err(Invalid::MissingSpProof);
    }
    if proofs.difference(&shares).next().is_some() {
        return Err(Invalid::MissingSpShare);
    }
    Ok(())
}
