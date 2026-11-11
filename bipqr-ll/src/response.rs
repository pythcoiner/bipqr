use alloc::{string::String, vec::Vec};

use crate::{
    sp,
    types::{
        ExtendedKey, Fingerprint, PublicKey, DLEQ_PROOF_LEN, MUSIG_PARTIAL_SIG_LEN,
        MUSIG_PUB_NONCE_LEN, SCHNORR_SIGNATURE_LEN,
    },
    Invalid, MessageType, MAX_DESCRIPTOR_ALIAS,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Keys(Keys),
    Registration(Registration),
    AddressUri(AddressUri),
    Signed(Signed),
    NoncesPrepared(NoncesPrepared),
    Info(Info),
    Error(ErrorBody),
}

impl Body {
    pub fn message_type(&self) -> MessageType {
        self.into()
    }
}

impl From<&Body> for MessageType {
    fn from(body: &Body) -> Self {
        match body {
            Body::Keys(_) => Self::GetKeys,
            Body::Registration(_) => Self::RegisterDescriptor,
            Body::AddressUri(_) => Self::AddressVerification,
            Body::Signed(_) => Self::Signing,
            Body::NoncesPrepared(_) => Self::NoncePreparation,
            Body::Info(_) => Self::GetInfo,
            Body::Error(e) => e.message_type,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keys {
    pub keys: Vec<ExtendedKey>,
    pub fingerprint: Fingerprint,
    pub vendor: String,
    pub model: String,
    pub version: FirmwareVersion,
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u32,
    pub flag: ReleaseFlag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseFlag {
    Stable,
    Alpha,
    Beta,
    ReleaseCandidate,
    Unknown(u8),
}

impl ReleaseFlag {
    pub fn value(self) -> u8 {
        self.into()
    }
}

impl From<ReleaseFlag> for u8 {
    fn from(flag: ReleaseFlag) -> Self {
        match flag {
            ReleaseFlag::Stable => 0x00,
            ReleaseFlag::Alpha => 0x01,
            ReleaseFlag::Beta => 0x02,
            ReleaseFlag::ReleaseCandidate => 0x03,
            ReleaseFlag::Unknown(value) => value,
        }
    }
}

impl From<u8> for ReleaseFlag {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Stable,
            0x01 => Self::Alpha,
            0x02 => Self::Beta,
            0x03 => Self::ReleaseCandidate,
            value => Self::Unknown(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities(pub u32);

impl Capabilities {
    pub const NONCE_CACHE: u32 = 1 << 4;
    pub const PSBT_TRIMMING: u32 = 1 << 5;

    pub fn supports_nonce_cache(self) -> bool {
        self.0 & Self::NONCE_CACHE != 0
    }

    pub fn supports_psbt_trimming(self) -> bool {
        self.0 & Self::PSBT_TRIMMING != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub vendor: String,
    pub model: String,
    pub version: FirmwareVersion,
    pub capabilities: Capabilities,
    pub state: State,
    pub networks: Networks,
    pub max_message: u32,
    pub max_alias: u8,
    /// Present only when `state` is `State::Ready`.
    pub fingerprint: Option<Fingerprint>,
}

impl Info {
    pub fn validate(&self) -> Result<(), Invalid> {
        if usize::from(self.max_alias) > MAX_DESCRIPTOR_ALIAS {
            return Err(Invalid::MaxAliasTooLarge(self.max_alias));
        }
        if self.fingerprint.is_some() && self.state != State::Ready {
            return Err(Invalid::FingerprintWhenNotReady);
        }
        Ok(())
    }
}

/// An unknown value counts as not ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Ready,
    Locked,
    Uninitialized,
    Unknown(u8),
}

impl State {
    pub fn value(self) -> u8 {
        self.into()
    }
}

impl From<State> for u8 {
    fn from(state: State) -> Self {
        match state {
            State::Ready => STATE_READY,
            State::Locked => STATE_LOCKED,
            State::Uninitialized => STATE_UNINITIALIZED,
            State::Unknown(value) => value,
        }
    }
}

impl From<u8> for State {
    fn from(value: u8) -> Self {
        match value {
            STATE_READY => Self::Ready,
            STATE_LOCKED => Self::Locked,
            STATE_UNINITIALIZED => Self::Uninitialized,
            value => Self::Unknown(value),
        }
    }
}

pub const STATE_READY: u8 = 0x00;
pub const STATE_LOCKED: u8 = 0x01;
pub const STATE_UNINITIALIZED: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Networks(pub u8);

impl Networks {
    pub const MAINNET: u8 = 1 << 1;
    pub const TESTNET: u8 = 1 << 2;
    pub const SIGNET: u8 = 1 << 3;
    pub const REGTEST: u8 = 1 << 4;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoncesPrepared {
    /// Present only when the signer initialized a new session for this answer.
    pub session: Option<Session>,
    /// The entry for key expression index `j` and input `i` is at
    /// `(j - start) * max_inputs + i`, with the request's `start` and `max_inputs`.
    pub nonces: Vec<[u8; MUSIG_PUB_NONCE_LEN]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    pub session_id: [u8; 4],
    pub session_ref: [u8; 4],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub descriptor_alias: String,
    pub registered: bool,
    pub stored: Option<bool>,
    pub proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressUri {
    pub uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signed {
    /// A serialized PSBT v0 or v2, carried without being parsed.
    Psbt(Vec<u8>),
    Signatures(Vec<SignatureEntry>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureEntry {
    Ecdsa {
        input_index: u32,
        public_key: PublicKey,
        signature: Vec<u8>,
    },
    TapKey {
        input_index: u32,
        signature: Vec<u8>,
    },
    TapScript {
        input_index: u32,
        xonly_public_key: [u8; 32],
        tap_leaf_hash: [u8; 32],
        signature: Vec<u8>,
    },
    MusigPubNonce {
        input_index: u32,
        participant: PublicKey,
        aggregate: PublicKey,
        leaf_hash: Option<[u8; 32]>,
        nonce: [u8; MUSIG_PUB_NONCE_LEN],
    },
    MusigPartialSig {
        input_index: u32,
        participant: PublicKey,
        aggregate: PublicKey,
        leaf_hash: Option<[u8; 32]>,
        signature: [u8; MUSIG_PARTIAL_SIG_LEN],
    },
    /// The value of BIP-375 `PSBT_GLOBAL_SP_ECDH_SHARE` or `PSBT_IN_SP_ECDH_SHARE`.
    SpEcdhShare {
        scope: SpScope,
        scan_key: PublicKey,
        share: PublicKey,
    },
    /// The value of BIP-375 `PSBT_GLOBAL_SP_DLEQ` or `PSBT_IN_SP_DLEQ`, a BIP-374 proof.
    SpDleqProof {
        scope: SpScope,
        scan_key: PublicKey,
        proof: [u8; DLEQ_PROOF_LEN],
    },
    /// An entry whose kind this codec does not know. It is kept rather than dropped so
    /// a consumer sees it and a relay re-encodes the message unchanged.
    Unknown {
        input_index: u32,
        kind: u8,
        fields: Vec<u8>,
    },
}

impl SignatureEntry {
    pub fn value(&self) -> u8 {
        match self {
            Self::Ecdsa { .. } => SIGNATURE_ECDSA,
            Self::TapKey { .. } => SIGNATURE_TAP_KEY,
            Self::TapScript { .. } => SIGNATURE_TAP_SCRIPT,
            Self::MusigPubNonce { .. } => SIGNATURE_MUSIG_PUB_NONCE,
            Self::MusigPartialSig { .. } => SIGNATURE_MUSIG_PARTIAL_SIG,
            Self::SpEcdhShare { .. } => SIGNATURE_SP_ECDH_SHARE,
            Self::SpDleqProof { .. } => SIGNATURE_SP_DLEQ_PROOF,
            Self::Unknown { kind, .. } => *kind,
        }
    }

    /// `None` for a global silent payment entry.
    pub fn input_index(&self) -> Option<u32> {
        match self {
            Self::Ecdsa { input_index, .. }
            | Self::TapKey { input_index, .. }
            | Self::TapScript { input_index, .. }
            | Self::MusigPubNonce { input_index, .. }
            | Self::MusigPartialSig { input_index, .. }
            | Self::Unknown { input_index, .. } => Some(*input_index),
            Self::SpEcdhShare { scope, .. } | Self::SpDleqProof { scope, .. } => {
                scope.input_index()
            }
        }
    }

    pub fn validate(&self) -> Result<(), Invalid> {
        let (Self::TapKey { signature, .. } | Self::TapScript { signature, .. }) = self else {
            return Ok(());
        };
        if !(SCHNORR_SIGNATURE_LEN..=SCHNORR_SIGNATURE_LEN + 1).contains(&signature.len()) {
            return Err(Invalid::TaprootSignatureLength(signature.len()));
        }
        Ok(())
    }
}

/// Whether a silent payment share or proof covers the whole transaction (the signer
/// owns every eligible input) or a single input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpScope {
    Global,
    Input(u32),
}

impl SpScope {
    pub fn from_wire(global: bool, input_index: u32) -> Option<Self> {
        match (global, input_index) {
            (false, index) => Some(Self::Input(index)),
            (true, sp::GLOBAL_INPUT_INDEX) => Some(Self::Global),
            (true, _) => None,
        }
    }

    pub fn input_index(self) -> Option<u32> {
        match self {
            Self::Global => None,
            Self::Input(index) => Some(index),
        }
    }
}

pub const SIGNATURE_ECDSA: u8 = 0x01;
pub const SIGNATURE_TAP_KEY: u8 = 0x02;
pub const SIGNATURE_TAP_SCRIPT: u8 = 0x03;
pub const SIGNATURE_MUSIG_PUB_NONCE: u8 = 0x04;
pub const SIGNATURE_MUSIG_PARTIAL_SIG: u8 = 0x05;
pub const SIGNATURE_SP_ECDH_SHARE: u8 = 0x06;
pub const SIGNATURE_SP_DLEQ_PROOF: u8 = 0x07;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorBody {
    pub message_type: MessageType,
    pub error: Error,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    UserDeclined,
    UnsupportedVersion,
    MalformedRequest,
    UnknownDescriptorAlias,
    DescriptorRegistrationFailed,
    UnsupportedDescriptorForm,
    InvalidProof,
    AddressMismatch,
    NothingToSign,
    InvalidPsbt,
    InternalError,
    PrivateKeyExportRefused,
    MusigSession,
    AlreadyRegistered,
    Vendor,
    Unknown(u8),
}

impl Error {
    pub fn value(self) -> u8 {
        self.into()
    }
}

impl From<Error> for u8 {
    fn from(error: Error) -> Self {
        match error {
            Error::UserDeclined => 0x01,
            Error::UnsupportedVersion => 0x02,
            Error::MalformedRequest => 0x03,
            Error::UnknownDescriptorAlias => 0x04,
            Error::DescriptorRegistrationFailed => 0x05,
            Error::UnsupportedDescriptorForm => 0x06,
            Error::InvalidProof => 0x07,
            Error::AddressMismatch => 0x08,
            Error::NothingToSign => 0x09,
            Error::InvalidPsbt => 0x0a,
            Error::InternalError => 0x0b,
            Error::PrivateKeyExportRefused => 0x0c,
            Error::MusigSession => 0x0d,
            Error::AlreadyRegistered => 0x0e,
            Error::Vendor => 0xff,
            Error::Unknown(value) => value,
        }
    }
}

impl From<u8> for Error {
    fn from(value: u8) -> Self {
        match value {
            0x01 => Self::UserDeclined,
            0x02 => Self::UnsupportedVersion,
            0x03 => Self::MalformedRequest,
            0x04 => Self::UnknownDescriptorAlias,
            0x05 => Self::DescriptorRegistrationFailed,
            0x06 => Self::UnsupportedDescriptorForm,
            0x07 => Self::InvalidProof,
            0x08 => Self::AddressMismatch,
            0x09 => Self::NothingToSign,
            0x0a => Self::InvalidPsbt,
            0x0b => Self::InternalError,
            0x0c => Self::PrivateKeyExportRefused,
            0x0d => Self::MusigSession,
            0x0e => Self::AlreadyRegistered,
            0xff => Self::Vendor,
            value => Self::Unknown(value),
        }
    }
}
