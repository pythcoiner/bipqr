//! Binary codec for the draft signing protocol described in `ENCODING.md`.
//!
//! The crate is `no_std` plus `alloc` and pulls no dependency of its own, so a
//! bare-metal signer can vendor it as-is. Enable `ffi` for the C binding; the
//! conversions to and from the `bitcoin` types live in the `bipqr` crate.

// Every field of this protocol was introduced in version 1. A field added in a later
// version is appended at the end of its message body and carries a `// since vN`
// marker, so decoding stops cleanly at the end of the fields this parser knows and
// whatever follows belongs to a newer version.

// A `staticlib` needs a global allocator and a panic handler, which a library cannot
// supply, so the C consumer links this rlib from its own staticlib crate.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub type ErrorCode = i32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorInfo {
    pub code: ErrorCode,
    pub message: &'static str,
}

macro_rules! c_string {
    ($s:literal) => {
        concat!($s, "\0")
    };
}

macro_rules! error_info {
    ($code:literal, $message:literal) => {
        ErrorInfo {
            code: $code,
            message: c_string!($message),
        }
    };
}

/// The message carries a trailing nul so the C binding can hand out the same literal.
macro_rules! error_display {
    ($ty:ty) => {
        impl core::fmt::Display for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let message = self.info().message;
                f.write_str(&message[..message.len() - 1])
            }
        }

        impl core::error::Error for $ty {}
    };
}

pub mod decode;
pub mod encode;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod reader;
pub mod request;
pub mod response;
pub mod sp;
pub mod types;

use alloc::vec::Vec;

const MAGIC: &[u8; 6] = b"BIPXXX";
const VERSION: u8 = 1;
const DIRECTION_RESPONSE: u8 = 0x80;
const DIRECTION_REQUEST: u8 = 0x0;
const STATUS_ERROR: u8 = 0x40;
const STATUS_OK: u8 = 0x0;
const TYPE_MASK: u8 = 0x3f;
pub const REQUEST_ID_LEN: usize = 2;
pub const MAX_DESCRIPTOR_ALIAS: usize = 32;

/// A protocol rule a message breaks, refused alike by the encoder and the decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    DuplicateSpShare,
    DuplicateSpProof,
    MissingSpProof,
    MissingSpShare,
    MaxAliasTooLarge(u8),
    FingerprintWhenNotReady,
    TaprootSignatureLength(usize),
    ZeroMaxInputs,
    ReversedExpressionRange,
    SessionRefWithoutId,
}

impl Invalid {
    pub fn info(&self) -> ErrorInfo {
        match self {
            Self::DuplicateSpShare => {
                error_info!(500, "duplicate silent payment ECDH share for a scan key")
            }
            Self::DuplicateSpProof => {
                error_info!(501, "duplicate silent payment DLEQ proof for a scan key")
            }
            Self::MissingSpProof => {
                error_info!(502, "silent payment ECDH share without its DLEQ proof")
            }
            Self::MissingSpShare => {
                error_info!(503, "silent payment DLEQ proof without its ECDH share")
            }
            Self::MaxAliasTooLarge(_) => {
                error_info!(504, "maximum alias length exceeds the alias bound")
            }
            Self::FingerprintWhenNotReady => {
                error_info!(505, "fingerprint is present while the signer is not ready")
            }
            Self::TaprootSignatureLength(_) => {
                error_info!(506, "taproot signature is not 64 or 65 bytes")
            }
            Self::ZeroMaxInputs => error_info!(507, "nonce cache max inputs must be at least 1"),
            Self::ReversedExpressionRange => {
                error_info!(508, "key expression range start must not exceed its end")
            }
            Self::SessionRefWithoutId => {
                error_info!(509, "nonce cache session ref requires a session id")
            }
        }
    }
}

error_display!(Invalid);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestId(pub [u8; REQUEST_ID_LEN]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub id: RequestId,
    pub body: request::Body,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub id: RequestId,
    pub body: response::Body,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Request(Request),
    Response(Response),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    GetInfo,
    GetKeys,
    RegisterDescriptor,
    AddressVerification,
    Signing,
    NoncePreparation,
}

impl MessageType {
    pub fn value(self) -> u8 {
        self.into()
    }
}

impl From<MessageType> for u8 {
    fn from(message_type: MessageType) -> Self {
        match message_type {
            MessageType::GetInfo => 0x01,
            MessageType::GetKeys => 0x02,
            MessageType::RegisterDescriptor => 0x03,
            MessageType::AddressVerification => 0x04,
            MessageType::Signing => 0x05,
            MessageType::NoncePreparation => 0x06,
        }
    }
}

impl TryFrom<u8> for MessageType {
    type Error = decode::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::GetInfo),
            0x02 => Ok(Self::GetKeys),
            0x03 => Ok(Self::RegisterDescriptor),
            0x04 => Ok(Self::AddressVerification),
            0x05 => Ok(Self::Signing),
            0x06 => Ok(Self::NoncePreparation),
            _ => Err(decode::Error::UnknownMessageType(value)),
        }
    }
}

// Shared by both directions: a request asks for a kind, a response announces one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignResponseKind {
    Psbt,
    Signatures,
}

impl SignResponseKind {
    pub fn value(self) -> u8 {
        self.into()
    }
}

impl From<SignResponseKind> for u8 {
    fn from(kind: SignResponseKind) -> Self {
        match kind {
            SignResponseKind::Psbt => 0x01,
            SignResponseKind::Signatures => 0x02,
        }
    }
}

impl TryFrom<u8> for SignResponseKind {
    type Error = decode::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Psbt),
            0x02 => Ok(Self::Signatures),
            _ => Err(decode::Error::UnknownSignResponseKind(value)),
        }
    }
}

pub fn encode_request(request: &Request) -> Result<Vec<u8>, encode::Error> {
    encode::encode_request(request)
}

pub fn encode_response(response: &Response) -> Result<Vec<u8>, encode::Error> {
    encode::encode_response(response)
}

pub fn decode(bytes: &[u8]) -> Result<Message, decode::Error> {
    decode::decode(bytes)
}
