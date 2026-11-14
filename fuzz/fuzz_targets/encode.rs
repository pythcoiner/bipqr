#![no_main]

use bipqr_ll::{
    MAX_DESCRIPTOR_ALIAS, Message, MessageType, Request, RequestId, Response, SignResponseKind,
    decode, encode_request, encode_response,
    request::{self, DescriptorBody, KeyKind, Scan, SpKeys},
    response::{
        self, Capabilities, ErrorBody, FirmwareVersion, Info, Networks, ReleaseFlag,
        SignatureEntry, SpScope, State,
    },
    types::{DerivationPath, ExtendedKey, Fingerprint, PublicKey, SecretKey},
};
use libfuzzer_sys::fuzz_target;

/// Reads the fuzz bytes as a stream of choices, all zero once it runs out.
struct Builder<'a> {
    data: &'a [u8],
}

impl Builder<'_> {
    fn u8(&mut self) -> u8 {
        let Some((first, rest)) = self.data.split_first() else {
            return 0;
        };
        self.data = rest;
        *first
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        out.iter_mut().for_each(|byte| *byte = self.u8());
        out
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.array())
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.array())
    }

    fn bool(&mut self) -> bool {
        self.u8() & 1 == 1
    }

    fn option<T>(&mut self, build: impl FnOnce(&mut Self) -> T) -> Option<T> {
        if self.bool() { Some(build(self)) } else { None }
    }

    /// Up to 0xff + 7 items, so a count reaches the 3-byte compact size.
    fn vec<T>(&mut self, mut build: impl FnMut(&mut Self) -> T) -> Vec<T> {
        let count = match self.u8() % 4 {
            0 => 0,
            1 | 2 => usize::from(self.u8() % 4),
            _ => 0xf8 + usize::from(self.u8() % 16),
        };
        (0..count).map(|_| build(self)).collect()
    }

    /// Lengths in every compact size form but the 9-byte one.
    fn len(&mut self) -> usize {
        match self.u8() % 4 {
            0 => usize::from(self.u8() % 8),
            1 => usize::from(self.u8()),
            2 => usize::from(self.u16()),
            _ => 0x1_0000 + usize::from(self.u8()),
        }
    }

    /// The first bytes come from the input, the rest repeat a fill byte.
    fn bytes_of_len(&mut self, len: usize) -> Vec<u8> {
        let fill = self.u8();
        let taken = len.min(self.data.len());
        let mut out = self.data[..taken].to_vec();
        self.data = &self.data[taken..];
        out.resize(len, fill);
        out
    }

    fn bytes(&mut self) -> Vec<u8> {
        let len = self.len();
        self.bytes_of_len(len)
    }

    /// Each byte becomes the char of that code point, so a nul byte stays a nul.
    fn string_of_len(&mut self, len: usize) -> String {
        self.bytes_of_len(len).into_iter().map(char::from).collect()
    }

    fn string(&mut self) -> String {
        let len = self.len();
        self.string_of_len(len)
    }

    fn alias(&mut self) -> String {
        let len = usize::from(self.u8()) % (MAX_DESCRIPTOR_ALIAS + 2);
        self.string_of_len(len)
    }

    /// Up to 259 children, past the 255 the wire can count.
    fn path(&mut self) -> DerivationPath {
        let count = match self.u8() % 4 {
            0 | 1 => self.u8() % 6,
            2 => self.u8(),
            _ => return DerivationPath(vec![0; 256 + usize::from(self.u8() % 4)]),
        };
        DerivationPath((0..count).map(|_| self.u32()).collect())
    }

    fn message_type(&mut self) -> MessageType {
        match self.u8() % 7 {
            0 => MessageType::GetInfo,
            1 => MessageType::GetKeys,
            2 => MessageType::RegisterDescriptor,
            3 => MessageType::AddressVerification,
            4 => MessageType::Signing,
            5 => MessageType::NoncePreparation,
            _ => MessageType::UnregisterDescriptor,
        }
    }

    fn sign_response_kind(&mut self) -> SignResponseKind {
        if self.bool() {
            SignResponseKind::Psbt
        } else {
            SignResponseKind::Signatures
        }
    }

    fn request(&mut self) -> Request {
        let id = RequestId(self.array());
        let body = match self.message_type() {
            MessageType::UnreadableRequest => unreachable!("message_type never draws it"),
            MessageType::GetInfo => request::Body::GetInfo,
            MessageType::GetKeys => request::Body::GetKeys(request::GetKeys {
                keys: self.vec(Self::key_request),
            }),
            MessageType::RegisterDescriptor => {
                request::Body::RegisterDescriptor(request::RegisterDescriptor {
                    descriptor_alias: self.alias(),
                    descriptor: self.option(Self::descriptor_body),
                })
            }
            MessageType::AddressVerification => {
                request::Body::VerifyAddress(request::VerifyAddress {
                    descriptor_alias: self.alias(),
                    derivation_path: self.path(),
                    address: self.option(Self::string),
                    descriptor: self.option(Self::descriptor_body),
                    proof: self.option(Self::bytes),
                })
            }
            MessageType::Signing => request::Body::Sign(request::Sign {
                descriptors: self.vec(Self::descriptor),
                psbt: self.bytes(),
                want_kind: self.option(Self::sign_response_kind),
                accept_trimmed: self.bool(),
            }),
            MessageType::NoncePreparation => request::Body::PrepareNonces(request::PrepareNonces {
                session_id: self.option(Self::array),
                session_ref: self.option(Self::array),
                descriptor: self.option(Self::descriptor),
                max_inputs: self.u32(),
                derivation_path: self.path(),
                start: self.u32(),
                end: self.option(Self::u32),
            }),
            MessageType::UnregisterDescriptor => {
                request::Body::UnregisterDescriptor(request::UnregisterDescriptor {
                    descriptor_alias: self.alias(),
                })
            }
        };
        Request { id, body }
    }

    fn key_request(&mut self) -> request::KeyRequest {
        request::KeyRequest {
            derivation_path: self.path(),
            kind: if self.bool() {
                KeyKind::Private
            } else {
                KeyKind::Public
            },
        }
    }

    fn descriptor(&mut self) -> request::Descriptor {
        request::Descriptor {
            alias: self.alias(),
            descriptor: self.option(Self::descriptor_body),
            proof: self.option(Self::bytes),
        }
    }

    fn descriptor_body(&mut self) -> DescriptorBody {
        match self.u8() % 3 {
            0 => DescriptorBody::Bip380(self.string()),
            1 => DescriptorBody::Bip388 {
                keys: self.vec(Self::string),
                policy: self.string(),
            },
            _ => DescriptorBody::SpKeys(SpKeys {
                fingerprint: Fingerprint(self.array()),
                spend_path: self.path(),
                scan: if self.bool() {
                    Scan::Path(self.path())
                } else {
                    Scan::Key(SecretKey(self.array()))
                },
            }),
        }
    }

    fn response(&mut self) -> Response {
        let id = RequestId(self.array());
        let body = if self.u8().is_multiple_of(8) {
            response::Body::Error(ErrorBody {
                message_type: if self.u8().is_multiple_of(8) {
                    MessageType::UnreadableRequest
                } else {
                    self.message_type()
                },
                error: self.error(),
                message: self.string(),
            })
        } else {
            match self.message_type() {
                MessageType::UnreadableRequest => unreachable!("message_type never draws it"),
                MessageType::GetInfo => response::Body::Info(self.info()),
                MessageType::GetKeys => response::Body::Keys(response::Keys {
                    keys: self.vec(|builder| ExtendedKey(builder.array())),
                    fingerprint: Fingerprint(self.array()),
                    vendor: self.string(),
                    model: self.string(),
                    version: self.version(),
                    capabilities: self.capabilities(),
                }),
                MessageType::RegisterDescriptor => {
                    response::Body::Registration(response::Registration {
                        descriptor_alias: self.alias(),
                        registered: self.bool(),
                        stored: self.option(Self::bool),
                        proof: self.option(Self::bytes),
                    })
                }
                MessageType::AddressVerification => {
                    response::Body::AddressUri(response::AddressUri { uri: self.string() })
                }
                MessageType::Signing => response::Body::Signed(match self.sign_response_kind() {
                    SignResponseKind::Psbt => response::Signed::Psbt(self.bytes()),
                    SignResponseKind::Signatures => {
                        response::Signed::Signatures(self.vec(Self::signature))
                    }
                }),
                MessageType::NoncePreparation => {
                    response::Body::NoncesPrepared(response::NoncesPrepared {
                        session: self.option(|builder| response::Session {
                            session_id: builder.array(),
                            session_ref: builder.array(),
                        }),
                        nonces: self.vec(Self::array),
                    })
                }
                MessageType::UnregisterDescriptor => {
                    response::Body::Unregistered(response::Unregistered {
                        descriptor_alias: self.alias(),
                    })
                }
            }
        };
        Response { id, body }
    }

    fn info(&mut self) -> Info {
        Info {
            vendor: self.string(),
            model: self.string(),
            version: self.version(),
            capabilities: self.capabilities(),
            state: match self.u8() % 4 {
                0 => State::Ready,
                1 => State::Locked,
                2 => State::Uninitialized,
                _ => State::Unknown(self.u8()),
            },
            networks: Networks(self.u8()),
            max_message: self.u32(),
            max_alias: self.u8(),
            fingerprint: self.option(|builder| Fingerprint(builder.array())),
        }
    }

    fn version(&mut self) -> FirmwareVersion {
        FirmwareVersion {
            major: self.u16(),
            minor: self.u16(),
            patch: self.u32(),
            flag: match self.u8() % 5 {
                0 => ReleaseFlag::Stable,
                1 => ReleaseFlag::Alpha,
                2 => ReleaseFlag::Beta,
                3 => ReleaseFlag::ReleaseCandidate,
                _ => ReleaseFlag::Unknown(self.u8()),
            },
        }
    }

    /// The defined bits, or any value.
    fn capabilities(&mut self) -> Capabilities {
        let value = self.u32();
        if self.bool() {
            Capabilities(value & (0xf | Capabilities::NONCE_CACHE | Capabilities::PSBT_TRIMMING))
        } else {
            Capabilities(value)
        }
    }

    fn error(&mut self) -> response::Error {
        match self.u8() % 18 {
            0 => response::Error::UserDeclined,
            1 => response::Error::UnsupportedVersion,
            2 => response::Error::MalformedRequest,
            3 => response::Error::UnknownDescriptorAlias,
            4 => response::Error::DescriptorRegistrationFailed,
            5 => response::Error::UnsupportedDescriptorForm,
            6 => response::Error::InvalidProof,
            7 => response::Error::AddressMismatch,
            8 => response::Error::NothingToSign,
            9 => response::Error::InvalidPsbt,
            10 => response::Error::InternalError,
            11 => response::Error::PrivateKeyExportRefused,
            12 => response::Error::MusigSession,
            13 => response::Error::AlreadyRegistered,
            14 => response::Error::UnsupportedOperation,
            15 => response::Error::NetworkMismatch,
            16 => response::Error::Vendor,
            _ => response::Error::Unknown(self.u8()),
        }
    }

    fn sp_scope(&mut self) -> SpScope {
        if self.bool() {
            SpScope::Global
        } else {
            SpScope::Input(self.u32())
        }
    }

    /// Taproot signatures are 63 to 66 bytes, around the 64 or 65 the codec accepts.
    fn taproot_signature(&mut self) -> Vec<u8> {
        let len = 63 + usize::from(self.u8() % 4);
        self.bytes_of_len(len)
    }

    fn signature(&mut self) -> SignatureEntry {
        match self.u8() % 8 {
            0 => SignatureEntry::Ecdsa {
                input_index: self.u32(),
                public_key: PublicKey(self.array()),
                signature: self.bytes(),
            },
            1 => SignatureEntry::TapKey {
                input_index: self.u32(),
                signature: self.taproot_signature(),
            },
            2 => SignatureEntry::TapScript {
                input_index: self.u32(),
                xonly_public_key: self.array(),
                tap_leaf_hash: self.array(),
                signature: self.taproot_signature(),
            },
            3 => SignatureEntry::MusigPubNonce {
                input_index: self.u32(),
                participant: PublicKey(self.array()),
                aggregate: PublicKey(self.array()),
                leaf_hash: self.option(Self::array),
                nonce: self.array(),
            },
            4 => SignatureEntry::MusigPartialSig {
                input_index: self.u32(),
                participant: PublicKey(self.array()),
                aggregate: PublicKey(self.array()),
                leaf_hash: self.option(Self::array),
                signature: self.array(),
            },
            5 => SignatureEntry::SpEcdhShare {
                scope: self.sp_scope(),
                scan_key: PublicKey(self.array()),
                share: PublicKey(self.array()),
            },
            6 => SignatureEntry::SpDleqProof {
                scope: self.sp_scope(),
                scan_key: PublicKey(self.array()),
                proof: self.array(),
            },
            _ => SignatureEntry::Unknown {
                input_index: self.u32(),
                kind: self.u8(),
                fields: self.bytes(),
            },
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut builder = Builder { data };
    let (message, encoded) = if builder.bool() {
        let request = builder.request();
        let encoded = encode_request(&request);
        (Message::Request(request), encoded)
    } else {
        let response = builder.response();
        let encoded = encode_response(&response);
        (Message::Response(response), encoded)
    };
    let Ok(bytes) = encoded else {
        return;
    };
    let decoded = decode(&bytes).expect("an encoded message must decode");
    assert_eq!(decoded, message);
    let again = match &decoded {
        Message::Request(request) => encode_request(request),
        Message::Response(response) => encode_response(response),
    };
    assert_eq!(again.expect("a decoded message must encode"), bytes);
});
