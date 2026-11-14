mod common;

use bipqr_ll::{
    self as protocol, Invalid, Message, decode::Error, reader, request, response,
    types::Fingerprint,
};
use serde_json::Value;

use common::{
    bip380, bip388, from_hex, key_request, musig_partial_sigs, musig_pub_nonces, path,
    sp_foreign_scan_keys, sp_global_send, sp_keys, sp_per_input_send, to_hex, xpriv, xpub,
    xpub_key,
};

// MSG_TYPE follows MAGIC and VERSION, and its bit 7 marks a response
const MSG_TYPE_OFFSET: usize = 7;
const RESPONSE_BIT: u8 = 0x80;

// the PSBT of an empty version 2 transaction
const PSBT_HEX: &str = "70736274ff01000a0200000000000000000000";

fn id() -> protocol::RequestId {
    protocol::RequestId([0, 1])
}

fn request(body: request::Body) -> Message {
    Message::Request(protocol::Request { id: id(), body })
}

fn response(body: response::Body) -> Message {
    Message::Response(protocol::Response { id: id(), body })
}

fn psbt() -> Vec<u8> {
    from_hex(PSBT_HEX)
}

fn register_descriptor_request(descriptor: Option<request::DescriptorBody>) -> Message {
    request(request::Body::RegisterDescriptor(
        request::RegisterDescriptor {
            descriptor_alias: "main".to_string(),
            descriptor,
        },
    ))
}

fn get_keys_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "get_keys_request_one_path",
            request(request::Body::GetKeys(request::GetKeys {
                keys: vec![key_request("m/48'/0'/0'/2'", request::KeyKind::Public)],
            })),
        ),
        (
            "get_keys_request_silent_payment_and_xpubs",
            request(request::Body::GetKeys(request::GetKeys {
                keys: vec![
                    key_request("m/352'/1'/0'/0'", request::KeyKind::Public),
                    key_request("m/352'/1'/0'/1'", request::KeyKind::Private),
                    key_request("m/86'/1'/0'", request::KeyKind::Public),
                    key_request("m/84'/1'/0'", request::KeyKind::Public),
                ],
            })),
        ),
        (
            "get_keys_response_ok",
            response(response::Body::Keys(response::Keys {
                keys: vec![xpub(), xpriv()],
                fingerprint: Fingerprint([0xde, 0xad, 0xbe, 0xef]),
                vendor: "bip".to_string(),
                model: "bip-signer".to_string(),
                version: response::FirmwareVersion {
                    major: 1,
                    minor: 2,
                    patch: 3,
                    flag: response::ReleaseFlag::Beta,
                },
                capabilities: response::Capabilities(0x0000_000f),
            })),
        ),
    ]
}

fn register_descriptor_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "register_descriptor_request_bip380",
            register_descriptor_request(Some(bip380())),
        ),
        (
            "register_descriptor_request_bip388",
            register_descriptor_request(Some(bip388())),
        ),
        (
            "register_descriptor_request_sp_keys",
            register_descriptor_request(Some(sp_keys())),
        ),
        (
            "register_descriptor_request_status_query",
            register_descriptor_request(None),
        ),
        (
            "register_descriptor_response_registered",
            response(response::Body::Registration(response::Registration {
                descriptor_alias: "main".to_string(),
                registered: true,
                stored: Some(true),
                proof: Some(vec![0xaa; 8]),
            })),
        ),
        (
            "register_descriptor_response_not_registered",
            response(response::Body::Registration(response::Registration {
                descriptor_alias: "main".to_string(),
                registered: false,
                stored: None,
                proof: None,
            })),
        ),
    ]
}

fn unregister_descriptor_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "unregister_descriptor_request",
            request(request::Body::UnregisterDescriptor(
                request::UnregisterDescriptor {
                    descriptor_alias: "main".to_string(),
                },
            )),
        ),
        (
            "unregister_descriptor_response",
            response(response::Body::Unregistered(response::Unregistered {
                descriptor_alias: "main".to_string(),
            })),
        ),
    ]
}

fn address_verification_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "address_verification_request",
            request(request::Body::VerifyAddress(request::VerifyAddress {
                descriptor_alias: "main".to_string(),
                derivation_path: path("m/7"),
                address: Some("bc1qxyz".to_string()),
                descriptor: Some(bip380()),
                proof: Some(vec![0x5a; 4]),
            })),
        ),
        (
            "address_verification_sp_request",
            request(request::Body::VerifyAddress(request::VerifyAddress {
                descriptor_alias: "main".to_string(),
                derivation_path: path("m"),
                address: Some("sp1qxyz".to_string()),
                descriptor: Some(sp_keys()),
                proof: None,
            })),
        ),
        (
            "address_verification_sp_request_with_por",
            request(request::Body::VerifyAddress(request::VerifyAddress {
                descriptor_alias: "main".to_string(),
                derivation_path: path("m"),
                address: Some("sp1qxyz".to_string()),
                descriptor: Some(sp_keys()),
                proof: Some(vec![0x5a; 4]),
            })),
        ),
        (
            "address_verification_sp_foreign_scan_request",
            request(request::Body::VerifyAddress(request::VerifyAddress {
                descriptor_alias: "main".to_string(),
                derivation_path: path("m/2"),
                address: Some("sp1qxyz".to_string()),
                descriptor: Some(sp_foreign_scan_keys()),
                proof: None,
            })),
        ),
        (
            "address_verification_response_uri",
            response(response::Body::AddressUri(response::AddressUri {
                uri: "bitcoin:bc1qxyz".to_string(),
            })),
        ),
    ]
}

fn sign_request(want_kind: protocol::SignResponseKind, accept_trimmed: bool) -> Message {
    request(request::Body::Sign(request::Sign {
        descriptors: vec![request::Descriptor {
            alias: "main".to_string(),
            descriptor: Some(bip380()),
            proof: Some(vec![0x5a; 4]),
        }],
        psbt: psbt(),
        want_kind: Some(want_kind),
        accept_trimmed,
    }))
}

fn signing_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "signing_request",
            sign_request(protocol::SignResponseKind::Signatures, false),
        ),
        (
            "signing_request_accept_trimmed",
            sign_request(protocol::SignResponseKind::Psbt, true),
        ),
        (
            "signing_response_psbt",
            response(response::Body::Signed(response::Signed::Psbt(psbt()))),
        ),
        (
            "signing_response_signatures",
            response(response::Body::Signed(response::Signed::Signatures(vec![
                response::SignatureEntry::Ecdsa {
                    input_index: 0,
                    public_key: xpub_key(),
                    signature: vec![0x30; 71],
                },
                response::SignatureEntry::TapKey {
                    input_index: 1,
                    signature: vec![0x01; 64],
                },
                response::SignatureEntry::TapScript {
                    input_index: 2,
                    xonly_public_key: [0x02; 32],
                    tap_leaf_hash: [0x03; 32],
                    signature: vec![0x04; 65],
                },
            ]))),
        ),
        (
            "signing_response_musig_pub_nonces",
            response(response::Body::Signed(response::Signed::Signatures(
                musig_pub_nonces(),
            ))),
        ),
        (
            "signing_response_musig_partial_sigs",
            response(response::Body::Signed(response::Signed::Signatures(
                musig_partial_sigs(),
            ))),
        ),
        (
            "signing_response_silent_payment_global",
            response(response::Body::Signed(response::Signed::Signatures(
                sp_global_send(),
            ))),
        ),
        (
            "signing_response_silent_payment_per_input",
            response(response::Body::Signed(response::Signed::Signatures(
                sp_per_input_send(),
            ))),
        ),
        (
            "signing_response_unknown_sig_kind",
            response(response::Body::Signed(response::Signed::Signatures(vec![
                response::SignatureEntry::Unknown {
                    input_index: 0,
                    kind: 0x08,
                    fields: vec![0xde, 0xad, 0xbe, 0xef],
                },
                response::SignatureEntry::TapKey {
                    input_index: 0,
                    signature: vec![0x01; 64],
                },
            ]))),
        ),
    ]
}

fn nonce_cache_messages() -> Vec<(&'static str, Message)> {
    let nonces = vec![[0x22; 66], [0x55; 66], [0x66; 66], [0x77; 66]];
    vec![
        (
            "nonce_preparation_request",
            request(request::Body::PrepareNonces(request::PrepareNonces {
                session_id: Some([0x51; 4]),
                session_ref: None,
                descriptor: None,
                max_inputs: 2,
                derivation_path: path("m/86'/1'/0'/0/3"),
                start: 0,
                end: Some(1),
            })),
        ),
        (
            "nonce_preparation_request_with_session_ref",
            request(request::Body::PrepareNonces(request::PrepareNonces {
                session_id: Some([0x51; 4]),
                session_ref: Some([0x52; 4]),
                descriptor: None,
                max_inputs: 2,
                derivation_path: path("m/86'/1'/0'/0/3"),
                start: 2,
                end: Some(3),
            })),
        ),
        (
            "nonce_preparation_request_with_descriptor",
            request(request::Body::PrepareNonces(request::PrepareNonces {
                session_id: Some([0x51; 4]),
                session_ref: None,
                descriptor: Some(request::Descriptor {
                    alias: "main".to_string(),
                    descriptor: Some(request::DescriptorBody::Bip388 {
                        keys: vec![
                            "[00000000/86h/1h/0h]xpub".to_string(),
                            "[11111111/86h/1h/0h]xpub".to_string(),
                        ],
                        policy: "tr(musig(@0,@1)/**)".to_string(),
                    }),
                    proof: None,
                }),
                max_inputs: 2,
                derivation_path: path("m/86'/1'/0'/0/3"),
                start: 0,
                end: Some(1),
            })),
        ),
        (
            "nonce_preparation_request_without_end",
            request(request::Body::PrepareNonces(request::PrepareNonces {
                session_id: Some([0x51; 4]),
                session_ref: None,
                descriptor: None,
                max_inputs: 2,
                derivation_path: path("m/86'/1'/0'/0/3"),
                start: 3,
                end: None,
            })),
        ),
        (
            "nonce_preparation_request_without_session_id",
            request(request::Body::PrepareNonces(request::PrepareNonces {
                session_id: None,
                session_ref: None,
                descriptor: None,
                max_inputs: 2,
                derivation_path: path("m/86'/1'/0'/0/3"),
                start: 0,
                end: Some(1),
            })),
        ),
        (
            "nonce_preparation_response_new_session",
            response(response::Body::NoncesPrepared(response::NoncesPrepared {
                session: Some(response::Session {
                    session_id: [0x51; 4],
                    session_ref: [0x52; 4],
                }),
                nonces: nonces.clone(),
            })),
        ),
        (
            "nonce_preparation_response_existing_session",
            response(response::Body::NoncesPrepared(response::NoncesPrepared {
                session: None,
                nonces,
            })),
        ),
    ]
}

fn info(state: response::State) -> response::Info {
    response::Info {
        vendor: "bip".to_string(),
        model: "bip-signer".to_string(),
        version: response::FirmwareVersion {
            major: 1,
            minor: 2,
            patch: 3,
            flag: response::ReleaseFlag::Beta,
        },
        capabilities: response::Capabilities(0x0000_000f),
        state,
        networks: response::Networks(0x00),
        max_message: 0,
        max_alias: 0,
        fingerprint: None,
    }
}

fn ready_info() -> response::Info {
    response::Info {
        networks: response::Networks(
            response::Networks::MAINNET
                | response::Networks::TESTNET
                | response::Networks::SIGNET
                | response::Networks::REGTEST,
        ),
        max_message: 512 * 1024,
        max_alias: 32,
        fingerprint: Some(Fingerprint([0xde, 0xad, 0xbe, 0xef])),
        ..info(response::State::Ready)
    }
}

fn get_info_messages() -> Vec<(&'static str, Message)> {
    vec![
        ("get_info_request", request(request::Body::GetInfo)),
        (
            "get_info_response_ready",
            response(response::Body::Info(ready_info())),
        ),
        (
            "get_info_response_psbt_trimming",
            response(response::Body::Info(response::Info {
                capabilities: response::Capabilities(0x0000_002f),
                ..ready_info()
            })),
        ),
        (
            "get_info_response_locked",
            response(response::Body::Info(response::Info {
                networks: response::Networks(response::Networks::MAINNET),
                max_message: 4096,
                max_alias: 16,
                ..info(response::State::Locked)
            })),
        ),
    ]
}

fn error_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "error_response_user_declined",
            response(response::Body::Error(response::ErrorBody {
                message_type: protocol::MessageType::Signing,
                error: response::Error::UserDeclined,
                message: "signing was declined".to_string(),
            })),
        ),
        (
            "error_response_vendor",
            response(response::Body::Error(response::ErrorBody {
                message_type: protocol::MessageType::Signing,
                error: response::Error::Vendor,
                message: "device is locked".to_string(),
            })),
        ),
        (
            "error_response_private_key_export_refused",
            response(response::Body::Error(response::ErrorBody {
                message_type: protocol::MessageType::GetKeys,
                error: response::Error::PrivateKeyExportRefused,
                message: "private key export refused".to_string(),
            })),
        ),
        (
            "error_response_musig_session",
            response(response::Body::Error(response::ErrorBody {
                message_type: protocol::MessageType::Signing,
                error: response::Error::MusigSession,
                message: "musig2 session missing".to_string(),
            })),
        ),
        (
            "error_response_already_registered",
            response(response::Body::Error(response::ErrorBody {
                message_type: protocol::MessageType::RegisterDescriptor,
                error: response::Error::AlreadyRegistered,
                message: "alias already registered".to_string(),
            })),
        ),
        (
            "error_response_unsupported_operation",
            response(response::Body::Error(response::ErrorBody {
                message_type: protocol::MessageType::AddressVerification,
                error: response::Error::UnsupportedOperation,
                message: "silent payments not supported".to_string(),
            })),
        ),
        (
            "error_response_network_mismatch",
            response(response::Body::Error(response::ErrorBody {
                message_type: protocol::MessageType::Signing,
                error: response::Error::NetworkMismatch,
                message: "wrong network".to_string(),
            })),
        ),
        (
            "error_response_reserved_code",
            response(response::Body::Error(response::ErrorBody {
                message_type: protocol::MessageType::GetKeys,
                error: response::Error::Unknown(0x11),
                message: "code added after version 1".to_string(),
            })),
        ),
        (
            "error_response_unreadable_request",
            Message::Response(protocol::Response::unreadable_request(
                "request header is unreadable".to_string(),
            )),
        ),
    ]
}

fn versioning_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "versioning_get_keys_request_version_two",
            request(request::Body::GetKeys(request::GetKeys {
                keys: vec![key_request("m/48'/0'/0'/2'", request::KeyKind::Public)],
            })),
        ),
        (
            "versioning_address_uri_response_version_two",
            response(response::Body::AddressUri(response::AddressUri {
                uri: "bitcoin:bc1qxyz".to_string(),
            })),
        ),
    ]
}

fn invalid_errors() -> Vec<(&'static str, Error)> {
    vec![
        ("invalid_magic", Error::InvalidMagic),
        (
            "invalid_unreadable_type_in_request",
            Error::UnreadableRequestType,
        ),
        (
            "invalid_unreadable_type_in_ok_response",
            Error::UnreadableRequestType,
        ),
        (
            "invalid_unreadable_type_request_id",
            Error::Invalid(Invalid::UnreadableRequestId),
        ),
        ("invalid_type_unknown", Error::UnknownMessageType(0x08)),
        ("invalid_status_on_request", Error::ErrorStatusOnRequest),
        ("invalid_truncated", Error::Read(reader::Error::Truncated)),
        ("invalid_key_kind", Error::UnknownKeyKind(0x02)),
        (
            "invalid_length_past_input",
            Error::Read(reader::Error::Truncated),
        ),
        (
            "invalid_sign_kind_reserved",
            Error::UnknownSignResponseKind(0x00),
        ),
        (
            "invalid_sign_kind_unknown",
            Error::UnknownSignResponseKind(0x03),
        ),
        (
            "invalid_presence",
            Error::Read(reader::Error::InvalidPresence(0x02)),
        ),
        (
            "invalid_nonce_max_inputs_zero",
            Error::Invalid(Invalid::ZeroMaxInputs),
        ),
        (
            "invalid_nonce_start_after_end",
            Error::Invalid(Invalid::ReversedExpressionRange),
        ),
        (
            "invalid_nonce_session_ref_without_id",
            Error::Invalid(Invalid::SessionRefWithoutId),
        ),
        ("invalid_nonce_response_id_only", Error::UnpairedSession),
        ("invalid_nonce_response_ref_only", Error::UnpairedSession),
        (
            "invalid_bool",
            Error::Read(reader::Error::InvalidBool(0x02)),
        ),
        (
            "invalid_accept_trimmed",
            Error::Read(reader::Error::InvalidBool(0x02)),
        ),
        ("invalid_form_reserved", Error::UnknownDescriptorForm(0x00)),
        ("invalid_form_unknown", Error::UnknownDescriptorForm(0x04)),
        (
            "invalid_alias_too_long",
            Error::Read(reader::Error::StringTooLarge(33)),
        ),
        (
            "invalid_unregister_descriptor_no_alias",
            Error::Read(reader::Error::Truncated),
        ),
        (
            "invalid_unregister_descriptor_status_on_request",
            Error::ErrorStatusOnRequest,
        ),
        (
            "invalid_unregister_descriptor_alias_too_long",
            Error::Read(reader::Error::StringTooLarge(33)),
        ),
        ("invalid_sp_keys_scan_path_and_key", Error::ScanPathAndKey),
        ("invalid_sp_keys_no_scan", Error::NoScan),
        (
            "invalid_string_utf8",
            Error::Read(reader::Error::InvalidUtf8(
                String::from_utf8(b"\xffevice is locked".to_vec()).unwrap_err(),
            )),
        ),
        ("invalid_string_nul", Error::Read(reader::Error::StringNul)),
        (
            "invalid_tapkey_signature_short",
            Error::Invalid(Invalid::TaprootSignatureLength(63)),
        ),
        (
            "invalid_taptree_signature_long",
            Error::Invalid(Invalid::TaprootSignatureLength(66)),
        ),
        (
            "invalid_entry_length_unfilled",
            Error::SignatureLength(0x01),
        ),
        (
            "invalid_entry_length_overflow",
            Error::SignatureLength(0x02),
        ),
        (
            "invalid_sp_share_without_proof",
            Error::Invalid(Invalid::MissingSpProof),
        ),
        (
            "invalid_sp_proof_without_share",
            Error::Invalid(Invalid::MissingSpShare),
        ),
        (
            "invalid_sp_duplicate_share",
            Error::Invalid(Invalid::DuplicateSpShare),
        ),
        (
            "invalid_sp_duplicate_proof",
            Error::Invalid(Invalid::DuplicateSpProof),
        ),
        ("invalid_sp_global_input_index", Error::GlobalInputIndex(1)),
        (
            "invalid_get_info_max_alias",
            Error::Invalid(Invalid::MaxAliasTooLarge(33)),
        ),
        (
            "invalid_get_info_fingerprint_locked",
            Error::Invalid(Invalid::FingerprintWhenNotReady),
        ),
    ]
}

fn check(json: &str, expected: &[(&str, Message)]) {
    pair(json, expected, check_vector);
}

fn check_invalid(json: &str, expected: &[(&str, Error)]) {
    pair(json, expected, check_invalid_vector);
}

fn pair<T>(json: &str, expected: &[(&str, T)], check_vector: fn(&Value, &T)) {
    let parsed: Value = serde_json::from_str(json).unwrap();
    let mut unpaired: Vec<&Value> = parsed["vectors"].as_array().unwrap().iter().collect();
    for (name, value) in expected {
        let index = unpaired
            .iter()
            .position(|vector| vector["name"] == *name)
            .unwrap_or_else(|| panic!("no json vector named {name}"));
        check_vector(unpaired.remove(index), value);
    }
    let extra: Vec<&str> = unpaired
        .iter()
        .map(|vector| vector["name"].as_str().unwrap())
        .collect();
    assert!(
        extra.is_empty(),
        "json vectors paired with nothing on the rust side: {extra:?}"
    );
}

fn check_vector(vector: &Value, message: &Message) {
    let name = vector["name"].as_str().unwrap();
    let hex = vector["hex"].as_str().unwrap();
    let (direction, encoded) = match message {
        Message::Request(request) => ("request", protocol::encode_request(request).unwrap()),
        Message::Response(response) => ("response", protocol::encode_response(response).unwrap()),
    };
    assert_eq!(vector["direction"], direction, "{name}: wrong direction");
    let bytes = from_hex(hex);
    assert_eq!(
        &protocol::decode(&bytes).unwrap(),
        message,
        "{name}: decodes to another message"
    );
    // a decode-only vector is not version 1, so the encoder cannot produce its bytes
    if vector["decode_only"].as_bool().unwrap() {
        return;
    }
    assert_eq!(to_hex(&encoded), hex, "{name}: encodes to other bytes");
}

fn check_invalid_vector(vector: &Value, error: &Error) {
    let name = vector["name"].as_str().unwrap();
    assert!(
        vector["decode_error"].as_bool().unwrap(),
        "{name}: not a decode error"
    );
    assert!(
        vector["decode_only"].as_bool().unwrap(),
        "{name}: a decode error is decode only"
    );
    let bytes = from_hex(vector["hex"].as_str().unwrap());
    let direction = if bytes[MSG_TYPE_OFFSET] & RESPONSE_BIT == 0 {
        "request"
    } else {
        "response"
    };
    assert_eq!(vector["direction"], direction, "{name}: wrong direction");
    assert_eq!(
        protocol::decode(&bytes),
        Err(error.clone()),
        "{name}: fails for another reason"
    );
}

#[test]
fn get_keys_vectors() {
    check(
        include_str!("../../test_vectors/get_keys.json"),
        &get_keys_messages(),
    );
}

#[test]
fn register_descriptor_vectors() {
    check(
        include_str!("../../test_vectors/register_descriptor.json"),
        &register_descriptor_messages(),
    );
}

#[test]
fn unregister_descriptor_vectors() {
    check(
        include_str!("../../test_vectors/unregister_descriptor.json"),
        &unregister_descriptor_messages(),
    );
}

#[test]
fn address_verification_vectors() {
    check(
        include_str!("../../test_vectors/address_verification.json"),
        &address_verification_messages(),
    );
}

#[test]
fn signing_vectors() {
    check(
        include_str!("../../test_vectors/signing.json"),
        &signing_messages(),
    );
}

#[test]
fn nonce_cache_vectors() {
    check(
        include_str!("../../test_vectors/nonce_cache.json"),
        &nonce_cache_messages(),
    );
}

#[test]
fn get_info_vectors() {
    check(
        include_str!("../../test_vectors/get_info.json"),
        &get_info_messages(),
    );
}

#[test]
fn error_vectors() {
    check(
        include_str!("../../test_vectors/errors.json"),
        &error_messages(),
    );
}

#[test]
fn versioning_vectors() {
    check(
        include_str!("../../test_vectors/versioning.json"),
        &versioning_messages(),
    );
}

#[test]
fn invalid_vectors() {
    check_invalid(
        include_str!("../../test_vectors/invalid.json"),
        &invalid_errors(),
    );
}
