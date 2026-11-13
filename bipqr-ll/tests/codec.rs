mod common;

use bipqr_ll::{
    Invalid, MAX_DESCRIPTOR_ALIAS, Message, MessageType, REQUEST_ID_LEN, Request, RequestId,
    Response, SignResponseKind, decode, encode, encode_request, encode_response, reader, request,
    response::{self, SpScope},
    types::{Fingerprint, SCHNORR_SIGNATURE_LEN},
};

use common::{
    aggregate, key_request, musig_partial_sigs, musig_pub_nonces, sp_global_send,
    sp_per_input_send, sp_proof, sp_share, xpub, xpub_key,
};

// MAGIC is 6 bytes, so VERSION sits at index 6 and MSG_TYPE right after it
const VERSION_OFFSET: usize = 6;
const MSG_TYPE_OFFSET: usize = 7;
const HEADER_LEN: usize = MSG_TYPE_OFFSET + 1 + REQUEST_ID_LEN;
// STORED's value follows the header, the alias "main" as a STRING (1 + 4),
// REGISTERED (1), and STORED's own presence byte
const STORED_VALUE_OFFSET: usize = HEADER_LEN + 5 + 1 + 1;
// the first SIG_ENTRY follows KIND and the SIG_ENTRY count
const FIRST_ENTRY_OFFSET: usize = HEADER_LEN + 1 + 1;
// INPUT_INDEX, SIG_KIND and a one-byte LENGTH come before an entry's KIND_FIELDS
const ENTRY_HEADER_LEN: usize = 4 + 1 + 1;
// the first LEAF_HASH presence byte of musig_pub_nonces() follows the entry header,
// PARTICIPANT and AGGREGATE
const FIRST_LEAF_HASH_PRESENCE_OFFSET: usize = FIRST_ENTRY_OFFSET + ENTRY_HEADER_LEN + 33 + 33;
// a tapkey entry holds a 64-byte SIGNATURE behind its own one-byte LENGTH
const TAP_KEY_ENTRY_LEN: usize = ENTRY_HEADER_LEN + 1 + 64;
// GLOBAL, SCAN_KEY and SHARE
const SP_SHARE_ENTRY_LEN: usize = ENTRY_HEADER_LEN + 1 + 33 + 33;
// the first KIND of get_keys_request() follows the KEYS count and its path m/48'/0'/0'/2'
// (CHILD_COUNT + 4 steps of 4 bytes)
const FIRST_KEY_KIND_OFFSET: usize = HEADER_LEN + 1 + 1 + 4 * 4;

fn id() -> RequestId {
    RequestId([42; REQUEST_ID_LEN])
}

fn get_keys_request() -> Request {
    Request {
        id: id(),
        body: request::Body::GetKeys(request::GetKeys {
            keys: vec![
                key_request("m/48'/0'/0'/2'", request::KeyKind::Public),
                key_request("m/84'/1'/0'", request::KeyKind::Public),
            ],
        }),
    }
}

fn keys_response(capabilities: u32) -> Response {
    Response {
        id: id(),
        body: response::Body::Keys(response::Keys {
            keys: vec![xpub()],
            fingerprint: Fingerprint([0xde, 0xad, 0xbe, 0xef]),
            vendor: "bip".to_string(),
            model: "bip-signer".to_string(),
            version: response::FirmwareVersion {
                major: 1,
                minor: 7,
                patch: 0x00ab_cdef,
                flag: response::ReleaseFlag::ReleaseCandidate,
            },
            capabilities: response::Capabilities(capabilities),
        }),
    }
}

fn registration_response(stored: Option<bool>) -> Response {
    Response {
        id: id(),
        body: response::Body::Registration(response::Registration {
            descriptor_alias: "main".to_string(),
            registered: true,
            stored,
            proof: Some(vec![0xaa; 32]),
        }),
    }
}

fn error_response(error: response::Error) -> Response {
    Response {
        id: id(),
        body: response::Body::Error(response::ErrorBody {
            message_type: MessageType::Signing,
            error,
            message: "signing was declined".to_string(),
        }),
    }
}

fn signatures_response(entries: Vec<response::SignatureEntry>) -> Response {
    Response {
        id: id(),
        body: response::Body::Signed(response::Signed::Signatures(entries)),
    }
}

fn register_descriptor_request(alias: String) -> Request {
    Request {
        id: id(),
        body: request::Body::RegisterDescriptor(request::RegisterDescriptor {
            descriptor_alias: alias,
            descriptor: None,
        }),
    }
}

fn sign_request(want_kind: Option<SignResponseKind>) -> Request {
    Request {
        id: id(),
        body: request::Body::Sign(request::Sign {
            descriptors: vec![],
            psbt: vec![0x70, 0x73, 0x62, 0x74, 0xff],
            want_kind,
            accept_trimmed: true,
        }),
    }
}

#[test]
fn decode_accepts_a_version_one_blob() {
    let request = get_keys_request();
    let bytes = encode_request(&request).unwrap();
    assert_eq!(bytes[VERSION_OFFSET], 1);
    assert_eq!(decode(&bytes), Ok(Message::Request(request)));
}

#[test]
fn decode_ignores_trailing_bytes_of_a_newer_version() {
    let request = get_keys_request();
    let mut bytes = encode_request(&request).unwrap();
    bytes[VERSION_OFFSET] = 2;
    bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    assert_eq!(decode(&bytes), Ok(Message::Request(request)));
}

#[test]
fn decode_ignores_trailing_bytes_at_version_one() {
    let request = get_keys_request();
    let mut bytes = encode_request(&request).unwrap();
    bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    assert_eq!(decode(&bytes), Ok(Message::Request(request)));
}

#[test]
fn decode_rejects_version_zero() {
    let mut bytes = encode_request(&get_keys_request()).unwrap();
    bytes[VERSION_OFFSET] = 0;
    assert_eq!(decode(&bytes), Err(decode::Error::ReservedVersion));
}

#[test]
fn decode_rejects_wrong_magic() {
    let mut bytes = encode_request(&get_keys_request()).unwrap();
    bytes[0] = b'X';
    assert_eq!(decode(&bytes), Err(decode::Error::InvalidMagic));
}

#[test]
fn decode_rejects_a_truncated_field() {
    let bytes = encode_request(&get_keys_request()).unwrap();
    assert_eq!(
        decode(&bytes[..bytes.len() - 1]),
        Err(decode::Error::Read(reader::Error::Truncated))
    );
}

#[test]
fn decode_rejects_an_unknown_message_type() {
    let mut bytes = encode_request(&get_keys_request()).unwrap();
    bytes[MSG_TYPE_OFFSET] = 0x3f;
    assert_eq!(decode(&bytes), Err(decode::Error::UnknownMessageType(0x3f)));
}

#[test]
fn decode_rejects_the_reserved_message_type_seven() {
    let mut bytes = encode_request(&get_keys_request()).unwrap();
    bytes[MSG_TYPE_OFFSET] = 0x07;
    assert_eq!(decode(&bytes), Err(decode::Error::UnknownMessageType(0x07)));
}

#[test]
fn decode_rejects_an_unknown_key_kind() {
    let mut bytes = encode_request(&get_keys_request()).unwrap();
    bytes[FIRST_KEY_KIND_OFFSET] = 0x02;
    assert_eq!(decode(&bytes), Err(decode::Error::UnknownKeyKind(0x02)));
}

#[test]
fn decode_ignores_an_unknown_want_kind() {
    let mut bytes = encode_request(&sign_request(Some(SignResponseKind::Signatures))).unwrap();
    // WANT_KIND's value is followed by ACCEPT_TRIMMED, the last message byte
    let want_kind = bytes.len() - 2;
    bytes[want_kind] = 0x03;
    assert_eq!(decode(&bytes), Ok(Message::Request(sign_request(None))));
}

#[test]
fn decode_rejects_an_accept_trimmed_byte_outside_bool() {
    let mut bytes = encode_request(&sign_request(None)).unwrap();
    // ACCEPT_TRIMMED is the last body field, so its value is the last message byte
    *bytes.last_mut().unwrap() = 0x02;
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Read(reader::Error::InvalidBool(0x02)))
    );
}

#[test]
fn decode_rejects_error_status_on_a_request() {
    let mut bytes = encode_request(&get_keys_request()).unwrap();
    bytes[MSG_TYPE_OFFSET] |= 0x40;
    assert_eq!(decode(&bytes), Err(decode::Error::ErrorStatusOnRequest));
}

#[test]
fn decode_rejects_an_invalid_stored_byte() {
    let mut bytes = encode_response(&registration_response(Some(true))).unwrap();
    bytes[STORED_VALUE_OFFSET] = 0x02;
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Read(reader::Error::InvalidBool(0x02)))
    );
}

#[test]
fn decode_rejects_a_string_holding_a_nul() {
    let response = registration_response(None);
    let bytes = encode_response(&response).unwrap();
    // the alias "main" starts right after the header and its length byte
    let mut bytes = bytes.clone();
    bytes[HEADER_LEN + 1] = 0;
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Read(reader::Error::StringNul))
    );
}

#[test]
fn decode_rejects_an_oversized_vector_without_allocating_it() {
    let mut bytes = encode_request(&get_keys_request()).unwrap();
    // the KEYS count is the first body byte, after the header
    bytes[HEADER_LEN] = 0xfd;
    bytes.splice(HEADER_LEN + 1..HEADER_LEN + 1, [0xff, 0x0f]);
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Read(reader::Error::Truncated))
    );
}

#[test]
fn encode_rejects_reserved_capability_bits() {
    assert_eq!(
        encode_response(&keys_response(0x0000_0040)),
        Err(encode::Error::ReservedCapabilityBits(0x0000_0040))
    );
}

#[test]
fn psbt_trimming_capability_is_bit_5_and_encodes() {
    assert_eq!(response::Capabilities::PSBT_TRIMMING, 0x20);
    assert!(!response::Capabilities(0x1f).supports_psbt_trimming());
    assert!(response::Capabilities(0x20).supports_psbt_trimming());
    let response = keys_response(0x0000_003f);
    assert_eq!(
        decode(&encode_response(&response).unwrap()),
        Ok(Message::Response(response))
    );
}

#[test]
fn encode_rejects_colliding_unknown_error_codes() {
    for value in [0x00, 0x03, 0xff] {
        assert_eq!(
            encode_response(&error_response(response::Error::Unknown(value))),
            Err(encode::Error::ErrorCodeOutOfRange(value))
        );
    }
}

#[test]
fn encode_rejects_a_string_holding_a_nul() {
    let request = register_descriptor_request("ma\0in".to_string());
    assert_eq!(encode_request(&request), Err(encode::Error::StringNul));
}

#[test]
fn encode_rejects_an_oversized_descriptor_alias() {
    let request = register_descriptor_request("a".repeat(MAX_DESCRIPTOR_ALIAS + 1));
    assert_eq!(
        encode_request(&request),
        Err(encode::Error::StringTooLong {
            len: MAX_DESCRIPTOR_ALIAS + 1,
            max: MAX_DESCRIPTOR_ALIAS,
        })
    );
}

#[test]
fn decode_rejects_an_oversized_descriptor_alias() {
    let request = register_descriptor_request("a".repeat(MAX_DESCRIPTOR_ALIAS));
    let mut bytes = encode_request(&request).unwrap();
    bytes[HEADER_LEN] = (MAX_DESCRIPTOR_ALIAS + 1) as u8;
    bytes.insert(HEADER_LEN + 1, b'a');
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Read(reader::Error::StringTooLarge(
            MAX_DESCRIPTOR_ALIAS + 1
        )))
    );
}

#[test]
fn encode_rejects_a_model_holding_a_nul() {
    let mut response = keys_response(0);
    let response::Body::Keys(body) = &mut response.body else {
        unreachable!()
    };
    body.model = "bip\0signer".to_string();
    assert_eq!(encode_response(&response), Err(encode::Error::StringNul));
}

#[test]
fn every_error_message_is_terminated_and_uniquely_coded() {
    let reader_errors = [
        reader::Error::Truncated,
        reader::Error::LengthOverflow,
        reader::Error::NonCanonicalCompactSize,
        reader::Error::CompactSizeTooLarge(0),
        reader::Error::InvalidBool(0),
        reader::Error::InvalidPresence(0),
        reader::Error::StringTooLarge(0),
        reader::Error::InvalidUtf8(String::from_utf8(vec![0xff]).unwrap_err()),
        reader::Error::StringNul,
    ];
    let decode_errors = [
        decode::Error::InvalidMagic,
        decode::Error::ReservedVersion,
        decode::Error::UnknownMessageType(0),
        decode::Error::ErrorStatusOnRequest,
        decode::Error::UnknownDescriptorForm(0),
        decode::Error::UnknownSignResponseKind(0),
        decode::Error::UnknownKeyKind(0),
        decode::Error::SignatureLength(0),
        decode::Error::GlobalInputIndex(0),
        decode::Error::ScanPathAndKey,
        decode::Error::NoScan,
        decode::Error::UnpairedSession,
    ];
    let encode_errors = [
        encode::Error::PathTooLong(0),
        encode::Error::PatchTooLarge(0),
        encode::Error::ReservedCapabilityBits(0),
        encode::Error::ErrorCodeOutOfRange(0),
        encode::Error::StringTooLong { len: 0, max: 0 },
        encode::Error::StringNul,
        encode::Error::Unreachable,
        encode::Error::DefinedSignatureKind(0),
        encode::Error::ReservedNetworkBits(0),
        encode::Error::DefinedState(0),
        encode::Error::DefinedReleaseFlag(0),
    ];
    let invalid_errors = [
        Invalid::DuplicateSpShare,
        Invalid::DuplicateSpProof,
        Invalid::MissingSpProof,
        Invalid::MissingSpShare,
        Invalid::MaxAliasTooLarge(0),
        Invalid::FingerprintWhenNotReady,
        Invalid::TaprootSignatureLength(0),
        Invalid::ZeroMaxInputs,
        Invalid::ReversedExpressionRange,
        Invalid::SessionRefWithoutId,
    ];

    let mut infos = Vec::new();
    infos.extend(reader_errors.iter().map(reader::Error::info));
    infos.extend(decode_errors.iter().map(decode::Error::info));
    infos.extend(encode_errors.iter().map(encode::Error::info));
    infos.extend(invalid_errors.iter().map(Invalid::info));

    let mut codes = Vec::new();
    for info in &infos {
        let code = info.code;
        let message = info.message;
        assert!(message.ends_with('\0'), "{message} is not nul-terminated");
        assert!(message.is_ascii(), "{message} is not ascii");
        assert!(message.len() > 1, "empty message for code {code}");
        codes.push(code);
    }
    codes.sort_unstable();
    let mut unique = codes.clone();
    unique.dedup();
    assert_eq!(codes, unique, "error codes are not unique");

    assert_eq!(
        decode::Error::Read(reader::Error::Truncated).info(),
        reader::Error::Truncated.info()
    );
    assert_eq!(reader::Error::Truncated.to_string(), "truncated field");
}

mod sp_keys {
    use bipqr_ll::{
        Message, Request, decode, encode, encode_request, reader, request,
        types::{DerivationPath, SECRET_KEY_LEN, SecretKey},
    };

    use crate::{
        common::{FOREIGN_SCAN_KEY, sp_foreign_scan_keys, sp_keys, sp_keys_with},
        id,
    };

    // the scan key, then the absent POR, close a request with a foreign scan key
    const SCAN_KEY_TAIL_LEN: usize = SECRET_KEY_LEN + 1;

    fn verify_address_request(descriptor: request::DescriptorBody) -> Request {
        Request {
            id: id(),
            body: request::Body::VerifyAddress(request::VerifyAddress {
                descriptor_alias: "main".to_string(),
                derivation_path: DerivationPath(vec![]),
                address: None,
                descriptor: Some(descriptor),
                proof: None,
            }),
        }
    }

    #[test]
    fn register_descriptor_requests_round_trip() {
        for keys in [sp_keys(), sp_foreign_scan_keys()] {
            let request = Request {
                id: id(),
                body: request::Body::RegisterDescriptor(request::RegisterDescriptor {
                    descriptor_alias: "main".to_string(),
                    descriptor: Some(keys),
                }),
            };
            let bytes = encode_request(&request).unwrap();
            assert_eq!(decode(&bytes), Ok(Message::Request(request)));
        }
    }

    #[test]
    fn verify_address_requests_with_a_proof_round_trip() {
        for keys in [sp_keys(), sp_foreign_scan_keys()] {
            let mut verify = verify_address_request(keys);
            let request::Body::VerifyAddress(body) = &mut verify.body else {
                unreachable!()
            };
            body.proof = Some(vec![0x5a; 4]);
            let bytes = encode_request(&verify).unwrap();
            assert_eq!(bytes[bytes.len() - 6..], [1, 4, 0x5a, 0x5a, 0x5a, 0x5a]);
            assert_eq!(decode(&bytes), Ok(Message::Request(verify)));
        }
    }

    fn foreign_scan_request(key: [u8; SECRET_KEY_LEN]) -> Request {
        verify_address_request(sp_keys_with(request::Scan::Key(SecretKey(key))))
    }

    // a valid request with a foreign scan key, whose scan key bytes are then replaced
    fn foreign_scan_bytes(key: [u8; SECRET_KEY_LEN]) -> Vec<u8> {
        let mut bytes = encode_request(&verify_address_request(sp_foreign_scan_keys())).unwrap();
        let start = bytes.len() - SCAN_KEY_TAIL_LEN;
        bytes[start..start + SECRET_KEY_LEN].copy_from_slice(&key);
        bytes
    }

    #[test]
    fn encode_rejects_a_path_over_255_steps() {
        let request =
            verify_address_request(sp_keys_with(request::Scan::Path(DerivationPath(vec![
                0;
                256
            ]))));
        assert_eq!(
            encode_request(&request),
            Err(encode::Error::PathTooLong(256))
        );
    }

    #[test]
    fn decode_rejects_a_truncated_scan_path() {
        let bytes = encode_request(&verify_address_request(sp_keys())).unwrap();
        // drop the absent POR and SCAN_KEY bytes and the last byte of the scan path
        assert_eq!(
            decode(&bytes[..bytes.len() - 3]),
            Err(decode::Error::Read(reader::Error::Truncated))
        );
    }

    #[test]
    fn decode_rejects_both_a_scan_path_and_a_scan_key() {
        let bytes = encode_request(&verify_address_request(sp_keys())).unwrap();
        // replace the absent SCAN_KEY and POR with a present SCAN_KEY and an absent POR
        let mut both = bytes[..bytes.len() - 2].to_vec();
        both.push(1);
        both.extend_from_slice(&FOREIGN_SCAN_KEY);
        both.push(0);
        assert_eq!(decode(&both), Err(decode::Error::ScanPathAndKey));
    }

    #[test]
    fn decode_rejects_neither_a_scan_path_nor_a_scan_key() {
        let bytes = encode_request(&verify_address_request(sp_foreign_scan_keys())).unwrap();
        // turn the present SCAN_KEY into an absent one, followed by the absent POR
        let mut neither = bytes[..bytes.len() - SCAN_KEY_TAIL_LEN - 1].to_vec();
        neither.extend_from_slice(&[0, 0]);
        assert_eq!(neither[neither.len() - 3], 0, "SCAN_PATH is absent");
        assert_eq!(decode(&neither), Err(decode::Error::NoScan));
    }

    #[test]
    fn any_scan_key_bytes_round_trip() {
        for key in [[0; SECRET_KEY_LEN], [0xff; SECRET_KEY_LEN]] {
            let bytes = foreign_scan_bytes(key);
            assert_eq!(encode_request(&foreign_scan_request(key)).unwrap(), bytes);
            assert_eq!(
                decode(&bytes),
                Ok(Message::Request(foreign_scan_request(key)))
            );
        }
    }

    #[test]
    fn debug_does_not_print_the_scan_key() {
        let printed = format!("{:?}", sp_foreign_scan_keys());
        assert!(printed.contains("SecretKey(\"[redacted]\")"), "{printed}");
        assert!(
            !printed.contains(&format!("{FOREIGN_SCAN_KEY:?}")),
            "{printed}"
        );
    }
}

#[test]
fn musig_signatures_round_trip() {
    let mut entries = musig_pub_nonces();
    entries.extend(musig_partial_sigs());
    let response = signatures_response(entries);
    let bytes = encode_response(&response).unwrap();
    assert_eq!(decode(&bytes), Ok(Message::Response(response)));
}

#[test]
fn musig_leaf_hash_presence_must_be_zero_or_one() {
    let mut bytes = encode_response(&signatures_response(musig_pub_nonces())).unwrap();
    assert_eq!(bytes[FIRST_LEAF_HASH_PRESENCE_OFFSET], 0);
    bytes[FIRST_LEAF_HASH_PRESENCE_OFFSET] = 0x02;
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Read(reader::Error::InvalidPresence(0x02)))
    );
}

#[test]
fn truncated_musig_nonce_is_refused() {
    let bytes = encode_response(&signatures_response(musig_pub_nonces())).unwrap();
    assert_eq!(
        decode(&bytes[..bytes.len() - 1]),
        Err(decode::Error::Read(reader::Error::Truncated))
    );
}

#[test]
fn every_error_code_round_trips() {
    for (error, code) in [
        (response::Error::UserDeclined, 0x01),
        (response::Error::UnsupportedVersion, 0x02),
        (response::Error::MalformedRequest, 0x03),
        (response::Error::UnknownDescriptorAlias, 0x04),
        (response::Error::DescriptorRegistrationFailed, 0x05),
        (response::Error::UnsupportedDescriptorForm, 0x06),
        (response::Error::InvalidProof, 0x07),
        (response::Error::AddressMismatch, 0x08),
        (response::Error::NothingToSign, 0x09),
        (response::Error::InvalidPsbt, 0x0a),
        (response::Error::InternalError, 0x0b),
        (response::Error::PrivateKeyExportRefused, 0x0c),
        (response::Error::MusigSession, 0x0d),
        (response::Error::AlreadyRegistered, 0x0e),
        (response::Error::UnsupportedOperation, 0x0f),
        (response::Error::NetworkMismatch, 0x10),
        (response::Error::Vendor, 0xff),
    ] {
        assert_eq!(u8::from(error), code);
        assert_eq!(response::Error::from(code), error);
        let response = error_response(error);
        let bytes = encode_response(&response).unwrap();
        assert_eq!(decode(&bytes), Ok(Message::Response(response)));
        assert_eq!(
            encode_response(&error_response(response::Error::Unknown(code))),
            Err(encode::Error::ErrorCodeOutOfRange(code))
        );
    }
    let response = error_response(response::Error::Unknown(0x11));
    let bytes = encode_response(&response).unwrap();
    assert_eq!(decode(&bytes), Ok(Message::Response(response)));
}

#[test]
fn every_release_flag_round_trips() {
    for (flag, value) in [
        (response::ReleaseFlag::Stable, 0x00),
        (response::ReleaseFlag::Alpha, 0x01),
        (response::ReleaseFlag::Beta, 0x02),
        (response::ReleaseFlag::ReleaseCandidate, 0x03),
        (response::ReleaseFlag::Unknown(0x04), 0x04),
        (response::ReleaseFlag::Unknown(0xff), 0xff),
    ] {
        assert_eq!(flag.value(), value);
        assert_eq!(response::ReleaseFlag::from(value), flag);
        let response = keys_response_with_flag(flag);
        let bytes = encode_response(&response).unwrap();
        assert_eq!(decode(&bytes), Ok(Message::Response(response)));
    }
}

#[test]
fn encode_rejects_an_unknown_release_flag_of_a_defined_value() {
    for value in [0x00, 0x01, 0x02, 0x03] {
        let response = keys_response_with_flag(response::ReleaseFlag::Unknown(value));
        assert_eq!(
            encode_response(&response),
            Err(encode::Error::DefinedReleaseFlag(value))
        );
    }
}

fn keys_response_with_flag(flag: response::ReleaseFlag) -> Response {
    let mut response = keys_response(0);
    let response::Body::Keys(keys) = &mut response.body else {
        unreachable!()
    };
    keys.version.flag = flag;
    response
}

#[test]
fn psbt_signing_response_round_trips() {
    // the PSBT of an empty version 2 transaction
    let psbt = vec![
        0x70, 0x73, 0x62, 0x74, 0xff, 0x01, 0x00, 0x0a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    let response = Response {
        id: id(),
        body: response::Body::Signed(response::Signed::Psbt(psbt)),
    };
    let bytes = encode_response(&response).unwrap();
    assert_eq!(decode(&bytes), Ok(Message::Response(response)));
}

fn tap_key_response() -> Response {
    signatures_response(vec![response::SignatureEntry::TapKey {
        input_index: 0,
        signature: vec![0x01; 64],
    }])
}

#[test]
fn decode_rejects_known_fields_overflowing_their_length() {
    let mut bytes = encode_response(&tap_key_response()).unwrap();
    let length = FIRST_ENTRY_OFFSET + ENTRY_HEADER_LEN - 1;
    assert_eq!(bytes[length], 0x41);
    // one byte short: the SIGNATURE no longer fits
    bytes[length] = 0x40;
    bytes.pop();
    assert_eq!(decode(&bytes), Err(decode::Error::SignatureLength(0x02)));
}

#[test]
fn decode_rejects_known_fields_short_of_their_length() {
    let mut bytes = encode_response(&tap_key_response()).unwrap();
    let length = FIRST_ENTRY_OFFSET + ENTRY_HEADER_LEN - 1;
    // one byte past the SIGNATURE that a tapkey entry does not hold
    bytes[length] = 0x42;
    bytes.push(0x00);
    assert_eq!(decode(&bytes), Err(decode::Error::SignatureLength(0x02)));
}

fn tap_key_entry(signature: Vec<u8>) -> response::SignatureEntry {
    response::SignatureEntry::TapKey {
        input_index: 0,
        signature,
    }
}

fn tap_script_entry(signature: Vec<u8>) -> response::SignatureEntry {
    response::SignatureEntry::TapScript {
        input_index: 0,
        xonly_public_key: [0x02; 32],
        tap_leaf_hash: [0x03; 32],
        signature,
    }
}

/// A one-entry Signing response whose taproot SIGNATURE is `len` bytes, built by hand
/// as the encoder refuses any length but 64 and 65.
fn taproot_signature_bytes(entry: response::SignatureEntry, len: usize) -> Vec<u8> {
    let mut bytes = encode_response(&signatures_response(vec![entry])).unwrap();
    // the entry ends with its 64-byte SIGNATURE, right after that SIGNATURE's LENGTH
    let signature = bytes.len() - SCHNORR_SIGNATURE_LEN;
    bytes.truncate(signature);
    bytes[signature - 1] = len as u8;
    bytes.resize(signature + len, 0x01);
    let length = FIRST_ENTRY_OFFSET + ENTRY_HEADER_LEN - 1;
    bytes[length] = (usize::from(bytes[length]) + len - SCHNORR_SIGNATURE_LEN) as u8;
    bytes
}

#[test]
fn taproot_signatures_of_64_or_65_bytes_round_trip() {
    for len in [64, 65] {
        for entry in [
            tap_key_entry(vec![0x01; len]),
            tap_script_entry(vec![0x01; len]),
        ] {
            let response = signatures_response(vec![entry]);
            let bytes = encode_response(&response).unwrap();
            assert_eq!(decode(&bytes), Ok(Message::Response(response)));
        }
    }
}

#[test]
fn taproot_signatures_of_another_length_are_rejected_in_both_directions() {
    for len in [0, 63, 66] {
        for entry in [
            tap_key_entry(vec![0x01; len]),
            tap_script_entry(vec![0x01; len]),
        ] {
            assert_eq!(
                encode_response(&signatures_response(vec![entry])),
                Err(encode::Error::Invalid(Invalid::TaprootSignatureLength(len)))
            );
        }
        for entry in [
            tap_key_entry(vec![0x01; 64]),
            tap_script_entry(vec![0x01; 64]),
        ] {
            assert_eq!(
                decode(&taproot_signature_bytes(entry, len)),
                Err(decode::Error::Invalid(Invalid::TaprootSignatureLength(len)))
            );
        }
    }
}

#[test]
fn ecdsa_signatures_are_not_bound_to_a_length() {
    let response = signatures_response(vec![response::SignatureEntry::Ecdsa {
        input_index: 0,
        public_key: xpub_key(),
        signature: vec![0x30; 9],
    }]);
    let bytes = encode_response(&response).unwrap();
    assert_eq!(decode(&bytes), Ok(Message::Response(response)));
}

#[test]
fn decode_keeps_an_unknown_kind_whatever_its_fields() {
    let mut bytes = encode_response(&tap_key_response()).unwrap();
    // the same entry under the reserved kind 0x00: 65 bytes no known kind would parse
    bytes[FIRST_ENTRY_OFFSET + 4] = 0x00;
    let mut fields = vec![0x40];
    fields.extend([0x01; 64]);
    assert_eq!(
        decode(&bytes),
        Ok(Message::Response(signatures_response(vec![
            response::SignatureEntry::Unknown {
                input_index: 0,
                kind: 0x00,
                fields,
            }
        ])))
    );
}

#[test]
fn encode_rejects_an_unknown_entry_of_a_defined_or_reserved_kind() {
    for kind in [0x00, 0x02, 0x07] {
        let response = signatures_response(vec![response::SignatureEntry::Unknown {
            input_index: 0,
            kind,
            fields: vec![],
        }]);
        assert_eq!(
            encode_response(&response),
            Err(encode::Error::DefinedSignatureKind(kind))
        );
    }
}

#[test]
fn silent_payment_entries_round_trip() {
    for entries in [sp_global_send(), sp_per_input_send()] {
        let response = signatures_response(entries);
        let bytes = encode_response(&response).unwrap();
        assert_eq!(decode(&bytes), Ok(Message::Response(response)));
    }
}

#[test]
fn a_global_entry_carries_input_index_zero() {
    let mut bytes = encode_response(&signatures_response(sp_global_send())).unwrap();
    let share = FIRST_ENTRY_OFFSET + 2 * TAP_KEY_ENTRY_LEN;
    assert_eq!(bytes[share..share + 5], [0, 0, 0, 0, 0x06]);
    bytes[share + 3] = 0x01;
    assert_eq!(decode(&bytes), Err(decode::Error::GlobalInputIndex(1)));
}

#[test]
fn decode_rejects_a_global_byte_outside_bool() {
    let mut bytes = encode_response(&signatures_response(sp_global_send())).unwrap();
    let global = FIRST_ENTRY_OFFSET + 2 * TAP_KEY_ENTRY_LEN + ENTRY_HEADER_LEN;
    assert_eq!(bytes[global], 0x01);
    bytes[global] = 0x02;
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Read(reader::Error::InvalidBool(0x02)))
    );
}

#[test]
fn a_share_without_its_proof_is_refused() {
    let scan = aggregate(0x02, 0x5a);
    let response = signatures_response(vec![sp_share(SpScope::Input(0), scan, 0xa0)]);
    assert_eq!(
        encode_response(&response),
        Err(encode::Error::Invalid(Invalid::MissingSpProof))
    );

    // a proof for another input does not cover the share of input 0
    let paired = signatures_response(vec![
        sp_share(SpScope::Input(0), scan, 0xa0),
        sp_proof(SpScope::Input(0), scan, 0xb0),
    ]);
    let mut bytes = encode_response(&paired).unwrap();
    let proof = FIRST_ENTRY_OFFSET + SP_SHARE_ENTRY_LEN;
    assert_eq!(bytes[proof..proof + 5], [0, 0, 0, 0, 0x07]);
    bytes[proof + 3] = 0x01;
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Invalid(Invalid::MissingSpProof))
    );
}

#[test]
fn a_global_proof_does_not_cover_a_per_input_share() {
    let scan = aggregate(0x02, 0x5a);
    let response = signatures_response(vec![
        sp_share(SpScope::Input(0), scan, 0xa0),
        sp_proof(SpScope::Global, scan, 0xb0),
    ]);
    assert_eq!(
        encode_response(&response),
        Err(encode::Error::Invalid(Invalid::MissingSpProof))
    );
}

#[test]
fn a_proof_without_its_share_is_refused() {
    let scan = aggregate(0x02, 0x5a);
    let response = signatures_response(vec![sp_proof(SpScope::Global, scan, 0xb0)]);
    assert_eq!(
        encode_response(&response),
        Err(encode::Error::Invalid(Invalid::MissingSpShare))
    );
}

#[test]
fn a_second_share_or_proof_for_a_scan_key_is_refused() {
    let scan = aggregate(0x02, 0x5a);
    let mut entries = sp_per_input_send();
    entries.push(sp_share(SpScope::Input(2), scan, 0xa3));
    assert_eq!(
        encode_response(&signatures_response(entries)),
        Err(encode::Error::Invalid(Invalid::DuplicateSpShare))
    );

    let mut entries = sp_per_input_send();
    entries.push(sp_proof(SpScope::Input(0), scan, 0xb3));
    assert_eq!(
        encode_response(&signatures_response(entries)),
        Err(encode::Error::Invalid(Invalid::DuplicateSpProof))
    );
}

mod get_info_response {
    use bipqr_ll::{
        Invalid, MAX_DESCRIPTOR_ALIAS, Message, Request, Response, decode, encode, encode_request,
        encode_response, reader, request, response, types::Fingerprint,
    };

    use crate::{HEADER_LEN, id};

    const VENDOR: &str = "bip";
    const MODEL: &str = "bip-signer";
    // VENDOR, MODEL (each a one-byte LENGTH and its text), VERSION and CAPABILITIES
    // come before STATE
    const STATE_OFFSET: usize = HEADER_LEN + 1 + VENDOR.len() + 1 + MODEL.len() + 8 + 4;
    const NETWORKS_OFFSET: usize = STATE_OFFSET + 1;
    // NETWORKS and MAX_MESSAGE come before MAX_ALIAS
    const MAX_ALIAS_OFFSET: usize = NETWORKS_OFFSET + 1 + 4;

    fn info(state: response::State, fingerprint: Option<Fingerprint>) -> response::Info {
        response::Info {
            vendor: VENDOR.to_string(),
            model: MODEL.to_string(),
            version: response::FirmwareVersion {
                major: 1,
                minor: 7,
                patch: 0x00ab_cdef,
                flag: response::ReleaseFlag::Stable,
            },
            capabilities: response::Capabilities(0x0000_001f),
            state,
            networks: response::Networks(response::Networks::SIGNET),
            max_message: 0x0001_0000,
            max_alias: MAX_DESCRIPTOR_ALIAS as u8,
            fingerprint,
        }
    }

    fn info_response(info: response::Info) -> Response {
        Response {
            id: id(),
            body: response::Body::Info(info),
        }
    }

    fn ready() -> response::Info {
        info(
            response::State::Ready,
            Some(Fingerprint([0xde, 0xad, 0xbe, 0xef])),
        )
    }

    #[test]
    fn the_request_has_an_empty_body() {
        let request = Request {
            id: id(),
            body: request::Body::GetInfo,
        };
        let bytes = encode_request(&request).unwrap();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(decode(&bytes), Ok(Message::Request(request)));
    }

    #[test]
    fn every_state_round_trips() {
        for info in [
            ready(),
            info(response::State::Ready, None),
            info(response::State::Locked, None),
            info(response::State::Uninitialized, None),
            info(response::State::Unknown(0x03), None),
            info(response::State::Unknown(0xff), None),
        ] {
            let response = info_response(info);
            let bytes = encode_response(&response).unwrap();
            assert_eq!(decode(&bytes), Ok(Message::Response(response)));
        }
    }

    #[test]
    fn encode_rejects_a_fingerprint_when_not_ready() {
        for state in [
            response::State::Locked,
            response::State::Uninitialized,
            response::State::Unknown(0x03),
        ] {
            let response = info_response(info(state, Some(Fingerprint([1, 2, 3, 4]))));
            assert_eq!(
                encode_response(&response),
                Err(encode::Error::Invalid(Invalid::FingerprintWhenNotReady))
            );
        }
    }

    #[test]
    fn decode_rejects_a_fingerprint_when_not_ready() {
        let mut bytes = encode_response(&info_response(ready())).unwrap();
        for state in [0x01, 0x02, 0x03] {
            bytes[STATE_OFFSET] = state;
            assert_eq!(
                decode(&bytes),
                Err(decode::Error::Invalid(Invalid::FingerprintWhenNotReady))
            );
        }
    }

    #[test]
    fn encode_rejects_a_max_alias_above_the_alias_bound() {
        let mut info = ready();
        info.max_alias = MAX_DESCRIPTOR_ALIAS as u8 + 1;
        assert_eq!(
            encode_response(&info_response(info)),
            Err(encode::Error::Invalid(Invalid::MaxAliasTooLarge(33)))
        );
    }

    #[test]
    fn decode_rejects_a_max_alias_above_the_alias_bound() {
        let mut bytes = encode_response(&info_response(ready())).unwrap();
        assert_eq!(bytes[MAX_ALIAS_OFFSET], 32);
        bytes[MAX_ALIAS_OFFSET] = 33;
        assert_eq!(
            decode(&bytes),
            Err(decode::Error::Invalid(Invalid::MaxAliasTooLarge(33)))
        );
    }

    #[test]
    fn encode_rejects_reserved_network_bits() {
        for reserved in [0x01, 0x20] {
            let mut info = ready();
            info.networks = response::Networks(reserved | response::Networks::MAINNET);
            assert_eq!(
                encode_response(&info_response(info)),
                Err(encode::Error::ReservedNetworkBits(
                    reserved | response::Networks::MAINNET
                ))
            );
        }
    }

    #[test]
    fn decode_ignores_reserved_network_bits() {
        let mut bytes = encode_response(&info_response(ready())).unwrap();
        assert_eq!(bytes[NETWORKS_OFFSET], response::Networks::SIGNET);
        // SIGNET with bit 0 and bits 5 to 7, all reserved, set
        bytes[NETWORKS_OFFSET] = 0xe9;
        let mut expected = ready();
        expected.networks = response::Networks(0xe9);
        assert_eq!(
            decode(&bytes),
            Ok(Message::Response(info_response(expected)))
        );
    }

    #[test]
    fn encode_rejects_an_unknown_state_of_a_defined_value() {
        for value in [0x00, 0x01, 0x02] {
            let response = info_response(info(response::State::Unknown(value), None));
            assert_eq!(
                encode_response(&response),
                Err(encode::Error::DefinedState(value))
            );
        }
    }

    #[test]
    fn decode_rejects_an_invalid_fingerprint_presence() {
        let mut bytes = encode_response(&info_response(ready())).unwrap();
        let presence = bytes.len() - 5;
        assert_eq!(bytes[presence], 0x01);
        bytes[presence] = 0x02;
        assert_eq!(
            decode(&bytes),
            Err(decode::Error::Read(reader::Error::InvalidPresence(0x02)))
        );
    }
}
