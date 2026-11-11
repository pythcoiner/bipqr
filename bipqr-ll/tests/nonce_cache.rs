use bipqr_ll::{
    decode, encode, encode_request, encode_response, reader, request, response,
    types::{DerivationPath, Fingerprint},
    Invalid, Message, MessageType, Request, RequestId, Response,
};

const ID: RequestId = RequestId([0x12, 0x34]);
const SESSION: [u8; 4] = [0x51; 4];
const SESSION_REF: [u8; 4] = [0x52; 4];

fn preparation() -> request::PrepareNonces {
    request::PrepareNonces {
        session_id: Some(SESSION),
        session_ref: None,
        descriptor: None,
        max_inputs: 2,
        derivation_path: DerivationPath(vec![0x8000_0056, 0x8000_0000, 0x8000_0000, 0, 3]),
        start: 4,
        end: Some(5),
    }
}

fn nonces(count: usize) -> Vec<[u8; 66]> {
    (0..count).map(|index| [index as u8; 66]).collect()
}

fn prepared() -> response::NoncesPrepared {
    response::NoncesPrepared {
        session: Some(response::Session {
            session_id: SESSION,
            session_ref: SESSION_REF,
        }),
        nonces: nonces(4),
    }
}

fn request(body: request::Body) -> Request {
    Request { id: ID, body }
}

fn response(body: response::Body) -> Response {
    Response { id: ID, body }
}

fn optional(bytes: &mut Vec<u8>, field: Option<[u8; 4]>) {
    match field {
        Some(field) => {
            bytes.push(1);
            bytes.extend_from_slice(&field);
        }
        None => bytes.push(0),
    }
}

// Build malformed bodies independently of the validating encoder.
fn raw_preparation(body: &request::PrepareNonces) -> Vec<u8> {
    let mut bytes = b"BIPXXX\x01\x06\x12\x34".to_vec();
    optional(&mut bytes, body.session_id);
    optional(&mut bytes, body.session_ref);
    // DESCRIPTOR, absent in every preparation built here
    bytes.push(0);
    bytes.extend_from_slice(&body.max_inputs.to_be_bytes());
    bytes.push(body.derivation_path.0.len() as u8);
    for child in &body.derivation_path.0 {
        bytes.extend_from_slice(&child.to_be_bytes());
    }
    bytes.extend_from_slice(&body.start.to_be_bytes());
    optional(&mut bytes, body.end.map(u32::to_be_bytes));
    bytes
}

fn raw_prepared(
    session_id: Option<[u8; 4]>,
    session_ref: Option<[u8; 4]>,
    nonces: &[[u8; 66]],
) -> Vec<u8> {
    let mut bytes = b"BIPXXX\x01\x86\x12\x34".to_vec();
    optional(&mut bytes, session_id);
    optional(&mut bytes, session_ref);
    bytes.push(nonces.len() as u8);
    for nonce in nonces {
        bytes.extend_from_slice(nonce);
    }
    bytes
}

fn reject_preparation(body: request::PrepareNonces, error: Invalid) {
    assert_eq!(
        decode(&raw_preparation(&body)),
        Err(decode::Error::Invalid(error))
    );
    assert_eq!(
        encode_request(&request(request::Body::PrepareNonces(body))),
        Err(encode::Error::Invalid(error))
    );
}

#[test]
fn preparation_messages_round_trip_every_field() {
    for (session_id, session_ref, end) in [
        (Some(SESSION), None, Some(5)),
        (Some(SESSION), Some(SESSION_REF), Some(5)),
        (Some(SESSION), None, None),
        (None, None, Some(5)),
        (None, None, None),
    ] {
        let mut body = preparation();
        body.session_id = session_id;
        body.session_ref = session_ref;
        body.end = end;
        let request = request(request::Body::PrepareNonces(body.clone()));
        let bytes = encode_request(&request).unwrap();
        assert_eq!(bytes, raw_preparation(&body));
        assert_eq!(bytes[6..10], [1, 0x06, 0x12, 0x34]);
        assert_eq!(decode(&bytes).unwrap(), Message::Request(request));
    }

    for (session, session_id, session_ref) in [
        (prepared().session, Some(SESSION), Some(SESSION_REF)),
        (None, None, None),
    ] {
        let body = response::NoncesPrepared {
            session,
            nonces: nonces(4),
        };
        let response = response(response::Body::NoncesPrepared(body.clone()));
        let bytes = encode_response(&response).unwrap();
        assert_eq!(bytes, raw_prepared(session_id, session_ref, &body.nonces));
        assert_eq!(bytes[6..10], [1, 0x86, 0x12, 0x34]);
        assert_eq!(decode(&bytes).unwrap(), Message::Response(response));
    }
}

#[test]
fn preparation_rejects_invalid_presence_bytes() {
    let mut body = preparation();
    body.session_ref = Some(SESSION_REF);
    let raw = raw_preparation(&body);
    let end_presence = raw.len() - 5;
    for offset in [10, 10 + 1 + SESSION.len(), end_presence] {
        let mut bytes = raw.clone();
        bytes[offset] = 0x02;
        assert_eq!(
            decode(&bytes),
            Err(decode::Error::Read(reader::Error::InvalidPresence(0x02)))
        );
    }
}

#[test]
fn preparation_accepts_any_ordered_range_and_input_count() {
    for (max_inputs, start, end) in [
        (1, 0, Some(0)),
        (1, u32::MAX, Some(u32::MAX)),
        (1, u32::MAX, None),
        (256, 4, Some(5)),
        (u32::MAX, 0, Some(u32::MAX)),
    ] {
        let mut body = preparation();
        body.max_inputs = max_inputs;
        body.start = start;
        body.end = end;
        let request = request(request::Body::PrepareNonces(body));
        assert_eq!(
            decode(&encode_request(&request).unwrap()).unwrap(),
            Message::Request(request)
        );
    }

    for count in [0, 1, 3, 256] {
        let response = response(response::Body::NoncesPrepared(response::NoncesPrepared {
            session: None,
            nonces: nonces(count),
        }));
        assert_eq!(
            decode(&encode_response(&response).unwrap()).unwrap(),
            Message::Response(response)
        );
    }
}

#[test]
fn preparation_rejects_invalid_session_coverage_and_range_in_both_directions() {
    let mut body = preparation();
    body.session_id = None;
    body.session_ref = Some(SESSION_REF);
    reject_preparation(body, Invalid::SessionRefWithoutId);

    let mut body = preparation();
    body.max_inputs = 0;
    reject_preparation(body, Invalid::ZeroMaxInputs);

    let mut body = preparation();
    body.start = 6;
    reject_preparation(body, Invalid::ReversedExpressionRange);
}

#[test]
fn preparation_response_rejects_an_unpaired_session() {
    for (session_id, session_ref) in [(Some(SESSION), None), (None, Some(SESSION_REF))] {
        assert_eq!(
            decode(&raw_prepared(session_id, session_ref, &nonces(4))),
            Err(decode::Error::UnpairedSession)
        );
    }
}

#[test]
fn nonce_cache_capability_is_separate_and_encodes() {
    assert_eq!(response::Capabilities::NONCE_CACHE, 0x10);
    assert!(!response::Capabilities(0x0f).supports_nonce_cache());
    for mask in [0x10, 0x1f] {
        assert!(response::Capabilities(mask).supports_nonce_cache());
        let response = response(response::Body::Keys(response::Keys {
            keys: vec![],
            fingerprint: Fingerprint([1, 2, 3, 4]),
            vendor: "bip".into(),
            model: "signer".into(),
            version: response::FirmwareVersion {
                major: 1,
                minor: 0,
                patch: 0,
                flag: response::ReleaseFlag::Stable,
            },
            capabilities: response::Capabilities(mask),
        }));
        assert_eq!(
            decode(&encode_response(&response).unwrap()).unwrap(),
            Message::Response(response)
        );
    }
}

// The old dispatch accepts only these five types, before reading any body.
fn old_message_type(bytes: &[u8]) -> Result<u8, decode::Error> {
    match bytes[7] & 0x3f {
        code @ 0x01..=0x05 => Ok(code),
        code => Err(decode::Error::UnknownMessageType(code)),
    }
}

#[test]
fn old_dispatch_rejects_preparation_even_with_a_newer_version() {
    let messages = [
        encode_request(&request(request::Body::PrepareNonces(preparation()))).unwrap(),
        encode_response(&response(response::Body::NoncesPrepared(prepared()))).unwrap(),
    ];
    for message in messages {
        for version in [1, 2, u8::MAX] {
            let mut bytes = message.clone();
            bytes[6] = version;
            assert_eq!(
                old_message_type(&bytes),
                Err(decode::Error::UnknownMessageType(0x06))
            );
            assert!(decode(&bytes).is_ok());
        }
        for end in 0..message.len() {
            assert!(
                decode(&message[..end]).is_err(),
                "accepted truncation at {end}"
            );
        }
    }
    assert_eq!(MessageType::NoncePreparation.value(), 0x06);
}

#[test]
fn nonce_cache_session_refusal_is_the_session_error() {
    assert_eq!(u8::from(response::Error::MusigSession), 0x0d);
    for message_type in [MessageType::NoncePreparation, MessageType::Signing] {
        let response = response(response::Body::Error(response::ErrorBody {
            message_type,
            error: response::Error::MusigSession,
            message: "session refused".into(),
        }));
        assert_eq!(
            decode(&encode_response(&response).unwrap()).unwrap(),
            Message::Response(response)
        );
    }
}

#[test]
fn nonce_cache_validation_errors_have_distinct_codes() {
    let errors = [
        (Invalid::ZeroMaxInputs, 507),
        (Invalid::ReversedExpressionRange, 508),
        (Invalid::SessionRefWithoutId, 509),
    ];
    for (error, code) in errors {
        assert_eq!(error.info().code, code);
        assert_eq!(encode::Error::Invalid(error).info(), error.info());
        assert_eq!(decode::Error::Invalid(error).info(), error.info());
        assert!(error.info().message.ends_with('\0'));
    }
}
