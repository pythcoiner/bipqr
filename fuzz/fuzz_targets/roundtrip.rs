#![no_main]

use bipqr_ll::{Message, decode, encode_request, encode_response};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(message) = decode(data) else {
        return;
    };
    let encoded = match &message {
        Message::Request(request) => encode_request(request),
        Message::Response(response) => encode_response(response),
    };
    // Encode is stricter than decode on some fields (reserved network bits), so a
    // decoded message may legitimately fail to encode.
    let Ok(bytes) = encoded else {
        return;
    };
    let again = decode(&bytes).expect("re-encoded message must decode");
    assert_eq!(message, again);
});
