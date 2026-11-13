#![no_main]

use std::{
    ffi::{CStr, c_char},
    ptr,
};

use bipqr_ll::{
    Message, MessageType, Request, RequestId, SignResponseKind, decode,
    ffi::{self, bipqr_request_decode, bipqr_request_free, types},
    request::{self, DescriptorBody, KeyKind, Scan, SpKeys},
    types::{DerivationPath, Fingerprint, SecretKey},
};
use libfuzzer_sys::fuzz_target;

// Every reader below rebuilds a Rust value from the C view, so each pointer the
// binding hands out is dereferenced under ASan.

unsafe fn string(ptr: *const c_char) -> String {
    assert!(!ptr.is_null());
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .expect("the binding hands out utf-8")
        .to_owned()
}

unsafe fn optional_string(ptr: *const c_char) -> Option<String> {
    (!ptr.is_null()).then(|| unsafe { string(ptr) })
}

unsafe fn bytes(view: types::Bytes) -> Vec<u8> {
    assert!(!view.is_absent());
    unsafe { view.as_slice() }.to_vec()
}

unsafe fn optional_bytes(view: types::Bytes) -> Option<Vec<u8>> {
    (!view.is_absent()).then(|| unsafe { bytes(view) })
}

unsafe fn path(view: types::Path) -> DerivationPath {
    DerivationPath(unsafe { view.as_slice() }.to_vec())
}

fn optional<T>(has: u8, value: T) -> Option<T> {
    match has {
        0 => None,
        1 => Some(value),
        _ => panic!("presence flag {has}"),
    }
}

unsafe fn descriptor_body(view: *const types::DescriptorBody) -> Option<DescriptorBody> {
    let view = unsafe { view.as_ref() }?;
    Some(match view.tag {
        request::DESCRIPTOR_BIP380 => DescriptorBody::Bip380(unsafe { string(view.value.bip380) }),
        request::DESCRIPTOR_BIP388 => {
            let bip388 = unsafe { view.value.bip388 };
            DescriptorBody::Bip388 {
                keys: unsafe { bip388.keys.as_slice() }
                    .iter()
                    .map(|key| unsafe { string(*key) })
                    .collect(),
                policy: unsafe { string(bip388.policy) },
            }
        }
        request::DESCRIPTOR_SP_KEYS => {
            let keys = unsafe { view.value.sp_keys };
            DescriptorBody::SpKeys(SpKeys {
                fingerprint: Fingerprint(keys.fingerprint),
                spend_path: unsafe { path(keys.spend_path) },
                scan: match keys.scan_kind {
                    types::SCAN_PATH => Scan::Path(unsafe { path(keys.scan.path) }),
                    types::SCAN_KEY => Scan::Key(SecretKey(unsafe { keys.scan.key })),
                    kind => panic!("scan kind {kind}"),
                },
            })
        }
        tag => panic!("descriptor tag {tag}"),
    })
}

unsafe fn descriptor(view: &types::Descriptor) -> request::Descriptor {
    request::Descriptor {
        alias: unsafe { string(view.alias) },
        descriptor: unsafe { descriptor_body(view.body) },
        proof: unsafe { optional_bytes(view.proof) },
    }
}

unsafe fn request_body(view: &types::Request) -> request::Body {
    let message_type = MessageType::try_from(view.message_type).expect("a known message type");
    match message_type {
        MessageType::UnreadableRequest => panic!("a request carries the unreadable request type"),
        MessageType::GetInfo => request::Body::GetInfo,
        MessageType::GetKeys => request::Body::GetKeys(request::GetKeys {
            keys: unsafe { view.body.get_keys.keys.as_slice() }
                .iter()
                .map(|key| request::KeyRequest {
                    derivation_path: unsafe { path(key.derivation_path) },
                    kind: KeyKind::try_from(key.kind).expect("a known key kind"),
                })
                .collect(),
        }),
        MessageType::RegisterDescriptor => {
            let body = unsafe { view.body.register_descriptor };
            request::Body::RegisterDescriptor(request::RegisterDescriptor {
                descriptor_alias: unsafe { string(body.descriptor_alias) },
                descriptor: unsafe { descriptor_body(body.descriptor) },
            })
        }
        MessageType::AddressVerification => {
            let body = unsafe { view.body.verify_address };
            request::Body::VerifyAddress(request::VerifyAddress {
                descriptor_alias: unsafe { string(body.descriptor_alias) },
                derivation_path: unsafe { path(body.derivation_path) },
                address: unsafe { optional_string(body.address) },
                descriptor: unsafe { descriptor_body(body.descriptor) },
                proof: unsafe { optional_bytes(body.proof) },
            })
        }
        MessageType::Signing => {
            let body = unsafe { view.body.sign };
            request::Body::Sign(request::Sign {
                descriptors: unsafe { body.descriptors.as_slice() }
                    .iter()
                    .map(|item| unsafe { descriptor(item) })
                    .collect(),
                psbt: unsafe { bytes(body.psbt) },
                want_kind: match body.want_kind {
                    types::ABSENT_KIND => None,
                    kind => Some(
                        u8::try_from(kind)
                            .ok()
                            .and_then(|kind| SignResponseKind::try_from(kind).ok())
                            .expect("a known signing response kind"),
                    ),
                },
                accept_trimmed: body.accept_trimmed,
            })
        }
        MessageType::NoncePreparation => {
            let body = unsafe { view.body.prepare_nonces };
            request::Body::PrepareNonces(request::PrepareNonces {
                session_id: optional(body.has_session_id, body.session_id),
                session_ref: optional(body.has_session_ref, body.session_ref),
                descriptor: unsafe { body.descriptor.as_ref() }
                    .map(|item| unsafe { descriptor(item) }),
                max_inputs: body.max_inputs,
                derivation_path: unsafe { path(body.derivation_path) },
                start: body.start,
                end: optional(body.has_end, body.end),
            })
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut view: *const types::Request = ptr::null();
    let mut err: *const c_char = ptr::null();
    let code = unsafe { bipqr_request_decode(data.as_ptr(), data.len(), &mut view, &mut err) };
    match decode(data) {
        Ok(Message::Request(expected)) => {
            assert_eq!(code, ffi::OK);
            assert!(err.is_null());
            let view_ref = unsafe { view.as_ref() }.expect("a decoded request");
            let rebuilt = Request {
                id: RequestId(view_ref.id),
                body: unsafe { request_body(view_ref) },
            };
            unsafe { bipqr_request_free(view) };
            assert_eq!(rebuilt, expected);
        }
        decoded => {
            let expected = match decoded {
                Ok(_) => ffi::Error::UnexpectedResponse.info(),
                Err(error) => error.info(),
            };
            assert_eq!(code, expected.code);
            assert!(view.is_null());
            assert_eq!(
                unsafe { CStr::from_ptr(err) }.to_bytes_with_nul(),
                expected.message.as_bytes()
            );
        }
    }
});
