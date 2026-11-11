//! A downstream crate sending its own `bitcoin` types through the codec: it only
//! compiles when bipqr's backend is that same release.

use bipqr::{
    backend::{Active, Backend},
    ll::{
        Message, Request, RequestId, Response, decode, encode_request, encode_response, request,
        response,
    },
};
use bitcoin::{
    PublicKey,
    bip32::{DerivationPath, Xpriv, Xpub},
    secp256k1::{Secp256k1, SecretKey},
};

const XPRIV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
const ID: RequestId = RequestId([0, 1]);

fn main() {
    let xpriv: Xpriv = XPRIV.parse().expect("valid xpriv");
    let xpub = Xpub::from_priv(&Secp256k1::new(), &xpriv);
    let fingerprint = xpub.fingerprint();
    let public_key = PublicKey::new(xpub.public_key);
    let scan_key = SecretKey::from_slice(&[0x01; 32]).expect("valid secret key");
    let spend_path: DerivationPath = "m/352'/1'/0'/0'/0".parse().expect("valid path");

    let request = Request {
        id: ID,
        body: request::Body::RegisterDescriptor(request::RegisterDescriptor {
            descriptor_alias: "main".to_string(),
            descriptor: Some(request::DescriptorBody::SpKeys(request::SpKeys {
                fingerprint: Active::to_ll_fingerprint(&fingerprint),
                spend_path: Active::to_ll_path(&spend_path),
                scan: request::Scan::Key(Active::to_ll_secret_key(&scan_key)),
            })),
        }),
    };
    let Message::Request(decoded) =
        decode(&encode_request(&request).expect("encode request")).expect("decode request")
    else {
        panic!("not a request");
    };
    let request::Body::RegisterDescriptor(register) = decoded.body else {
        panic!("not a register descriptor request");
    };
    let Some(request::DescriptorBody::SpKeys(keys)) = register.descriptor else {
        panic!("not silent payment keys");
    };
    let request::Scan::Key(scan) = keys.scan else {
        panic!("not a scan key");
    };
    assert_eq!(Active::from_ll_fingerprint(&keys.fingerprint), fingerprint);
    assert_eq!(Active::from_ll_path(&keys.spend_path), spend_path);
    assert_eq!(Active::from_ll_secret_key(&scan), Ok(scan_key));

    let response = Response {
        id: ID,
        body: response::Body::Signed(response::Signed::Signatures(vec![
            response::SignatureEntry::Ecdsa {
                input_index: 0,
                public_key: Active::to_ll_public_key(&public_key).expect("compressed key"),
                signature: vec![0x30; 71],
            },
        ])),
    };
    let Message::Response(decoded) =
        decode(&encode_response(&response).expect("encode response")).expect("decode response")
    else {
        panic!("not a response");
    };
    let response::Body::Signed(response::Signed::Signatures(entries)) = decoded.body else {
        panic!("not a signatures response");
    };
    let [
        response::SignatureEntry::Ecdsa {
            public_key: key, ..
        },
    ] = entries.as_slice()
    else {
        panic!("not a single ecdsa entry");
    };
    assert_eq!(Active::from_ll_public_key(key), Ok(public_key));

    let response = Response {
        id: ID,
        body: response::Body::Keys(response::Keys {
            keys: vec![Active::to_ll_xpub(&xpub), Active::to_ll_xpriv(&xpriv)],
            fingerprint: Active::to_ll_fingerprint(&fingerprint),
            vendor: "example".to_string(),
            model: "roundtrip".to_string(),
            version: response::FirmwareVersion {
                major: 0,
                minor: 1,
                patch: 0,
                flag: response::ReleaseFlag::Stable,
            },
            capabilities: response::Capabilities(0),
        }),
    };
    let Message::Response(decoded) =
        decode(&encode_response(&response).expect("encode response")).expect("decode response")
    else {
        panic!("not a response");
    };
    let response::Body::Keys(keys) = decoded.body else {
        panic!("not a keys response");
    };
    let [public, private] = keys.keys.as_slice() else {
        panic!("not two keys");
    };
    assert_eq!(Active::from_ll_xpub(public), Ok(xpub));
    assert_eq!(Active::from_ll_xpriv(private), Ok(xpriv));
    assert_eq!(Active::from_ll_fingerprint(&keys.fingerprint), fingerprint);
}
