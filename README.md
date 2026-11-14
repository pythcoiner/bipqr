# bipqr

Rust implementation of the draft QR signing protocol: the byte encoding of the
messages a coordinator and a signer exchange (Get Info, Get Keys, Register
Descriptor, Address Verification, Signing, Nonce Preparation, Unregister
Descriptor). The format is
specified in [ENCODING.md](ENCODING.md); the encoding is transport agnostic, so
framing (BBQR) and QR rendering are out of scope.

The codec is imported from bwk.

## Crates

- [`bipqr-ll`](bipqr-ll/README.md): the codec. `no_std` plus `alloc` with no
  dependency at all, so a bare-metal signer can depend on it directly. Its `ffi`
  feature adds the C binding ([`bipqr-ll/include/bipqr.h`](bipqr-ll/include/bipqr.h)).
- `bipqr`: re-exports `bipqr-ll` as `bipqr::ll` and adds `bipqr::backend`, the
  conversions between the codec's wire types and those of a `bitcoin` release.

The codec carries keys and paths as raw bytes (`ExtendedKey`, `Fingerprint`,
`PublicKey`, `SecretKey`, `DerivationPath`). The orphan rule rules out `From` impls
between them and the `bitcoin` types, so the backend converts through the
`Backend` trait, implemented by `bipqr::backend::Active` for the selected release:

```rust
use bipqr::{
    backend::{Active, Backend},
    ll::{Message, decode},
};

let path = Active::to_ll_path(&"m/84'/0'/0'".parse()?);
let xpub = Active::from_ll_xpub(&extended_key)?;

match decode(bytes)? {
    Message::Request(request) => { /* a signer answers it */ }
    Message::Response(response) => { /* a coordinator consumes it */ }
}
```

Converting to the wire only fails for an uncompressed public key; converting from
the wire fails on bytes that are not a valid key.
`bipqr::bitcoin` re-exports the `bitcoin` release the backend is built on. `bipqr`
is `no_std` and depends on it without default features, so `std` comes from the
caller's own `bitcoin` dependency.

## Features

| Feature flag     | Default | Description                                          |
|------------------|---------|------------------------------------------------------|
| `bitcoin_0_32`   | -       | Convert to and from `bitcoin` 0.32 (0.32.0 or later) |
| `bitcoin_latest` | yes     | Alias for `bitcoin_0_32`                             |

Without a backend feature (`default-features = false`), `bipqr` is only the
`bipqr::ll` re-export. A new `bitcoin` major release gets its own feature.

[`examples/`](examples) holds one downstream crate pinned at `bitcoin` 0.32.0, the
oldest supported release, and one at 0.32.5, the release Liana builds with. Both
run [`examples/shared/roundtrip.rs`](examples/shared/roundtrip.rs), which converts
their own `bitcoin` types through the backend, encodes, decodes and converts back,
so each only compiles when the backend is that same release.

## Test vectors

[`test_vectors/`](test_vectors) holds the machine-checkable vectors of the
specification, one JSON file per operation (see the Test Vectors section of
[ENCODING.md](ENCODING.md) for their format). `bipqr-ll/tests/vectors.rs` checks
every one of them.

## Development

```sh
just ci          # lint, tests and release builds, as the CI runs them
just fuzz 60     # every fuzz target for 60 seconds each (nightly + cargo-fuzz)
```

The fuzz targets live in [`fuzz/`](fuzz): `decode` feeds arbitrary bytes to the
decoder, which must never panic, `roundtrip` checks that a decoded message
encodes back to bytes that decode to the same message, `encode` builds messages
from the fuzz bytes and checks that whatever encodes decodes back to the same
message, and `ffi_decode` decodes through the C binding, reads the whole result
back and frees it. `just fuzz` first seeds every corpus with the test vectors
(`fuzz/seed.sh`).

MSRV: 1.88.

## License

MIT, see [LICENSE](LICENSE). The specification text in ENCODING.md is BSD-2-Clause.
