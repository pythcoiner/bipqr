#!/usr/bin/env sh
# Shared by CI and `just ci`.
set -eu
cargo test -p bipqr-ll --verbose --color always -- --nocapture
cargo test -p bipqr-ll --features ffi --verbose --color always -- --nocapture
cargo test --verbose --color always -- --nocapture
cargo test --no-default-features --verbose --color always -- --nocapture
cargo test --no-default-features --features bitcoin_0_32 --verbose --color always -- --nocapture
# downstream crates built against the oldest and Liana's bitcoin 0.32 release
cargo run --manifest-path examples/bitcoin_0_32_0/Cargo.toml
cargo run --manifest-path examples/bitcoin_0_32_5/Cargo.toml
