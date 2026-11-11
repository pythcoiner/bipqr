#!/usr/bin/env sh
# Shared by CI and `just ci`.
set -eu
# the codec must build with zero dependencies
cargo build --release -p bipqr-ll
cargo build --release -p bipqr-ll --features ffi
cargo build --release
cargo build --release --no-default-features
cargo build --release --manifest-path examples/bitcoin_0_32_0/Cargo.toml
cargo build --release --manifest-path examples/bitcoin_0_32_5/Cargo.toml
