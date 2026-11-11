#!/usr/bin/env sh
# Shared by CI and `just ci`.
set -eu
cargo fmt -- --check
# the example crates share their source, so one check covers both
cargo fmt --manifest-path examples/bitcoin_0_32_0/Cargo.toml -- --check
cargo clippy -p bipqr-ll --all-targets -- -D warnings
cargo clippy -p bipqr-ll --all-targets --features ffi -- -D warnings
cargo clippy --all-targets -- -D warnings
# without a backend the crate is only the codec re-export
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --no-default-features --features bitcoin_0_32 -- -D warnings
# downstream crates built against the oldest and Liana's bitcoin 0.32 release
cargo clippy --manifest-path examples/bitcoin_0_32_0/Cargo.toml -- -D warnings
cargo clippy --manifest-path examples/bitcoin_0_32_5/Cargo.toml -- -D warnings
