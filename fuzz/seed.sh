#!/usr/bin/env sh
# Seed every fuzz target's corpus with the raw bytes of each test vector, one file per
# vector named after it. Rerunning rewrites the same files and keeps what the fuzzer added.
set -eu
cd "$(dirname "$0")"

# Prints the bytes of a lowercase hex string, through printf octal escapes.
unhex() {
    hex=$1
    escaped=
    while [ -n "$hex" ]; do
        rest=${hex#??}
        byte=$((0x${hex%"$rest"}))
        escaped="$escaped\\$((byte >> 6))$((byte >> 3 & 7))$((byte & 7))"
        hex=$rest
    done
    printf "$escaped"
}

vectors=$(sed -n \
    -e 's/^ *"name": *"\([^"]*\)".*/\1/p' \
    -e 's/^ *"hex": *"\([0-9a-f]*\)".*/\1/p' \
    ../test_vectors/*.json)

for target in fuzz_targets/*.rs; do
    corpus=corpus/$(basename "$target" .rs)
    mkdir -p "$corpus"
    printf '%s\n' "$vectors" | while read -r name && read -r hex; do
        unhex "$hex" >"$corpus/$name"
    done
done
