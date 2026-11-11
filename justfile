# Run all CI checks locally (lint, test, build).
ci:
    ./contrib/lint.sh
    ./contrib/test.sh
    ./contrib/build.sh

# Remove all build artifacts, for the crates and the fuzz workspace.
clean:
    cargo clean
    cargo clean --manifest-path fuzz/Cargo.toml

# Seed every corpus with the test vectors, then run every fuzz target for `seconds` seconds
# each on `jobs` processes (all CPUs by default); stop and report on the first crash.
[doc("Run every fuzz target for `seconds` each, on `jobs` processes.")]
fuzz seconds jobs=num_cpus():
    #!/usr/bin/env sh
    set -eu
    ./fuzz/seed.sh
    for target in $(cargo fuzz list); do
        echo "=== fuzzing $target for {{seconds}}s ==="
        if ! cargo +nightly fuzz build "$target"; then
            echo "!!! build failed for $target" >&2
            exit 1
        fi
        if ! cargo +nightly fuzz run --jobs {{jobs}} "$target" -- -max_total_time={{seconds}}; then
            echo "!!! crash in $target, artifact in fuzz/artifacts/$target/" >&2
            exit 1
        fi
    done
