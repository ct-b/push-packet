default:
    @just --list

# Assess code coverage
cover:
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=env cargo +nightly llvm-cov --workspace --exclude push-packet-ebpf --show-missing-lines

# Run the full check suite
check:
    cargo +nightly fmt --all -- --check
    cargo clippy --workspace --exclude push-packet-ebpf --all-targets --all-features -- -D warnings
    cargo test --workspace --exclude push-packet-ebpf --all-features
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude push-packet-ebpf --all-features --no-deps

# Format and apply clippy suggestions
fix:
    cargo +nightly fmt --all
    cargo clippy --workspace --exclude push-packet-ebpf --all-targets --all-features --fix --allow-dirty --allow-staged

# Lint the ebpf crate against its actual BPF target
lint-ebpf:
    cd push-packet-ebpf && cargo +nightly clippy --target bpfel-unknown-none -Z build-std=core -- -D warnings

# Build all ebpf bin targets and copy them into push-packet/ebpf-bin/
build-ebpf:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo +nightly build -p push-packet-ebpf --release -Z build-std=core --target bpfel-unknown-none
    target_dir="${CARGO_TARGET_DIR:-target}"
    find "$target_dir/bpfel-unknown-none/release" -maxdepth 1 -type f \
        ! -name '*.d' ! -name '*.rlib' ! -name '.*' \
        -exec cp -v {} push-packet/ebpf-bin/ \;

# Full check including the ebpf crate
check-all: check lint-ebpf
