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

# Full check including the ebpf crate
check-all: check lint-ebpf
