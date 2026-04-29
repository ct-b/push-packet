# push-packet
[![ci](https://github.com/ct-b/push-packet/actions/workflows/ci.yml/badge.svg)](https://github.com/ct-b/push-packet/actions/workflows/ci.yml)

push-packet is a packet-inspecting and routing library for Linux, built on [eBPF] with [aya]. It provides a simple rules-based interface for dropping packets, copying entire or partial packets, and routing packets to userspace via [AF_XDP].

## Features
- Attach an XDP program to any Linux network interface.
- Match packets based on source/destination CIDR, port range, and protocol.
- Drop, copy (whole or partial), or redirect packets to userspace via [AF_XDP].
- Add and remove rules dynamically while the program is attached.
- Swappable trait-based matching Engine for different performance targets.

## Example

Copy all packets on an interface to userspace.

```rust
use push_packet::{Tap, rules::{Rule, Action}};

fn main() -> Result<(), push_packet::Error> {
    let mut tap = Tap::builder("wlp3s0")?
        .rule(
            Rule::builder()
                .source_cidr("0.0.0.0/0")
                .action(Action::Copy { take: None }),
        )?
        .build()?;

    let mut rx = tap.copy_receiver()?;
    while let Ok(event) = rx.recv() {
        println!("Received packet of length {}", event.packet_len());
    }
    Ok(())
}
```

## Overview
push-packet utilizes eBPF XDP programs to drop, copy, and route packets. XDP runs before the packet enters the kernel network stack, enabling low-latency processing.

#### Copy
Packets are copied to userspace using a [BPF ring buffer]. Compared to a [perf event buffer], this preserves packet ordering at the cost of potential atomic contention under high load. Support for the [perf event buffer] may be added in the future.

#### Route
Packets are routed to userspace using an [AF_XDP] socket. This allows for zero-copy routing on compatible network devices.

The [AF_XDP] implementation currently consists of one [UMEM] region with one socket, and addresses exchanged via a queue. In the future, other configurations may be supported, such as:
- Multiple sockets (1 per queue_id) with a shared [UMEM].
- Multiple independent socket/[UMEM] setups, one per queue_id.

## Building

Prerequisites:

- stable Rust toolchain
- nightly Rust toolchain with `rust-src` (used to compile the eBPF programs)
- `bpf-linker`: `cargo install bpf-linker`

```shell
cargo build --release
```

The build script compiles the eBPF crate and embeds the result automatically.

Runtime requirements: Linux 5.8+ (for the BPF ring buffer), `CAP_NET_ADMIN` + `CAP_BPF`. Anything using the library (integration tests, examples, your own programs) must run as root. The repo configures Cargo's runner to prepend `sudo -E` automatically; see `.cargo/config.toml`.

## License

With the exception of eBPF code, push-packet is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

#### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
[aya]: https://aya-rs.dev
[eBPF]: https://ebpf.io/
[AF_XDP]: https://www.kernel.org/doc/html/latest/networking/af_xdp.html
[BPF ring buffer]: https://www.kernel.org/doc/html/latest/bpf/ringbuf.html
[perf event buffer]: https://www.kernel.org/doc/html/latest/bpf/map_perf_event_array.html
[UMEM]: https://www.kernel.org/doc/html/latest/networking/af_xdp.html#umem
