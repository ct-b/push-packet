# push-packet
[![ci](https://github.com/ct-b/push-packet/actions/workflows/ci.yml/badge.svg)](https://github.com/ct-b/push-packet/actions/workflows/ci.yml)

push-packet is a packet-inspecting and routing library for Linux, built on [eBPF] with [aya]. It provides a simple rules-based interface for dropping packets, copying entire or partial packets, and routing packets to userspace via [AF_XDP].

## Features
- Attach an XDP program to any Linux network interface.
- Match packets based on source/destination CIDR, port range, and protocol.
- Drop, copy (whole or partial), or redirect packets to userspace via AF_XDP.
- Add and remove rules dynamically while the program is attached.
- Swappable trait-based matching Engine for different performance targets.

## Examples

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

Add and remove rules at runtime.
```rust
use push_packet::{Tap, rules::{Rule, Action, Protocol}, CopyConfig};

fn main() -> Result<(), push_packet::Error> {
    let mut tap = Tap::builder("wlp3s0")?
        // Set force_enabled on the copy config so we can use copy rules later.
        .copy_config(CopyConfig::default().force_enabled())
        .build()?;

    // call add_rule to get a RuleId
    let drop_rule_id = tap.add_rule(
        Rule::protocol(Protocol::Tcp)
            .source_cidr("127.0.0.1")
            .source_port(3000..4000)
            .action(Action::Drop),
    )?;

    // [traffic dropped]

    // Remove a rule with RuleId
    tap.remove_rule(drop_rule_id)?;

    // Read some traffic instead
    tap.add_rule(
        Rule::source_cidr("127.0.0.1")
            .source_port(3001)
            .action(Action::COPY_ALL),
    )?;

    let mut rx = tap.copy_receiver()?;
    while let Ok(event) = rx.recv() {
        println!("Received packet of length {}", event.packet_len());
    }

    Ok(())
}
```

*The [histogram](https://github.com/ct-b/push-packet/tree/main/push-packet/examples/histogram) example program captures all traffic and displays a histogram showing distribution of traffic over a given time window.*
![histogram demo](https://raw.githubusercontent.com/ct-b/push-packet/main/assets/histogram.gif)

## Overview
push-packet utilizes eBPF XDP programs to drop, copy, and route packets. XDP runs before the packet enters the kernel network stack, enabling low-latency processing. As such this currently only supports monitoring and affecting ingress, though [TC] programs may be included in the future for egress control.

#### Engine
Push-packet is oriented around an [Engine] trait, which specifies the accompanying BPF files that apply the matching rules. Currently there is only one implementation, the [LinearEngine], which scans rules linearly. This is abstracted so other strategies such as tries and bit vectors can be used in the future, and so users can utilize their own Engine and BPF code to suit their individual needs.

#### Copy
Packets are copied to userspace using a [BPF ring buffer]. Compared to a [perf event buffer], this preserves packet ordering at the cost of potential atomic contention under high load. Support for the perf event buffer may be added in the future.

Events returned from the [`copy::Receiver`] borrow into the ring buffer; they should be dropped quickly or converted with [`CopyEvent::into_owned`] to ensure all packets are copied.

#### Route
Packets are routed to userspace using an AF_XDP socket. This allows for zero-copy routing on compatible network devices.

The AF_XDP implementation currently consists of one [UMEM] region with one socket, and addresses exchanged via a queue. In the future, other configurations may be supported, such as:
- Multiple sockets (1 per queue_id) with a shared UMEM.
- Multiple independent socket/UMEM setups, one per queue_id.

Events returned from the [`route::Receiver`] borrow into the UMEM region of the AF_XDP socket. They should be dropped quickly or converted with [`RouteEvent::into_owned`] to avoid depleting available UMEM frames.

## Motivation

While learning about kernel-bypass methods for low-latency work, I came across a blog post that mentioned eBPF as a potential *reasonably* low-latency method to bypass most of the networking stack. Traditionally, the options are to use a specialized NIC, or have [DPDK] capture all traffic from the card. That led me to aya, and the original plan was to make a simple AF_XDP-based networking stack bypass that interfaces to [smoltcp], allowing users to bypass only the address ranges they care about.

After getting acquainted with aya, I realized it wouldn't take considerably more effort to offer a copy path as well. Coupled with a simple rules-based system for copying and routing traffic, I felt like repositioning this as a flexible, easy-to-use library for people to build simple traffic analysis tools with.

I still plan to support a smoltcp integration, and other controls for the AF_XDP socket configuration (busy-poll, etc.), but my goals have changed to providing an ergonomic, general-purpose packet-inspection and routing system for modern Linux.

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
[GNU General Public License, Version 2] or the MIT license, at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: https://github.com/ct-b/push-packet/blob/main/LICENSE-APACHE
[MIT license]: https://github.com/ct-b/push-packet/blob/main/LICENSE-MIT
[GNU General Public License, Version 2]: https://github.com/ct-b/push-packet/blob/main/LICENSE-GPL2
[aya]: https://aya-rs.dev
[eBPF]: https://ebpf.io/
[AF_XDP]: https://www.kernel.org/doc/html/latest/networking/af_xdp.html
[BPF ring buffer]: https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_RINGBUF/
[perf event buffer]: https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_PERF_EVENT_ARRAY/
[UMEM]: https://www.kernel.org/doc/html/latest/networking/af_xdp.html#umem
[smoltcp]: https://github.com/smoltcp-rs/smoltcp
[DPDK]: https://www.dpdk.org/
[TC]: https://man7.org/linux/man-pages/man8/tc-bpf.8.html
[Engine]: https://github.com/ct-b/push-packet/blob/main/push-packet/src/engine/mod.rs
[LinearEngine]: https://github.com/ct-b/push-packet/blob/main/push-packet/src/engine/linear/mod.rs
[`copy::Receiver`]: https://github.com/ct-b/push-packet/blob/main/push-packet/src/channels/copy.rs
[`CopyEvent::into_owned`]: https://github.com/ct-b/push-packet/blob/main/push-packet/src/events/copy.rs
[`route::Receiver`]: https://github.com/ct-b/push-packet/blob/main/push-packet/src/channels/route.rs
[`RouteEvent::into_owned`]: https://github.com/ct-b/push-packet/blob/main/push-packet/src/events/route.rs
