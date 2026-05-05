#![deny(missing_docs)]
#![deny(rustdoc::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::multiple_unsafe_ops_per_block)]
#![deny(clippy::as_conversions)]
#![allow(clippy::cast_possible_truncation)]
//! push-packet is a high-level, extensible packet routing library built on eBPF with aya. It is
//! intended to be a simple, yet flexible foundation for traffic analysis applications and
//! network-stack bypass.
//!
//! # Example: Tap into a network interface, and copy all packets to userspace.
//! ```no_run
//! # use push_packet::{Tap, rules::{Rule, Action}};
//! # fn main() -> Result<(), push_packet::Error> {
//! let mut tap = Tap::builder("wlp3s0")
//!     .rule(Rule::source_cidr("0.0.0.0/0").action(Action::Copy { take: None }))
//!     .build()?;
//!
//! let mut rx = tap.copy_receiver()?;
//! while let Ok(event) = rx.recv() {
//!     println!("Received packet of length {}", event.packet_len());
//! }
//! # Ok(())
//! # }
//! ```
//! # Example: Tap into an interface, add and remove rules dynamically.
//! ```no_run
//! # use push_packet::{Tap, rules::{Rule, Action, Protocol}, CopyConfig};
//! # fn main() -> Result<(), push_packet::Error> {
//! let mut tap = Tap::builder("wlp3s0")
//!     // Set force_enabled on the copy config so we can use copy rules later.
//!     .copy_config(CopyConfig::default().force_enabled())
//!     .build()?;
//!
//! // call add_rule to get a RuleId
//! let drop_rule_id = tap.add_rule(
//!     Rule::protocol(Protocol::Tcp)
//!         .source_cidr("127.0.0.1")
//!         .source_port(3000..4000)
//!         .action(Action::Drop),
//! )?;
//!
//! // [traffic dropped]
//!
//! // Remove a rule with RuleId
//! tap.remove_rule(drop_rule_id)?;
//!
//! // Read some traffic instead
//! tap.add_rule(
//!     Rule::source_cidr("127.0.0.1")
//!         .source_port(3001)
//!         .action(Action::COPY_ALL),
//! )?;
//!
//! let mut rx = tap.copy_receiver()?;
//! while let Ok(event) = rx.recv() {
//!     println!("Received packet of length {}", event.packet_len());
//! }
//!
//! # Ok(())
//! # }
//! ```

mod af_xdp;
mod array_ext;
mod cast;
mod ebpf;
mod error;
mod filter;
mod interface;
mod loader;
mod relay;
mod tap;

pub mod channels;
pub mod engine;
pub mod events;
pub mod rules;

pub use channels::ChannelError;
pub use error::Error;
pub use interface::Interface;
pub use loader::Loader;
pub use push_packet_common::FrameKind;
pub use rules::RuleError;
pub use tap::{CopyConfig, RouteConfig, Tap, TapBuilder};
