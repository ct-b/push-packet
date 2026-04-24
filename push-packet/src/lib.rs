#![deny(missing_docs)]
#![deny(rustdoc::all)]
#![deny(clippy::pedantic)]
//! push-packet is a high-level, extensible packet routing library built on eBPF with aya. It is
//! intended to be a simple, yet flexible foundation for traffic analysis applications and
//! network-stack bypass.
//!
//! # Example: Tap into a network interface, and copy all packets to userspace.
//! ```no_run
//! # use push_packet::{Tap, rules::{Rule, Action}};
//! # fn main() -> Result<(), push_packet::Error> {
//! let mut tap = Tap::builder("wlp3s0")?
//!     .rule(
//!         Rule::builder()
//!             .source_cidr("0.0.0.0/0")
//!             .action(Action::Copy { take: None }),
//!     )?
//!     .build()?;
//!
//! let mut rx = tap.copy_receiver()?;
//! while let Ok(event) = rx.recv() {
//!     println!("Received packet of length {}", event.packet_len());
//! }
//! # Ok(())
//! # }
//! ```

mod array_ext;
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

pub use error::Error;
pub use interface::Interface;
pub use loader::Loader;
pub use tap::{CopyConfig, RouteConfig, Tap, TapBuilder};
