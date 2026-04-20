//! Defines [`Engine`] traits.
#[cfg(feature = "linear")]
pub mod linear;

use aya::Ebpf;

use crate::{
    error::Error,
    rules::{Rule, RuleId},
};

/// The Engine trait defines how rules are evaluated in the eBPF program. Each Engine requires a
/// matching eBPF program.
pub trait Engine {
    /// The raw bytes of the eBPF program
    const EBPF_BYTES: &'static [u8];

    /// The eBPF program name
    const EBPF_PROGRAM_NAME: &'static str;

    /// If this engnine is limited in max capacity, return the capcacity
    fn capacity(&self) -> Option<usize>;
    /// Add a rule to the engine
    fn add_rule(&mut self, rule_id: RuleId, rule: &Rule, ebpf: &mut Ebpf) -> Result<(), Error>;
    /// Remove a rule from the engine
    fn remove_rule(&mut self, rule_id: RuleId, rule: &Rule, ebpf: &mut Ebpf) -> Result<(), Error>;
}
