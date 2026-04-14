#[cfg(feature = "linear")]
pub mod linear;

use aya::Ebpf;

use crate::{
    error::Error,
    rules::{Rule, RuleId},
};

pub trait Engine {
    const EBPF_BYTES: &'static [u8];
    const EBPF_PROGAM_NAME: &'static str;
    fn capacity(&self) -> Option<usize>;
    fn add_rule(&mut self, rule_id: RuleId, rule: &Rule, ebpf: &mut Ebpf) -> Result<(), Error>;
    fn remove_rule(&mut self, rule_id: RuleId, rule: &Rule, ebpf: &mut Ebpf) -> Result<(), Error>;
    fn map_capacities(&self) -> impl Iterator<Item = (&str, u32)>;
}
