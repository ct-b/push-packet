#[cfg(feature = "linear")]
pub mod linear;

use crate::{
    error::Error,
    rules::{Rule, RuleId},
};

pub trait Engine {
    const EBPF_BYTES: &'static [u8];
    fn capacity(&self) -> Option<usize>;
    fn add_rule(&mut self, rule_id: RuleId, rule: &Rule) -> Result<(), Error>;
    fn remove_rule(&mut self, rule_id: RuleId, rule: &Rule) -> Result<(), Error>;
}
