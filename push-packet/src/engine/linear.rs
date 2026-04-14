use aya::include_bytes_aligned;

use crate::{
    engine::Engine,
    error::Error,
    rules::{Rule, RuleId},
};

pub struct LinearEngine {}

impl LinearEngine {
    pub fn new() -> Self {
        Self {}
    }
}

impl Engine for LinearEngine {
    #[cfg(feature = "build-ebpf")]
    const EBPF_BYTES: &'static [u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/linear"));
    #[cfg(not(feature = "build-ebpf"))]
    const EBPF_BYTES: &'static [u8] = include_bytes_aligned!("../../ebpf-bin/linear");
    fn capacity(&self) -> Option<usize> {
        None
    }

    fn add_rule(&mut self, rule_id: RuleId, rule: &Rule) -> Result<(), Error> {
        Ok(())
    }

    fn remove_rule(&mut self, rule_id: RuleId, rule: &Rule) -> Result<(), Error> {
        Ok(())
    }
}
