//! Defines the [`LinearEngine`]
mod rules;
use aya::{Ebpf, include_bytes_aligned};
use push_packet_common::engine::linear::{CAPACITY, Ipv4Rule, Ipv6Rule};

use crate::{
    ebpf::{array_mut, clear_array, set_array},
    engine::Engine,
    error::Error,
    rules::{AddressFamily, Rule, RuleId},
};

/// Name of the ipv4 map
const IP_V4_MAP: &str = "LINEAR_MAP_V4";
/// Name of the ipv6 map
const IP_V6_MAP: &str = "LINEAR_MAP_V6";
/// Name of the rule count map
const RULE_COUNT_MAP: &str = "LINEAR_RULE_COUNT";

/// The `LinearEngine` is a simple rule-matching engine that processes rules in order. It has a max
/// capacity of [`CAPACITY`], but stops early based on the number of rules populated.
#[derive(Default)]
pub struct LinearEngine {
    v4_count: usize,
    v6_count: usize,
}

impl LinearEngine {
    fn update_counts(&self, ebpf: &mut Ebpf) -> Result<(), Error> {
        let v4_count: u32 = self.v4_count.try_into()?;
        let v6_count: u32 = self.v6_count.try_into()?;
        let mut map = array_mut(ebpf, RULE_COUNT_MAP)?;
        map.set(0, v4_count, 0)?;
        map.set(1, v6_count, 0)?;
        Ok(())
    }

    fn add_ipv4_rule(
        &mut self,
        rule_id: RuleId,
        rule: &Rule,
        ebpf: &mut Ebpf,
    ) -> Result<(), Error> {
        let rule: Ipv4Rule = rule.into();
        set_array(ebpf, IP_V4_MAP, u32::try_from(rule_id.0)?, rule)?;
        self.v4_count = self.v4_count.max(rule_id.0 + 1);
        self.update_counts(ebpf)
    }

    fn add_ipv6_rule(
        &mut self,
        rule_id: RuleId,
        rule: &Rule,
        ebpf: &mut Ebpf,
    ) -> Result<(), Error> {
        let rule: Ipv6Rule = rule.into();
        set_array(ebpf, IP_V6_MAP, u32::try_from(rule_id.0)?, rule)?;
        self.v6_count = self.v6_count.max(rule_id.0 + 1);
        self.update_counts(ebpf)
    }
}

impl Engine for LinearEngine {
    const EBPF_PROGRAM_NAME: &'static str = "linear";
    #[cfg(feature = "build-ebpf")]
    const EBPF_BYTES: &'static [u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/linear"));

    #[cfg(not(feature = "build-ebpf"))]
    const EBPF_BYTES: &'static [u8] = include_bytes_aligned!("../../../ebpf-bin/linear");

    fn capacity(&self) -> Option<usize> {
        Some(CAPACITY)
    }

    fn init(&mut self, ebpf: &mut Ebpf) -> Result<(), Error> {
        self.update_counts(ebpf)
    }

    fn add_rule(&mut self, rule_id: RuleId, rule: &Rule, ebpf: &mut Ebpf) -> Result<(), Error> {
        match rule.address_family() {
            AddressFamily::Ipv4 => self.add_ipv4_rule(rule_id, rule, ebpf),
            AddressFamily::Ipv6 => self.add_ipv6_rule(rule_id, rule, ebpf),
            AddressFamily::Any => {
                self.add_ipv4_rule(rule_id, rule, ebpf)?;
                self.add_ipv6_rule(rule_id, rule, ebpf)?;
                Ok(())
            }
        }
    }

    fn remove_rule(&mut self, rule_id: RuleId, rule: &Rule, ebpf: &mut Ebpf) -> Result<(), Error> {
        let rule_id: u32 = rule_id.0.try_into()?;
        match rule.address_family() {
            AddressFamily::Ipv4 => clear_array::<Ipv4Rule>(ebpf, IP_V4_MAP, rule_id)?,
            AddressFamily::Ipv6 => clear_array::<Ipv6Rule>(ebpf, IP_V6_MAP, rule_id)?,
            AddressFamily::Any => {
                clear_array::<Ipv4Rule>(ebpf, IP_V4_MAP, rule_id)?;
                clear_array::<Ipv6Rule>(ebpf, IP_V6_MAP, rule_id)?;
            }
        }
        Ok(())
    }
}
