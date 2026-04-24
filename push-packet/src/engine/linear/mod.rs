//! Defines the [`LinearEngine`]
mod rules;
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{Array, MapData},
};
use push_packet_common::engine::linear::{CAPACITY, Ipv4Rule, Ipv6Rule};

use crate::{
    array_ext::ArrayExt,
    ebpf::{array_owned, xdp_program},
    engine::Engine,
    error::Error,
    loader::Loader,
    rules::{AddressFamily, Rule, RuleId},
};

/// Name of the ipv4 map
const IP_V4_MAP: &str = "LINEAR_MAP_V4";
/// Name of the ipv6 map
const IP_V6_MAP: &str = "LINEAR_MAP_V6";
/// Name of the rule count map
const RULE_COUNT_MAP: &str = "LINEAR_RULE_COUNT";

#[derive(Default)]
/// Loader for a [`LinearEngine`].
pub struct LinearEngineLoader;

impl Loader for LinearEngineLoader {
    type Component = LinearEngine;
    fn load(self, ebpf: &mut Ebpf) -> Result<Self::Component, Error> {
        let ipv4_rules = array_owned::<Ipv4Rule>(ebpf, IP_V4_MAP)?;
        let ipv6_rules = array_owned::<Ipv6Rule>(ebpf, IP_V6_MAP)?;
        let rule_count = array_owned::<u32>(ebpf, RULE_COUNT_MAP)?;
        xdp_program(ebpf, LinearEngine::EBPF_PROGRAM_NAME)?.load()?;
        Ok(LinearEngine {
            v4_count: 0,
            v6_count: 0,
            ipv4_rules,
            ipv6_rules,
            rule_count,
        })
    }
}

/// The `LinearEngine` is a simple rule-matching engine that processes rules in order. It has a max
/// capacity of [`CAPACITY`], but stops early based on the number of rules populated.
pub struct LinearEngine {
    v4_count: usize,
    v6_count: usize,
    ipv4_rules: Array<MapData, Ipv4Rule>,
    ipv6_rules: Array<MapData, Ipv6Rule>,
    rule_count: Array<MapData, u32>,
}

impl LinearEngine {
    fn update_counts(&mut self) -> Result<(), Error> {
        let v4_count: u32 = self.v4_count.try_into()?;
        let v6_count: u32 = self.v6_count.try_into()?;
        self.rule_count.set(0, v4_count, 0)?;
        self.rule_count.set(1, v6_count, 0)?;
        Ok(())
    }

    fn add_ipv4_rule(&mut self, rule_id: RuleId, rule: &Rule) -> Result<(), Error> {
        let rule: Ipv4Rule = rule.into();
        self.ipv4_rules.set(rule_id.0.try_into()?, rule, 0)?;
        self.v4_count = self.v4_count.max(rule_id.0 + 1);
        self.update_counts()
    }

    fn add_ipv6_rule(&mut self, rule_id: RuleId, rule: &Rule) -> Result<(), Error> {
        let rule: Ipv6Rule = rule.into();
        self.ipv6_rules.set(rule_id.0.try_into()?, rule, 0)?;
        self.v6_count = self.v6_count.max(rule_id.0 + 1);
        self.update_counts()
    }
}

impl Engine for LinearEngine {
    type Loader = LinearEngineLoader;
    const EBPF_PROGRAM_NAME: &'static str = "linear";
    #[cfg(feature = "build-ebpf")]
    const EBPF_BYTES: &'static [u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/linear"));

    #[cfg(not(feature = "build-ebpf"))]
    const EBPF_BYTES: &'static [u8] = include_bytes_aligned!("../../../ebpf-bin/linear");

    fn capacity(&self) -> Option<usize> {
        Some(CAPACITY)
    }

    fn add_rule(&mut self, rule_id: RuleId, rule: &Rule) -> Result<(), Error> {
        match rule.address_family() {
            AddressFamily::Ipv4 => self.add_ipv4_rule(rule_id, rule),
            AddressFamily::Ipv6 => self.add_ipv6_rule(rule_id, rule),
            AddressFamily::Any => {
                self.add_ipv4_rule(rule_id, rule)?;
                self.add_ipv6_rule(rule_id, rule)?;
                Ok(())
            }
        }
    }

    fn remove_rule(&mut self, rule_id: RuleId, rule: &Rule) -> Result<(), Error> {
        let rule_id: u32 = rule_id.0.try_into()?;
        match rule.address_family() {
            AddressFamily::Ipv4 => self.ipv4_rules.clear(rule_id)?,
            AddressFamily::Ipv6 => self.ipv6_rules.clear(rule_id)?,
            AddressFamily::Any => {
                self.ipv4_rules.clear(rule_id)?;
                self.ipv6_rules.clear(rule_id)?;
            }
        }
        Ok(())
    }
}
