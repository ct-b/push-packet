//! Defines the [`LinearEngine`]
mod rules;
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{Array, MapData},
};
use push_packet_common::engine::linear::{CAPACITY, Ipv4Rule, Ipv6Rule};

use crate::{
    engine::Engine,
    error::Error,
    rules::{AddressFamily, Rule, RuleId},
};

/// The `LinearEngine` is a simple rule-matching engine that processes rules in order. It has a max
/// capacity of [`CAPACITY`], but stops early based on the number of rules populated.
#[derive(Default)]
pub struct LinearEngine;

impl LinearEngine {
    /// Name of the ipv4 map
    const IP_V4_MAP_NAME: &'static str = "LINEAR_MAP_V4";
    /// Name of the ipv6 map
    const IP_V6_MAP_NAME: &'static str = "LINEAR_MAP_V6";

    fn ipv4_map_mut(ebpf: &mut Ebpf) -> Result<Array<&mut MapData, Ipv4Rule>, Error> {
        let map = ebpf
            .map_mut(Self::IP_V4_MAP_NAME)
            .ok_or(Error::MissingEbpfMap)?;
        let map = Array::try_from(map)?;
        Ok(map)
    }

    fn add_ipv4_rule(
        &mut self,
        rule_id: RuleId,
        rule: &Rule,
        ebpf: &mut Ebpf,
    ) -> Result<(), Error> {
        let rule: Ipv4Rule = rule.into();
        Self::ipv4_map_mut(ebpf)?.set(u32::try_from(rule_id.0)?, rule, 0)?;
        Ok(())
    }

    fn ipv6_map_mut(ebpf: &mut Ebpf) -> Result<Array<&mut MapData, Ipv6Rule>, Error> {
        let map = ebpf
            .map_mut(Self::IP_V6_MAP_NAME)
            .ok_or(Error::MissingEbpfMap)?;
        let map = Array::try_from(map)?;
        Ok(map)
    }

    fn add_ipv6_rule(
        &mut self,
        rule_id: RuleId,
        rule: &Rule,
        ebpf: &mut Ebpf,
    ) -> Result<(), Error> {
        let rule: Ipv6Rule = rule.into();
        Self::ipv6_map_mut(ebpf)?.set(u32::try_from(rule_id.0)?, rule, 0)?;
        Ok(())
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
        match rule.address_family() {
            AddressFamily::Ipv4 => {
                Self::ipv4_map_mut(ebpf)?.set(u32::try_from(rule_id.0)?, Ipv4Rule::default(), 0)?;
            }
            AddressFamily::Ipv6 => {
                Self::ipv6_map_mut(ebpf)?.set(u32::try_from(rule_id.0)?, Ipv6Rule::default(), 0)?;
            }
            AddressFamily::Any => {
                Self::ipv4_map_mut(ebpf)?.set(u32::try_from(rule_id.0)?, Ipv4Rule::default(), 0)?;
                Self::ipv6_map_mut(ebpf)?.set(u32::try_from(rule_id.0)?, Ipv6Rule::default(), 0)?;
            }
        }
        Ok(())
    }
}
