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

pub struct LinearEngine {
    capacity: usize,
}

impl LinearEngine {
    const IP_V4_MAP_NAME: &'static str = "LINEAR_MAP_V4";
    const IP_V6_MAP_NAME: &'static str = "LINEAR_MAP_V6";
    pub fn new(capacity: Option<usize>) -> Self {
        Self {
            capacity: capacity.unwrap_or(CAPACITY),
        }
    }

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
    const EBPF_PROGAM_NAME: &'static str = "linear";
    #[cfg(feature = "build-ebpf")]
    const EBPF_BYTES: &'static [u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/linear"));

    fn map_capacities(&self) -> impl Iterator<Item = (&str, u32)> {
        [
            (Self::IP_V4_MAP_NAME, self.capacity as u32),
            (Self::IP_V6_MAP_NAME, self.capacity as u32),
        ]
        .into_iter()
    }
    #[cfg(not(feature = "build-ebpf"))]
    const EBPF_BYTES: &'static [u8] = include_bytes_aligned!("../../../ebpf-bin/linear");
    fn capacity(&self) -> Option<usize> {
        Some(self.capacity)
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
