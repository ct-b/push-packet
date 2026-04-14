use ipnet::IpNet;
use push_packet_common::engine::linear::{
    FLAG_DESTINATION_CIDR, FLAG_DESTINATION_PORT, FLAG_PROTOCOL, FLAG_SOURCE_CIDR,
    FLAG_SOURCE_PORT, Ipv4Rule, Ipv6Rule, RuleExt,
};

use crate::rules::Rule;

impl From<&Rule> for Ipv4Rule {
    fn from(value: &Rule) -> Self {
        let Rule {
            name: _,
            action,
            protocol,
            source_cidr,
            source_port,
            destination_cidr,
            destination_port,
        } = value;
        let mut rule = Ipv4Rule::default();
        let (action, take) = (*action).into_common_action();
        rule.action = action;
        if let Some(take) = take {
            rule.take = take;
        }
        if let Some(protocol) = protocol {
            rule.protocol = *protocol;
            rule.set_flag(FLAG_PROTOCOL);
        }
        if let Some(IpNet::V4(source_cidr)) = source_cidr {
            rule.source_cidr = source_cidr.addr().into();
            rule.source_prefix_len = source_cidr.prefix_len();
            rule.set_flag(FLAG_SOURCE_CIDR);
        }

        if let Some(source_port) = source_port {
            rule.source_port_min = *source_port.start();
            rule.source_port_max = *source_port.end();
            rule.set_flag(FLAG_SOURCE_PORT);
        }
        if let Some(IpNet::V4(destination_cidr)) = destination_cidr {
            rule.destination_cidr = destination_cidr.addr().into();
            rule.destination_prefix_len = destination_cidr.prefix_len();
            rule.set_flag(FLAG_DESTINATION_CIDR);
        }

        if let Some(destination_port) = destination_port {
            rule.destination_port_min = *destination_port.start();
            rule.destination_port_max = *destination_port.end();
            rule.set_flag(FLAG_DESTINATION_PORT);
        }
        rule
    }
}

impl From<&Rule> for Ipv6Rule {
    fn from(value: &Rule) -> Self {
        let Rule {
            name: _,
            action,
            protocol,
            source_cidr,
            source_port,
            destination_cidr,
            destination_port,
        } = value;
        let mut rule = Ipv6Rule::default();
        let (action, take) = action.into_common_action();
        rule.action = action;
        if let Some(take) = take {
            rule.take = take;
        }
        if let Some(protocol) = protocol {
            rule.protocol = *protocol;
            rule.set_flag(FLAG_PROTOCOL);
        }
        if let Some(IpNet::V6(source_cidr)) = source_cidr {
            rule.source_cidr = source_cidr.addr().octets();
            rule.source_prefix_len = source_cidr.prefix_len();
            rule.set_flag(FLAG_SOURCE_CIDR);
        }

        if let Some(source_port) = source_port {
            rule.source_port_min = *source_port.start();
            rule.source_port_max = *source_port.end();
            rule.set_flag(FLAG_SOURCE_PORT);
        }
        if let Some(IpNet::V6(destination_cidr)) = destination_cidr {
            rule.destination_cidr = destination_cidr.addr().octets();
            rule.destination_prefix_len = destination_cidr.prefix_len();
            rule.set_flag(FLAG_DESTINATION_CIDR);
        }

        if let Some(destination_port) = destination_port {
            rule.destination_port_min = *destination_port.start();
            rule.destination_port_max = *destination_port.end();
            rule.set_flag(FLAG_DESTINATION_PORT);
        }
        rule
    }
}
