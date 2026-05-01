//! Rule definitions and builders.

mod action;
mod net;
mod port;

use std::ops::RangeInclusive;

pub use action::Action;
use ipnet::IpNet;
use net::IntoIpNet;
use port::IntoPortRange;
pub use push_packet_common::Protocol;

use crate::error::Error;

/// ID for a [`Rule`]. This can be used to track rules for dynamic removal. Removed [`RuleId`]s are
/// reclaimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleId(pub(crate) usize);

/// A rule for controlling packet routing. Rules can be build with [`RuleBuilder`] and require at
/// least one filter constraint, and an action.
pub struct Rule {
    pub(crate) action: Action,
    pub(crate) protocol: Option<Protocol>,
    pub(crate) source_cidr: Option<IpNet>,
    pub(crate) source_port: Option<RangeInclusive<u16>>,
    pub(crate) destination_cidr: Option<IpNet>,
    pub(crate) destination_port: Option<RangeInclusive<u16>>,
}

impl TryFrom<RuleBuilder> for Rule {
    type Error = Error;
    fn try_from(value: RuleBuilder) -> Result<Self, Self::Error> {
        value.build()
    }
}

#[non_exhaustive]
pub(crate) enum AddressFamily {
    Any,
    Ipv4,
    Ipv6,
}

impl Rule {
    pub(crate) fn address_family(&self) -> AddressFamily {
        match (self.source_cidr, self.destination_cidr) {
            (Some(net), _) | (_, Some(net)) => match net {
                IpNet::V4(_) => AddressFamily::Ipv4,
                IpNet::V6(_) => AddressFamily::Ipv6,
            },
            _ => AddressFamily::Any,
        }
    }
    /// Creates a [`RuleBuilder`]
    #[must_use]
    pub fn builder() -> RuleBuilder {
        RuleBuilder::default()
    }

    /// Creates a [`RuleBuilder`] and sets the rule's [`Action`]
    ///
    /// The action applies to all packets matching the rule, unless overridden by successive rules.
    #[must_use]
    pub fn action(action: Action) -> RuleBuilder {
        Rule::builder().action(action)
    }

    /// Creates a [`RuleBuilder`] and sets the rule's [`Protocol`]
    #[must_use]
    pub fn protocol(protocol: Protocol) -> RuleBuilder {
        Rule::builder().protocol(protocol)
    }

    /// Creates a [`RuleBuilder`] and sets the source CIDR.
    ///
    /// Accepts any IP address or CIDR notation:
    /// - `"127.0.0.1"`: matches a single IP
    /// - `"10.0.0.0/24"`: matches a CIDR
    ///
    /// This additionally accepts [`std::net::IpAddr`], [`std::net::Ipv4Addr`],
    /// [`std::net::Ipv6Addr`], [`ipnet::IpNet`], [`ipnet::Ipv4Net`], and [`ipnet::Ipv6Net`].
    pub fn source_cidr(cidr_range: impl IntoIpNet) -> RuleBuilder {
        Rule::builder().source_cidr(cidr_range)
    }

    /// Creates a [`RuleBuilder`] and sets the source port
    ///
    /// Accepts a [`u16`] or range
    pub fn source_port(port: impl IntoPortRange) -> RuleBuilder {
        Rule::builder().source_port(port)
    }

    /// Creates a [`RuleBuilder`] and sets the destination CIDR.
    ///
    /// Accepts any IP address or CIDR notation:
    /// - `"127.0.0.1"`: matches a single IP
    /// - `"10.0.0.0/24"`: matches a CIDR
    ///
    /// This additionally accepts [`std::net::IpAddr`], [`std::net::Ipv4Addr`],
    /// [`std::net::Ipv6Addr`], [`ipnet::IpNet`], [`ipnet::Ipv4Net`], and [`ipnet::Ipv6Net`].
    pub fn destination_cidr(cidr_range: impl IntoIpNet) -> RuleBuilder {
        Rule::builder().destination_cidr(cidr_range)
    }

    /// Creates a [`RuleBuilder`] and sets the destination port
    ///
    /// Accepts a [`u16`] or range
    pub fn destination_port(port: impl IntoPortRange) -> RuleBuilder {
        Rule::builder().destination_port(port)
    }
}

/// A builder struct for [`Rule`]s. This should generally be constructed with [`Rule::builder`], or
/// a shortcut such as [`Rule::source_cidr`].
#[derive(Default)]
pub struct RuleBuilder {
    action: Option<Action>,
    protocol: Option<Protocol>,
    source_cidr: Option<Result<IpNet, Error>>,
    source_port: Option<RangeInclusive<u16>>,
    destination_cidr: Option<Result<IpNet, Error>>,
    destination_port: Option<RangeInclusive<u16>>,
}

impl RuleBuilder {
    /// Sets the rule's [`Action`]
    ///
    /// The action applies to all packets matching the rule, unless overridden by successive rules.
    #[must_use]
    pub fn action(mut self, action: Action) -> Self {
        self.action = Some(action);
        self
    }

    /// Sets the rule's [`Protocol`]
    #[must_use]
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Sets the source CIDR.
    ///
    /// Accepts any IP address or CIDR notation:
    /// - `"127.0.0.1"`: matches a single IP
    /// - `"10.0.0.0/24"`: matches a CIDR
    ///
    /// This additionally accepts [`std::net::IpAddr`], [`std::net::Ipv4Addr`],
    /// [`std::net::Ipv6Addr`], [`ipnet::IpNet`], [`ipnet::Ipv4Net`], and [`ipnet::Ipv6Net`].
    #[must_use]
    pub fn source_cidr(mut self, cidr_range: impl IntoIpNet) -> Self {
        let source_cidr = cidr_range.into_ip_net();
        self.source_cidr = Some(source_cidr);
        self
    }

    /// Sets the source port
    ///
    /// Accepts a [`u16`] or range
    #[must_use]
    pub fn source_port(mut self, port: impl IntoPortRange) -> Self {
        self.source_port = Some(port.into_port_range());
        self
    }

    /// Sets the destination CIDR.
    ///
    /// Accepts any IP address or CIDR notation:
    /// - `"127.0.0.1"`: matches a single IP
    /// - `"10.0.0.0/24"`: matches a CIDR
    ///
    /// This additionally accepts [`std::net::IpAddr`], [`std::net::Ipv4Addr`],
    /// [`std::net::Ipv6Addr`], [`ipnet::IpNet`], [`ipnet::Ipv4Net`], and [`ipnet::Ipv6Net`].
    #[must_use]
    pub fn destination_cidr(mut self, cidr_range: impl IntoIpNet) -> Self {
        let destination_cidr = cidr_range.into_ip_net();
        self.destination_cidr = Some(destination_cidr);
        self
    }

    /// Sets the destination port
    ///
    /// Accepts a [`u16`] or range
    #[must_use]
    pub fn destination_port(mut self, port: impl IntoPortRange) -> Self {
        self.destination_port = Some(port.into_port_range());
        self
    }

    /// Builds the [`Rule`].
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if there is a missing action, invalid cidr, or no constraints (ips,
    /// ports, protocols).
    pub fn build(self) -> Result<Rule, Error> {
        let Self {
            action,
            protocol,
            source_cidr,
            source_port,
            destination_cidr,
            destination_port,
        } = self;

        let action = action.ok_or(Error::MissingRuleAction)?;

        if protocol.is_none()
            && source_cidr.is_none()
            && source_port.is_none()
            && destination_cidr.is_none()
            && destination_port.is_none()
        {
            return Err(Error::MissingRuleConstraint);
        }

        let (source_cidr, destination_cidr) = match (source_cidr, destination_cidr) {
            (Some(src), Some(dst)) => {
                let (src, dst) = (src?, dst?);
                match (&src, &dst) {
                    (IpNet::V4(_), IpNet::V6(_)) | (IpNet::V6(_), IpNet::V4(_)) => {
                        return Err(Error::IncompatibleAddresses);
                    }
                    _ => (Some(src), Some(dst)),
                }
            }
            (Some(src), None) => (Some(src?), None),
            (None, Some(src)) => (None, Some(src?)),
            _ => (None, None),
        };

        Ok(Rule {
            action,
            protocol,
            source_cidr,
            source_port,
            destination_cidr,
            destination_port,
        })
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        error::Error,
        rules::{Rule, action::Action},
    };

    #[test]
    fn rule_builder_requires_action() {
        assert!(matches!(
            Rule::source_cidr("127.0.0.1").build(),
            Err(Error::MissingRuleAction)
        ));
    }

    #[test]
    fn rule_builder_requires_a_constraint() {
        assert!(matches!(
            Rule::action(Action::Pass).build(),
            Err(Error::MissingRuleConstraint)
        ));
    }

    #[test]
    fn rule_builder_builds_with_one_constraint_and_action() {
        assert!(
            Rule::protocol(push_packet_common::Protocol::Tcp)
                .action(Action::Pass)
                .build()
                .is_ok()
        );
    }

    #[test]
    fn rule_builder_builds_with_all_constraints_and_action() {
        let rule = Rule::builder()
            .protocol(push_packet_common::Protocol::Tcp)
            .source_cidr("127.0.0.1")
            .destination_cidr("127.0.0.1")
            .source_port(3000)
            .destination_port(80)
            .action(Action::Route)
            .build();
        assert!(rule.is_ok());
    }

    #[test]
    fn rule_builder_bad_ip_propagates() {
        assert!(
            Rule::builder()
                .source_cidr("badip")
                .action(Action::Pass)
                .build()
                .is_err_and(|e| matches!(e, Error::InvalidAddress(_)))
        );
    }
}
