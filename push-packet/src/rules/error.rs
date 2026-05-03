#[non_exhaustive]
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("each rule must have at least one constraint, such as cidr or port")]
    MissingConstraint,
    #[error("each rule must have an Action")]
    MissingAction,
    #[error("invalid IP address: {addr}")]
    InvalidAddress {
        addr: String,
        #[source]
        source: std::net::AddrParseError,
    },
    #[error("invalid CIDR range: {addr}")]
    InvalidCidr {
        addr: String,
        #[source]
        source: ipnet::AddrParseError,
    },
    #[error("a rule may not contain both ipv4 and ipv6 addresses")]
    IncompatibleAddresses,
}

impl RuleError {
    pub(crate) fn invalid_address(
        addr: impl Into<String>,
        source: std::net::AddrParseError,
    ) -> Self {
        let addr = addr.into();
        Self::InvalidAddress { addr, source }
    }

    pub(crate) fn invalid_cidr(addr: impl Into<String>, source: ipnet::AddrParseError) -> Self {
        let addr = addr.into();
        Self::InvalidCidr { addr, source }
    }
}
