use std::convert::Infallible;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid address")]
    InvalidAddress(#[from] std::net::AddrParseError),
    #[error("invalid cidr range")]
    InvalidNetAddress(#[from] ipnet::AddrParseError),
    #[error("at least one constraint (port, cidr, address, etc.) must be applied to the rule")]
    MissingRuleConstraint,
    #[error("each rule must have an accompanying action set")]
    MissingRuleAction,
    #[error(transparent)]
    Infallible(#[from] Infallible),
}
