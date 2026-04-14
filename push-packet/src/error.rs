use std::{convert::Infallible, ffi::IntoStringError};

use aya::{EbpfError, programs::ProgramError};

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
    #[error("the matching engine is at capacity and cannot accept additional rules")]
    EngineAtCapacity,
    #[error("no rule found with this RuleId")]
    MissingRuleId,
    #[error("invalid network interface {0}")]
    InvalidInterfaceIndex(u32),
    #[error("invalid network interface {0}")]
    InvalidInterfaceName(String),
    #[error(transparent)]
    IntoStringError(#[from] IntoStringError),
    #[error(transparent)]
    EbpfError(#[from] EbpfError),
    #[error(transparent)]
    ProgramError(#[from] ProgramError),
    #[error(transparent)]
    Infallible(#[from] Infallible),
}
