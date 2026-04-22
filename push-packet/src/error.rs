//! Defines error variants.
use std::{convert::Infallible, ffi::IntoStringError, num::TryFromIntError};

use aya::{EbpfError, programs::ProgramError};

#[allow(missing_docs)]
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
    #[error("source and destination addresses must be of the same address family")]
    IncompatibleAddresses,
    #[error("missing eBPF map")]
    MissingEbpfMap,
    #[error("missing eBPF program")]
    MissingEbpfProgram,
    #[error("invalid frame kind: {0}")]
    InvalidFrameKind(u32),
    #[error("no ringbuf has been allocated")]
    MissingRingBuf,
    #[error("the eBPF program has not been started")]
    ProgramNotRunning,
    #[error("the RingBufItem is not ready")]
    NoRingBufItem,
    #[error("the channel has disconnected")]
    ChannelDisconnected,
    #[error(
        "to dynamically add Copy rules, use a Copy rule before Tap::start() or use TapConfig::with_copy"
    )]
    CopyNotEnabled,
    #[error(
        "to dynamically add Route rules, use a Route rule before Tap::start() or use TapConfig::with_copy"
    )]
    RouteNotEnabled,
    #[error(transparent)]
    NixError(#[from] nix::errno::Errno),
    #[error(transparent)]
    TryFromIntError(#[from] TryFromIntError),
    #[error(transparent)]
    MapError(#[from] aya::maps::MapError),
    #[error(transparent)]
    IntoStringError(#[from] IntoStringError),
    #[error(transparent)]
    EbpfError(#[from] EbpfError),
    #[error(transparent)]
    ProgramError(#[from] ProgramError),
    #[error(transparent)]
    Infallible(#[from] Infallible),
}
