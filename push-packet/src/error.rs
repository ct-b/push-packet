//! Defines error variants.

use crate::{
    channels::ChannelError,
    rules::{RuleError, RuleId},
};

pub(crate) trait ErrnoExt<T> {
    fn xsk_error(self, description: impl Into<String>) -> Result<T, Error>;
}

impl<T> ErrnoExt<T> for Result<T, xdpilone::Errno> {
    fn xsk_error(self, description: impl Into<String>) -> Result<T, Error> {
        let description = description.into();
        self.map_err(|e| {
            let source = std::io::Error::from_raw_os_error(e.get_raw());
            Error::AfXdp {
                description,
                source,
            }
        })
    }
}

impl Error {
    pub(crate) fn map(map_name: impl Into<String>, e: aya::maps::MapError) -> Self {
        let map_name = map_name.into();
        Self::Map { map_name, e }
    }

    pub(crate) fn load_program(
        program_name: impl Into<String>,
        e: aya::programs::ProgramError,
    ) -> Self {
        let program_name = program_name.into();
        Self::LoadProgram { program_name, e }
    }

    pub(crate) fn attach_program(
        program_name: impl Into<String>,
        e: aya::programs::ProgramError,
    ) -> Self {
        let program_name = program_name.into();
        Self::AttachProgram { program_name, e }
    }
}

#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    // From internal error types
    #[error("rule error at index: {index}")]
    BuilderRule {
        index: usize,
        #[source]
        source: RuleError,
    },
    #[error(transparent)]
    RuntimeRule(#[from] RuleError),
    #[error(transparent)]
    Channel(#[from] ChannelError),

    #[error("no such rule: {0}")]
    MissingRule(RuleId),

    // Aya errors
    #[error("error updating map: {map_name}")]
    Map {
        map_name: String,
        #[source]
        e: aya::maps::MapError,
    },
    #[error("missing eBPF map: {0}")]
    MissingMap(String),
    #[error("error loading program: {program_name}")]
    LoadProgram {
        program_name: String,
        #[source]
        e: aya::programs::ProgramError,
    },
    #[error("error attaching program: {program_name}")]
    AttachProgram {
        program_name: String,
        #[source]
        e: aya::programs::ProgramError,
    },

    #[error("invalid program type for: {program_name}")]
    InvalidProgramType {
        program_name: String,
        #[source]
        e: aya::programs::ProgramError,
    },
    #[error("missing eBPF program: {0}")]
    MissingProgram(String),
    #[error("error getting file descriptor")]
    FileDescriptor(#[source] aya::programs::ProgramError),
    #[error("error loading eBPF")]
    LoadEbpf(#[source] aya::EbpfError),

    // Config
    #[error("start with CopyConfig::force_enabled() or a copy rule before build")]
    CopyNotEnabled,
    #[error("start with RouteConfig::force_enabled() or a route rule before build")]
    RouteNotEnabled,
    #[error("the channel has already been taken.")]
    ChannelNotAvailable,

    // Interface Errors
    #[error("invalid network interface {0}")]
    InvalidInterfaceIndex(u32),
    #[error("invalid network interface {0}")]
    InvalidInterfaceName(String),
    #[error("invalid frame kind: {0}")]
    InvalidFrameKind(u32),

    // Af Xdp
    #[error("invalid size: {0}")]
    InvalidSize(&'static str),
    #[error("{description}")]
    AfXdp {
        description: String,
        #[source]
        source: std::io::Error,
    },

    // Engine cap
    #[error("the matching engine is at capacity and cannot accept additional rules")]
    EngineAtCapacity,
}
