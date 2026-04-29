#![no_std]
pub mod engine;

pub const RING_BUF_NAME: &str = "PP_RING_BUF";

/// Shared protocol, used for setting and executing filter rules
#[non_exhaustive]
#[repr(u8)]
#[derive(Clone, Copy, Default)]
pub enum Protocol {
    Icmp = 1,
    #[default]
    Tcp = 6,
    Udp = 17,
    Icmpv6 = 58,
}

/// Shared action
#[non_exhaustive]
#[repr(u8)]
#[derive(Clone, Copy, Default)]
pub enum Action {
    #[default]
    Pass = 0,
    Drop = 1,
    Copy = 2,
    Route = 3,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum FrameKind {
    Eth = 0,
    Ip = 1,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FrameKind {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CopyArgs {
    pub take: u32,
    pub rule_id: u32,
    pub packet_len: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RouteArgs {
    pub rule_id: u32,
}
