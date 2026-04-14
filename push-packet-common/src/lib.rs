#![no_std]
pub mod engine;

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
