#![no_std]

/// Shared protocol, used for setting and executing filter rules
#[non_exhaustive]
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Protocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Icmpv6 = 58,
}

/// Shared action
#[non_exhaustive]
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Action {
    Pass = 0,
    Drop = 1,
    Copy = 2,
    Route = 3,
}
