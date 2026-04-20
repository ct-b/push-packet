use crate::{Action, Protocol};

pub const CAPACITY: usize = 64;

pub const FLAG_SOURCE_CIDR: u8 = 1;
pub const FLAG_DESTINATION_CIDR: u8 = 1 << 1;
pub const FLAG_SOURCE_PORT: u8 = 1 << 2;
pub const FLAG_DESTINATION_PORT: u8 = 1 << 3;
pub const FLAG_PROTOCOL: u8 = 1 << 4;

pub trait RuleExt {
    fn flags(&self) -> &u8;

    fn flags_mut(&mut self) -> &mut u8;

    fn set_flag(&mut self, flag: u8) {
        *self.flags_mut() |= flag;
    }

    fn remove_flag(&mut self, flag: u8) {
        *self.flags_mut() &= !flag;
    }

    fn flag_is_set(&self, flag: u8) -> bool {
        self.flags() & flag != 0
    }

    fn source_cidr_set(&self) -> bool {
        self.flag_is_set(FLAG_SOURCE_CIDR)
    }

    fn source_port_set(&self) -> bool {
        self.flag_is_set(FLAG_SOURCE_PORT)
    }

    fn destination_cidr_set(&self) -> bool {
        self.flag_is_set(FLAG_DESTINATION_CIDR)
    }

    fn destination_port_set(&self) -> bool {
        self.flag_is_set(FLAG_DESTINATION_PORT)
    }

    fn protocol_set(&self) -> bool {
        self.flag_is_set(FLAG_PROTOCOL)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RuleCommon {
    pub source_port_min: u16,
    pub source_port_max: u16,
    pub destination_port_min: u16,
    pub destination_port_max: u16,
    pub take: u32,
    pub source_prefix_len: u8,
    pub destination_prefix_len: u8,
    pub flags: u8,
    pub action: Action,
    pub protocol: Protocol,
    // Padded to 20 bytes for eBPF map layout
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Ipv4Rule {
    pub source_cidr: u32,
    pub destination_cidr: u32,
    pub common: RuleCommon,
}

impl RuleExt for Ipv4Rule {
    fn flags(&self) -> &u8 {
        &self.common.flags
    }
    fn flags_mut(&mut self) -> &mut u8 {
        &mut self.common.flags
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Ipv6Rule {
    pub source_cidr: [u8; 16],
    pub destination_cidr: [u8; 16],
    pub common: RuleCommon,
}

impl RuleExt for Ipv6Rule {
    fn flags(&self) -> &u8 {
        &self.common.flags
    }
    fn flags_mut(&mut self) -> &mut u8 {
        &mut self.common.flags
    }
}

#[cfg(feature = "user")]
mod pod {
    use aya::Pod;

    use crate::engine::linear::{Ipv4Rule, Ipv6Rule};

    unsafe impl Pod for Ipv4Rule {}
    unsafe impl Pod for Ipv6Rule {}
}
