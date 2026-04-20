#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action::{self, XDP_PASS},
    btf_maps::Array,
    macros::{btf_map, map, xdp},
    maps::ProgramArray,
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};
use push_packet_common::{
    Action, CopyArgs, FrameKind,
    engine::linear::{CAPACITY, Ipv4Rule, Ipv6Rule, RuleExt},
};
use push_packet_ebpf::{
    CopyArgsExt,
    context_ext::{Boundaries, ContextExt},
    try_copy_packet,
};

#[map]
static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(2, 0);

#[btf_map]
static LINEAR_MAP_V4: Array<Ipv4Rule, CAPACITY> = Array::new();

#[btf_map]
static LINEAR_MAP_V6: Array<Ipv6Rule, CAPACITY> = Array::new();

#[btf_map]
static FRAME_KIND_MAP: Array<FrameKind, 1> = Array::new();

#[xdp]
pub fn copy_packet(ctx: XdpContext) -> u32 {
    match try_copy_packet(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[xdp]
pub fn linear(ctx: XdpContext) -> u32 {
    match try_linear(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn eval_ipv6_hdr(
    _context: &XdpContext,
    _boundaries: &Boundaries,
    _offset: usize,
) -> Result<u32, ()> {
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn v4_cidr_match(address: u32, rule_address: u32, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let mask = !0 << (32 - prefix_len);
    (address & mask) == (rule_address & mask)
}

#[inline(always)]
fn eval_ipv4_hdr(context: &XdpContext, boundaries: &Boundaries, offset: usize) -> Result<u32, ()> {
    let hdr: *const Ipv4Hdr = boundaries.ptr_at(offset)?;
    let hdr = unsafe { &*hdr };
    let src_addr = u32::from_be_bytes(hdr.src_addr);
    let dst_addr = u32::from_be_bytes(hdr.dst_addr);
    let proto = hdr.proto;
    let ip_hdr_len = hdr.ihl() as usize;

    let transport_offset = offset + ip_hdr_len;
    let (src_port, dst_port) = match proto {
        IpProto::Tcp | IpProto::Udp => {
            let ports: *const [u16; 2] = boundaries.ptr_at(transport_offset)?;
            (
                u16::from_be(unsafe { (*ports)[0] }),
                u16::from_be(unsafe { (*ports)[1] }),
            )
        }
        _ => (0, 0),
    };

    for i in 0..CAPACITY {
        let Some(rule) = LINEAR_MAP_V4.get(i as u32) else {
            continue;
        };
        if rule.common.flags == 0 {
            continue;
        }
        if rule.source_cidr_set()
            && !v4_cidr_match(src_addr, rule.source_cidr, rule.common.source_prefix_len)
        {
            continue;
        }
        if rule.destination_cidr_set()
            && !v4_cidr_match(
                dst_addr,
                rule.destination_cidr,
                rule.common.destination_prefix_len,
            )
        {
            continue;
        }
        if rule.protocol_set() && proto as u8 != rule.common.protocol as u8 {
            continue;
        }
        if rule.source_port_set()
            && (src_port < rule.common.source_port_min || src_port > rule.common.source_port_max)
        {
            continue;
        }

        if rule.destination_port_set()
            && (dst_port < rule.common.destination_port_min
                || dst_port > rule.common.destination_port_max)
        {
            continue;
        }
        return match rule.common.action {
            Action::Pass => Ok(xdp_action::XDP_PASS),
            Action::Drop => Ok(xdp_action::XDP_DROP),
            Action::Copy => {
                CopyArgs::set(rule.common.take, i as u32, boundaries.len() as u32)?;
                unsafe { JUMP_TABLE.tail_call(context, 0).map_err(|_| ())? };
                Ok(xdp_action::XDP_PASS)
            }
            Action::Route => Ok(xdp_action::XDP_PASS),
            _ => Ok(xdp_action::XDP_PASS),
        };
    }
    Ok(XDP_PASS)
}

#[inline(always)]
fn try_linear(ctx: XdpContext) -> Result<u32, ()> {
    let boundaries = ctx.boundaries();
    let Some(frame_kind) = FRAME_KIND_MAP.get(0) else {
        return Err(());
    };
    match &frame_kind {
        FrameKind::Eth => {
            let ether_type: *const EtherType =
                boundaries.ptr_at(mem::offset_of!(EthHdr, ether_type))?;
            match unsafe { *ether_type } {
                EtherType::Ipv4 => eval_ipv4_hdr(&ctx, &boundaries, EthHdr::LEN),
                EtherType::Ipv6 => eval_ipv6_hdr(&ctx, &boundaries, EthHdr::LEN),
                _ => Ok(xdp_action::XDP_PASS),
            }
        }
        FrameKind::Ip => {
            let version: *const u16 = boundaries.ptr_at(0)?;
            let version = (unsafe { u16::from_be(*version) } >> 12);
            match version {
                4 => eval_ipv4_hdr(&ctx, &boundaries, 0),
                6 => eval_ipv6_hdr(&ctx, &boundaries, 0),
                _ => Ok(xdp_action::XDP_PASS),
            }
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
