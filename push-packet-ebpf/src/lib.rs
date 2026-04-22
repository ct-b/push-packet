#![no_std]
#![allow(clippy::result_unit_err)]
#![allow(clippy::len_without_is_empty)]

pub mod context_ext;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::generated::bpf_xdp_load_bytes,
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::XdpContext,
};
use push_packet_common::CopyArgs;

const ARGS_LEN: usize = core::mem::size_of::<CopyArgs>();
const DEFAULT_RING_BUF_SIZE: u32 = 262144;

// Input parameters for the copy program
#[map]
pub static COPY_ARGS: PerCpuArray<CopyArgs> = PerCpuArray::with_max_entries(1, 0);

// Ring buf for copying packets to userspace
#[map]
static PP_RING_BUF: RingBuf = RingBuf::with_byte_size(DEFAULT_RING_BUF_SIZE, 0);

pub trait CopyArgsExt
where
    Self: Sized,
{
    fn set(take: u32, rule_id: u32, packet_len: u32) -> Result<(), ()>;
    fn get() -> Result<Self, ()>;
}

impl CopyArgsExt for CopyArgs {
    #[inline(always)]
    fn set(take: u32, rule_id: u32, packet_len: u32) -> Result<(), ()> {
        let ptr = COPY_ARGS.get_ptr_mut(0).ok_or(())?;
        unsafe {
            *ptr = CopyArgs {
                take,
                rule_id,
                packet_len,
            }
        };
        Ok(())
    }

    #[inline(always)]
    fn get() -> Result<Self, ()> {
        COPY_ARGS.get(0).ok_or(()).copied()
    }
}

// Find the power of 2 >= n
#[inline(always)]
fn power_of_2_bucket(n: usize) -> usize {
    let leading_zeroes = (n - 1).leading_zeros();
    let bits_to_shift = usize::BITS - leading_zeroes;
    1 << bits_to_shift
}

macro_rules! reserve_and_copy {
    ($bucket_size:literal, $copy_args:ident, $packet_len:ident, $ctx:ident) => {{
        let mut res = PP_RING_BUF.reserve_bytes($bucket_size, 0).ok_or(())?;
        let args = res.as_mut_ptr() as *mut CopyArgs;
        unsafe { *args = $copy_args };
        const MAX_PAYLOAD: usize = $bucket_size - ARGS_LEN;
        let len = if $packet_len > MAX_PAYLOAD {
            MAX_PAYLOAD
        } else {
            $packet_len
        };
        if len == 0 {
            res.discard(0);
            return Ok(xdp_action::XDP_PASS);
        }
        let ret = unsafe {
            bpf_xdp_load_bytes(
                $ctx.ctx as *mut _,
                0,
                res.as_mut_ptr().add(ARGS_LEN) as *mut _,
                len as u32,
            )
        };
        if ret < 0 {
            res.discard(0);
        } else {
            res.submit(0);
        }
        Ok(xdp_action::XDP_PASS)
    }};
}

#[inline(always)]
pub fn try_copy_packet(ctx: XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let len = data_end - data;
    let copy_args = CopyArgs::get()?;
    let take = copy_args.take as usize;
    let packet_len = if take > 0 && take < len { take } else { len };
    let bucket_len = ARGS_LEN + packet_len;
    match power_of_2_bucket(bucket_len) {
        0..=64 => reserve_and_copy!(64, copy_args, packet_len, ctx),
        128 => reserve_and_copy!(128, copy_args, packet_len, ctx),
        256 => reserve_and_copy!(256, copy_args, packet_len, ctx),
        512 => reserve_and_copy!(512, copy_args, packet_len, ctx),
        1024 => reserve_and_copy!(1024, copy_args, packet_len, ctx),
        2048 => reserve_and_copy!(2048, copy_args, packet_len, ctx),
        4096 => reserve_and_copy!(4096, copy_args, packet_len, ctx),
        8192 => reserve_and_copy!(8192, copy_args, packet_len, ctx),
        16384 => reserve_and_copy!(16384, copy_args, packet_len, ctx),
        _ => Ok(xdp_action::XDP_PASS),
    }
}
