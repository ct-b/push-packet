#![no_std]

pub mod context_ext;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::generated::bpf_xdp_load_bytes,
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::XdpContext,
};

const ARGS_LEN: usize = core::mem::size_of::<CopyArgs>();
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CopyArgs {
    take: u32,
    rule_id: u32,
}

impl CopyArgs {
    #[inline(always)]
    pub fn set(take: u32, rule_id: u32) -> Result<(), ()> {
        let ptr = COPY_ARGS.get_ptr_mut(0).ok_or(())?;
        unsafe { *ptr = CopyArgs { take, rule_id } };
        Ok(())
    }

    #[inline(always)]
    pub fn get() -> Result<Self, ()> {
        COPY_ARGS.get(0).ok_or(()).map(|&s| s)
    }
}

#[map]
pub static COPY_ARGS: PerCpuArray<CopyArgs> = PerCpuArray::pinned(1, 0);

// Find the power of 2 >= n
#[inline(always)]
fn power_of_2_bucket(n: usize) -> usize {
    let leading_zeroes = (n - 1).leading_zeros();
    let bits_to_shift = usize::BITS - leading_zeroes;
    1 << bits_to_shift
}

#[map]
static PP_RING_BUF: RingBuf = RingBuf::with_byte_size(262144, 0);

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
        0..=8000 => {
            let mut res = PP_RING_BUF.reserve_bytes(8192, 0).ok_or(())?;
            let args = res.as_mut_ptr() as *mut CopyArgs;
            unsafe { *args = copy_args };
            const MAX_PAYLOAD: usize = 8192 - ARGS_LEN;
            let len = if packet_len > MAX_PAYLOAD {
                MAX_PAYLOAD
            } else {
                packet_len
            };
            if len == 0 {
                res.discard(0);
                return Ok(xdp_action::XDP_PASS);
            }
            let ret = unsafe {
                bpf_xdp_load_bytes(
                    ctx.ctx as *mut _,
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
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}
