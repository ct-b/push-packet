use push_packet_common::{CopyArgs, RouteArgs};

use crate::{COPY_ARGS, ROUTE_ARGS};

pub trait RouteArgsExt
where
    Self: Sized,
{
    fn set(rule_id: u32) -> Result<(), ()>;
    fn get() -> Result<Self, ()>;
}
impl RouteArgsExt for RouteArgs {
    #[inline(always)]
    fn set(rule_id: u32) -> Result<(), ()> {
        let ptr = ROUTE_ARGS.get_ptr_mut(0).ok_or(())?;
        unsafe { *ptr = RouteArgs { rule_id } };
        Ok(())
    }

    #[inline(always)]
    fn get() -> Result<Self, ()> {
        ROUTE_ARGS.get(0).ok_or(()).copied()
    }
}

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
