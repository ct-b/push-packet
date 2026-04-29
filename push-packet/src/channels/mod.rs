//! Defines channels for copying and routing packets to userspace with `BPF_RING_BUG` and `AF_XDP`

pub mod copy;

pub mod route;

mod poll;
