use std::{
    ops::Deref,
    os::fd::{AsRawFd, BorrowedFd},
};

use aya::maps::{MapData, RingBuf, ring_buf::RingBufItem};
use nix::poll::{self, PollFd, PollFlags, PollTimeout, poll};
use push_packet_common::FrameKind;

pub struct CopyRx {
    pub(crate) ring_buf: RingBuf<MapData>,
    pub(crate) frame_kind: FrameKind,
}

impl CopyRx {
    pub fn try_recv(&mut self) -> Option<impl Deref<Target = [u8]>> {
        self.ring_buf.next()
    }

    pub fn recv<'a>(&'a mut self) -> Option<RingBufItem<'a>> {
        let raw_fd = self.ring_buf.as_raw_fd();
        let ptr = &mut self.ring_buf as *mut RingBuf<MapData>;
        loop {
            if let Some(item) = unsafe { &mut *ptr }.next() {
                return Some(item);
            }
            let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
            let mut poll_fd = [PollFd::new(fd, PollFlags::POLLIN)];
            let _ = poll(&mut poll_fd, PollTimeout::NONE);
        }
    }
}
