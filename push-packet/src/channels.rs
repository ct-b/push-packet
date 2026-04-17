use std::os::fd::{AsRawFd, BorrowedFd};

use aya::maps::{MapData, RingBuf};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

use crate::events::CopyEvent;

pub struct CopyRx {
    pub(crate) ring_buf: RingBuf<MapData>,
}

impl CopyRx {
    pub fn try_recv(&mut self) -> Option<CopyEvent<'_>> {
        self.ring_buf.next().map(|i| i.into())
    }

    pub fn recv(&mut self) -> Option<CopyEvent<'_>> {
        let raw_fd = self.ring_buf.as_raw_fd();
        let ptr = &mut self.ring_buf as *mut RingBuf<MapData>;
        loop {
            if let Some(item) = unsafe { &mut *ptr }.next() {
                return Some(item.into());
            }
            let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
            let mut poll_fd = [PollFd::new(fd, PollFlags::POLLIN)];
            let _ = poll(&mut poll_fd, PollTimeout::NONE);
        }
    }
}
