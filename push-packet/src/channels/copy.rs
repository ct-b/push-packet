//! Module containing the implmentation for a copy [`Receiver`].
use std::os::fd::{AsRawFd, BorrowedFd};

use aya::maps::{MapData, RingBuf};
use nix::poll::PollFlags;

use crate::{error::Error, events::copy::CopyEvent};

/// A receiver that receives [`CopyEvent`]s from the underlying [`RingBuf`]. Note that
/// [`CopyEvent`]s hold a reference to the underlying [`RingBuf`] and must be dropped to restore
/// capacity.
pub struct Receiver {
    pub(crate) ring_buf: RingBuf<MapData>,
}

impl From<RingBuf<MapData>> for Receiver {
    fn from(value: RingBuf<MapData>) -> Self {
        Self { ring_buf: value }
    }
}

impl Receiver {
    /// Attempts to receive a [`CopyEvent`] without blocking.
    ///
    /// # Errors
    /// Returns [`Error::NoRingBufItem`] if there is not a [`aya::maps::ring_buf::RingBufItem`]
    /// available.
    pub fn try_recv(&mut self) -> Result<CopyEvent<'_>, Error> {
        self.ring_buf
            .next()
            .map(std::convert::Into::into)
            .ok_or(Error::NoRingBufItem)
    }

    /// Blocks until a [`CopyEvent`] is available
    ///
    /// # Errors
    ///
    /// Returns [`Error::ChannelDisconnected`] if the connection is dropped.
    /// Returns [`Error::NixError`] on unexpected nix errors.
    pub fn recv(&mut self) -> Result<CopyEvent<'_>, Error> {
        let ptr = &raw mut self.ring_buf;
        loop {
            // Safety: The &mut self is held through the whole fn, this satisfies the borrow
            // checker.
            if let Some(item) = unsafe { (*ptr).next() } {
                return Ok(item.into());
            }
            // Safety: This version of aya doesn't expose as_fd(), wait for release.
            let borrowed_fd = unsafe { BorrowedFd::borrow_raw(self.ring_buf.as_raw_fd()) };
            crate::channels::poll::poll_fd(borrowed_fd, PollFlags::POLLIN)?;
        }
    }
}
