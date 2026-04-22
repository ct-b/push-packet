//! Module containing the implmentation for a copy [`Receiver`].
use std::os::fd::AsFd;

use aya::maps::{MapData, RingBuf};
use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, PollTimeout, poll},
};

use crate::{error::Error, events::CopyEvent};

/// A receiver that receives [`CopyEvent`]s from the underlying [`RingBuf`]. Note that
/// [`CopyEvent`]s hold a reference to the underlying [`RingBuf`] and must be dropped to restore
/// capacity.
pub struct Receiver {
    pub(crate) ring_buf: RingBuf<MapData>,
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

    fn poll(&self) -> Result<(), Error> {
        let mut poll_fd = [PollFd::new(self.ring_buf.as_fd(), PollFlags::POLLIN)];
        loop {
            match poll(&mut poll_fd, PollTimeout::NONE) {
                Ok(_) => {
                    let revents = poll_fd[0].revents().unwrap_or(PollFlags::empty());
                    if revents
                        .intersects(PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL)
                    {
                        return Err(Error::ChannelDisconnected);
                    }
                    if revents.contains(PollFlags::POLLIN) {
                        return Ok(());
                    }
                }
                Err(Errno::EINTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
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
            // I don't think there is an alternative to this unsafe call
            if let Some(item) = unsafe { (*ptr).next() } {
                return Ok(item.into());
            }
            self.poll()?;
        }
    }
}
