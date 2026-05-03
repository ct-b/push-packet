use std::os::fd::BorrowedFd;

use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, PollTimeout},
};

use crate::channels::ChannelError;

pub(crate) fn poll_fd(fd: BorrowedFd<'_>, flags: PollFlags) -> Result<(), ChannelError> {
    let mut poll_fd = [PollFd::new(fd, flags)];
    loop {
        match nix::poll::poll(&mut poll_fd, PollTimeout::NONE) {
            Ok(_) => {
                let revents = poll_fd[0].revents().unwrap_or(PollFlags::empty());
                if revents.intersects(PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL)
                {
                    return Err(ChannelError::Disconnected);
                }
                if revents.contains(PollFlags::POLLIN) {
                    return Ok(());
                }
            }
            Err(Errno::EINTR) => {}
            Err(e) => return Err(ChannelError::Poll(e)),
        }
    }
}
