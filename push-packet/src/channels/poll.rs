use std::os::fd::BorrowedFd;

use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, PollTimeout},
};

use crate::Error;

pub(crate) fn poll_fd(fd: BorrowedFd<'_>, flags: PollFlags) -> Result<(), Error> {
    let mut poll_fd = [PollFd::new(fd, flags)];
    loop {
        match nix::poll::poll(&mut poll_fd, PollTimeout::NONE) {
            Ok(_) => {
                let revents = poll_fd[0].revents().unwrap_or(PollFlags::empty());
                if revents.intersects(PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL)
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
