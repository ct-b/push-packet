//! Communication primitives for routing packets to userspace

use std::{collections::VecDeque, os::fd::BorrowedFd, sync::Arc};

use crossbeam_queue::ArrayQueue;
use nix::poll::PollFlags;
use xdpilone::{CompletionQueue, FillQueue, RingRx, RingTx, xdp::XdpDesc};

use crate::{Error, af_xdp::OwnedUmem, events::route::RouteEvent};

const CACHE_CAPACITY: usize = 64;
const FREE_LIST_BATCH: u32 = 64;

/// Receiver for an `AF_XDP` socket.
pub struct Receiver {
    rx: RingRx,
    fill_queue: FillQueue,
    umem: Arc<OwnedUmem>,
    cache: VecDeque<XdpDesc>,
    free_list: Arc<ArrayQueue<u64>>,
}

impl Receiver {
    pub(crate) fn new(
        rx: RingRx,
        fill_queue: FillQueue,
        umem: Arc<OwnedUmem>,
        free_list: Arc<ArrayQueue<u64>>,
    ) -> Self {
        Self {
            rx,
            fill_queue,
            umem,
            cache: VecDeque::with_capacity(CACHE_CAPACITY),
            free_list,
        }
    }

    fn replenish_fill_queue(&mut self) {
        if self.free_list.len() < FREE_LIST_BATCH as usize {
            return;
        }
        {
            let mut wf = self.fill_queue.fill(FREE_LIST_BATCH);
            while let Some(addr) = self.free_list.pop() {
                if !wf.insert_once(addr) {
                    self.free_list
                        .push(addr)
                        .expect("Frame count == free list cap");
                    break;
                }
            }
            wf.commit();
        }
        if self.fill_queue.needs_wakeup() {
            self.fill_queue.wake();
        }
    }

    /// Blocks until a packet is available.
    /// This returns a [`RouteEvent`], which references the underlying memory. It should quickly be
    /// dropped or converted into an [`OwnedRouteEvent`] to avoid frame starvation.
    ///
    /// # Errors
    /// Returns [`Error::ChannelDisconnected`] if the channel is closed.
    /// Returns [`Error::NixError`] on other poll failures.
    #[allow(clippy::missing_panics_doc)]
    pub fn recv(&mut self) -> Result<RouteEvent<'_>, Error> {
        self.replenish_fill_queue();

        while self.cache.is_empty() {
            {
                let mut reader = self.rx.receive(CACHE_CAPACITY as u32);
                self.cache.extend(reader.by_ref());
                reader.release();
            }
            if self.cache.is_empty() {
                // Safety: the fd is owned by self.rx, outlives this borrow
                let fd = unsafe { BorrowedFd::borrow_raw(self.rx.as_raw_fd()) };
                crate::channels::poll::poll_fd(fd, PollFlags::POLLIN)?;
            }
        }

        let XdpDesc { addr, len, .. } = self
            .cache
            .pop_front()
            .expect("cache non-empty after loop and poll");
        Ok(RouteEvent {
            address: addr,
            len,
            umem: &self.umem,
            free_list: &self.free_list,
        })
    }
    /// Attempts to receive a packet.
    /// This returns a [`RouteEvent`], which references the underlying memory. It should quickly be
    /// dropped or converted into an [`OwnedRouteEvent`] to avoid frame starvation.
    ///
    /// # Errors
    /// Returns [`Error::ChannelDisconnected`] if the channel is closed.
    /// Returns [`Error::NixError`] on other poll failures.
    /// Returns [`Error::WouldBlock`] if the operation would block.
    pub fn try_recv(&mut self) -> Result<RouteEvent<'_>, Error> {
        self.replenish_fill_queue();
        if self.cache.is_empty() {
            let mut reader = self.rx.receive(CACHE_CAPACITY as u32);
            self.cache.extend(reader.by_ref());
            reader.release();
        }
        let XdpDesc { addr, len, .. } = self.cache.pop_front().ok_or(Error::WouldBlock)?;

        Ok(RouteEvent {
            len,
            address: addr,
            umem: &self.umem,
            free_list: &self.free_list,
        })
    }
}

/// Sender for an `AF_XDP` socket
pub struct Sender {
    tx: RingTx,
    completion_queue: CompletionQueue,
    umem: Arc<OwnedUmem>,
    free_list: Arc<ArrayQueue<u64>>,
}

impl Sender {
    pub(crate) fn new(
        tx: RingTx,
        completion_queue: CompletionQueue,
        umem: Arc<OwnedUmem>,
        free_list: Arc<ArrayQueue<u64>>,
    ) -> Self {
        Self {
            tx,
            completion_queue,
            umem,
            free_list,
        }
    }

    fn drain_completion_queue(&mut self) {
        let mut rc = self.completion_queue.complete(FREE_LIST_BATCH);
        if rc.capacity() < FREE_LIST_BATCH {
            return;
        }
        while let Some(addr) = rc.read() {
            self.free_list.push(addr).expect("free list = frame count");
        }
        rc.release();
    }

    /// Attempts to send a packet.
    ///
    /// # Errors
    /// Returns [`Error::ChannelDisconnected`] if the channel is closed.
    /// Returns [`Error::NixError`] for poll errors.
    #[allow(clippy::missing_panics_doc)]
    pub fn try_send(&mut self, data: impl AsRef<[u8]>) -> Result<(), Error> {
        self.drain_completion_queue();
        let bytes = data.as_ref();
        let address = self.free_list.pop().ok_or(Error::WouldBlock)?;
        // Safety: The address is from free_list, not accessible to the kernel.
        unsafe {
            self.umem.write_at(address as usize, bytes);
        }
        {
            let mut wt = self.tx.transmit(1);
            if !wt.insert_once(XdpDesc {
                addr: address,
                len: bytes.len() as u32,
                options: 0,
            }) {
                self.free_list
                    .push(address)
                    .expect("free list cap = frame count");
                return Err(Error::WouldBlock);
            }
            wt.commit();
        }
        if self.tx.needs_wakeup() {
            self.tx.wake();
        }
        Ok(())
    }

    /// Blocks until the packet is sent.
    ///
    /// # Errors
    /// Returns [`Error::ChannelDisconnected`] if the channel is closed.
    /// Returns [`Error::NixError`] for poll errors.
    pub fn send(&mut self, data: impl AsRef<[u8]>) -> Result<(), Error> {
        let bytes = data.as_ref();

        let address = loop {
            self.drain_completion_queue();
            if let Some(address) = self.free_list.pop() {
                break address;
            }
            // Safety: the fd is owned by self.tx, outlives this borrow
            let fd = unsafe { BorrowedFd::borrow_raw(self.tx.as_raw_fd()) };

            crate::channels::poll::poll_fd(fd, PollFlags::POLLIN | PollFlags::POLLOUT)?;
        };

        // Safety: The address came from free_list, and not accessible to the kernel
        unsafe {
            self.umem.write_at(address as usize, bytes);
        }

        loop {
            let mut wt = self.tx.transmit(1);
            if wt.insert_once(XdpDesc {
                addr: address,
                len: bytes.len() as u32,
                options: 0,
            }) {
                wt.commit();
                break;
            }
            drop(wt);
            // Safety: the fd is owned by self.tx, outlives this borrow
            let fd = unsafe { BorrowedFd::borrow_raw(self.tx.as_raw_fd()) };
            crate::channels::poll::poll_fd(fd, PollFlags::POLLIN | PollFlags::POLLOUT)?;
        }

        if self.tx.needs_wakeup() {
            self.tx.wake();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::channels::route::{Receiver, Sender};

    fn assert_send<T: Send>() {}

    #[test]
    fn sender_is_send() {
        assert_send::<Sender>();
    }

    #[test]
    fn receiver_is_send() {
        assert_send::<Receiver>();
    }
}
