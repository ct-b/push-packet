use std::{
    alloc::{Layout, alloc, dealloc, handle_alloc_error},
    ptr::NonNull,
    sync::Arc,
};

use aya::maps::{MapData, XskMap};
use crossbeam_queue::ArrayQueue;
use push_packet_common::RouteArgs;
use xdpilone::{IfInfo, Socket, SocketConfig, Umem, UmemConfig};

use crate::{Error, Loader, cast, channels::route, ebpf::map_owned, error::ErrnoExt};

const XSK_MAP_NAME: &str = "XSK_MAP";

struct PacketBuffer(NonNull<u8>, Layout);

impl PacketBuffer {
    fn new(size: usize) -> Result<Self, Error> {
        let layout = Layout::from_size_align(size, 4096)
            .map_err(|_| Error::InvalidSize("buffer size invalid"))?;
        // Safety: layout is non-zero
        let ptr = unsafe { alloc(layout) };
        let ptr = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));
        Ok(Self(ptr, layout))
    }

    fn as_slice(&self) -> NonNull<[u8]> {
        NonNull::slice_from_raw_parts(self.0, self.1.size())
    }
}

impl Drop for PacketBuffer {
    fn drop(&mut self) {
        // Safety: ptr returned from alloc with this layout and hasn't been freed.
        unsafe { dealloc(self.0.as_ptr(), self.1) }
    }
}
pub(crate) struct OwnedUmem {
    // Held for drop
    #[allow(dead_code)]
    umem: Umem,
    buffer: Box<PacketBuffer>,
}

impl OwnedUmem {
    pub(crate) fn read<T: Copy>(&self, address: usize) -> T {
        // Safety: Address is kernel managed, guaranteed in bounds and not used for writes.
        #[allow(clippy::as_conversions)]
        let ptr = unsafe { self.buffer.0.as_ptr().add(address) as *const T };
        // Safety: Address is kernel managed, guaranteed not currently used for writes.
        unsafe { ptr.read() }
    }
    pub(crate) fn data(&self, address: u64, len: u32) -> &[u8] {
        // Safety: Address is kernel managed, guaranteed in bounds and not used for writes.
        let ptr = unsafe {
            self.buffer
                .0
                .as_ptr()
                .add(cast::umem_offset_to_usize(address))
        };
        // Safety: Address is kernel managed, guaranteed not currently used for writes.
        unsafe { core::slice::from_raw_parts(ptr, cast::packet_len_to_usize(len)) }
    }

    pub(crate) unsafe fn write_at(&self, address: usize, bytes: &[u8]) {
        // Safety: Address is from free list, guaranteed to be in bounds and available for writes.
        let ptr = unsafe { self.buffer.0.as_ptr().add(address) };
        // Safety: Address is from free list, guaranteed to be in bounds and available for writes.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len()) };
    }
}

// Safety: OwnedUmem owns the Umem and PacketBuffer, no other references
unsafe impl Send for OwnedUmem {}
// Safety: Frames are managed via free_list, write_at can never hit the same address at once.
unsafe impl Sync for OwnedUmem {}

pub struct AfXdpSocketLoader {
    umem_config: UmemConfig,
    socket_config: SocketConfig,
    frame_count: u32,
    interface_index: u32,
    queue_id: u32,
}

impl AfXdpSocketLoader {
    pub fn new(
        umem_config: UmemConfig,
        socket_config: SocketConfig,
        frame_count: u32,
        interface_index: u32,
        queue_id: u32,
    ) -> Self {
        Self {
            umem_config,
            socket_config,
            frame_count,
            interface_index,
            queue_id,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        let headroom = cast::xsk_config_usize(self.umem_config.headroom);
        if headroom < core::mem::size_of::<RouteArgs>() {
            return Err(Error::InvalidSize("increase headroom to fit RouteArgs"));
        }
        if self.frame_count == 0 {
            return Err(Error::InvalidSize("frame_count must be greater than zero"));
        }
        if self.umem_config.fill_size > self.frame_count {
            return Err(Error::InvalidSize("fill_size must be <= frame_count"));
        }
        Ok(())
    }
}

impl Loader for AfXdpSocketLoader {
    type Component = AfXdpSocket;

    fn configure(&self, ebpf_loader: &mut aya::EbpfLoader) -> Result<(), Error> {
        // Set to queue_id + 1 to allow a 1-1 NIC queue_id -> map index relationship
        ebpf_loader.set_max_entries(XSK_MAP_NAME, self.queue_id + 1);
        Ok(())
    }
    fn load(self, ebpf: &mut aya::Ebpf) -> Result<Self::Component, crate::Error> {
        self.validate()?;
        let frame_size = self.umem_config.frame_size;
        let fill_size = self.umem_config.fill_size;
        let buffer_size = cast::xsk_config_usize(self.umem_config.frame_size)
            * cast::xsk_config_usize(self.frame_count);
        let buffer = Box::new(PacketBuffer::new(buffer_size)?);
        // Safety: Properly page-aligned to 4096 bytes, buffer outlives umem in OwnedUmem
        let umem = unsafe {
            Umem::new(self.umem_config, buffer.as_slice()).xsk_error("couldn't create umem")?
        };

        let mut info = IfInfo::invalid();
        info.from_ifindex(self.interface_index)
            .xsk_error("couldn't get IfInfo from ifindex")?;
        info.set_queue(self.queue_id);

        let sock = Socket::with_shared(&info, &umem)
            .xsk_error("couldn't create socket with shared umem")?;

        let device = umem
            .fq_cq(&sock)
            .xsk_error("couldn't create fill and completion queues")?;
        let (mut fill_queue, completion_queue) = device.into_parts();

        // Prefill the fill queue;
        {
            let mut wf = fill_queue.fill(fill_size);
            let iter = (0..fill_size).map(|i| u64::from(i) * u64::from(frame_size));
            wf.insert(iter);
            wf.commit();
        }
        // Set remaining frames as free
        let free_list = Arc::new(ArrayQueue::new(cast::xsk_config_usize(self.frame_count)));
        (fill_size..self.frame_count)
            .map(|i| u64::from(i) * u64::from(frame_size))
            .for_each(|addr| {
                free_list
                    .push(addr)
                    .expect("frames cannot exceed frame_count, must fit");
            });

        let rx_tx = umem
            .rx_tx(&sock, &self.socket_config)
            .xsk_error("couldn't create rx and tx rings")?;
        let rx = rx_tx.map_rx().xsk_error("couldn't map rx ring")?;
        let tx = rx_tx.map_tx().xsk_error("couldn't map tx ring")?;
        umem.bind(&rx_tx).xsk_error("couldn't bind umem")?;

        let umem = OwnedUmem { umem, buffer };
        let umem = Arc::new(umem);
        let sender = route::Sender::new(tx, completion_queue, umem.clone(), free_list.clone());
        let receiver = route::Receiver::new(rx, fill_queue, umem.clone(), free_list);

        let mut xsk_map: XskMap<MapData> = map_owned(ebpf, XSK_MAP_NAME)?;
        xsk_map
            .set(self.queue_id, sock.as_raw_fd(), 0)
            .map_err(|e| Error::map(XSK_MAP_NAME, e))?;

        Ok(AfXdpSocket {
            channel: Some((sender, receiver)),
            xsk_map,
            umem,
        })
    }
}

pub struct AfXdpSocket {
    pub(crate) channel: Option<(route::Sender, route::Receiver)>,
    // Held for drop
    #[allow(dead_code)]
    xsk_map: XskMap<MapData>,
    // Held for drop
    #[allow(dead_code)]
    umem: Arc<OwnedUmem>,
}
