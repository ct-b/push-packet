use std::{
    alloc::{Layout, alloc, dealloc},
    ptr::NonNull,
    sync::Arc,
};

use aya::maps::{MapData, XskMap};
use crossbeam_queue::ArrayQueue;
use push_packet_common::RouteArgs;
use xdpilone::{IfInfo, Socket, SocketConfig, Umem, UmemConfig};

use crate::{Error, Loader, channels::route, ebpf::map_owned};

const XSK_MAP_NAME: &str = "XSK_MAP";

struct PacketBuffer(NonNull<u8>, Layout);

impl PacketBuffer {
    fn new(size: usize) -> Result<Self, Error> {
        let layout = Layout::from_size_align(size, 4096)
            .map_err(|_| Error::InvalidSize("buffer size invalid"))?;
        let ptr = unsafe { alloc(layout) };
        let ptr = NonNull::new(ptr).ok_or(Error::NullPointer)?;
        Ok(Self(ptr, layout))
    }

    fn as_slice(&self) -> NonNull<[u8]> {
        NonNull::slice_from_raw_parts(self.0, self.1.size())
    }
}

impl Drop for PacketBuffer {
    fn drop(&mut self) {
        unsafe { dealloc(self.0.as_ptr(), self.1) }
    }
}
pub(crate) struct OwnedUmem {
    umem: Umem,
    buffer: Box<PacketBuffer>,
}

impl OwnedUmem {
    pub(crate) fn read<T: Copy>(&self, address: usize) -> T {
        let ptr = unsafe { self.buffer.0.as_ptr().add(address) as *const T };
        unsafe { ptr.read() }
    }
    pub(crate) fn data(&self, address: u64, len: u32) -> &[u8] {
        unsafe {
            let ptr = self.buffer.0.as_ptr().add(address as usize);
            core::slice::from_raw_parts(ptr, len as usize)
        }
    }

    pub(crate) unsafe fn write_at(&self, address: usize, bytes: &[u8]) {
        let ptr = unsafe { self.buffer.0.as_ptr().add(address) };
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len()) };
    }
}

unsafe impl Send for OwnedUmem {}
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
        let headroom = self.umem_config.headroom as usize;
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
        ebpf_loader.map_max_entries(XSK_MAP_NAME, self.queue_id + 1);
        Ok(())
    }
    fn load(self, ebpf: &mut aya::Ebpf) -> Result<Self::Component, crate::Error> {
        self.validate()?;
        let frame_size = self.umem_config.frame_size;
        let fill_size = self.umem_config.fill_size;
        let buffer_size = self.umem_config.frame_size as usize * self.frame_count as usize;
        let buffer = Box::new(PacketBuffer::new(buffer_size)?);
        let umem = unsafe { Umem::new(self.umem_config, buffer.as_slice())? };

        let mut info = IfInfo::invalid();
        info.from_ifindex(self.interface_index)?;
        info.set_queue(self.queue_id);

        let sock = Socket::with_shared(&info, &umem)?;

        let device = umem.fq_cq(&sock)?;
        let (mut fill_queue, completion_queue) = device.into_parts();

        // Prefill the fill queue;
        {
            let mut wf = fill_queue.fill(fill_size);
            let iter = (0..fill_size).map(|i| i as u64 * frame_size as u64);
            wf.insert(iter);
            wf.commit();
        }
        // Set remaining frames as free
        let free_list = Arc::new(ArrayQueue::new((self.frame_count) as usize));
        (fill_size..self.frame_count)
            .map(|i| i as u64 * frame_size as u64)
            .for_each(|addr| {
                free_list
                    .push(addr)
                    .expect("frames cannot exceed frame_count, must fit")
            });

        let rx_tx = umem.rx_tx(&sock, &self.socket_config)?;
        let rx = rx_tx.map_rx()?;
        let tx = rx_tx.map_tx()?;
        umem.bind(&rx_tx)?;

        let umem = OwnedUmem { umem, buffer };
        let umem = Arc::new(umem);
        let sender = route::Sender::new(tx, completion_queue, umem.clone(), free_list.clone());
        let receiver = route::Receiver::new(rx, fill_queue, umem.clone(), free_list);

        let mut xsk_map: XskMap<MapData> = map_owned(ebpf, XSK_MAP_NAME)?;
        xsk_map.set(self.queue_id, sock.as_raw_fd(), 0)?;

        Ok(AfXdpSocket {
            channel: Some((sender, receiver)),
            xsk_map,
            umem,
        })
    }
}

pub struct AfXdpSocket {
    pub(crate) channel: Option<(route::Sender, route::Receiver)>,
    xsk_map: XskMap<MapData>,
    umem: Arc<OwnedUmem>,
}
