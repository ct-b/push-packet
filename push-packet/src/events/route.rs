//! Defines events for [`crate::rules::Action::Route`].
use std::sync::Arc;

use crossbeam_queue::ArrayQueue;
use push_packet_common::RouteArgs;

use crate::{af_xdp::OwnedUmem, cast, rules::RuleId};

/// A packet event captured with [`crate::rules::Action::Route`]. This will take a frame in the
/// `AF_AXP` socket until it is [dropped](`Drop`), so it should be consumed quickly. Calling
/// [`RouteEvent::into_owned`] returns an [`OwnedRouteEvent`], releasing the frame at the cost of a
/// copy.
pub struct RouteEvent<'a> {
    pub(crate) address: u64,
    pub(crate) len: u32,
    pub(crate) umem: &'a OwnedUmem,
    pub(crate) free_list: &'a Arc<ArrayQueue<u64>>,
}

impl Drop for RouteEvent<'_> {
    fn drop(&mut self) {
        self.free_list
            .push(self.address)
            .expect("Frame count cannot exceed free list");
    }
}

impl RouteEvent<'_> {
    /// Returns the [`RuleId`] that the packet matched on
    #[must_use]
    pub fn rule_id(&self) -> RuleId {
        RuleId(self.route_args().rule_id)
    }

    /// Returns the raw packet data
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.umem.data(self.address, self.len)
    }

    fn route_args(&self) -> RouteArgs {
        let address = cast::umem_offset_to_usize(self.address) - core::mem::size_of::<RouteArgs>();
        self.umem.read(address)
    }

    /// Converts to an [`OwnedRouteEvent`], releasing the underlying `AF_XDP` socket frame.
    #[must_use]
    pub fn into_owned(self) -> OwnedRouteEvent {
        let route_args = self.route_args();
        let data = self.data().into();
        OwnedRouteEvent { data, route_args }
    }
}
/// An owned version of [`RouteEvent`] that contains data copied from the `AF_XDP` socket frame.
pub struct OwnedRouteEvent {
    data: Box<[u8]>,
    route_args: RouteArgs,
}

impl OwnedRouteEvent {
    /// Returns the [`RuleId`] that matched for this packet.
    #[must_use]
    pub fn rule_id(&self) -> RuleId {
        RuleId(self.route_args.rule_id)
    }

    /// Returns the raw packet data
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}
