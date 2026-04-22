use aya::programs::XdpFlags;

/// Configuration for a [`crate::tap::Tap`]. This struct configures settings for Linux primitives
/// used to route data from eBPF to userspace.
#[derive(Default)]
pub struct TapConfig {
    pub(crate) ring_buf_size: Option<u32>,
    pub(crate) copy_enabled: bool,
    pub(crate) route_enabled: bool,
    pub(crate) xdp_flags: XdpFlags,
}

impl TapConfig {
    /// Applies a max size to the `BPF_RING_BUF` [`aya::maps::RingBuf`]. If unset, this defaults to
    /// 256kb.
    #[must_use]
    pub fn with_ring_buf_size(mut self, size: u32) -> Self {
        self.ring_buf_size = Some(size);
        self
    }

    /// Provision a [`aya::maps::RingBuf`] for copying data. This is set automatically if
    /// [`crate::tap::Tap::start`] is called after adding rules with
    /// [`crate::rules::Action::Copy`].
    #[must_use]
    pub fn with_copy(mut self) -> Self {
        self.copy_enabled = true;
        self
    }

    /// Provision an `AF_XDP` socket for routing data. This is set automatically if
    /// [`crate::tap::Tap::start`] is called after adding rules with
    /// [`crate::rules::Action::Route`]
    #[must_use]
    pub fn with_route(mut self) -> Self {
        self.route_enabled = true;
        self
    }

    /// Set custom [`XdpFlags`].
    #[must_use]
    pub fn with_xdp_flags(mut self, xdp_flags: XdpFlags) -> Self {
        self.xdp_flags = xdp_flags;
        self
    }
}
