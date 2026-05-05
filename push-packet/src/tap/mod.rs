use std::{marker::PhantomData, num::NonZeroU32};

use aya::{Ebpf, EbpfLoader, programs::XdpFlags};
use push_packet_common::{DEFAULT_RING_BUF_SIZE, FrameKind};
use xdpilone::{SocketConfig, UmemConfig};

use crate::{
    RuleError,
    channels::{self},
    ebpf::{EbpfVar, xdp_program},
    engine::{Engine, linear::LinearEngine},
    error::Error,
    filter::Filter,
    interface::Interface,
    loader::Loader,
    relay::{Relay, RelayLoader},
    rules::{Action, Rule, RuleId},
};

const FRAME_KIND_MAP: &str = "FRAME_KIND_MAP";

/// Optional configuration for copying packets.
///
/// This [`Default`]s to the following:
/// - `ring_buf_size`: 256kb
/// - `force_enabled`: false
pub struct CopyConfig {
    pub(crate) ring_buf_size: u32,
    pub(crate) force_enabled: bool,
}

impl Default for CopyConfig {
    fn default() -> Self {
        Self {
            ring_buf_size: DEFAULT_RING_BUF_SIZE,
            force_enabled: false,
        }
    }
}

impl CopyConfig {
    /// Force the [`Tap`] to provision copy primitives, even if no rules use copy. Set this if you
    /// want to dynamically add a rule with [`Action::Copy`] later.
    #[must_use]
    pub fn force_enabled(mut self) -> Self {
        self.force_enabled = true;
        self
    }

    /// Override the default ring buffer size.
    #[must_use]
    pub fn ring_buf_size(mut self, ring_buf_size: u32) -> Self {
        self.ring_buf_size = ring_buf_size;
        self
    }
}

/// Optional configuration for routing packets.
///
/// Presently, `AF_XDP` routing is configured with a shared UMEM region, with a queue serving as a
/// free list to coordinate available frames.
///
/// This [`Default`]s to the following:
/// - `force_enabled`: false
/// - `umem_config.fill_size`: 2048 frames
/// - `umem_config.complete_size`: 2048 frames
/// - `umem_config.frame_size`: 4096 bytes
/// - `umem_config.headroom`: 32 bytes
/// - `umem_config.flags`: 0
/// - `socket_config.rx_size`: 2048 frames
/// - `socket_config.tx_size`: 2048 frames
/// - `socket_config.bind_flags`: `SocketConfig::XDP_BIND_NEED_WAKEUP`
/// - `frame_count`: 8192
/// - `queue_id`: 0
pub struct RouteConfig {
    pub(crate) force_enabled: bool,
    pub(crate) umem_config: UmemConfig,
    pub(crate) socket_config: SocketConfig,
    pub(crate) frame_count: u32,
    pub(crate) queue_id: u32,
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            force_enabled: false,
            umem_config: UmemConfig {
                fill_size: 2048,
                complete_size: 2048,
                frame_size: 4096,
                headroom: 32,
                flags: 0,
            },
            socket_config: SocketConfig {
                rx_size: NonZeroU32::new(2048),
                tx_size: NonZeroU32::new(2048),
                bind_flags: SocketConfig::XDP_BIND_NEED_WAKEUP,
            },
            frame_count: 8192,
            queue_id: 0,
        }
    }
}

impl RouteConfig {
    /// Force the [`Tap`] to provision route primitives, even if no rules use route. Set this if you
    /// want to dynamically add a rule with [`Action::Route`] later.
    #[must_use]
    pub fn force_enabled(mut self) -> Self {
        self.force_enabled = true;
        self
    }

    /// Overrides the default [`UmemConfig`] for the `AF_XDP` socket.
    #[must_use]
    pub fn umem_config(mut self, umem_config: UmemConfig) -> Self {
        self.umem_config = umem_config;
        self
    }

    /// Overrides the default [`SocketConfig`] for the `AF_XDP` socket.
    #[must_use]
    pub fn socket_config(mut self, socket_config: SocketConfig) -> Self {
        self.socket_config = socket_config;
        self
    }
    /// Sets the `frame_count` for the `AF_XDP` socket. Combined with the [`UmemConfig`] settings,
    /// this will determine the total size of the Umem region.
    #[must_use]
    pub fn frame_count(mut self, frame_count: u32) -> Self {
        self.frame_count = frame_count;
        self
    }

    /// Sets the `queue_id` for the `AF_XDP` socket.
    ///
    /// # Note
    /// The `queue_id` is likely not going to contain all of the traffic you expect unless you
    /// specifially route traffic to that queue id, for example, using `ethtool`.
    /// <https://www.kernel.org/doc/html/latest/networking/af_xdp.html#faq>
    #[must_use]
    pub fn queue_id(mut self, queue_id: u32) -> Self {
        self.queue_id = queue_id;
        self
    }
}

/// Builder for a [`Tap`].
pub struct TapBuilder<E: Engine = LinearEngine> {
    interface: Result<Interface, Error>,
    xdp_flags: XdpFlags,
    copy_config: CopyConfig,
    route_config: RouteConfig,
    rules: Vec<Result<Rule, RuleError>>,
    _marker: PhantomData<E>,
}

impl<E: Engine> TapBuilder<E> {
    /// Creates a new [`TapBuilder`] from the given interface name or number.
    pub fn new<I>(interface: I) -> Self
    where
        I: TryInto<Interface>,
        I::Error: Into<Error>,
    {
        let interface = interface.try_into().map_err(Into::into);
        let copy_config = CopyConfig::default();
        let route_config = RouteConfig::default();
        let xdp_flags = XdpFlags::default();
        let rules = vec![];
        let _marker = PhantomData;

        Self {
            interface,
            xdp_flags,
            copy_config,
            route_config,
            rules,
            #[allow(clippy::used_underscore_binding)]
            _marker,
        }
    }

    /// Set the [`XdpFlags`].
    #[must_use]
    pub fn xdp_flags(mut self, xdp_flags: XdpFlags) -> Self {
        self.xdp_flags = xdp_flags;
        self
    }

    /// Set the [`CopyConfig`].
    #[must_use]
    pub fn copy_config(mut self, copy_config: CopyConfig) -> Self {
        self.copy_config = copy_config;
        self
    }

    /// Set the [`RouteConfig`].
    #[must_use]
    pub fn route_config(mut self, route_config: RouteConfig) -> Self {
        self.route_config = route_config;
        self
    }

    /// Chain a rule in a builder pattern.
    #[must_use]
    pub fn rule<R>(mut self, rule: R) -> Self
    where
        R: TryInto<Rule, Error = RuleError>,
    {
        let rule = rule.try_into();
        self.rules.push(rule);
        self
    }

    /// Builds the [`Tap`].
    ///
    /// # Errors
    /// Returns [`Error::BuilderRule`] if a rule builder fails to build.
    /// Returns [`Error::InvalidInterfaceName`] or [`Error::InvalidInterfaceIndex`] if the interface
    /// provided is invalid.
    /// Returns [`Error::InvalidFrameKind`] if the interface does not use Eth or IP frames.
    /// May return additional [`Error`]s if the eBPF programs fail to load or attach.
    pub fn build(self) -> Result<Tap<E>, Error> {
        let Self {
            interface,
            xdp_flags,
            copy_config,
            route_config,
            rules,
            ..
        } = self;
        let interface = interface?;
        let frame_kind = interface.frame_kind()?;

        let mut filter = Filter::default();
        for (i, rule) in rules.into_iter().enumerate() {
            let rule = rule.map_err(|e| Error::BuilderRule {
                index: i,
                source: e,
            })?;
            filter.add(rule);
        }

        let engine_loader = E::Loader::default();
        let mut ebpf_loader = EbpfLoader::new();

        let relay_loader = RelayLoader::new(copy_config, route_config, &filter, &interface);
        relay_loader.configure(&mut ebpf_loader)?;
        engine_loader.configure(&mut ebpf_loader)?;

        let mut ebpf = ebpf_loader.load(E::EBPF_BYTES).map_err(Error::LoadEbpf)?;
        let mut engine = engine_loader.load(&mut ebpf)?;
        let frame_kind = (frame_kind, FRAME_KIND_MAP).load(&mut ebpf)?;
        let relay = relay_loader.load(&mut ebpf)?;

        for (rule_id, rule) in filter.iter_rules() {
            engine.add_rule(rule_id, rule)?;
        }

        let program = xdp_program(&mut ebpf, E::EBPF_PROGRAM_NAME)?;
        program
            .attach(interface.name(), xdp_flags)
            .map_err(|e| Error::attach_program(E::EBPF_PROGRAM_NAME, e))?;

        Ok(Tap {
            interface,
            engine,
            filter,
            ebpf,
            frame_kind,
            relay,
        })
    }
}

/// Taps into a network interface. This struct stores all eBPF primitives required for the specific
/// combination of [`Action`]s and the [`Engine`]. It defaults to using a [`LinearEngine`].
pub struct Tap<E: Engine = LinearEngine> {
    interface: Interface,
    engine: E,
    filter: Filter,
    #[allow(unused)]
    ebpf: Ebpf,
    frame_kind: EbpfVar<FrameKind>,
    relay: Relay,
}

impl Tap {
    /// Creates a new [`TapBuilder`] with the specified [`Interface`].
    pub fn builder<I>(interface: I) -> TapBuilder
    where
        I: TryInto<Interface>,
        I::Error: Into<Error>,
    {
        TapBuilder::new(interface)
    }
}

impl<E: Engine> Tap<E> {
    /// Returns the [`FrameKind`] for the selected interface
    pub fn frame_kind(&self) -> FrameKind {
        self.frame_kind.get().to_owned()
    }

    /// Returns a tuple of [`channels::route::Sender`] and [`channels::route::Receiver`].
    ///
    /// # Errors
    /// Returns [`Error::RouteNotEnabled`] if routing is not enabled.
    /// Returns [`Error::ChannelNotAvailable`] if the channel has already been taken.
    pub fn route_channel(
        &mut self,
    ) -> Result<(channels::route::Sender, channels::route::Receiver), Error> {
        if !self.relay.route_enabled {
            return Err(Error::RouteNotEnabled);
        }

        self.relay
            .af_xdp_socket
            .as_mut()
            .and_then(|c| c.channel.take())
            .ok_or(Error::ChannelNotAvailable)
    }

    /// Returns a [`channels::copy::Receiver`] for receiving data.
    ///
    /// # Errors
    /// Returns [`Error::CopyNotEnabled`] if copying is not enabled..
    /// Returns [`Error::ChannelNotAvailable`] if the channel has already been taken.
    pub fn copy_receiver(&mut self) -> Result<channels::copy::Receiver, Error> {
        if !self.relay.copy_enabled {
            return Err(Error::CopyNotEnabled);
        }
        self.relay
            .copy_receiver
            .take()
            .ok_or(Error::ChannelNotAvailable)
    }

    /// Add a [`Rule`] or [`RuleBuilder`](crate::rules::RuleBuilder).
    ///
    /// # Errors
    /// Returns [`Error::CopyNotEnabled`] or [`Error::RouteNotEnabled`] if the [`Tap`] hasn't
    /// provisioned the required primitives.
    /// Returns an [`Error`] if the engine cannot add the rule.
    pub fn add_rule<R>(&mut self, rule: R) -> Result<RuleId, Error>
    where
        R: TryInto<Rule>,
        R::Error: Into<Error>,
    {
        let rule = rule.try_into().map_err(Into::into)?;
        let rule_id = self.filter.next_rule_id();
        match rule.action {
            Action::Copy { .. } if !self.relay.copy_enabled => {
                return Err(Error::CopyNotEnabled);
            }
            Action::Route if !self.relay.route_enabled => {
                return Err(Error::RouteNotEnabled);
            }
            _ => {}
        }
        self.engine.add_rule(rule_id, &rule)?;
        self.filter.add(rule);
        Ok(rule_id)
    }

    /// Remove a [`Rule`] by its [`RuleId`].
    ///
    /// # Errors
    /// Returns [`Error::MissingRule`] if the [`RuleId`] is invalid.
    /// Returns an error if the [`Engine`] cannot remove the rule.
    pub fn remove_rule(&mut self, rule_id: RuleId) -> Result<Rule, Error> {
        let rule = self
            .filter
            .get(rule_id)
            .ok_or(Error::MissingRule(rule_id))?;
        self.engine.remove_rule(rule_id, rule)?;
        self.filter
            .remove(rule_id)
            .ok_or(Error::MissingRule(rule_id))
    }

    /// Access the [`Interface`]
    pub fn interface(&self) -> &Interface {
        &self.interface
    }
}
