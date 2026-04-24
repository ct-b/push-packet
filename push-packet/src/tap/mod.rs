use aya::{Ebpf, EbpfLoader, programs::XdpFlags};
use push_packet_common::FrameKind;

use crate::{
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
#[derive(Default)]
pub struct CopyConfig {
    pub(crate) ring_buf_size: Option<u32>,
    pub(crate) force_enabled: bool,
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
        self.ring_buf_size = Some(ring_buf_size);
        self
    }
}

/// Optional configuration for routing packets.
#[derive(Default)]
pub struct RouteConfig {
    pub(crate) force_enabled: bool,
}

impl RouteConfig {
    /// Force the [`Tap`] to provision route primitives, even if no rules use route. Set this if you
    /// want to dynamically add a rule with [`Action::Route`] later.
    #[must_use]
    pub fn force_enabled(mut self) -> Self {
        self.force_enabled = true;
        self
    }
}

/// Builder for a [`Tap`].
pub struct TapBuilder<E: Engine = LinearEngine> {
    interface: Interface,
    frame_kind: FrameKind,
    engine_loader: E::Loader,
    filter: Filter,
    xdp_flags: XdpFlags,
    copy_config: CopyConfig,
    route_config: RouteConfig,
}

impl<E: Engine> TapBuilder<E> {
    /// Creates a new [`TapBuilder`] from the given interface name or number.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the [`Interface`] is invalid, or uses an unsupported [`FrameKind`].
    pub fn new<I>(interface: I) -> Result<Self, Error>
    where
        I: TryInto<Interface>,
        I::Error: Into<Error>,
    {
        let interface = interface.try_into().map_err(Into::into)?;
        let frame_kind = interface.frame_kind()?;
        let engine_loader = E::Loader::default();
        let filter = Filter::default();
        let copy_config = CopyConfig::default();
        let route_config = RouteConfig::default();
        let xdp_flags = XdpFlags::default();

        Ok(Self {
            interface,
            frame_kind,
            engine_loader,
            filter,
            xdp_flags,
            copy_config,
            route_config,
        })
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
    ///
    /// # Errors
    /// Returns an [`Error`] if a provided [`crate::rules::RuleBuilder`] fails to build.
    pub fn rule<R>(mut self, rule: R) -> Result<Self, Error>
    where
        R: TryInto<Rule>,
        R::Error: Into<Error>,
    {
        let rule = rule.try_into().map_err(Into::into)?;
        self.filter.add(rule);
        Ok(self)
    }

    /// Builds the [`Tap`].
    ///
    /// # Errors
    /// Returns an [`Error`] if any subcomponents fail to load or attach
    pub fn build(self) -> Result<Tap<E>, Error> {
        let Self {
            interface,
            frame_kind,
            engine_loader,
            filter,
            xdp_flags,
            copy_config,
            route_config,
        } = self;
        let mut ebpf_loader = EbpfLoader::new();

        let relay_loader = RelayLoader::new(&copy_config, &route_config, &filter);
        relay_loader.configure(&mut ebpf_loader)?;
        engine_loader.configure(&mut ebpf_loader)?;

        let mut ebpf = ebpf_loader.load(E::EBPF_BYTES)?;
        let mut engine = engine_loader.load(&mut ebpf)?;
        let frame_kind = (frame_kind, FRAME_KIND_MAP).load(&mut ebpf)?;
        let relay = relay_loader.load(&mut ebpf)?;

        for (rule_id, rule) in filter.iter_rules() {
            engine.add_rule(rule_id, rule)?;
        }

        let program = xdp_program(&mut ebpf, E::EBPF_PROGRAM_NAME)?;
        program.attach(interface.name(), xdp_flags)?;

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
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInterfaceName`] or [`Error::InvalidInterfaceIndex`] if the interface
    /// is invalid.
    pub fn builder<I>(interface: I) -> Result<TapBuilder, Error>
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

    /// Returns a [`channels::copy::Receiver`] for receiving data.
    ///
    /// # Errors
    /// Returns [`Error::MissingRingBuf`] if the [`aya::maps::RingBuf`] does not exist.
    pub fn copy_receiver(&mut self) -> Result<channels::copy::Receiver, Error> {
        self.relay.copy_receiver.take().ok_or(Error::MissingRingBuf)
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
    /// Returns [`Error::MissingRuleId`] if the [`RuleId`] is invalid.
    /// Returns an error if the [`Engine`] cannot remove the rule.
    pub fn remove_rule(&mut self, rule_id: RuleId) -> Result<Rule, Error> {
        let rule = self.filter.get(rule_id).ok_or(Error::MissingRuleId)?;
        self.engine.remove_rule(rule_id, rule)?;
        self.filter.remove(rule_id).ok_or(Error::MissingRuleId)
    }

    /// Access the [`Interface`]
    pub fn interface(&self) -> &Interface {
        &self.interface
    }
}
