use aya::{
    Ebpf, EbpfLoader,
    maps::{MapData, ProgramArray, RingBuf},
};
use push_packet_common::{FrameKind, RING_BUF_NAME};

use crate::{
    channels,
    ebpf::{map_owned, set_array, xdp_program},
    engine::{Engine, linear::LinearEngine},
    error::Error,
    filter::Filter,
    interface::Interface,
    rules::{self, Action, Rule, RuleId},
};

mod config;
pub use config::TapConfig;

const FRAME_KIND_MAP: &str = "FRAME_KIND_MAP";
const COPY_PROGRAM_NAME: &str = "copy_packet";
const JUMP_TABLE_NAME: &str = "JUMP_TABLE";

/// Taps into a network interface. This struct stores all eBPF primitives required for the specific
/// combination of [`Action`]s and the [`Engine`]. It defaults to using a [`LinearEngine`].
pub struct Tap<E: Engine = LinearEngine> {
    interface: Interface,
    engine: E,
    filter: Filter,
    ebpf: Option<Ebpf>,
    copy_receiver: Option<channels::copy::Receiver>,
    frame_kind: FrameKind,
    jump_table: Option<ProgramArray<MapData>>,
    config: TapConfig,
}

impl Tap<LinearEngine> {
    /// Creates a [`Tap`] with the default [`LinearEngine`].
    ///
    /// # Errors
    /// Returns an error if the [`Interface`] is invalid, or [`FrameKind`] cannot be determined.
    pub fn new<I>(interface: I) -> Result<Self, Error>
    where
        I: TryInto<Interface>,
        I::Error: Into<Error>,
    {
        Self::with_engine(interface, LinearEngine::default())
    }
}

impl<E: Engine> Tap<E> {
    /// Creates a [`Tap`] with a specific engine.
    ///
    /// # Errors
    /// Returns an error if the [`Interface`] is invalid, or [`FrameKind`] cannot be determined.
    pub fn with_engine<I>(interface: I, engine: E) -> Result<Self, Error>
    where
        I: TryInto<Interface>,
        I::Error: Into<Error>,
    {
        let interface = interface.try_into().map_err(Into::into)?;
        let frame_kind = interface.frame_kind()?;
        let filter = Filter::default();
        Ok(Self {
            interface,
            engine,
            filter,
            ebpf: None,
            copy_receiver: None,
            frame_kind,
            jump_table: None,
            config: TapConfig::default(),
        })
    }

    /// Sets [`TapConfig`] in a builder pattern
    #[must_use]
    pub fn with_config(mut self, config: TapConfig) -> Self {
        self.config = config;
        self
    }

    /// Returns the [`FrameKind`] for the selected interface
    pub fn frame_kind(&self) -> FrameKind {
        self.frame_kind
    }

    /// Returns a [`channels::copy::Receiver`] for receiving data.
    ///
    /// # Errors
    /// Returns [`Error::MissingRingBuf`] if the [`RingBuf`] does not exist. This will happen if it
    /// is accessed before calling [`Tap::start`].
    pub fn copy_rx(&mut self) -> Result<channels::copy::Receiver, Error> {
        self.copy_receiver.take().ok_or(Error::MissingRingBuf)
    }

    fn init_copy_receiver(&mut self, ebpf: &mut Ebpf) -> Result<(), Error> {
        let ring_buf: RingBuf<MapData> = map_owned(ebpf, RING_BUF_NAME)?;
        self.copy_receiver = Some(channels::copy::Receiver { ring_buf });
        Ok(())
    }

    fn update_config_from_rules(&mut self) {
        for (_, rule) in self.filter.iter_rules() {
            if self.config.copy_enabled && self.config.route_enabled {
                break;
            }
            if !self.config.copy_enabled && matches!(rule.action, rules::Action::Copy { .. }) {
                self.config.copy_enabled = true;
            } else if !self.config.route_enabled && matches!(rule.action, rules::Action::Route) {
                self.config.route_enabled = true;
            }
        }
    }

    fn load_ebpf(&self) -> Result<Ebpf, Error> {
        let mut loader = EbpfLoader::new();

        // Apply all map size overrides using TapConfig
        if self.config.copy_enabled
            && let Some(size) = self.config.ring_buf_size
        {
            loader.map_max_entries(RING_BUF_NAME, size);
        }
        let ebpf = loader.load(E::EBPF_BYTES)?;
        Ok(ebpf)
    }

    fn populate_maps(&self, ebpf: &mut Ebpf) -> Result<(), Error> {
        set_array(ebpf, FRAME_KIND_MAP, 0, self.frame_kind)
    }

    fn load_programs(&mut self, ebpf: &mut Ebpf) -> Result<(), Error> {
        xdp_program(ebpf, E::EBPF_PROGRAM_NAME)?.load()?;
        if self.config.copy_enabled || self.config.route_enabled {
            if self.config.copy_enabled {
                let fd = {
                    let program = xdp_program(ebpf, COPY_PROGRAM_NAME)?;
                    program.load()?;
                    program.info()?.fd()?
                };
                let mut jump_table: ProgramArray<_> = map_owned(ebpf, JUMP_TABLE_NAME)?;
                jump_table.set(0, &fd, 0)?;
                self.jump_table = Some(jump_table);
                self.init_copy_receiver(ebpf)?;
            }

            if self.config.route_enabled {
                todo!();
            }
        }

        Ok(())
    }

    fn attach(&self, ebpf: &mut Ebpf) -> Result<(), Error> {
        let program = xdp_program(ebpf, E::EBPF_PROGRAM_NAME)?;
        program.attach(self.interface.name(), self.config.xdp_flags)?;
        Ok(())
    }

    fn apply_rules(&mut self, ebpf: &mut Ebpf) -> Result<(), Error> {
        for (rule_id, rule) in self.filter.iter_rules() {
            self.engine.add_rule(rule_id, rule, ebpf)?;
        }
        Ok(())
    }

    /// Starts the tap. This handles loading the eBPF programs, and optionally provisioning a
    /// [`RingBuf`] and/or `AF_XDP` socket based on the applied [`Rule`]s.
    ///
    /// # Errors
    /// Returns various [`Error`]s if there are issues loading programs, populating maps, or
    /// initializing the [`Engine`].
    pub fn start(&mut self) -> Result<(), Error> {
        self.update_config_from_rules();
        let mut ebpf = self.load_ebpf()?;
        self.populate_maps(&mut ebpf)?;
        self.load_programs(&mut ebpf)?;
        self.apply_rules(&mut ebpf)?;
        self.engine.init(&mut ebpf)?;
        self.attach(&mut ebpf)?;
        self.ebpf = Some(ebpf);
        Ok(())
    }

    /// Chain a rule in a builder pattern. This returns a [`Result`] as it accepts
    /// [`RuleBuilder`](crate::rules::RuleBuilder)s in addition to [`Rule`]s.
    ///
    /// This method should not be called after [`Self::start`].
    ///
    /// # Errors
    /// Returns [`Error::CopyNotEnabled`] or [`Error::RouteNotEnabled`] if the [`Tap`] hasn't
    /// provisioned the required primitives.
    /// Returns an [`Error`] if the engine cannot add the rule.
    pub fn with_rule<R>(mut self, rule: R) -> Result<Self, Error>
    where
        R: TryInto<Rule>,
        R::Error: Into<Error>,
    {
        self.add_rule(rule)?;
        Ok(self)
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
        if let Some(ebpf) = &mut self.ebpf {
            match rule.action {
                Action::Copy { .. } if !self.config.copy_enabled => {
                    return Err(Error::CopyNotEnabled);
                }
                Action::Route if !self.config.route_enabled => return Err(Error::RouteNotEnabled),
                _ => {}
            }
            self.engine.add_rule(rule_id, &rule, ebpf)?;
        }
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
        if let Some(ebpf) = &mut self.ebpf {
            self.engine.remove_rule(rule_id, rule, ebpf)?;
        }
        self.filter.remove(rule_id).ok_or(Error::MissingRuleId)
    }
}
