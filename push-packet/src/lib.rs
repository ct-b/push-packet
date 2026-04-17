pub mod channels;
pub mod constants;
pub mod engine;
pub mod error;
pub mod events;
pub mod filter;
pub mod frame_kind;
pub mod interface;
pub mod rules;

use aya::{
    Ebpf,
    maps::{Array, Map, MapData, ProgramArray, RingBuf},
    programs::{Xdp, XdpFlags},
};
pub use push_packet_common::FrameKind;
use push_packet_common::RING_BUF_NAME;

use crate::{
    channels::CopyRx,
    constants::{COPY_PROGRAM_NAME, FRAME_KIND_MAP, JUMP_TABLE_NAME},
    engine::{Engine, linear::LinearEngine},
    error::Error,
    filter::Filter,
    interface::Interface,
    rules::{Action, Rule, RuleId},
};

pub struct Tap<E: Engine = LinearEngine> {
    interface: Interface,
    engine: E,
    filter: Filter,
    ebpf: Option<Ebpf>,
    ring_buf: Option<CopyRx>,
    frame_kind: FrameKind,
    jump_table: Option<ProgramArray<MapData>>,
}

impl Tap {
    pub fn new<I>(interface: I) -> Result<Self, Error>
    where
        I: TryInto<Interface>,
        I::Error: Into<Error>,
    {
        Self::new_with_engine(interface, LinearEngine::new(None))
    }
}

impl<E: Engine> Tap<E> {
    pub fn engine(&self) -> &E {
        &self.engine
    }
    pub fn engine_mut(&mut self) -> &mut E {
        &mut self.engine
    }
    pub fn ebpf(&self) -> Option<&Ebpf> {
        self.ebpf.as_ref()
    }
    pub fn ebpf_mut(&mut self) -> Option<&mut Ebpf> {
        self.ebpf.as_mut()
    }
    pub fn new_with_engine<I>(interface: I, engine: E) -> Result<Self, Error>
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
            ring_buf: None,
            frame_kind,
            jump_table: None,
        })
    }

    /// Returns the FrameKind for the selected interface
    pub fn frame_kind(&self) -> FrameKind {
        self.frame_kind
    }

    /// Returns a CopyRx for receiving data.
    pub fn copy_rx(&mut self) -> Result<CopyRx, Error> {
        self.ring_buf.take().ok_or(Error::MissingRingBuf)
    }

    fn init_ring_buf(&mut self, ebpf: &mut Ebpf) -> Result<(), Error> {
        let ring_buf: RingBuf<MapData> = Self::get_map_owned(RING_BUF_NAME, ebpf)?;
        self.ring_buf = Some(CopyRx { ring_buf });
        Ok(())
    }

    fn get_map_owned<T>(name: &str, ebpf: &mut Ebpf) -> Result<T, Error>
    where
        T: TryFrom<Map>,
        T::Error: Into<Error>,
    {
        let map = ebpf.take_map(name).ok_or(Error::MissingEbpfMap)?;
        T::try_from(map).map_err(Into::into)
    }

    fn get_map_mut<'a, T>(name: &str, ebpf: &'a mut Ebpf) -> Result<T, Error>
    where
        T: TryFrom<&'a mut Map>,
        T::Error: Into<Error>,
    {
        let map = ebpf.map_mut(name).ok_or(Error::MissingEbpfMap)?;
        T::try_from(map).map_err(Into::into)
    }

    fn get_xdp_program<'a>(name: &str, ebpf: &'a mut Ebpf) -> Result<&'a mut Xdp, Error> {
        let program: &mut Xdp = ebpf
            .program_mut(name)
            .ok_or(Error::MissingEbpfProgram)?
            .try_into()?;
        Ok(program)
    }

    /// Starts the tap. This handles loading the eBPF programs, and optionally provisioning a
    /// RingBuf and/or AF_XDP socket based on the applied Rules
    pub fn start(&mut self) -> Result<(), Error> {
        let mut loader = aya::EbpfLoader::new();
        for (name, size) in self.engine.map_capacities() {
            loader.map_max_entries(name, size);
        }
        let mut ebpf = loader.load(E::EBPF_BYTES)?;

        let mut copy_enabled = false;
        let mut route_enabled = false;
        for (rule_id, rule) in self.filter.iter_rules() {
            match rule.action {
                Action::Copy { .. } => copy_enabled = true,
                Action::Route => route_enabled = true,
                _ => {}
            }
            self.engine.add_rule(rule_id, rule, &mut ebpf)?;
        }
        let mut frame_kind: Array<&mut MapData, FrameKind> =
            Self::get_map_mut(FRAME_KIND_MAP, &mut ebpf)?;
        frame_kind.set(0, self.frame_kind, 0)?;

        // Load engine program
        Self::get_xdp_program(E::EBPF_PROGAM_NAME, &mut ebpf)?.load()?;

        if copy_enabled {
            // Load copy program. The ordering of events here matters. All programs must be loaded
            // before taking an owned map.
            let fd = {
                let program = Self::get_xdp_program(COPY_PROGRAM_NAME, &mut ebpf)?;
                program.load()?;
                program.info()?.fd()?
            };
            let mut jump_table: ProgramArray<_> = Self::get_map_owned(JUMP_TABLE_NAME, &mut ebpf)?;
            jump_table.set(0, &fd, 0)?;
            self.jump_table = Some(jump_table);
            self.init_ring_buf(&mut ebpf)?;
        }

        // Attach engine program
        Self::get_xdp_program(E::EBPF_PROGAM_NAME, &mut ebpf)?
            .attach(self.interface.name(), XdpFlags::default())?;

        self.ebpf = Some(ebpf);
        Ok(())
    }

    /// Chain a rule in a builder pattern. This returns a result as it accepts RuleBuilders in
    /// addition to Rules.
    ///
    /// This method should not be called after start().
    pub fn with_rule<R>(mut self, rule: R) -> Result<Self, Error>
    where
        R: TryInto<Rule>,
        R::Error: Into<Error>,
    {
        let rule = rule.try_into().map_err(Into::into)?;
        self.filter.add(rule);
        Ok(self)
    }

    /// Add a Rule or RuleBuilder
    pub fn add_rule<R>(&mut self, rule: R) -> Result<RuleId, Error>
    where
        R: TryInto<Rule>,
        R::Error: Into<Error>,
    {
        let rule = rule.try_into().map_err(Into::into)?;
        let rule_id = self.filter.next_rule_id();
        if let Some(ebpf) = &mut self.ebpf {
            self.engine.add_rule(rule_id, &rule, ebpf)?;
        }
        self.filter.add(rule);
        Ok(rule_id)
    }

    /// Remove a Rule or RuleBuilder
    pub fn remove_rule(&mut self, rule_id: RuleId) -> Result<Rule, Error> {
        let rule = self.filter.get(rule_id).ok_or(Error::MissingRuleId)?;
        if let Some(ebpf) = &mut self.ebpf {
            self.engine.remove_rule(rule_id, rule, ebpf)?;
        }
        self.filter.remove(rule_id).ok_or(Error::MissingRuleId)
    }
}
