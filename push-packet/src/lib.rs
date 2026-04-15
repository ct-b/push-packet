pub mod channels;
pub mod engine;
pub mod error;
pub mod filter;
pub mod frame_kind;
pub mod interface;
pub mod rules;

use aya::{
    Ebpf,
    maps::{Array, Map, MapData, ProgramArray, RingBuf},
    programs::{Xdp, XdpFlags},
};
use push_packet_common::{FrameKind, RING_BUF_NAME};

use crate::{
    channels::CopyRx,
    engine::{Engine, linear::LinearEngine},
    error::Error,
    filter::Filter,
    interface::Interface,
    rules::{Action, Rule, RuleId},
};

const FRAME_KIND_MAP: &str = "FRAME_KIND_MAP";
const COPY_PROGRAM_NAME: &str = "copy_packet";
const JUMP_TABLE_NAME: &str = "JUMP_TABLE";

pub struct Tap<E: Engine = LinearEngine> {
    interface: Interface,
    engine: E,
    filter: Filter,
    ebpf: Option<Ebpf>,
    ring_buf: Option<CopyRx>,
    frame_kind: FrameKind,
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
        })
    }

    pub fn copy_rx(&mut self) -> Result<CopyRx, Error> {
        self.ring_buf.take().ok_or(Error::MissingRingBuf)
    }

    fn init_ring_buf(&mut self, ebpf: &mut Ebpf) -> Result<(), Error> {
        let ring_buf = ebpf.take_map(RING_BUF_NAME).ok_or(Error::MissingEbpfMap)?;
        let ring_buf = RingBuf::try_from(ring_buf)?;
        self.ring_buf = Some(CopyRx {
            ring_buf,
            frame_kind: FrameKind::Ip,
        });
        Ok(())
    }

    fn get_map_mut<'a, T>(&mut self, name: &str, ebpf: &'a mut Ebpf) -> Result<T, Error>
    where
        T: TryFrom<&'a mut Map>,
        T::Error: Into<Error>,
    {
        let map = ebpf.map_mut(name).ok_or(Error::MissingEbpfMap)?;
        T::try_from(map).map_err(Into::into)
    }

    fn load_xdp_program<'a>(name: &str, ebpf: &'a mut Ebpf) -> Result<&'a mut Xdp, Error> {
        let program: &mut Xdp = ebpf
            .program_mut(name)
            .ok_or(Error::MissingEbpfProgram)?
            .try_into()?;
        program.load()?;
        Ok(program)
    }

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
        if copy_enabled {
            let jump_table_info = {
                let program = Self::load_xdp_program(COPY_PROGRAM_NAME, &mut ebpf)?;
                program.info()?
            };
            let mut jump_table: ProgramArray<_> = self.get_map_mut(JUMP_TABLE_NAME, &mut ebpf)?;
            jump_table.set(0, &jump_table_info.fd()?, 0)?;
            self.init_ring_buf(&mut ebpf)?;
        }
        let mut frame_kind: Array<&mut MapData, FrameKind> =
            self.get_map_mut(FRAME_KIND_MAP, &mut ebpf)?;
        frame_kind.set(0, self.frame_kind, 0)?;

        let program = Self::load_xdp_program(E::EBPF_PROGAM_NAME, &mut ebpf)?;
        program.attach(self.interface.name(), XdpFlags::default())?;
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
