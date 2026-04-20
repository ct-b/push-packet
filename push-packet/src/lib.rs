#![deny(missing_docs)]
#![deny(rustdoc::all)]
#![deny(clippy::pedantic)]
//! push-packet is a high-level, extensible packet routing library built on eBPF with aya. It is
//! intended to be a simple, yet flexible foundation for traffic analysis applications and
//! network-stack bypass.
//!
//! # Example: Tap into a network interface, and copy all packets to userspace.
//! ```no_run
//! # use push_packet::{Tap, rules::{Rule, Action}};
//! # fn main() -> Result<(), push_packet::error::Error> {
//! let mut tap = Tap::new("wlp3s0")?.with_rule(
//!     Rule::builder()
//!         .source_cidr("0.0.0.0/0")
//!         .action(Action::Copy { take: None }),
//! )?;
//!
//! tap.start()?;
//!
//! let mut rx = tap.copy_rx()?;
//! while let Ok(event) = rx.recv() {
//!     println!("Received packet of length {}", event.packet_len());
//! }
//! # Ok(())
//! # }
//! ```
pub mod channels;
mod constants;
pub mod engine;
pub mod error;
pub mod events;
mod filter;
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
    constants::{COPY_PROGRAM_NAME, FRAME_KIND_MAP, JUMP_TABLE_NAME},
    engine::{Engine, linear::LinearEngine},
    error::Error,
    filter::Filter,
    interface::Interface,
    rules::{Action, Rule, RuleId},
};

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
}

impl Tap<LinearEngine> {
    /// Creates a [`Tap`] with the default [`LinearEngine`].
    pub fn new<I>(interface: I) -> Result<Self, Error>
    where
        I: TryInto<Interface>,
        I::Error: Into<Error>,
    {
        Self::with_engine(interface, LinearEngine)
    }
}

impl<E: Engine> Tap<E> {
    /// Creates a [`Tap`] with a specific engine.
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
        })
    }

    /// Returns the [`FrameKind`] for the selected interface
    pub fn frame_kind(&self) -> FrameKind {
        self.frame_kind
    }

    /// Returns a [`channels::copy::Receiver`] for receiving data.
    pub fn copy_rx(&mut self) -> Result<channels::copy::Receiver, Error> {
        self.copy_receiver.take().ok_or(Error::MissingRingBuf)
    }

    fn init_copy_receiver(&mut self, ebpf: &mut Ebpf) -> Result<(), Error> {
        let ring_buf: RingBuf<MapData> = Self::get_map_owned(RING_BUF_NAME, ebpf)?;
        self.copy_receiver = Some(channels::copy::Receiver { ring_buf });
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
    /// [`RingBuf`] and/or `AF_XDP` socket based on the applied [`Rule`]s.
    pub fn start(&mut self) -> Result<(), Error> {
        let mut loader = aya::EbpfLoader::new();
        let mut ebpf = loader.load(E::EBPF_BYTES)?;

        let mut copy_enabled = false;
        // let mut route_enabled = false;
        for (rule_id, rule) in self.filter.iter_rules() {
            match rule.action {
                Action::Copy { .. } => copy_enabled = true,
                Action::Route => todo!("Add routing"),
                _ => {}
            }
            self.engine.add_rule(rule_id, rule, &mut ebpf)?;
        }
        let mut frame_kind: Array<&mut MapData, FrameKind> =
            Self::get_map_mut(FRAME_KIND_MAP, &mut ebpf)?;
        frame_kind.set(0, self.frame_kind, 0)?;

        // Load engine program
        Self::get_xdp_program(E::EBPF_PROGRAM_NAME, &mut ebpf)?.load()?;

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
            self.init_copy_receiver(&mut ebpf)?;
        }

        // Attach engine program
        Self::get_xdp_program(E::EBPF_PROGRAM_NAME, &mut ebpf)?
            .attach(self.interface.name(), XdpFlags::default())?;

        self.ebpf = Some(ebpf);
        Ok(())
    }

    /// Chain a rule in a builder pattern. This returns a [`Result`] as it accepts
    /// [`RuleBuilder`](crate::rules::RuleBuilder)s in addition to [`Rule`]s.
    ///
    /// This method should not be called after [`Self::start`].
    pub fn with_rule<R>(mut self, rule: R) -> Result<Self, Error>
    where
        R: TryInto<Rule>,
        R::Error: Into<Error>,
    {
        let rule = rule.try_into().map_err(Into::into)?;
        self.filter.add(rule);
        Ok(self)
    }

    /// Add a [`Rule`] or [`RuleBuilder`](crate::rules::RuleBuilder).
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

    /// Remove a [`Rule`] by its [`RuleId`].
    pub fn remove_rule(&mut self, rule_id: RuleId) -> Result<Rule, Error> {
        let rule = self.filter.get(rule_id).ok_or(Error::MissingRuleId)?;
        if let Some(ebpf) = &mut self.ebpf {
            self.engine.remove_rule(rule_id, rule, ebpf)?;
        }
        self.filter.remove(rule_id).ok_or(Error::MissingRuleId)
    }
}
