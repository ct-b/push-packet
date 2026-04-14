use aya::{
    Ebpf,
    programs::{Xdp, XdpFlags},
};

use crate::{
    engine::{Engine, linear::LinearEngine},
    error::Error,
    filter::Filter,
    interface::Interface,
    rules::{Rule, RuleId},
};
pub mod engine;
pub mod error;
pub mod filter;
pub mod interface;
pub mod rules;
pub mod trie;

pub struct Tap<E: Engine = LinearEngine> {
    interface: Interface,
    engine: E,
    filter: Filter,
    ebpf: Option<Ebpf>,
}

impl Tap {
    pub fn new<I>(interface: I) -> Result<Self, Error>
    where
        I: TryInto<Interface>,
        I::Error: Into<Error>,
    {
        let interface = interface.try_into().map_err(Into::into)?;
        let engine = LinearEngine::new();
        let filter = Filter::default();
        Ok(Self {
            interface,
            engine,
            filter,
            ebpf: None,
        })
    }
}

impl<E: Engine> Tap<E> {
    pub fn new_with_engine<I>(interface: I, engine: E) -> Result<Self, Error>
    where
        I: TryInto<Interface>,
        I::Error: Into<Error>,
    {
        let interface = interface.try_into().map_err(Into::into)?;
        let filter = Filter::default();
        Ok(Self {
            interface,
            engine,
            filter,
            ebpf: None,
        })
    }

    pub fn start(&mut self) -> Result<(), Error> {
        let mut ebpf = aya::Ebpf::load(E::EBPF_BYTES)?;
        let program: &mut Xdp = ebpf.program_mut("push_packet").unwrap().try_into()?;
        program.load()?;
        program.attach(self.interface.name(), XdpFlags::default())?;
        self.ebpf = Some(ebpf);
        Ok(())
    }

    pub fn with_rule<R>(mut self, rule: R) -> Result<Self, Error>
    where
        R: TryInto<Rule>,
        R::Error: Into<Error>,
    {
        let rule = rule.try_into().map_err(Into::into)?;
        let rule_id = self.filter.next_rule_id();
        self.engine.add_rule(rule_id, &rule)?;
        self.filter.add(rule);
        Ok(self)
    }

    pub fn add_rule<R>(&mut self, rule: R) -> Result<RuleId, Error>
    where
        R: TryInto<Rule>,
        R::Error: Into<Error>,
    {
        let rule = rule.try_into().map_err(Into::into)?;
        let rule_id = self.filter.next_rule_id();
        self.engine.add_rule(rule_id, &rule)?;
        self.filter.add(rule);
        Ok(rule_id)
    }

    pub fn remove_rule(&mut self, rule_id: RuleId) -> Result<Rule, Error> {
        let rule = self.filter.get(rule_id).ok_or(Error::MissingRuleId)?;
        self.engine.remove_rule(rule_id, rule)?;
        self.filter.remove(rule_id).ok_or(Error::MissingRuleId)
    }
}
