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
        let engine = LinearEngine::new(None);
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
        let filter = Filter::default();
        Ok(Self {
            interface,
            engine,
            filter,
            ebpf: None,
        })
    }

    pub fn start(&mut self) -> Result<(), Error> {
        let mut loader = aya::EbpfLoader::new();
        for (name, size) in self.engine.map_capacities() {
            loader.map_max_entries(name, size);
        }
        let mut ebpf = loader.load(E::EBPF_BYTES)?;
        for (rule_id, rule) in self.filter.iter_rules() {
            self.engine.add_rule(rule_id, rule, &mut ebpf)?;
        }
        let program: &mut Xdp = ebpf
            .program_mut(E::EBPF_PROGAM_NAME)
            .ok_or(Error::MissingEbpfProgram)?
            .try_into()?;
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
        if let Some(ebpf) = &mut self.ebpf {
            self.engine.add_rule(rule_id, &rule, ebpf)?;
        }
        self.filter.add(rule);
        Ok(rule_id)
    }

    pub fn remove_rule(&mut self, rule_id: RuleId) -> Result<Rule, Error> {
        let rule = self.filter.get(rule_id).ok_or(Error::MissingRuleId)?;
        if let Some(ebpf) = &mut self.ebpf {
            self.engine.remove_rule(rule_id, rule, ebpf)?;
        }
        self.filter.remove(rule_id).ok_or(Error::MissingRuleId)
    }
}
