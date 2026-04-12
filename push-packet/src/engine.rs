use crate::{
    error::Error,
    rules::{Rule, RuleId},
};

pub trait Engine {
    fn new() -> Self;
    fn capacity(&self) -> Option<usize>;
    fn add_rule(&mut self, rule_id: RuleId, rule: &Rule) -> Result<(), Error>;
    fn remove_rule(&mut self, rule_id: RuleId, rule: &Rule) -> Result<(), Error>;
}

pub struct LinearEngine {}

impl Engine for LinearEngine {
    fn new() -> Self {
        Self {}
    }
    fn capacity(&self) -> Option<usize> {
        None
    }

    fn add_rule(&mut self, rule_id: RuleId, rule: &Rule) -> Result<(), Error> {
        Ok(())
    }

    fn remove_rule(&mut self, rule_id: RuleId, rule: &Rule) -> Result<(), Error> {
        Ok(())
    }
}
