use crate::{
    engine::{Engine, LinearEngine},
    error::Error,
    rules::{Rule, RuleId},
};

/// The Filter is a collection of `Rule`s which govern which packets are affected, and the action
/// taken for each. The filter contains an `Engine` which governs how rules are applied to packets
pub struct Filter<E: Engine = LinearEngine> {
    rules: Vec<Option<Rule>>,
    free: Vec<usize>,
    engine: E,
}

impl Filter {
    pub fn new() -> Self {
        Self {
            rules: vec![],
            free: vec![],
            engine: LinearEngine::new(),
        }
    }

    fn place_rule(&mut self, rule: Rule) -> Result<RuleId, Error> {
        let rules_count = self.rules.len() - self.free.len();
        if self.engine.capacity().is_some_and(|cap| cap == rules_count) {
            return Err(Error::EngineAtCapacity);
        }
        if self.free.is_empty() {
            let rule_id = RuleId(self.rules.len());
            self.engine.add_rule(rule_id, &rule)?;
            self.rules.push(Some(rule));
            Ok(rule_id)
        } else {
            let rule_id = RuleId(self.free.remove(0));
            self.engine.add_rule(rule_id, &rule)?;
            self.rules[rule_id.0] = Some(rule);
            Ok(rule_id)
        }
    }

    pub fn rule<R>(mut self, rule: R) -> Result<Self, Error>
    where
        R: TryInto<Rule>,
        R::Error: Into<Error>,
    {
        let rule = rule.try_into().map_err(Into::into)?;
        self.place_rule(rule)?;
        Ok(self)
    }

    pub fn add_rule<R>(&mut self, rule: R) -> Result<RuleId, Error>
    where
        R: TryInto<Rule>,
        R::Error: Into<Error>,
    {
        let rule = rule.try_into().map_err(Into::into)?;
        self.place_rule(rule)
    }

    pub fn remove_rule(&mut self, rule_id: RuleId) -> Result<(), Error> {
        let RuleId(index) = rule_id;
        if index >= self.rules.len() {
            return Err(Error::MissingRuleId);
        }
        match &self.rules[index] {
            None => Err(Error::MissingRuleId),
            Some(rule) => {
                self.engine.remove_rule(RuleId(index), rule)?;
                self.free.push(index);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        error::Error,
        filter::Filter,
        rules::{Action, Rule},
    };

    #[test]
    fn filter_accepts_rule() {
        let rule = Rule::action(Action::Pass)
            .source_cidr("127.0.0.1")
            .build()
            .unwrap();
        let filter = Filter::new().rule(rule);
        assert!(filter.is_ok())
    }

    #[test]
    fn filter_accepts_valid_rule_builder() {
        let builder = Rule::source_cidr("127.0.0.1").action(Action::Pass);
        let filter = Filter::new().rule(builder);
        assert!(filter.is_ok());
    }

    #[test]
    fn filter_propagates_invalid_rule_builder() {
        let builder = Rule::source_cidr("127.0.0.1");
        let filter = Filter::new().rule(builder);
        assert!(filter.is_err_and(|e| matches!(e, Error::MissingRuleAction)))
    }

    #[test]
    fn filter_rules_increment() {
        let mut filter = Filter::new();
        let rule_id_1 = filter
            .add_rule(Rule::source_cidr("127.0.0.1").action(Action::Pass))
            .unwrap();
        let rule_id_2 = filter
            .add_rule(Rule::source_cidr("127.0.0.1").action(Action::Pass))
            .unwrap();
        assert!(rule_id_1.0 + 1 == rule_id_2.0)
    }

    #[test]
    fn filter_rules_reclaim_ids() {
        let mut filter = Filter::new();
        let rule_id_1 = filter
            .add_rule(Rule::source_cidr("127.0.0.1").action(Action::Pass))
            .unwrap();
        filter.remove_rule(rule_id_1.clone()).unwrap();
        let rule_id_2 = filter
            .add_rule(Rule::source_cidr("127.0.0.1").action(Action::Pass))
            .unwrap();
        assert!(rule_id_1.0 == rule_id_2.0)
    }
}
