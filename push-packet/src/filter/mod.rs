use crate::{error::Error, filter::rules::Rule};

pub mod rules;

/// The Filter is a collection of `Rule`s which govern which packets are affected, and the action
/// taken for each. Rules are applied in sequence such that last match takes priority.
pub struct Filter {
    rules: Vec<Rule>,
}

impl Filter {
    pub fn new() -> Self {
        Self { rules: vec![] }
    }

    pub fn rule<R>(mut self, rule: R) -> Result<Self, Error>
    where
        R: TryInto<Rule>,
        R::Error: Into<Error>,
    {
        self.rules.push(rule.try_into().map_err(Into::into)?);
        Ok(self)
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        error::Error,
        filter::{
            Filter,
            rules::{Action, Rule},
        },
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
}
