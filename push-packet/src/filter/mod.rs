use crate::{
    cast,
    rules::{Rule, RuleId},
};

/// A simple interface for storing [`Rule`]s and getting the next available [`RuleId`] with id
/// reclamation.
#[derive(Default)]
pub(crate) struct Filter {
    rules: Vec<Option<Rule>>,
    free: Vec<u32>,
}

impl Filter {
    pub fn next_rule_id(&self) -> RuleId {
        match self.free.last() {
            Some(&index) => RuleId(index),
            None => RuleId(cast::usize_to_rule_index(self.rules.len())),
        }
    }

    pub fn add(&mut self, rule: Rule) {
        match self.free.pop() {
            None => self.rules.push(Some(rule)),
            Some(index) => self.rules[cast::rule_index_to_usize(index)] = Some(rule),
        }
    }

    pub fn get(&self, rule_id: RuleId) -> Option<&Rule> {
        match self.rules.get(cast::rule_index_to_usize(rule_id.0)) {
            Some(Some(rule)) => Some(rule),
            _ => None,
        }
    }

    pub fn remove(&mut self, rule_id: RuleId) -> Option<Rule> {
        if cast::rule_index_to_usize(rule_id.0) >= self.rules.len() {
            return None;
        }
        match self.rules[cast::rule_index_to_usize(rule_id.0)].take() {
            None => None,
            Some(rule) => {
                self.free.push(rule_id.0);
                Some(rule)
            }
        }
    }

    pub fn iter_rules(&self) -> impl Iterator<Item = (RuleId, &Rule)> {
        self.rules.iter().enumerate().filter_map(|(index, rule)| {
            rule.as_ref()
                .map(|rule| (RuleId(cast::usize_to_rule_index(index)), rule))
        })
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        filter::Filter,
        rules::{Action, Rule},
    };

    fn test_rule() -> Rule {
        Rule::source_cidr("127.0.0.1")
            .action(Action::Pass)
            .build()
            .unwrap()
    }

    #[test]
    fn filter_ids_increment() {
        let mut filter = Filter::default();
        let id = filter.next_rule_id();
        filter.add(test_rule());
        let id_2 = filter.next_rule_id();
        assert_eq!(id.0, 0);
        assert_eq!(id_2.0, 1);
    }

    #[test]
    fn filter_reclaims_ids() {
        let mut filter = Filter::default();
        let id = filter.next_rule_id();
        filter.add(test_rule());
        filter.remove(id);
        let id_2 = filter.next_rule_id();
        filter.add(test_rule());
        let id_3 = filter.next_rule_id();
        assert_eq!(id.0, 0);
        assert_eq!(id_2.0, 0);
        assert_eq!(id_3.0, 1);
    }

    #[test]
    fn filter_double_remove_returns_none() {
        let mut filter = Filter::default();
        let id = filter.next_rule_id();
        filter.add(test_rule());
        assert!(filter.remove(id).is_some());
        assert!(filter.remove(id).is_none());
    }
}
