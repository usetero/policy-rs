//! Match key for grouping patterns by field and negation.

use crate::field::LogFieldSelector;

/// Key for grouping patterns in Hyperscan databases.
///
/// Patterns are grouped by the field they match against and whether
/// they are negated. This allows us to scan each field value once
/// against all patterns for that field.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MatchKey {
    /// The field this pattern matches against.
    pub field: LogFieldSelector,
    /// Whether this is a negated matcher.
    pub negated: bool,
}

impl MatchKey {
    /// Create a new match key.
    pub fn new(field: LogFieldSelector, negated: bool) -> Self {
        Self { field, negated }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tero::policy::v1::LogField;
    use std::collections::HashMap;

    #[test]
    fn match_key_equality() {
        let key1 = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let key2 = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let key3 = MatchKey::new(LogFieldSelector::Simple(LogField::Body), true);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn match_key_hash() {
        let mut map: HashMap<MatchKey, i32> = HashMap::new();

        let key1 = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let key2 = MatchKey::new(LogFieldSelector::Simple(LogField::Body), true);
        let key3 = MatchKey::new(LogFieldSelector::LogAttribute("test".to_string()), false);

        map.insert(key1.clone(), 1);
        map.insert(key2.clone(), 2);
        map.insert(key3.clone(), 3);

        assert_eq!(map.get(&key1), Some(&1));
        assert_eq!(map.get(&key2), Some(&2));
        assert_eq!(map.get(&key3), Some(&3));
    }
}
