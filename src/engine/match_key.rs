//! Match key for grouping patterns by field and negation.

use super::signal::Signal;

/// Key for grouping patterns in Hyperscan databases.
///
/// Patterns are grouped by the field they match against and whether
/// they are negated. This allows us to scan each field value once
/// against all patterns for that field.
pub struct MatchKey<S: Signal> {
    /// The field this pattern matches against.
    pub field: S::FieldSelector,
    /// Whether this is a negated matcher.
    pub negated: bool,
}

// Manual impls to avoid derive adding bounds on S itself.
// Only S::FieldSelector needs the trait bounds, which Signal already guarantees.

impl<S: Signal> std::fmt::Debug for MatchKey<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatchKey")
            .field("field", &self.field)
            .field("negated", &self.negated)
            .finish()
    }
}

impl<S: Signal> Clone for MatchKey<S> {
    fn clone(&self) -> Self {
        Self {
            field: self.field.clone(),
            negated: self.negated,
        }
    }
}

impl<S: Signal> PartialEq for MatchKey<S> {
    fn eq(&self, other: &Self) -> bool {
        self.field == other.field && self.negated == other.negated
    }
}

impl<S: Signal> Eq for MatchKey<S> {}

impl<S: Signal> std::hash::Hash for MatchKey<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.field.hash(state);
        self.negated.hash(state);
    }
}

impl<S: Signal> MatchKey<S> {
    /// Create a new match key.
    pub fn new(field: S::FieldSelector, negated: bool) -> Self {
        Self { field, negated }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::signal::LogSignal;
    use crate::field::LogFieldSelector;
    use crate::proto::tero::policy::v1::LogField;
    use std::collections::HashMap;

    #[test]
    fn match_key_equality() {
        let key1 = MatchKey::<LogSignal>::new(LogFieldSelector::Simple(LogField::Body), false);
        let key2 = MatchKey::<LogSignal>::new(LogFieldSelector::Simple(LogField::Body), false);
        let key3 = MatchKey::<LogSignal>::new(LogFieldSelector::Simple(LogField::Body), true);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn match_key_hash() {
        let mut map: HashMap<MatchKey<LogSignal>, i32> = HashMap::new();

        let key1 = MatchKey::new(LogFieldSelector::Simple(LogField::Body), false);
        let key2 = MatchKey::new(LogFieldSelector::Simple(LogField::Body), true);
        let key3 = MatchKey::new(
            LogFieldSelector::LogAttribute(vec!["test".to_string()]),
            false,
        );

        map.insert(key1.clone(), 1);
        map.insert(key2.clone(), 2);
        map.insert(key3.clone(), 3);

        assert_eq!(map.get(&key1), Some(&1));
        assert_eq!(map.get(&key2), Some(&2));
        assert_eq!(map.get(&key3), Some(&3));
    }
}
