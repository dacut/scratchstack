use {
    serde::{Deserialize, Serialize},
    std::fmt::{Display, Formatter, Result as FmtResult},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Effect {
    Allow,
    Deny,
}

impl Display for Effect {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Allow => f.write_str("Allow"),
            Self::Deny => f.write_str("Deny"),
        }
    }
}

#[cfg(test)]
mod tests {
    use {crate::Effect, pretty_assertions::assert_eq, std::collections::HashMap};

    #[test_log::test]
    fn test_hash() {
        let mut hash_map = HashMap::new();
        hash_map.insert(Effect::Allow, 1);
        hash_map.insert(Effect::Deny, 2);

        assert_eq!(hash_map.get(&Effect::Allow), Some(&1));
        assert_eq!(hash_map.get(&Effect::Deny), Some(&2));
    }

    #[test_log::test]
    fn test_display() {
        assert_eq!(format!("{}", Effect::Allow), "Allow");
        assert_eq!(format!("{}", Effect::Deny), "Deny");
    }
}
