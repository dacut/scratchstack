/// Whether an operator carries the `IfExists` suffix, for the comparisons that admit nothing else.
///
/// `Binary` and `Bool` are defined by AWS in two forms apiece -- `BinaryEquals` and
/// `BinaryEqualsIfExists`, `Bool` and `BoolIfExists` -- with no negated form. They carry this
/// rather than a [`Variant`] so that the combinations AWS gives no name to cannot be built at all,
/// and [`ConditionOp::as_str`][crate::ConditionOp::as_str] is therefore total.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IfExists {
    /// The plain operator: the condition fails when the key is absent.
    #[default]
    No,

    /// The `IfExists` operator: the condition passes over a key the request did not supply.
    Yes,
}

impl IfExists {
    /// Indicates whether this is [`IfExists::Yes`]: the condition passes over a key the request
    /// did not supply, rather than failing.
    #[inline]
    pub fn if_exists(self) -> bool {
        matches!(self, Self::Yes)
    }
}

/// The variant on an operation.
///
/// A comparison and a variant together name an operator. Which name that is comes from matching on
/// both, rather than from any numbering, so these carry no representation the rest of the crate
/// depends on.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Variant {
    /// No variation on the basic operation.
    None,

    /// IfExists variant.
    IfExists,

    /// Negated: Equals => NotEquals, LessThan => GreaterThanEquals, etc.
    Negated,

    /// IfExists and Negated.
    IfExistsNegated,
}

impl Variant {
    /// Indicates whether this carries the `IfExists` suffix: the condition passes over a key the
    /// request did not supply, rather than failing.
    #[inline]
    pub fn if_exists(self) -> bool {
        matches!(self, Self::IfExists | Self::IfExistsNegated)
    }

    /// Indicates whether this is a negated operator: `StringNotEquals` rather than
    /// `StringEquals`, `DateGreaterThanEquals` rather than `DateLessThan`.
    #[inline]
    pub fn negated(self) -> bool {
        matches!(self, Self::Negated | Self::IfExistsNegated)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{IfExists, Variant},
        pretty_assertions::assert_eq,
    };

    #[test_log::test]
    fn test_clone() {
        assert_eq!(Variant::None.clone(), Variant::None);
        assert_eq!(Variant::IfExists.clone(), Variant::IfExists);
        assert_eq!(Variant::Negated.clone(), Variant::Negated);
        assert_eq!(Variant::IfExistsNegated.clone(), Variant::IfExistsNegated);
    }

    /// The two questions a variant answers are independent, and each of the four values answers
    /// them differently.
    #[test_log::test]
    fn test_variant_predicates() {
        assert_eq!((Variant::None.if_exists(), Variant::None.negated()), (false, false));
        assert_eq!((Variant::IfExists.if_exists(), Variant::IfExists.negated()), (true, false));
        assert_eq!((Variant::Negated.if_exists(), Variant::Negated.negated()), (false, true));
        assert_eq!((Variant::IfExistsNegated.if_exists(), Variant::IfExistsNegated.negated()), (true, true));

        assert!(!IfExists::No.if_exists());
        assert!(IfExists::Yes.if_exists());
    }
}
