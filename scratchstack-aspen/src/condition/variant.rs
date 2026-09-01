/// Whether an operator carries the `IfExists` suffix, for the comparisons that admit nothing else.
///
/// `Binary` and `Bool` are defined by AWS in two forms apiece -- `BinaryEquals` and
/// `BinaryEqualsIfExists`, `Bool` and `BoolIfExists` -- with no negated form. They carry this
/// rather than a [`Variant`] so that the combinations AWS gives no name to cannot be built at all,
/// and [`ConditionOp::as_str`][crate::ConditionOp::as_str] is therefore total.
///
/// The offsets used in the representation are used to index into the operation names.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum IfExists {
    /// The plain operator: the condition fails when the key is absent.
    #[default]
    No = 0,

    /// The `IfExists` operator: the condition passes over a key the request did not supply.
    Yes = 1,
}

impl IfExists {
    /// Return the index into the operation names for this variant.
    #[inline]
    pub(super) const fn as_usize(self) -> usize {
        self as usize
    }

    /// Indicates whether this is [`IfExists::Yes`]: the condition passes over a key the request
    /// did not supply, rather than failing.
    #[inline]
    pub fn if_exists(self) -> bool {
        matches!(self, Self::Yes)
    }
}

/// The variant on an operation.
///
/// The offsets used in the representation are used to index into the operation names.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Variant {
    /// No variation on the basic operation.
    None = 0,

    /// IfExists variant.
    IfExists = 1,

    /// Negated: Equals => NotEquals, LessThan => GreaterThanEquals, etc.
    Negated = 2,

    /// IfExists and Negated.
    IfExistsNegated = 3,
}

impl Variant {
    /// Return the index into the operation names for this variant.
    #[inline]
    pub(super) const fn as_usize(self) -> usize {
        self as usize
    }

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

    /// The discriminants are offsets into the tables of operator names, so a comparison reserves
    /// four consecutive slots and the variant picks one of them.
    ///
    /// That the tables are laid out to match is covered by
    /// `condition::op::tests::test_every_operator_has_a_name_that_parses_back`, which walks every
    /// operator through both directions of the mapping.
    #[test_log::test]
    fn test_variant_offsets() {
        assert_eq!(Variant::None.as_usize(), 0);
        assert_eq!(Variant::IfExists.as_usize(), 1);
        assert_eq!(Variant::Negated.as_usize(), 2);
        assert_eq!(Variant::IfExistsNegated.as_usize(), 3);

        assert_eq!(IfExists::No.as_usize(), 0);
        assert_eq!(IfExists::Yes.as_usize(), 1);
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
