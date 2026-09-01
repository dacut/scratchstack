/// The suffix an operator carries, for the comparisons that admit no other modifier.
///
/// This is exactly a [`Variant`] with negation removed, and its two values are named for the
/// [`Variant`] values they correspond to. `Binary` and `Bool` are defined by AWS in two forms
/// apiece -- `BinaryEquals` and `BinaryEqualsIfExists`, `Bool` and `BoolIfExists` -- with no
/// negated form, so they carry this rather than a [`Variant`]. The combinations AWS gives no name
/// to therefore cannot be built at all, which is what makes
/// [`ConditionOp::as_str`][crate::ConditionOp::as_str] total.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Suffix {
    /// No suffix: the condition fails when the key is absent.
    #[default]
    None,

    /// The `IfExists` suffix: the condition passes over a key the request did not supply.
    IfExists,
}

impl Suffix {
    /// Indicates whether this carries the `IfExists` suffix: the condition passes over a key the
    /// request did not supply, rather than failing.
    #[inline]
    pub fn if_exists(self) -> bool {
        matches!(self, Self::IfExists)
    }
}

impl From<Suffix> for Variant {
    /// A [`Suffix`] is a [`Variant`] that happens not to be negated.
    fn from(suffix: Suffix) -> Self {
        match suffix {
            Suffix::None => Self::None,
            Suffix::IfExists => Self::IfExists,
        }
    }
}

/// The modifiers an operator carries: whether it is negated, and whether it takes the `IfExists`
/// suffix.
///
/// The two are independent, so there are four values. A comparison that admits only the suffix
/// carries a [`Suffix`] instead, which is this type with the negated values removed.
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
        super::{Suffix, Variant},
        pretty_assertions::assert_eq,
    };

    /// A suffix converts to the variant it corresponds to, which is what makes it a subset rather
    /// than a parallel vocabulary.
    #[test_log::test]
    fn test_suffix_is_a_variant_without_negation() {
        assert_eq!(Variant::from(Suffix::None), Variant::None);
        assert_eq!(Variant::from(Suffix::IfExists), Variant::IfExists);

        // And the question both answer agrees across the conversion.
        for suffix in [Suffix::None, Suffix::IfExists] {
            assert_eq!(suffix.if_exists(), Variant::from(suffix).if_exists());
            assert!(!Variant::from(suffix).negated(), "a suffix is never negated");
        }
    }

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

        assert!(!Suffix::None.if_exists());
        assert!(Suffix::IfExists.if_exists());
    }
}
