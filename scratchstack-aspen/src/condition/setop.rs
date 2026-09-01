use super::variant::{Suffix, Variant};

/// The set operator qualifying a condition clause operator.
///
/// A handful of condition keys are multivalued: `aws:TagKeys` names every tag key a request
/// carries, for example. Comparing such a key against the values a policy lists needs a rule for
/// combining the individual comparisons, which is what a set operator supplies. It is written as a
/// prefix on the operator name -- `ForAllValues:StringEquals`, `ForAnyValue:StringLike` -- and
/// applies the comparison to each value of the key in turn.
///
/// A single-valued key is a set of one, so a set operator may be used with any key.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SetOperator {
    /// No set operator: the key is compared as a single value.
    #[default]
    None,

    /// The condition matches if every value of the key matches. A key with no values matches
    /// vacuously.
    ForAllValues,

    /// The condition matches if at least one value of the key matches. A key with no values does
    /// not match, unless the operator carries the `IfExists` variant.
    ForAnyValue,
}

/// The prefix written before an operator name to apply [`SetOperator::ForAllValues`].
pub(super) const FOR_ALL_VALUES_PREFIX: &str = "ForAllValues";

/// The prefix written before an operator name to apply [`SetOperator::ForAnyValue`].
pub(super) const FOR_ANY_VALUE_PREFIX: &str = "ForAnyValue";

/// The names one condition operator goes by, one for each [`SetOperator`] that can qualify it.
///
/// The prefixed forms are spelled out rather than assembled on demand because [`Borrow<str>`] for
/// [`super::ConditionOp`] hands back a reference: the name has to already exist somewhere with a
/// `'static` lifetime. Build these with [`display_names`], which applies the prefixes at compile
/// time.
///
/// [`Borrow<str>`]: std::borrow::Borrow
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OperatorNames {
    /// The name with no set operator qualifying it: `StringEquals`.
    pub(super) plain: &'static str,

    /// The name qualified by [`SetOperator::ForAllValues`]: `ForAllValues:StringEquals`.
    pub(super) for_all_values: &'static str,

    /// The name qualified by [`SetOperator::ForAnyValue`]: `ForAnyValue:StringEquals`.
    pub(super) for_any_value: &'static str,
}

impl OperatorNames {
    /// Returns the name the operator goes by under the given set operator.
    #[inline]
    pub(super) const fn name(&self, set_op: SetOperator) -> &'static str {
        match set_op {
            SetOperator::None => self.plain,
            SetOperator::ForAllValues => self.for_all_values,
            SetOperator::ForAnyValue => self.for_any_value,
        }
    }
}

/// The names one comparison goes by, one for each [`Variant`] it can carry.
///
/// A comparison and a variant together name an operator, and every such pairing is spelled out
/// rather than computed: there is no index, so there is no arithmetic to get wrong and no way to
/// land outside the set of names. Adding a [`Variant`] fails to compile here until every
/// comparison supplies a name for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct VariantNames {
    /// The name with no variant: `StringEquals`.
    pub(super) none: OperatorNames,

    /// The name carrying the `IfExists` suffix: `StringEqualsIfExists`.
    pub(super) if_exists: OperatorNames,

    /// The negated name, which is an operator of its own rather than a suffix: `StringNotEquals`,
    /// and `DateGreaterThanEquals` for the comparison written `DateLessThan`.
    pub(super) negated: OperatorNames,

    /// The negated name carrying the `IfExists` suffix: `StringNotEqualsIfExists`.
    pub(super) if_exists_negated: OperatorNames,
}

impl VariantNames {
    /// Returns the name the operator goes by under the given variant and set operator.
    #[inline]
    pub(super) const fn name(&self, variant: Variant, set_op: SetOperator) -> &'static str {
        match variant {
            Variant::None => self.none.name(set_op),
            Variant::IfExists => self.if_exists.name(set_op),
            Variant::Negated => self.negated.name(set_op),
            Variant::IfExistsNegated => self.if_exists_negated.name(set_op),
        }
    }
}

/// The names one comparison goes by, for a comparison AWS defines in two forms rather than four.
///
/// The counterpart to [`VariantNames`] for `Binary` and `Bool`, which have no negated form. Their
/// carrying a [`Suffix`] rather than a [`Variant`] is what makes naming them total.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SuffixNames {
    /// The name with no suffix: `BinaryEquals`.
    pub(super) none: OperatorNames,

    /// The name carrying the `IfExists` suffix: `BinaryEqualsIfExists`.
    pub(super) if_exists: OperatorNames,
}

impl SuffixNames {
    /// Returns the name the operator goes by under the given suffix and set operator.
    #[inline]
    pub(super) const fn name(&self, suffix: Suffix, set_op: SetOperator) -> &'static str {
        match suffix {
            Suffix::None => self.none.name(set_op),
            Suffix::IfExists => self.if_exists.name(set_op),
        }
    }
}

/// Builds the [`OperatorNames`] for one operator.
///
/// Only the bare name is written out: the set operator prefixes are applied here, so no prefixed
/// operator name is ever spelled by hand.
///
/// The types are named by full path rather than relying on what the expansion site imported, so
/// these macros carry no hidden import requirement.
macro_rules! display_names {
    ($name:literal) => {
        $crate::condition::setop::OperatorNames {
            plain: $name,
            for_all_values: concat!("ForAllValues:", $name),
            for_any_value: concat!("ForAnyValue:", $name),
        }
    };
}

/// Builds the [`VariantNames`] for one comparison, in the order a [`Variant`] reads: plain, then
/// `IfExists`, then negated, then both.
macro_rules! variant_names {
    ($none:literal, $if_exists:literal, $negated:literal, $if_exists_negated:literal $(,)?) => {
        $crate::condition::setop::VariantNames {
            none: display_names!($none),
            if_exists: display_names!($if_exists),
            negated: display_names!($negated),
            if_exists_negated: display_names!($if_exists_negated),
        }
    };
}

/// Builds the [`SuffixNames`] for one comparison: the unsuffixed name, then the `IfExists` one.
macro_rules! suffix_names {
    ($none:literal, $if_exists:literal $(,)?) => {
        $crate::condition::setop::SuffixNames {
            none: display_names!($none),
            if_exists: display_names!($if_exists),
        }
    };
}

pub(super) use {display_names, suffix_names, variant_names};

#[cfg(test)]
mod tests {
    use {
        super::{SetOperator, Suffix, Variant},
        pretty_assertions::assert_eq,
    };

    #[test_log::test]
    fn test_derived() {
        assert_eq!(SetOperator::default(), SetOperator::None);
        assert_eq!(SetOperator::None.clone(), SetOperator::None);
        assert_eq!(SetOperator::ForAllValues.clone(), SetOperator::ForAllValues);
        assert_eq!(SetOperator::ForAnyValue.clone(), SetOperator::ForAnyValue);
        assert_eq!(format!("{:?}", SetOperator::ForAnyValue), "ForAnyValue");

        assert!(SetOperator::None < SetOperator::ForAllValues);
        assert!(SetOperator::ForAllValues < SetOperator::ForAnyValue);
    }

    /// Every operator names itself the same way: the bare name, and that name behind each set
    /// operator's prefix.
    #[test_log::test]
    fn test_operator_names() {
        let names = display_names!["StringEquals"];

        assert_eq!(names.name(SetOperator::None), "StringEquals");
        assert_eq!(names.name(SetOperator::ForAllValues), "ForAllValues:StringEquals");
        assert_eq!(names.name(SetOperator::ForAnyValue), "ForAnyValue:StringEquals");
    }

    /// A comparison's four names are selected by matching on the variant, so every variant has a
    /// name and no pairing can land outside the set.
    #[test_log::test]
    fn test_variant_names() {
        let names =
            variant_names!["StringEquals", "StringEqualsIfExists", "StringNotEquals", "StringNotEqualsIfExists",];

        assert_eq!(names.name(Variant::None, SetOperator::None), "StringEquals");
        assert_eq!(names.name(Variant::IfExists, SetOperator::None), "StringEqualsIfExists");
        assert_eq!(names.name(Variant::Negated, SetOperator::None), "StringNotEquals");
        assert_eq!(names.name(Variant::IfExistsNegated, SetOperator::None), "StringNotEqualsIfExists");

        // The set operator prefix applies to whichever name the variant selected.
        assert_eq!(names.name(Variant::Negated, SetOperator::ForAllValues), "ForAllValues:StringNotEquals");
    }

    /// The two-form comparisons select the same way, on a [`Suffix`] rather than a [`Variant`].
    #[test_log::test]
    fn test_suffix_names() {
        let names = suffix_names!["Bool", "BoolIfExists"];

        assert_eq!(names.name(Suffix::None, SetOperator::None), "Bool");
        assert_eq!(names.name(Suffix::IfExists, SetOperator::None), "BoolIfExists");
        assert_eq!(names.name(Suffix::IfExists, SetOperator::ForAnyValue), "ForAnyValue:BoolIfExists");
    }
}
