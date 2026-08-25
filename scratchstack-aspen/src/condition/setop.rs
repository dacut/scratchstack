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

/// Builds the [`OperatorNames`] for one condition operator, or for a family of them.
///
/// Given a single name it yields one [`OperatorNames`]; given several it yields an array of them,
/// in the order the comparison and [`super::Variant`] discriminants index it. Only the bare names
/// are written out: the set operator prefixes are applied here, so no prefixed operator name is
/// ever spelled by hand.
macro_rules! display_names {
    ($name:literal) => {
        OperatorNames {
            plain: $name,
            for_all_values: concat!("ForAllValues:", $name),
            for_any_value: concat!("ForAnyValue:", $name),
        }
    };

    ($($name:literal),+ $(,)?) => {
        [$(display_names!($name)),+]
    };
}

pub(super) use display_names;

#[cfg(test)]
mod tests {
    use {
        super::{OperatorNames, SetOperator},
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

        // A family of them is indexed by the comparison and variant discriminants, each entry
        // carrying its own three forms.
        let family = display_names!["Bool", "BoolIfExists"];

        assert_eq!(family[0].name(SetOperator::None), "Bool");
        assert_eq!(family[1].name(SetOperator::ForAnyValue), "ForAnyValue:BoolIfExists");
    }
}
