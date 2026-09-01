use {
    super::{
        setop::{SetOperator, VariantNames, display_names, variant_names},
        variant::Variant,
    },
    crate::{AspenError, Context, PolicyVersion, serutil::StringLikeList},
    scratchstack_aws_principal::SessionValue,
    std::str::FromStr,
};

/// A comparison between the number a request carries and one the policy lists.
type NumericOp = fn(i64, i64) -> bool;

/// The names `NumericEquals` goes by.
const NUMERIC_EQUALS_NAMES: VariantNames =
    variant_names!["NumericEquals", "NumericEqualsIfExists", "NumericNotEquals", "NumericNotEqualsIfExists",];

/// The names `NumericLessThan` goes by. Negated, it is `NumericGreaterThanEquals`.
const NUMERIC_LESS_THAN_NAMES: VariantNames = variant_names![
    "NumericLessThan",
    "NumericLessThanIfExists",
    "NumericGreaterThanEquals",
    "NumericGreaterThanEqualsIfExists",
];

/// The names `NumericLessThanEquals` goes by. Negated, it is `NumericGreaterThan`.
const NUMERIC_LESS_THAN_EQUALS_NAMES: VariantNames = variant_names![
    "NumericLessThanEquals",
    "NumericLessThanEqualsIfExists",
    "NumericGreaterThan",
    "NumericGreaterThanIfExists",
];

/// The comparison a numeric condition operator performs.
///
/// AWS names six numeric operators; three are represented here, because a negated ordering
/// comparison is another one of the six rather than an operator of its own.
/// `NumericGreaterThanEquals` is [`LessThan`][`NumericCmp::LessThan`] negated, and
/// `NumericGreaterThan` is [`LessThanEquals`][`NumericCmp::LessThanEquals`] negated.
///
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NumericCmp {
    /// The comparison written `NumericEquals`, or `NumericNotEquals` when negated.
    Equals,

    /// The comparison written `NumericLessThan`, or `NumericGreaterThanEquals` when negated.
    LessThan,

    /// The comparison written `NumericLessThanEquals`, or `NumericGreaterThan` when negated.
    LessThanEquals,
}

impl NumericCmp {
    /// Returns the names this comparison goes by, one per [`Variant`].
    const fn names(&self) -> &'static VariantNames {
        match self {
            Self::Equals => &NUMERIC_EQUALS_NAMES,
            Self::LessThan => &NUMERIC_LESS_THAN_NAMES,
            Self::LessThanEquals => &NUMERIC_LESS_THAN_EQUALS_NAMES,
        }
    }

    pub(super) const fn display_name(&self, set_op: SetOperator, variant: &Variant) -> &'static str {
        self.names().name(*variant, set_op)
    }
}

/// Indicates whether the number a condition key holds satisfies this comparison against the
/// numbers the policy lists.
///
/// A key holding a string is compared as the number it spells. One that spells no number is
/// nothing to compare against: only `NumericNotEquals` has an answer for it, and the answer is
/// that the value does indeed differ from every number the policy lists. The ordering comparisons
/// do not match, in either direction -- an unparsable value is neither less than nor greater than
/// a number -- which is why the negated ones cannot simply return the opposite.
pub(super) fn numeric_match(
    context: &Context,
    pv: PolicyVersion,
    allowed: &StringLikeList<String>,
    value: &SessionValue,
    cmp: NumericCmp,
    variant: Variant,
) -> Result<bool, AspenError> {
    match value {
        SessionValue::Null => Ok(variant.if_exists()),
        SessionValue::Integer(value) => numeric_match_i64(context, pv, allowed, *value, cmp, variant),
        SessionValue::String(value) => match i64::from_str(value) {
            Ok(value) => numeric_match_i64(context, pv, allowed, value, cmp, variant),
            Err(_) => match cmp {
                NumericCmp::Equals => Ok(variant.negated()),
                NumericCmp::LessThan | NumericCmp::LessThanEquals => Ok(false),
            },
        },
        _ => Ok(false),
    }
}

fn numeric_match_i64(
    context: &Context,
    pv: PolicyVersion,
    allowed: &StringLikeList<String>,
    value: i64,
    cmp: NumericCmp,
    variant: Variant,
) -> Result<bool, AspenError> {
    // Negation means two different things here. With Equals it is the NumericNotEquals operator,
    // whose negation covers the whole clause: the value has to differ from every value the policy
    // lists. With the ordering comparisons it names an operator of its own -- GreaterThanEquals is
    // not "less than" negated across the clause -- and its values are OR-ed like any other's.
    let (fn_op, negated_clause): (NumericOp, bool) = match (cmp, variant.negated()) {
        (NumericCmp::Equals, false) => (|a, b| a == b, false),
        (NumericCmp::Equals, true) => (|a, b| a == b, true),
        (NumericCmp::LessThan, false) => (|a, b| a < b, false),
        (NumericCmp::LessThan, true) => (|a, b| a >= b, false),
        (NumericCmp::LessThanEquals, false) => (|a, b| a <= b, false),
        (NumericCmp::LessThanEquals, true) => (|a, b| a > b, false),
    };

    let mut matched = false;

    for el in allowed.iter() {
        let el = match pv {
            PolicyVersion::None | PolicyVersion::V2008_10_17 => el.clone(),
            PolicyVersion::V2012_10_17 => context.subst_vars_plain(el)?,
        };

        if let Ok(parsed) = i64::from_str(&el)
            && fn_op(value, parsed)
        {
            matched = true;
            break;
        }
    }

    Ok(matched != negated_clause)
}

#[cfg(test)]
mod tests {
    use {super::NumericCmp, pretty_assertions::assert_eq};

    #[test_log::test]
    fn test_clone() {
        assert_eq!(NumericCmp::Equals.clone(), NumericCmp::Equals);
        assert_eq!(NumericCmp::LessThan.clone(), NumericCmp::LessThan);
        assert_eq!(NumericCmp::LessThanEquals.clone(), NumericCmp::LessThanEquals);
    }
}
