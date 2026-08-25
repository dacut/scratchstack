use {
    super::{
        setop::{OperatorNames, SetOperator, display_names},
        variant::Variant,
    },
    crate::{AspenError, Context, PolicyVersion, serutil::StringLikeList},
    scratchstack_aws_principal::SessionValue,
    std::str::FromStr,
};

/// A comparison between the number a request carries and one the policy lists.
type NumericOp = fn(i64, i64) -> bool;

/// Numeric operation names.
pub(super) const NUMERIC_DISPLAY_NAMES: [OperatorNames; 12] = display_names![
    "NumericEquals",
    "NumericEqualsIfExists",
    "NumericNotEquals",
    "NumericNotEqualsIfExists",
    "NumericLessThan",
    "NumericLessThanIfExists",
    "NumericGreaterThanEquals",
    "NumericGreaterThanEqualsIfExists",
    "NumericLessThanEquals",
    "NumericLessThanEqualsIfExists",
    "NumericGreaterThan",
    "NumericGreaterThanIfExists",
];

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum NumericCmp {
    Equals = 0,
    LessThan = 4,
    LessThanEquals = 8,
}

impl NumericCmp {
    pub(super) const fn display_name(&self, set_op: SetOperator, variant: &Variant) -> &'static str {
        NUMERIC_DISPLAY_NAMES[*self as usize | variant.as_usize()].name(set_op)
    }
}

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
            Err(_) => Ok(false),
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
