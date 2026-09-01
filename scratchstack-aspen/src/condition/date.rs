use {
    super::{
        setop::{SetOperator, VariantNames, display_names, variant_names},
        variant::Variant,
    },
    crate::{AspenError, Context, PolicyVersion, serutil::StringLikeList},
    chrono::{DateTime, Utc},
    scratchstack_aws_principal::SessionValue,
    std::str::FromStr,
};

/// A comparison between the timestamp a request carries and one the policy lists.
type DateOp = fn(DateTime<Utc>, DateTime<Utc>) -> bool;

/// The names `DateEquals` goes by.
const DATE_EQUALS_NAMES: VariantNames =
    variant_names!["DateEquals", "DateEqualsIfExists", "DateNotEquals", "DateNotEqualsIfExists"];

/// The names `DateLessThan` goes by. Negated, it is `DateGreaterThanEquals`.
const DATE_LESS_THAN_NAMES: VariantNames =
    variant_names!["DateLessThan", "DateLessThanIfExists", "DateGreaterThanEquals", "DateGreaterThanEqualsIfExists",];

/// The names `DateLessThanEquals` goes by. Negated, it is `DateGreaterThan`.
const DATE_LESS_THAN_EQUALS_NAMES: VariantNames =
    variant_names!["DateLessThanEquals", "DateLessThanEqualsIfExists", "DateGreaterThan", "DateGreaterThanIfExists",];

/// The comparison a date condition operator performs.
///
/// AWS names six date operators; three are represented here, because a negated ordering comparison
/// is another one of the six rather than an operator of its own. `DateGreaterThanEquals` is
/// [`LessThan`][`DateCmp::LessThan`] negated, and `DateGreaterThan` is
/// [`LessThanEquals`][`DateCmp::LessThanEquals`] negated.
///
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DateCmp {
    /// The comparison written `DateEquals`, or `DateNotEquals` when negated.
    Equals,

    /// The comparison written `DateLessThan`, or `DateGreaterThanEquals` when negated.
    LessThan,

    /// The comparison written `DateLessThanEquals`, or `DateGreaterThan` when negated.
    LessThanEquals,
}

impl DateCmp {
    /// Returns the names this comparison goes by, one per [`Variant`].
    const fn names(&self) -> &'static VariantNames {
        match self {
            Self::Equals => &DATE_EQUALS_NAMES,
            Self::LessThan => &DATE_LESS_THAN_NAMES,
            Self::LessThanEquals => &DATE_LESS_THAN_EQUALS_NAMES,
        }
    }

    pub(super) const fn display_name(&self, set_op: SetOperator, variant: &Variant) -> &'static str {
        self.names().name(*variant, set_op)
    }
}

/// Indicates whether the timestamp a condition key holds satisfies this comparison against the
/// timestamps the policy lists.
///
/// A key holding a string is compared as the timestamp it spells. One that spells no timestamp is
/// nothing to compare against: only `DateNotEquals` has an answer for it, and the answer is that
/// the value does indeed differ from every timestamp the policy lists. The ordering comparisons do
/// not match, in either direction -- an unparsable value is neither before nor after a timestamp
/// -- which is why the negated ones cannot simply return the opposite.
pub(super) fn date_match(
    context: &Context,
    pv: PolicyVersion,
    allowed: &StringLikeList<String>,
    value: &SessionValue,
    cmp: DateCmp,
    variant: Variant,
) -> Result<bool, AspenError> {
    match value {
        SessionValue::Null => Ok(variant.if_exists()),
        SessionValue::String(value) => match DateTime::parse_from_rfc3339(value) {
            Err(_) => match cmp {
                DateCmp::Equals => Ok(variant.negated()),
                DateCmp::LessThan | DateCmp::LessThanEquals => Ok(false),
            },
            Ok(value) => {
                let value = DateTime::<Utc>::from(value);
                date_match_datetime(context, pv, allowed, value, cmp, variant)
            }
        },
        SessionValue::Timestamp(value) => date_match_datetime(context, pv, allowed, *value, cmp, variant),
        _ => Ok(false),
    }
}

fn date_match_datetime(
    context: &Context,
    pv: PolicyVersion,
    allowed: &StringLikeList<String>,
    value: DateTime<Utc>,
    cmp: DateCmp,
    variant: Variant,
) -> Result<bool, AspenError> {
    // Negation means two different things here. With Equals it is the DateNotEquals operator,
    // whose negation covers the whole clause: the value has to differ from every value the policy
    // lists. With the ordering comparisons it names an operator of its own -- GreaterThanEquals is
    // not "less than" negated across the clause -- and its values are OR-ed like any other's.
    let (fn_op, negated_clause): (DateOp, bool) = match (cmp, variant.negated()) {
        (DateCmp::Equals, false) => (|a, b| a == b, false),
        (DateCmp::Equals, true) => (|a, b| a == b, true),
        (DateCmp::LessThan, false) => (|a, b| a < b, false),
        (DateCmp::LessThan, true) => (|a, b| a >= b, false),
        (DateCmp::LessThanEquals, false) => (|a, b| a <= b, false),
        (DateCmp::LessThanEquals, true) => (|a, b| a > b, false),
    };

    let mut matched = false;

    for el in allowed.iter() {
        let el = match pv {
            PolicyVersion::None | PolicyVersion::V2008_10_17 => el.clone(),
            PolicyVersion::V2012_10_17 => context.subst_vars_plain(el)?,
        };

        let parsed = match DateTime::parse_from_rfc3339(&el) {
            Ok(allowed) => Some(DateTime::from_naive_utc_and_offset(allowed.naive_utc(), Utc)),
            Err(_) => {
                if let Ok(unix_seconds) = i64::from_str(&el) {
                    DateTime::from_timestamp(unix_seconds, 0)
                } else {
                    None
                }
            }
        };

        if let Some(parsed) = parsed
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
    use {super::DateCmp, pretty_assertions::assert_eq};

    #[test_log::test]
    fn test_clone() {
        assert_eq!(DateCmp::Equals.clone(), DateCmp::Equals);
        assert_eq!(DateCmp::LessThan.clone(), DateCmp::LessThan);
        assert_eq!(DateCmp::LessThanEquals.clone(), DateCmp::LessThanEquals);
    }
}
