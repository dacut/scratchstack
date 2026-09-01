use {
    super::{
        setop::{OperatorNames, SetOperator, display_names},
        variant::Variant,
    },
    crate::{AspenError, Context, PolicyVersion, eval::regex_from_glob, serutil::StringLikeList},
    scratchstack_arn::Arn,
    scratchstack_aws_principal::SessionValue,
    std::str::FromStr,
};

/// The comparison an ARN condition operator performs.
///
/// The two behave identically: `ArnEquals` globs the policy's pattern against the value's six
/// components exactly as `ArnLike` does, matching AWS. The distinction is carried so that an
/// operator round-trips to the name the policy was written with.
///
/// The discriminants index the table of names the operators are written with, leaving
/// room for the [`Variant`] that follows each comparison.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ArnCmp {
    /// The comparison written `ArnEquals`, or `ArnNotEquals` when negated.
    Equals = 0,

    /// The comparison written `ArnLike`, or `ArnNotLike` when negated.
    Like = 4,
}

impl ArnCmp {
    pub(super) const fn display_name(&self, set_op: SetOperator, variant: &Variant) -> &'static str {
        ARN_DISPLAY_NAMES[*self as usize | variant.as_usize()].name(set_op)
    }
}

// The order is important here. For a given operation, the if-exists variant must follow, then the negated variant,
// then the negated if-exists variant.

/// ARN operation names.
const ARN_DISPLAY_NAMES: [OperatorNames; 8] = display_names![
    "ArnEquals",
    "ArnEqualsIfExists",
    "ArnNotEquals",
    "ArnNotEqualsIfExists",
    "ArnLike",
    "ArnLikeIfExists",
    "ArnNotLike",
    "ArnNotLikeIfExists",
];

pub(super) fn arn_match(
    context: &Context,
    pv: PolicyVersion,
    allowed: &StringLikeList<String>,
    value: &SessionValue,
    _cmp: ArnCmp, // not used; ArnLike and ArnEquals are equivalent.
    variant: Variant,
) -> Result<bool, AspenError> {
    match value {
        SessionValue::Null => Ok(variant.if_exists()),
        SessionValue::String(value) => {
            let matched = match Arn::from_str(value) {
                // A value that is not an ARN at all matches none of the ARNs the policy lists.
                Err(_) => false,
                Ok(value) => arn_matches_any(context, pv, allowed, &value)?,
            };

            // ArnNotEquals and ArnNotLike negate the whole clause: the value has to match none of
            // the ARNs the policy lists, rather than differ from any one of them.
            Ok(matched != variant.negated())
        }
        _ => Ok(false),
    }
}

/// Indicates whether `value` matches any of the ARN patterns the policy lists.
fn arn_matches_any(
    context: &Context,
    pv: PolicyVersion,
    allowed: &StringLikeList<String>,
    value: &Arn,
) -> Result<bool, AspenError> {
    for el in allowed.iter() {
        let parts = el.splitn(6, ':').collect::<Vec<&str>>();
        if parts.len() != 6 || parts[0] != "arn" {
            continue;
        }

        let partition = regex_from_glob(parts[1], false);
        let service = regex_from_glob(parts[2], false);
        let region = regex_from_glob(parts[3], false);
        let account_id = regex_from_glob(parts[4], false);
        let resource = context.matcher(parts[5], pv, false)?;

        let is_match = partition.is_match(value.partition())
            && service.is_match(value.service())
            && region.is_match(value.region())
            && account_id.is_match(value.account_id())
            && resource.is_match(value.resource());
        if is_match {
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use {super::ArnCmp, pretty_assertions::assert_eq};

    #[test_log::test]
    fn test_clone() {
        assert_eq!(ArnCmp::Equals.clone(), ArnCmp::Equals);
        assert_eq!(ArnCmp::Like.clone(), ArnCmp::Like);
    }
}
