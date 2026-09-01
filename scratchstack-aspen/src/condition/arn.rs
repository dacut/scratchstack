use {
    super::{
        setop::{SetOperator, VariantNames, display_names, variant_names},
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
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ArnCmp {
    /// The comparison written `ArnEquals`, or `ArnNotEquals` when negated.
    Equals,

    /// The comparison written `ArnLike`, or `ArnNotLike` when negated.
    Like,
}

/// The names `ArnEquals` goes by.
const ARN_EQUALS_NAMES: VariantNames =
    variant_names!["ArnEquals", "ArnEqualsIfExists", "ArnNotEquals", "ArnNotEqualsIfExists"];

/// The names `ArnLike` goes by.
const ARN_LIKE_NAMES: VariantNames = variant_names!["ArnLike", "ArnLikeIfExists", "ArnNotLike", "ArnNotLikeIfExists"];

impl ArnCmp {
    /// Returns the names this comparison goes by, one per [`Variant`].
    const fn names(&self) -> &'static VariantNames {
        match self {
            Self::Equals => &ARN_EQUALS_NAMES,
            Self::Like => &ARN_LIKE_NAMES,
        }
    }

    pub(super) const fn display_name(&self, set_op: SetOperator, variant: &Variant) -> &'static str {
        self.names().name(*variant, set_op)
    }
}

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
