use {
    super::{
        setop::{SetOperator, VariantNames, display_names, variant_names},
        variant::Variant,
    },
    crate::{AspenError, Context, PolicyVersion, serutil::StringLikeList},
    scratchstack_aws_principal::SessionValue,
};

/// The names `StringEquals` goes by.
const STRING_EQUALS_NAMES: VariantNames =
    variant_names!["StringEquals", "StringEqualsIfExists", "StringNotEquals", "StringNotEqualsIfExists",];

/// The names `StringEqualsIgnoreCase` goes by.
const STRING_EQUALS_IGNORE_CASE_NAMES: VariantNames = variant_names![
    "StringEqualsIgnoreCase",
    "StringEqualsIgnoreCaseIfExists",
    "StringNotEqualsIgnoreCase",
    "StringNotEqualsIgnoreCaseIfExists",
];

/// The names `StringLike` goes by.
const STRING_LIKE_NAMES: VariantNames =
    variant_names!["StringLike", "StringLikeIfExists", "StringNotLike", "StringNotLikeIfExists"];

/// The comparison a string condition operator performs.
///
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StringCmp {
    /// Equality: `StringEquals`, or `StringNotEquals` when negated.
    Equals,

    /// Equality ignoring case: `StringEqualsIgnoreCase`, or `StringNotEqualsIgnoreCase` when
    /// negated.
    EqualsIgnoreCase,

    /// A glob match, in which `*` stands for any run of characters and `?` for any one of them:
    /// `StringLike`, or `StringNotLike` when negated.
    Like,
}

impl StringCmp {
    /// Returns the names this comparison goes by, one per [`Variant`].
    const fn names(&self) -> &'static VariantNames {
        match self {
            Self::Equals => &STRING_EQUALS_NAMES,
            Self::EqualsIgnoreCase => &STRING_EQUALS_IGNORE_CASE_NAMES,
            Self::Like => &STRING_LIKE_NAMES,
        }
    }

    pub(super) const fn display_name(&self, set_op: SetOperator, variant: &Variant) -> &'static str {
        self.names().name(*variant, set_op)
    }
}

pub(super) fn string_match(
    context: &Context,
    pv: PolicyVersion,
    allowed: &StringLikeList<String>,
    value: &SessionValue,
    cmp: StringCmp,
    variant: Variant,
) -> Result<bool, AspenError> {
    match value {
        SessionValue::Null => Ok(variant.if_exists()),
        SessionValue::String(value) => {
            let matched = match cmp {
                StringCmp::Like => string_like_match(context, pv, allowed, value)?,
                StringCmp::Equals => string_equal_match(context, allowed, value, |a: &str, b: &str| a == b)?,
                StringCmp::EqualsIgnoreCase => string_equal_match(context, allowed, value, |a: &str, b: &str| {
                    a.to_lowercase() == b.to_lowercase()
                })?,
            };

            // Every negated string operator is a "Not" operator, whose negation covers the whole
            // clause: the value has to match none of the values the policy lists, rather than
            // differ from any one of them.
            Ok(matched != variant.negated())
        }
        _ => Ok(false),
    }
}

/// Indicates whether `value` matches any of the glob patterns the policy lists.
fn string_like_match(
    context: &Context,
    pv: PolicyVersion,
    allowed: &StringLikeList<String>,
    value: &str,
) -> Result<bool, AspenError> {
    for el in allowed.iter() {
        let el = context.matcher(el, pv, false)?;
        let is_match = el.is_match(value);
        sensitive_trace!("regex={:?} value={:?} is_match={:?}", el, value, is_match);

        if is_match {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Indicates whether `value` equals any of the values the policy lists, under `fn_op`.
fn string_equal_match<F: Fn(&str, &str) -> bool>(
    context: &Context,
    allowed: &StringLikeList<String>,
    value: &str,
    fn_op: F,
) -> Result<bool, AspenError> {
    for el in allowed.iter() {
        let el = context.subst_vars_plain(el)?;

        if fn_op(value, &el) {
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use {super::StringCmp, pretty_assertions::assert_eq};

    #[test_log::test]
    fn test_clone() {
        assert_eq!(StringCmp::Equals.clone(), StringCmp::Equals);
        assert_eq!(StringCmp::EqualsIgnoreCase.clone(), StringCmp::EqualsIgnoreCase);
        assert_eq!(StringCmp::Like.clone(), StringCmp::Like);
    }
}
