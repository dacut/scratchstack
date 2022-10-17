use {
    super::variant::Variant,
    crate::{serutil::StringLikeList, AspenError, Context, PolicyVersion},
    scratchstack_aws_principal::SessionValue,
};

/// String operation names.
const STRING_DISPLAY_NAMES: [&str; 12] = [
    "StringEquals",
    "StringEqualsIfExists",
    "StringNotEquals",
    "StringNotEqualsIfExists",
    "StringEqualsIgnoreCase",
    "StringEqualsIgnoreCaseIfExists",
    "StringNotEqualsIgnoreCase",
    "StringNotEqualsIgnoreCaseIfExists",
    "StringLike",
    "StringLikeIfExists",
    "StringNotLike",
    "StringNotLikeIfExists",
];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum StringCmp {
    Equals = 0,
    EqualsIgnoreCase = 4,
    Like = 8,
}

impl StringCmp {
    pub(super) fn display_name(&self, variant: &Variant) -> &'static str {
        STRING_DISPLAY_NAMES[*self as usize | variant.as_usize()]
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
            match cmp {
                StringCmp::Like => {
                    // Convert each entry to a glob pattern.
                    for el in allowed.iter() {
                        let el = context.matcher(el, pv)?.build().unwrap();
                        let is_match = el.is_match(value);

                        // If it is a match and we're not negated, or it is not a match and we are negated, return true.
                        if is_match != variant.negated() {
                            return Ok(true);
                        }
                    }

                    Ok(false)
                }
                _ => {
                    let fn_op = match cmp {
                        StringCmp::Equals => |a: &str, b: &str| a == b,
                        StringCmp::EqualsIgnoreCase => |a: &str, b: &str| a.to_lowercase() == b.to_lowercase(),
                        _ => unreachable!(),
                    };

                    for el in allowed.iter() {
                        let el = context.subst_vars_plain(el)?;
                        let is_match = fn_op(value, &el);

                        // If it is a match and we're not negated, or it is not a match and we are negated, return true.
                        if is_match != variant.negated() {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                }
            }
        }
        _ => Ok(false),
    }
}
