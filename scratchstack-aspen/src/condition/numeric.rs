use {
    super::variant::Variant,
    crate::{serutil::StringLikeList, AspenError, Context, PolicyVersion},
    scratchstack_aws_principal::SessionValue,
    std::str::FromStr,
};

/// Numeric operation names.
pub(super) const NUMERIC_DISPLAY_NAMES: [&str; 12] = [
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum NumericCmp {
    Equals = 0,
    LessThan = 4,
    LessThanEquals = 8,
}

impl NumericCmp {
    pub(super) fn display_name(&self, variant: &Variant) -> &'static str {
        NUMERIC_DISPLAY_NAMES[*self as usize | variant.as_usize()]
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
        SessionValue::Integer(value) => {
            let fn_op = match (cmp, variant.negated()) {
                (NumericCmp::Equals, false) => |a: i64, b: i64| a == b,
                (NumericCmp::Equals, true) => |a: i64, b: i64| a != b,
                (NumericCmp::LessThan, false) => |a: i64, b: i64| a < b,
                (NumericCmp::LessThan, true) => |a: i64, b: i64| a >= b,
                (NumericCmp::LessThanEquals, false) => |a: i64, b: i64| a <= b,
                (NumericCmp::LessThanEquals, true) => |a: i64, b: i64| a > b,
            };

            for el in allowed.iter() {
                let el = match pv {
                    PolicyVersion::None => el.clone(),
                    PolicyVersion::V2012_10_17 => context.subst_vars_plain(el)?,
                };

                if let Ok(parsed) = i64::from_str(&el) {
                    if fn_op(*value, parsed) {
                        return Ok(true);
                    }
                }
            }

            Ok(false)
        }
        _ => Ok(false),
    }
}
