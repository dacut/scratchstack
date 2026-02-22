use {
    super::variant::Variant,
    crate::{serutil::StringLikeList, AspenError, Context, PolicyVersion},
    chrono::{DateTime, NaiveDateTime, Utc},
    scratchstack_aws_principal::SessionValue,
    std::str::FromStr,
};

/// Date operation names.
pub(super) const DATE_DISPLAY_NAMES: [&str; 12] = [
    "DateEquals",
    "DateEqualsIfExists",
    "DateNotEquals",
    "DateNotEqualsIfExists",
    "DateLessThan",
    "DateLessThanIfExists",
    "DateGreaterThanEquals",
    "DateGreaterThanEqualsIfExists",
    "DateLessThanEquals",
    "DateLessThanEqualsIfExists",
    "DateGreaterThan",
    "DateGreaterThanIfExists",
];

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DateCmp {
    Equals = 0,
    LessThan = 4,
    LessThanEquals = 8,
}

impl DateCmp {
    pub(super) fn display_name(&self, variant: &Variant) -> &'static str {
        DATE_DISPLAY_NAMES[*self as usize | variant.as_usize()]
    }
}

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
                _ => Ok(false),
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
    let fn_op = match (cmp, variant.negated()) {
        (DateCmp::Equals, false) => |a: DateTime<Utc>, b: DateTime<Utc>| a == b,
        (DateCmp::Equals, true) => |a: DateTime<Utc>, b: DateTime<Utc>| a != b,
        (DateCmp::LessThan, false) => |a: DateTime<Utc>, b: DateTime<Utc>| a < b,
        (DateCmp::LessThan, true) => |a: DateTime<Utc>, b: DateTime<Utc>| a >= b,
        (DateCmp::LessThanEquals, false) => |a: DateTime<Utc>, b: DateTime<Utc>| a <= b,
        (DateCmp::LessThanEquals, true) => |a: DateTime<Utc>, b: DateTime<Utc>| a > b,
    };

    for el in allowed.iter() {
        let el = match pv {
            PolicyVersion::None | PolicyVersion::V2008_10_17 => el.clone(),
            PolicyVersion::V2012_10_17 => context.subst_vars_plain(el)?,
        };

        let parsed = match DateTime::parse_from_rfc3339(&el) {
            Ok(allowed) => Some(DateTime::from_utc(allowed.naive_utc(), Utc)),
            Err(_) => {
                if let Ok(unix_seconds) = i64::from_str(&el) {
                    NaiveDateTime::from_timestamp_opt(unix_seconds, 0).map(|ndt| DateTime::from_utc(ndt, Utc))
                } else {
                    None
                }
            }
        };

        if let Some(parsed) = parsed {
            if fn_op(value, parsed) {
                return Ok(true);
            }
        }
    }

    Ok(false)
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
