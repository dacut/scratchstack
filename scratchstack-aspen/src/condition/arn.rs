use {
    super::variant::Variant,
    crate::{eval::regex_from_glob, serutil::StringLikeList, AspenError, Context, PolicyVersion},
    log::trace,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::SessionValue,
    std::str::FromStr,
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ArnCmp {
    Equals = 0,
    Like = 4,
}

impl ArnCmp {
    pub(super) fn display_name(&self, variant: &Variant) -> &'static str {
        ARN_DISPLAY_NAMES[*self as usize | variant.as_usize()]
    }
}

// The order is important here. For a given operation, the if-exists variant must follow, then the negated variant,
// then the negated if-exists variant.

/// ARN operation names.
const ARN_DISPLAY_NAMES: [&str; 8] = [
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
            match Arn::from_str(value) {
                Err(_) => {
                    // Failed to convert, so this won't match anything. If not-equals (negated), return true;
                    // otherwise, false.
                    Ok(variant.negated())
                }
                Ok(value) => {
                    for el in allowed.iter() {
                        let parts = el.splitn(6, ':').collect::<Vec<&str>>();
                        if parts.len() != 6 || parts[0] != "arn" {
                            continue;
                        }

                        let partition = regex_from_glob(parts[1]).build().unwrap();
                        let service = regex_from_glob(parts[2]).build().unwrap();
                        let region = regex_from_glob(parts[3]).build().unwrap();
                        let account_id = regex_from_glob(parts[4]).build().unwrap();
                        let resource = context.matcher(parts[5], pv)?.build().unwrap();

                        trace!(
                            "partition={} service={} region={} account_id={} resource={}",
                            partition,
                            service,
                            region,
                            account_id,
                            resource
                        );
                        trace!("value={}", value);

                        let is_match = partition.is_match(value.partition())
                            && service.is_match(value.service())
                            && region.is_match(value.region())
                            && account_id.is_match(value.account_id())
                            && resource.is_match(value.resource());
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

#[cfg(test)]
mod tests {
    use {super::ArnCmp, pretty_assertions::assert_eq};

    #[test_log::test]
    fn test_clone() {
        assert_eq!(ArnCmp::Equals.clone(), ArnCmp::Equals);
        assert_eq!(ArnCmp::Like.clone(), ArnCmp::Like);
    }
}
