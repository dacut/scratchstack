use {
    super::variant::Variant,
    crate::{serutil::StringLikeList, AspenError, Context, PolicyVersion},
    scratchstack_aws_principal::SessionValue,
};

/// Binary operation names.
pub(super) const BINARY_DISPLAY_NAMES: [&str; 2] = ["BinaryEquals", "BinaryEqualsIfExists"];

pub(super) fn binary_match(
    _context: &Context,
    _pv: PolicyVersion,
    allowed: &StringLikeList<String>,
    value: &SessionValue,
    variant: Variant,
) -> Result<bool, AspenError> {
    match value {
        SessionValue::Null => Ok(variant.if_exists()),
        SessionValue::Binary(value) => {
            for el in allowed.iter() {
                if let Ok(el) = base64::decode(el) {
                    // Note: negated is not a valid variant here, so no need to check for !=.
                    if el == *value {
                        return Ok(true);
                    }
                }
            }

            Ok(false)
        }
        SessionValue::String(value) => {
            for el in allowed.iter() {
                if let Ok(el) = base64::decode(el) {
                    if el == value.as_bytes() {
                        return Ok(true);
                    }
                }
            }

            Ok(false)
        }
        _ => Ok(false),
    }
}
