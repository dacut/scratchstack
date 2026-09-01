use {
    super::{
        setop::{SuffixNames, display_names, suffix_names},
        variant::Suffix,
    },
    crate::{AspenError, Context, PolicyVersion, serutil::StringLikeList},
    base64::{Engine, engine::general_purpose::STANDARD},
    scratchstack_aws_principal::SessionValue,
};

/// The names the binary comparison goes by. AWS defines no negated form.
pub(super) const BINARY_DISPLAY_NAMES: SuffixNames = suffix_names!["BinaryEquals", "BinaryEqualsIfExists"];

pub(super) fn binary_match(
    _context: &Context,
    _pv: PolicyVersion,
    allowed: &StringLikeList<String>,
    value: &SessionValue,
    suffix: Suffix,
) -> Result<bool, AspenError> {
    match value {
        SessionValue::Null => Ok(suffix.if_exists()),
        SessionValue::Binary(value) => {
            for el in allowed.iter() {
                // Note: negated is not a valid variant here, so no need to check for !=.
                if let Ok(el) = STANDARD.decode(el)
                    && el == *value
                {
                    return Ok(true);
                }
            }

            Ok(false)
        }
        SessionValue::String(value) => {
            for el in allowed.iter() {
                if let Ok(el) = STANDARD.decode(el)
                    && el == value.as_bytes()
                {
                    return Ok(true);
                }
            }

            Ok(false)
        }
        _ => Ok(false),
    }
}
