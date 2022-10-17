use {
    super::variant::Variant,
    crate::{serutil::StringLikeList, AspenError, Context, PolicyVersion},
    scratchstack_aws_principal::SessionValue,
};

/// Boolean operation names.
pub(super) const BOOL_DISPLAY_NAMES: [&str; 2] = ["Bool", "BoolIfExists"];

pub(super) fn bool_match(
    context: &Context,
    pv: PolicyVersion,
    allowed: &StringLikeList<String>,
    value: &SessionValue,
    variant: Variant,
) -> Result<bool, AspenError> {
    match value {
        SessionValue::Null => Ok(variant.if_exists()),
        SessionValue::Bool(value) => {
            let mut allowed_bool = Vec::with_capacity(2);
            for el in allowed.iter() {
                let el = match pv {
                    PolicyVersion::None => el.clone(),
                    PolicyVersion::V2012_10_17 => context.subst_vars_plain(el)?,
                };

                match el.as_str() {
                    "true" => allowed_bool.push(true),
                    "false" => allowed_bool.push(false),
                    _ => (),
                }
            }
            Ok(allowed_bool.contains(value))
        }
        _ => Ok(false),
    }
}
