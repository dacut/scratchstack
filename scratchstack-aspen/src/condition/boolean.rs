use {
    super::{
        setop::{SuffixNames, display_names, suffix_names},
        variant::Suffix,
    },
    crate::{AspenError, Context, PolicyVersion, serutil::StringLikeList},
    scratchstack_aws_principal::SessionValue,
};

/// The names the boolean comparison goes by. AWS defines no negated form.
pub(super) const BOOL_DISPLAY_NAMES: SuffixNames = suffix_names!["Bool", "BoolIfExists"];

pub(super) fn bool_match(
    context: &Context,
    pv: PolicyVersion,
    allowed: &StringLikeList<String>,
    value: &SessionValue,
    suffix: Suffix,
) -> Result<bool, AspenError> {
    match value {
        SessionValue::Null => Ok(suffix.if_exists()),
        SessionValue::Bool(value) => {
            let mut allowed_bool = Vec::with_capacity(2);
            for el in allowed.iter() {
                let el = match pv {
                    PolicyVersion::None | PolicyVersion::V2008_10_17 => el.clone(),
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
