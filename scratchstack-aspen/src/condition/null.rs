use {
    crate::{serutil::StringLikeList, AspenError, Context, PolicyVersion},
    scratchstack_aws_principal::SessionValue,
};

/// Null operation name.
pub(super) const NULL_DISPLAY_NAME: &str = "Null";

pub(super) fn null_match(
    context: &Context,
    pv: PolicyVersion,
    allowed: &StringLikeList<String>,
    value: &SessionValue,
) -> Result<bool, AspenError> {
    let mut allowed_bools = Vec::with_capacity(2);

    for el in allowed.iter() {
        let el = match pv {
            PolicyVersion::None | PolicyVersion::V2008_10_17 => el.clone(),
            PolicyVersion::V2012_10_17 => context.subst_vars_plain(el)?,
        };
        match el.as_str() {
            "true" => allowed_bools.push(true),
            "false" => allowed_bools.push(false),
            _ => (),
        }
    }

    let is_null = value.is_null();
    Ok(allowed_bools.contains(&is_null))
}
