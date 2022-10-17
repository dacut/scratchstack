use {
    super::variant::Variant,
    crate::{serutil::StringLikeList, AspenError, Context, PolicyVersion},
    ipnet::IpNet,
    scratchstack_aws_principal::SessionValue,
    std::net::IpAddr,
};

/// IP address operation names.
pub(super) const IP_ADDRESS_DISPLAY_NAMES: [&str; 4] =
    ["IpAddress", "IpAddressIfExists", "NotIpAddress", "NotIpAddressIfExists"];

pub(super) fn ip_address_match(
    context: &Context,
    pv: PolicyVersion,
    allowed: &StringLikeList<String>,
    value: &SessionValue,
    variant: Variant,
) -> Result<bool, AspenError> {
    match value {
        SessionValue::Null => Ok(variant.if_exists()),
        SessionValue::IpAddr(value) => {
            let fn_op = if !variant.negated() {
                |a: &IpAddr, b: IpNet| b.contains(a)
            } else {
                |a: &IpAddr, b: IpNet| !b.contains(a)
            };

            for el in allowed.iter() {
                let el = match pv {
                    PolicyVersion::None => el.clone(),
                    PolicyVersion::V2012_10_17 => context.subst_vars_plain(el)?,
                };

                let parsed = match el.parse::<IpNet>() {
                    Ok(net) => Some(net),
                    Err(_) => match el.parse::<IpAddr>() {
                        Ok(addr) => Some(IpNet::from(addr)),
                        Err(_) => None,
                    },
                };
                if let Some(parsed) = parsed {
                    if fn_op(value, parsed) {
                        return Ok(true);
                    }
                }
            }

            Ok(false)
        }
        _ => Ok(false),
    }
}
