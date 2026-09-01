use {
    super::{
        setop::{VariantNames, display_names, variant_names},
        variant::Variant,
    },
    crate::{AspenError, Context, PolicyVersion, serutil::StringLikeList},
    ipnet::IpNet,
    scratchstack_aws_principal::SessionValue,
    std::net::IpAddr,
};

/// The names the IP address comparison goes by.
pub(super) const IP_ADDRESS_DISPLAY_NAMES: VariantNames =
    variant_names!["IpAddress", "IpAddressIfExists", "NotIpAddress", "NotIpAddressIfExists"];

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
            let mut matched = false;

            for el in allowed.iter() {
                let el = match pv {
                    PolicyVersion::None | PolicyVersion::V2008_10_17 => el.clone(),
                    PolicyVersion::V2012_10_17 => context.subst_vars_plain(el)?,
                };

                let parsed = match el.parse::<IpNet>() {
                    Ok(net) => Some(net),
                    Err(_) => match el.parse::<IpAddr>() {
                        Ok(addr) => Some(IpNet::from(addr)),
                        Err(_) => None,
                    },
                };
                if let Some(parsed) = parsed
                    && parsed.contains(value)
                {
                    matched = true;
                    break;
                }
            }

            // NotIpAddress negates the whole clause: the address has to fall outside every range
            // the policy lists, rather than outside any one of them.
            Ok(matched != variant.negated())
        }
        _ => Ok(false),
    }
}
