//! Configuration for taking a request's client address from a forwarded header. This module
//! provides the [`ForwardedForConfig`] struct.

use {
    crate::{Resolvable, error::ConfigError},
    bon::Builder,
    http::header::HeaderName,
    ipnet::IpNet,
    serde::Deserialize,
    std::{net::IpAddr, str::FromStr as _},
};

/// The header consulted for the client address when none is named. This is the header load
/// balancers conventionally append the client address to.
pub const DEFAULT_HEADER: &str = "x-forwarded-for";

/// How a service behind a load balancer recovers the address of the client that reached the load
/// balancer, rather than the address of the load balancer itself.
///
/// A request's peer address is the last hop that connected, so a service behind a proxy sees the
/// proxy for every request. Proxies record the address they accepted the request from in a
/// header -- conventionally `X-Forwarded-For` -- appending to whatever the request already
/// carried. That header is therefore only as trustworthy as the hop that appended to it: a client
/// connecting directly can put anything it likes in it, so the header is consulted only for
/// requests arriving from [`trusted_proxies`][Self::trusted_proxies], and only the portion of it
/// those proxies contributed is believed.
///
/// Leaving this configuration out entirely -- the default -- means the peer address is always
/// used and no header is ever consulted.
///
/// This struct is `#[non_exhaustive]`: outside this crate it must be built with
/// [`ForwardedForConfig::builder`] rather than struct literal syntax, so that adding a field stays
/// a non-breaking change. The fields remain public for reading.
///
/// ```compile_fail,E0639
/// # use scratchstack_config::ForwardedForConfig;
/// let _ = ForwardedForConfig {
///     header: None,
/// };
/// ```
#[derive(Builder, Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ForwardedForConfig {
    /// The header carrying the forwarded client address. Defaults to [`DEFAULT_HEADER`].
    #[builder(into)]
    #[serde(default)]
    pub header: Option<String>,

    /// The proxies whose forwarded header is believed, as IP addresses or CIDR blocks. A request
    /// arriving from any other peer is attributed to that peer, whatever the header says.
    ///
    /// This has no default: a configuration that names a header without saying whose word to
    /// take for it is rejected rather than guessed at. To believe every peer -- appropriate only
    /// when nothing but the load balancer can reach the listener at all -- say so explicitly
    /// with `["0.0.0.0/0", "::/0"]`.
    #[serde(default)]
    pub trusted_proxies: Option<Vec<String>>,
}

/// Resolved forwarded-header configuration. Optional fields from [`ForwardedForConfig`] have been
/// resolved and defaults have been applied.
///
/// This struct is `#[non_exhaustive]`: outside this crate it must be built with
/// [`ResolvedForwardedForConfig::builder`] rather than struct literal syntax, so that adding a
/// field stays a non-breaking change. The fields remain public for reading.
///
/// ```compile_fail,E0639
/// # use scratchstack_config::ResolvedForwardedForConfig;
/// let _ = ResolvedForwardedForConfig {
///     trusted_proxies: Vec::new(),
/// };
/// ```
#[derive(Builder, Clone, Debug)]
#[non_exhaustive]
pub struct ResolvedForwardedForConfig {
    /// The header carrying the forwarded client address.
    pub header: HeaderName,

    /// The proxies whose forwarded header is believed.
    pub trusted_proxies: Vec<IpNet>,
}

impl ForwardedForConfig {
    /// Updates this configuration with values from another configuration. This is used to apply
    /// overrides from a service-specific configuration to the base configuration.
    pub fn update_from(&mut self, other: &ForwardedForConfig) {
        if let Some(header) = &other.header {
            self.header = Some(header.clone());
        }
        if let Some(trusted_proxies) = &other.trusted_proxies {
            self.trusted_proxies = Some(trusted_proxies.clone());
        }
    }
}

impl Resolvable for ForwardedForConfig {
    type Resolved = ResolvedForwardedForConfig;

    fn resolve(&self) -> Result<Self::Resolved, ConfigError> {
        let header = self.header.as_deref().unwrap_or(DEFAULT_HEADER);
        let header = HeaderName::from_str(header).map_err(|_| {
            ConfigError::InvalidConfig(format!("listener.forwarded_for.header is not a valid header name: {header}"))
        })?;

        let Some(trusted_proxies) = self.trusted_proxies.as_ref().filter(|proxies| !proxies.is_empty()) else {
            return Err(ConfigError::InvalidConfig(
                "listener.forwarded_for requires a non-empty trusted_proxies list; to believe every peer, \
                 say so explicitly with trusted_proxies = [\"0.0.0.0/0\", \"::/0\"]"
                    .to_string(),
            ));
        };

        let trusted_proxies =
            trusted_proxies.iter().map(|proxy| parse_proxy(proxy)).collect::<Result<Vec<IpNet>, ConfigError>>()?;

        Ok(ResolvedForwardedForConfig {
            header,
            trusted_proxies,
        })
    }
}

impl ResolvedForwardedForConfig {
    /// Indicates whether `addr` is one of the proxies whose forwarded header this configuration
    /// believes.
    pub fn trusts(&self, addr: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|proxy| proxy.contains(&addr))
    }
}

/// Parse one entry of the trusted proxy list, which may name either a CIDR block or a single
/// address.
fn parse_proxy(proxy: &str) -> Result<IpNet, ConfigError> {
    if let Ok(net) = IpNet::from_str(proxy) {
        return Ok(net);
    }

    match IpAddr::from_str(proxy) {
        Ok(addr) => Ok(IpNet::from(addr)),
        Err(_) => Err(ConfigError::InvalidConfig(format!(
            "listener.forwarded_for.trusted_proxies entry is not an IP address or CIDR block: {proxy}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{DEFAULT_HEADER, ForwardedForConfig},
        crate::{HttpListenerConfig, Resolvable as _},
        std::net::{IpAddr, Ipv4Addr, Ipv6Addr},
    };

    fn config(toml: &str) -> ForwardedForConfig {
        toml::from_str(toml).expect("failed to parse forwarded_for configuration")
    }

    #[test]
    fn the_header_defaults_to_x_forwarded_for() {
        let resolved = config(r#"trusted_proxies = ["10.0.0.0/8"]"#).resolve().expect("failed to resolve");
        assert_eq!(resolved.header.as_str(), DEFAULT_HEADER);

        let resolved =
            config("header = \"X-Real-Ip\"\ntrusted_proxies = [\"10.0.0.0/8\"]").resolve().expect("failed to resolve");
        assert_eq!(resolved.header.as_str(), "x-real-ip");
    }

    /// Trusted proxies may be named as CIDR blocks or as single addresses, in either family.
    #[test]
    fn trusted_proxies_accept_blocks_and_single_addresses() {
        let resolved = config(r#"trusted_proxies = ["10.0.0.0/8", "192.0.2.7", "2001:db8::/32"]"#)
            .resolve()
            .expect("failed to resolve");

        assert!(resolved.trusts(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(resolved.trusts(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))));
        assert!(resolved.trusts(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));

        assert!(!resolved.trusts(IpAddr::V4(Ipv4Addr::new(11, 1, 2, 3))));
        assert!(!resolved.trusts(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8))));
        assert!(!resolved.trusts(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1))));
    }

    /// Naming a header without saying whose word to take for it would believe every client, so
    /// it is rejected rather than guessed at.
    #[test]
    fn trusted_proxies_are_required() {
        let e = config(r#"header = "x-forwarded-for""#).resolve().expect_err("expected a missing-proxies error");
        assert!(e.to_string().contains("trusted_proxies"), "{e}");

        let e = config("trusted_proxies = []").resolve().expect_err("expected a missing-proxies error");
        assert!(e.to_string().contains("trusted_proxies"), "{e}");
    }

    #[test]
    fn malformed_values_are_rejected() {
        let e = config(r#"trusted_proxies = ["10.0.0.0/8", "not-an-address"]"#)
            .resolve()
            .expect_err("expected an invalid-proxy error");
        assert!(e.to_string().contains("not-an-address"), "{e}");

        let e = config("header = \"not a header\"\ntrusted_proxies = [\"10.0.0.0/8\"]")
            .resolve()
            .expect_err("expected an invalid-header error");
        assert!(e.to_string().contains("not a header"), "{e}");
    }

    /// A service overriding one setting keeps the rest of the section it inherited.
    #[test]
    fn overrides_merge_into_the_inherited_section() {
        let mut listener: HttpListenerConfig = toml::from_str(
            r#"
address = "127.0.0.1"

[forwarded_for]
trusted_proxies = ["10.0.0.0/8"]
"#,
        )
        .expect("failed to parse defaults");

        let service: HttpListenerConfig = toml::from_str(
            r#"
[forwarded_for]
header = "x-real-ip"
"#,
        )
        .expect("failed to parse service section");

        listener.update_from(&service);
        let resolved = listener.resolve().expect("failed to resolve").forwarded_for.expect("no forwarded_for");

        assert_eq!(resolved.header.as_str(), "x-real-ip");
        assert!(resolved.trusts(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
    }

    /// A listener that says nothing about forwarding does not consult any header.
    #[test]
    fn omitting_the_section_leaves_no_forwarding() {
        let listener: HttpListenerConfig = toml::from_str(r#"address = "127.0.0.1""#).expect("failed to parse");

        assert!(listener.resolve().expect("failed to resolve").forwarded_for.is_none());
    }
}
