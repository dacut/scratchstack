//! HTTP listener configuration for a service. This module provides the [`HttpListenerConfig`]
//! struct.

use {
    super::TlsConfig,
    crate::{ForwardedForConfig, Resolvable, ResolvedForwardedForConfig, error::ConfigError},
    bon::Builder,
    rustls::ServerConfig as TlsServerConfig,
    serde::Deserialize,
    std::{
        fmt::{Debug, Formatter, Result as FmtResult},
        net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    },
};

/// The default address to listen on if none is specified. This is the localhost address (`::1`),
/// which does not accept external connections.
pub const DEFAULT_ADDRESS: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

/// HTTP listener configuration data for a service. This allows for optional fields and references
/// to files for the TLS configuration.
#[derive(Builder, Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpListenerConfig {
    /// The IP address to listen on. Defaults to the localhost address (`::1`), which does
    /// not accept external connections.
    #[serde(default)]
    address: Option<IpAddr>,

    /// How to recover the client address when this service sits behind a load balancer. If
    /// unspecified, the address the connection came from is used.
    #[serde(default)]
    forwarded_for: Option<ForwardedForConfig>,

    /// The port to listen on. Defaults to port 80 if a TLS configuration is not specified, or
    /// port 443 if a TLS configuration is specified.
    #[serde(default)]
    port: Option<u16>,

    /// TLS configuration for the service. If unspecified, TLS will be disabled.
    #[serde(default)]
    tls: Option<TlsConfig>,
}

/// Resolved HTTP listener configuration data for a service. Optional fields and references to files
/// from [`HttpListenerConfig`] have been resolved and defaults have been applied.
///
/// This struct is `#[non_exhaustive]`: outside this crate it must be built with
/// [`ResolvedHttpListenerConfig::builder`] rather than struct literal syntax, so that adding a field stays a
/// non-breaking change. The fields remain public for reading.
///
/// ```compile_fail,E0639
/// # use scratchstack_config::ResolvedHttpListenerConfig;
/// let _ = ResolvedHttpListenerConfig {
///     tls: None,
/// };
/// ```
#[derive(Builder, Clone)]
#[non_exhaustive]
pub struct ResolvedHttpListenerConfig {
    /// How to recover the client address of a forwarded request, if this service sits behind a
    /// load balancer.
    pub forwarded_for: Option<ResolvedForwardedForConfig>,

    /// The socket address to listen on.
    pub socket_addr: SocketAddr,

    /// TLS configuration for the service.
    pub tls: Option<TlsServerConfig>,
}

impl HttpListenerConfig {
    /// Returns the HTTP listener address, or `::1` (localhost) if a listener address has not
    /// been specified.
    #[inline(always)]
    pub fn address(&self) -> IpAddr {
        self.address.unwrap_or(DEFAULT_ADDRESS)
    }

    /// Returns the HTTP listener port, defaulting to either 80 (HTTP) or 443 (HTTPS) if a port has
    /// not been specified.
    ///
    /// The default is 443 if a TLS configuration was provided; otherwise 80 is used.
    #[inline(always)]
    pub fn port(&self) -> u16 {
        match (self.port, &self.tls) {
            (Some(port), _) => port,
            (None, Some(_)) => 443,
            (None, None) => 80,
        }
    }

    /// Returns the socket address to listen on, combining the resolved IP address and port.
    pub fn socket_addr(&self) -> SocketAddr {
        self.socket_addr_with_default_port(self.port())
    }

    /// Returns the socket address to listen on, using `default_port` if this configuration does
    /// not specify a port.
    ///
    /// Services each listen on their own port, so the port a service falls back to is a property
    /// of the service rather than of the configuration file; this lets the caller supply it.
    pub fn socket_addr_with_default_port(&self, default_port: u16) -> SocketAddr {
        let port = self.port.unwrap_or(default_port);
        match self.address() {
            IpAddr::V4(ipv4) => SocketAddr::V4(SocketAddrV4::new(ipv4, port)),
            IpAddr::V6(ipv6) => SocketAddr::V6(SocketAddrV6::new(ipv6, port, 0, 0)),
        }
    }

    /// Returns the resolved forwarded-header configuration for the service if one was specified.
    /// This may return an error if the configuration is invalid.
    pub fn forwarded_for_config(&self) -> Result<Option<ResolvedForwardedForConfig>, ConfigError> {
        self.forwarded_for.as_ref().map(Resolvable::resolve).transpose()
    }

    /// Returns the TLS server configuration for the service if one was specified. This may return
    /// an error if the TLS configuration is invalid.
    pub fn tls_config(&self) -> Result<Option<TlsServerConfig>, ConfigError> {
        if let Some(tls) = self.tls.as_ref() {
            Ok(Some(tls.try_into()?))
        } else {
            Ok(None)
        }
    }

    /// Updates this configuration with values from another configuration. This is used to apply
    /// overrides from a service-specific configuration to the base configuration.
    pub fn update_from(&mut self, other: &HttpListenerConfig) {
        if let Some(address) = other.address {
            self.address = Some(address);
        }
        if let Some(forwarded_for) = &other.forwarded_for {
            // Merge rather than replace, so a service can override one setting -- the header, or
            // the trusted proxies -- without restating the section inherited from the defaults.
            match &mut self.forwarded_for {
                Some(current) => current.update_from(forwarded_for),
                None => self.forwarded_for = Some(forwarded_for.clone()),
            }
        }
        if let Some(port) = other.port {
            self.port = Some(port);
        }
        if let Some(tls) = &other.tls {
            self.tls = Some(tls.clone());
        }
    }

    /// Resolve this configuration, using `default_port` if it does not specify a port.
    pub fn resolve_with_default_port(&self, default_port: u16) -> Result<ResolvedHttpListenerConfig, ConfigError> {
        Ok(ResolvedHttpListenerConfig {
            forwarded_for: self.forwarded_for_config()?,
            socket_addr: self.socket_addr_with_default_port(default_port),
            tls: self.tls_config()?,
        })
    }
}

impl Resolvable for HttpListenerConfig {
    type Resolved = ResolvedHttpListenerConfig;
    fn resolve(&self) -> Result<Self::Resolved, ConfigError> {
        Ok(ResolvedHttpListenerConfig {
            forwarded_for: self.forwarded_for_config()?,
            socket_addr: self.socket_addr(),
            tls: self.tls_config()?,
        })
    }
}

impl Debug for ResolvedHttpListenerConfig {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("ResolvedHttpListenerConfig")
            .field("forwarded_for", &self.forwarded_for)
            .field("socket_addr", &self.socket_addr)
            .field("tls", &self.tls.as_ref().map(|_| "<present>").unwrap_or("<absent>"))
            .finish()
    }
}

impl Default for ResolvedHttpListenerConfig {
    fn default() -> Self {
        Self {
            forwarded_for: None,
            socket_addr: SocketAddr::new(DEFAULT_ADDRESS, 80),
            tls: None,
        }
    }
}
