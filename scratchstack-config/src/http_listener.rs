//! HTTP listener configuration for a service. This module provides the [`HttpListenerConfig`]
//! struct.

use {
    super::TlsConfig,
    crate::{Resolvable, error::ConfigError},
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
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HttpListenerConfig {
    /// The IP address to listen on. Defaults to the localhost address (`::1`), which does
    /// not accept external connections.
    #[serde(default)]
    address: Option<IpAddr>,

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
#[derive(Clone)]
pub struct ResolvedHttpListenerConfig {
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
        match self.address() {
            IpAddr::V4(ipv4) => SocketAddr::V4(SocketAddrV4::new(ipv4, self.port())),
            IpAddr::V6(ipv6) => SocketAddr::V6(SocketAddrV6::new(ipv6, self.port(), 0, 0)),
        }
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
        if let Some(port) = other.port {
            self.port = Some(port);
        }
        if let Some(tls) = &other.tls {
            self.tls = Some(tls.clone());
        }
    }
}

impl Resolvable for HttpListenerConfig {
    type Resolved = ResolvedHttpListenerConfig;
    fn resolve(&self) -> Result<Self::Resolved, ConfigError> {
        Ok(ResolvedHttpListenerConfig {
            socket_addr: self.socket_addr(),
            tls: self.tls_config()?,
        })
    }
}

impl Debug for ResolvedHttpListenerConfig {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("ResolvedHttpListenerConfig")
            .field("socket_addr", &self.socket_addr.ip())
            .field("tls", &self.tls.as_ref().map(|_| "<present>").unwrap_or("<absent>"))
            .finish()
    }
}

impl Default for ResolvedHttpListenerConfig {
    fn default() -> Self {
        Self {
            socket_addr: SocketAddr::new(DEFAULT_ADDRESS, 80),
            tls: None,
        }
    }
}
