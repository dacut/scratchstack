mod iam;
mod sts;

use {
    super::TlsConfig,
    crate::{DatabaseConfig, error::ConfigError},
    rustls::ServerConfig as TlsServerConfig,
    serde::Deserialize,
    std::{
        fmt::{Debug, Formatter, Result as FmtResult},
        net::{IpAddr, Ipv6Addr, SocketAddr},
    },
};

pub use self::{
    iam::{Iam, ResolvedIam},
    sts::{ResolvedSts, Sts},
};

/// Configuration for all services.
#[derive(Debug, Deserialize)]
pub struct ServiceConfig {
    pub iam: Option<Iam>,
    pub sts: Option<Sts>,
}

const DEFAULT_ADDRESS: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

const DEFAULT_PARTITION: &str = "aws";

const DEFAULT_THREADS: usize = 1;

/// Base configuration data for a service. This allows for optional fields and references to files
/// for the TLS configuration.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BaseServiceConfig {
    /// The IP address to listen on. Defaults to the localhost address (`::1`), which does
    /// not accept external connections.
    #[serde(default)]
    pub address: Option<IpAddr>,

    /// The port to listen on. If unspecified, a random port will be chosen at runtime.
    #[serde(default)]
    pub port: Option<u16>,

    /// The cloud partition this service is running in.
    #[serde(default = "BaseServiceConfig::default_partition")]
    pub partition: String,

    /// The region this service is running in. This must be specified.
    pub region: String,

    /// TLS configuration for the service. If unspecified, TLS will be disabled.
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// The number of threads to use for the service. If unspecified, defaults to the number of
    /// cores on the machine.
    #[serde(default)]
    pub threads: Option<usize>,

    /// Database configuration for the service.
    pub database: DatabaseConfig,
}

impl BaseServiceConfig {
    /// Returns the default partition to use.
    #[inline(always)]
    pub fn default_partition() -> String {
        DEFAULT_PARTITION.to_string()
    }

    /// Resolves the configuration by filling in default values and validating fields. This should be called
    /// before starting the service to ensure the configuration is valid and complete.
    pub fn resolve(&self) -> Result<ResolvedBaseServiceConfig, ConfigError> {
        let address = self.address.unwrap_or(DEFAULT_ADDRESS);
        let port = self.port.unwrap_or_default();

        let partition = self.partition.clone();
        if partition.is_empty() {
            return Err(ConfigError::InvalidPartition);
        }

        let region = self.region.clone();
        if region.is_empty() {
            return Err(ConfigError::InvalidRegion);
        }

        let threads = self.threads.unwrap_or(DEFAULT_THREADS);

        let tls = match &self.tls {
            None => None,
            Some(c) => Some(c.to_server_config()?),
        };

        Ok(ResolvedBaseServiceConfig {
            address: SocketAddr::new(address, port),
            partition,
            region,
            threads,
            tls,
        })
    }
}

/// The resolved configuration where optional values have been replaced.
pub struct ResolvedBaseServiceConfig {
    pub address: SocketAddr,
    pub partition: String,
    pub region: String,
    pub threads: usize,
    pub tls: Option<TlsServerConfig>,
}

impl Debug for ResolvedBaseServiceConfig {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let tls_debug = match &self.tls {
            None => "None",
            Some(_) => "Some(TlsServerConfig)",
        };

        f.debug_struct("ResolvedConfig")
            .field("address", &self.address)
            .field("partition", &self.partition)
            .field("region", &self.region)
            .field("threads", &self.threads)
            .field("tls", &tls_debug)
            .finish()
    }
}
