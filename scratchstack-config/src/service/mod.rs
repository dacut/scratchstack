mod iam;
mod sts;

use {
    super::TlsConfig,
    crate::error::ConfigError,
    serde::Deserialize,
    std::{
        fmt::{Debug, Formatter, Result as FmtResult},
        net::{IpAddr, Ipv6Addr, SocketAddr},
    },
    tokio_rustls::rustls::ServerConfig as TlsServerConfig,
};

pub use self::{
    iam::{Iam, ResolvedIam},
    sts::{Sts, ResolvedSts},
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

/// Base configuration data for a service. This allows for optional fields and references  to files for things like
/// TLS certificates and keys.
#[derive(Debug, Deserialize)]
pub struct BaseServiceConfig {
    #[serde(default)]
    pub address: Option<IpAddr>,

    #[serde(default)]
    pub port: Option<u16>,

    #[serde(default)]
    pub partition: Option<String>,

    pub region: String,

    #[serde(default)]
    pub tls: Option<TlsConfig>,

    #[serde(default)]
    pub threads: Option<usize>,
}

impl BaseServiceConfig {
    pub fn resolve(&self, default_port: u16) -> Result<ResolvedBaseServiceConfig, ConfigError> {
        let address = self.address.unwrap_or(DEFAULT_ADDRESS);

        let port = self.port.unwrap_or(default_port);
        if port == 0 {
            return Err(ConfigError::InvalidPort);
        }

        let partition = self.partition.clone().unwrap_or_else(|| DEFAULT_PARTITION.to_string());
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

/// The resolved configuration: optional values have been replaced
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
