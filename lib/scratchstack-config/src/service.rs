use {
    super::{DatabaseConfig, ResolvedServiceConfig, TlsConfig},
    crate::error::ConfigError,
    serde::Deserialize,
    std::{
        fmt::Debug,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    },
};

const DEFAULT_PORT: u16 = 8080;

#[inline]
const fn get_default_port() -> u16 {
    DEFAULT_PORT
}

#[inline]
const fn get_default_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[inline]
const fn get_default_threads() -> usize {
    1
}

fn get_default_partition() -> String {
    "aws".into()
}

/// The configuration data for the server, as specified by the user. This allows for optional fields and references
/// to files for things like TLS certificates and keys.
#[derive(Debug, Deserialize)]
pub struct ServiceConfig {
    #[serde(default = "get_default_port")]
    pub port: u16,

    #[serde(default = "get_default_address")]
    pub address: IpAddr,

    #[serde(default = "get_default_partition")]
    pub partition: String,

    pub region: String,

    #[serde(default)]
    pub tls: Option<TlsConfig>,

    #[serde(rename = "threads", default = "get_default_threads")]
    pub threads: usize,

    #[serde(rename = "database")]
    pub database: DatabaseConfig,
}

impl ServiceConfig {
    pub fn resolve(&self) -> Result<ResolvedServiceConfig, ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::InvalidPort);
        }

        if self.partition.is_empty() {
            return Err(ConfigError::InvalidPartition);
        }

        if self.region.is_empty() {
            return Err(ConfigError::InvalidRegion);
        }

        let tls_config = match &self.tls {
            None => None,
            Some(c) => Some(c.to_server_config()?),
        };

        Ok(ResolvedServiceConfig {
            address: SocketAddr::new(self.address, self.port),
            partition: self.partition.clone(),
            region: self.region.clone(),
            threads: self.threads,
            tls: tls_config,
            database_url: self.database.get_database_url()?,
            pool_options: self.database.get_pool_options()?,
        })
    }
}
