use {
    sqlx::{any::Any as AnyDB, pool::PoolOptions},
    std::{
        fmt::{Debug, Formatter, Result as FmtResult},
        net::SocketAddr,
    },
    tokio_rustls::rustls::ServerConfig as TlsServerConfig,
};

/// The resolved configuration: optional values have been replaced
pub struct ResolvedServiceConfig {
    pub address: SocketAddr,
    pub partition: String,
    pub region: String,
    pub threads: usize,
    pub tls: Option<TlsServerConfig>,
    pub database_url: String,
    pub pool_options: PoolOptions<AnyDB>,
}

impl Debug for ResolvedServiceConfig {
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
            .field("database_url", &self.database_url)
            .field("pool_options", &self.pool_options)
            .finish()
    }
}
