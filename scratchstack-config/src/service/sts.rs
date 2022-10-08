use {
    super::{BaseServiceConfig, ResolvedBaseServiceConfig},
    crate::{error::ConfigError, DatabaseConfig, ResolvedDatabaseConfig},
    serde::Deserialize,
    std::fmt::Debug,
};

const DEFAULT_PORT: u16 = 8190;

/// Service configuration for Security Token Service (STS).
#[derive(Debug, Deserialize)]
pub struct Sts {
    #[serde(flatten)]
    pub base: BaseServiceConfig,

    #[serde(rename = "database")]
    pub database: DatabaseConfig,
}

#[derive(Debug)]
pub struct ResolvedSts {
    pub service: ResolvedBaseServiceConfig,
    pub database: ResolvedDatabaseConfig,
}

impl Sts {
    pub fn resolve(&self) -> Result<ResolvedSts, ConfigError> {
        let service = self.base.resolve(DEFAULT_PORT)?;
        let database = self.database.resolve()?;

        Ok(ResolvedSts {
            service,
            database,
        })
    }
}
