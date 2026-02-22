use {
    super::{BaseServiceConfig, ResolvedBaseServiceConfig},
    crate::{error::ConfigError, DatabaseConfig, ResolvedDatabaseConfig},
    serde::Deserialize,
    std::fmt::Debug,
};

const DEFAULT_PORT: u16 = 8150;

/// Service configuration for Identity and Access Management (IAM).
#[derive(Debug, Deserialize)]
pub struct Iam {
    #[serde(flatten)]
    pub base: BaseServiceConfig,

    #[serde(rename = "database")]
    pub database: DatabaseConfig,
}

#[derive(Debug)]
pub struct ResolvedIam {
    pub service: ResolvedBaseServiceConfig,
    pub database: ResolvedDatabaseConfig,
}

impl Iam {
    pub fn resolve(&self) -> Result<ResolvedIam, ConfigError> {
        let service = self.base.resolve(DEFAULT_PORT)?;
        let database = self.database.resolve()?;

        Ok(ResolvedIam {
            service,
            database,
        })
    }
}
