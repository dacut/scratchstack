use {
    crate::{BaseServiceConfig, DatabaseConfig, ResolvedBaseServiceConfig, ResolvedDatabaseConfig, error::ConfigError},
    serde::Deserialize,
    std::fmt::Debug,
};

/// Service configuration for Security Token Service (STS).
#[derive(Debug, Deserialize)]
pub struct Sts {
    /// The base configuration for the STS service.
    #[serde(flatten)]
    pub base: BaseServiceConfig,

    /// The database configuration for the STS service.
    #[serde(flatten)]
    pub database: DatabaseConfig,
}

/// The resolved configuration for STS after validating fields and resolving any references.
#[derive(Debug)]
pub struct ResolvedSts {
    /// The resolved base configuration for the STS service.
    pub service: ResolvedBaseServiceConfig,

    /// The resolved database configuration for the STS service.
    pub database: ResolvedDatabaseConfig,
}

impl Sts {
    /// Resolve the configuration by validating fields and resolving any references.
    pub async fn resolve(&self) -> Result<ResolvedSts, ConfigError> {
        let service = self.base.resolve()?;
        let database = self.database.resolve().await?;

        Ok(ResolvedSts {
            service,
            database,
        })
    }
}
