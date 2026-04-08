use {
    crate::{BaseServiceConfig, DatabaseConfig, ResolvedBaseServiceConfig, ResolvedDatabaseConfig, error::ConfigError},
    serde::Deserialize,
    std::fmt::Debug,
};

/// Service configuration for Identity and Access Management (IAM).
#[derive(Debug, Deserialize)]
pub struct Iam {
    /// The base configuration for the IAM service.
    #[serde(flatten)]
    pub base: BaseServiceConfig,

    /// The database configuration for the IAM service.
    #[serde(flatten)]
    pub database: DatabaseConfig,
}

/// The resolved configuration for IAM after validating fields and resolving any references.
#[derive(Debug)]
pub struct ResolvedIam {
    /// The resolved base configuration for the IAM service.
    pub service: ResolvedBaseServiceConfig,

    /// The resolved database configuration for the IAM service.
    pub database: ResolvedDatabaseConfig,
}

impl Iam {
    /// Resolve the configuration by validating fields and resolving any references.
    pub async fn resolve(&self) -> Result<ResolvedIam, ConfigError> {
        let service = self.base.resolve()?;
        let database = self.database.resolve().await?;

        Ok(ResolvedIam {
            service,
            database,
        })
    }
}
