use {
    super::{BaseServiceConfig, ResolvedBaseServiceConfig},
    crate::{DatabaseConfig, ResolvedDatabaseConfig, error::ConfigError},
    serde::Deserialize,
    std::fmt::Debug,
};

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
    pub async fn resolve(&self) -> Result<ResolvedIam, ConfigError> {
        let service = self.base.resolve()?;
        let database = self.database.resolve().await?;

        Ok(ResolvedIam {
            service,
            database,
        })
    }
}
