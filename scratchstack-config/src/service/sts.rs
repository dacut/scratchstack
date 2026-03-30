use {
    super::{BaseServiceConfig, ResolvedBaseServiceConfig},
    crate::{DatabaseConfig, ResolvedDatabaseConfig, error::ConfigError},
    serde::Deserialize,
    std::fmt::Debug,
};

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
    pub async fn resolve(&self) -> Result<ResolvedSts, ConfigError> {
        let service = self.base.resolve()?;
        let database = self.database.resolve().await?;

        Ok(ResolvedSts {
            service,
            database,
        })
    }
}
