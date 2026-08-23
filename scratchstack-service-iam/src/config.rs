//! Scratchstack IAM service configuration types.
use {
    bon::Builder,
    scratchstack_config::{
        CommonServiceConfig, ConfigError, Resolvable, ResolvedCommonServiceConfig, read_config_file,
    },
    serde::Deserialize,
    std::path::Path,
};

/// Configuration schema for the Scratchstack IAM service.
#[derive(Builder, Clone, Debug, Deserialize)]
pub struct IamServiceConfig {
    /// Configuration common to all Scratchstack services.
    #[serde(flatten)]
    pub common: CommonServiceConfig,
}

/// Resolved configuration for the Scratchstack IAM service.
#[derive(Builder, Clone, Debug)]
pub struct ResolvedIamServiceConfig {
    /// Configuration common to all Scratchstack services.
    pub common: ResolvedCommonServiceConfig,
}

impl IamServiceConfig {
    /// Reads the IAM service configuration from a file.
    pub fn read_file(path: &Path) -> Result<Self, ConfigError> {
        read_config_file(path)
    }
}

impl Resolvable for IamServiceConfig {
    type Resolved = ResolvedIamServiceConfig;

    fn resolve(&self) -> Result<Self::Resolved, ConfigError> {
        Ok(ResolvedIamServiceConfig {
            common: self.common.resolve()?,
        })
    }
}
