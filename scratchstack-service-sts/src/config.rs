//! Scratchstack STS service configuration types.
use {
    bon::Builder,
    scratchstack_config::{
        CommonServiceConfig, ConfigError, Resolvable, ResolvedCommonServiceConfig, read_config_file,
    },
    serde::Deserialize,
    std::path::Path,
};

/// Configuration schema for the Scratchstack STS service.
#[derive(Builder, Clone, Debug, Deserialize)]
pub struct StsServiceConfig {
    /// Configuration common to all Scratchstack services.
    #[serde(flatten)]
    pub common: CommonServiceConfig,
}

/// Resolved configuration for the Scratchstack STS service.
#[derive(Builder, Clone, Debug)]
pub struct ResolvedStsServiceConfig {
    /// Configuration common to all Scratchstack services.
    pub common: ResolvedCommonServiceConfig,
}

impl StsServiceConfig {
    /// Reads the STS service configuration from a file.
    pub fn read_file(path: &Path) -> Result<Self, ConfigError> {
        read_config_file(path)
    }
}

impl Resolvable for StsServiceConfig {
    type Resolved = ResolvedStsServiceConfig;

    fn resolve(&self) -> Result<Self::Resolved, ConfigError> {
        Ok(ResolvedStsServiceConfig {
            common: self.common.resolve()?,
        })
    }
}
