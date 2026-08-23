//! Cloud scope configuration types.

use {
    crate::{Resolvable, error::ConfigError},
    bon::Builder,
    scratchstack_arn::utils::{validate_partition, validate_region},
    serde::Deserialize,
};

/// The default cloud partition to use if none is specified.
pub const DEFAULT_PARTITION: &str = "aws";

/// Cloud scope configuration for a service.
///
/// This struct is `#[non_exhaustive]`: outside this crate it must be built with
/// [`ScopeConfig::builder`] rather than struct literal syntax, so that adding a field stays a
/// non-breaking change. The fields remain public for reading.
///
/// ```compile_fail,E0639
/// # use scratchstack_config::ScopeConfig;
/// let _ = ScopeConfig {
///     region: Some("us-east-1".to_string()),
/// };
/// ```
#[derive(Builder, Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ScopeConfig {
    /// The cloud partition this service is running in.
    #[builder(into)]
    pub partition: Option<String>,

    /// The region this service is running in. This must be specified.
    #[builder(into)]
    pub region: Option<String>,
}

/// Resolved cloud scope configuration for a service.
///
/// This struct is `#[non_exhaustive]`: outside this crate it must be built with
/// [`ResolvedScopeConfig::builder`] rather than struct literal syntax, so that adding a field stays a
/// non-breaking change. The fields remain public for reading.
///
/// ```compile_fail,E0639
/// # use scratchstack_config::ResolvedScopeConfig;
/// let _ = ResolvedScopeConfig {
///     partition: "aws".to_string(),
/// };
/// ```
#[derive(Builder, Clone, Debug)]
#[non_exhaustive]
pub struct ResolvedScopeConfig {
    /// The cloud partition this service is running in.
    #[builder(into)]
    pub partition: String,

    /// The region this service is running in.
    #[builder(into)]
    pub region: String,
}

impl ScopeConfig {
    /// Updates this configuration with values from another configuration. This is used to apply
    /// overrides from a service-specific configuration to the base configuration.
    pub fn update_from(&mut self, other: &ScopeConfig) {
        if let Some(partition) = &other.partition {
            self.partition = Some(partition.clone());
        }

        if let Some(region) = &other.region {
            self.region = Some(region.clone());
        }
    }
}

impl Resolvable for ScopeConfig {
    type Resolved = ResolvedScopeConfig;

    fn resolve(&self) -> Result<Self::Resolved, ConfigError> {
        let partition = self.partition.clone().unwrap_or_else(|| DEFAULT_PARTITION.to_string());
        let region = self.region.clone().ok_or(ConfigError::MissingRegion)?;

        if validate_partition(&partition).is_err() {
            return Err(ConfigError::InvalidPartition);
        }

        if validate_region(&region).is_err() {
            return Err(ConfigError::InvalidRegion);
        }

        Ok(ResolvedScopeConfig {
            partition,
            region,
        })
    }
}
