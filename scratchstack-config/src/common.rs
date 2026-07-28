//! Configuration common to all Scratchstack services.
use {
    crate::{
        ConfigError, DatabaseConfig, HttpListenerConfig, Resolvable, ResolvedDatabaseConfig,
        ResolvedHttpListenerConfig, ResolvedRuntimeConfig, ResolvedScopeConfig, RuntimeConfig, ScopeConfig,
    },
    serde::Deserialize,
};

/// Configuration schema common to all Scratchstack services.
///
/// Service configuration types embed this via `#[serde(flatten)]` so the common sections appear
/// at the top level of the service's configuration file alongside any service-specific sections.
#[derive(Clone, Debug, Deserialize)]
pub struct CommonServiceConfig {
    /// HTTP listener configuration.
    #[serde(default)]
    pub listener: Option<HttpListenerConfig>,

    /// Cloud scope configuration.
    pub scope: ScopeConfig,

    /// Database configuration.
    pub database: DatabaseConfig,

    /// Runtime configuration.
    pub runtime: RuntimeConfig,
}

/// Resolved configuration common to all Scratchstack services.
#[derive(Clone, Debug)]
pub struct ResolvedCommonServiceConfig {
    /// HTTP listener configuration
    pub listener: ResolvedHttpListenerConfig,

    /// Cloud scope configuration.
    pub scope: ResolvedScopeConfig,

    /// Database configuration.
    pub database: ResolvedDatabaseConfig,

    /// Runtime configuration.
    pub runtime: ResolvedRuntimeConfig,
}

impl Resolvable for CommonServiceConfig {
    type Resolved = ResolvedCommonServiceConfig;

    fn resolve(&self) -> Result<Self::Resolved, ConfigError> {
        let listener = if let Some(listener) = &self.listener {
            listener.resolve()?
        } else {
            ResolvedHttpListenerConfig::default()
        };

        let scope = self.scope.resolve()?;
        let database = self.database.resolve()?;
        let runtime = self.runtime.resolve()?;

        Ok(ResolvedCommonServiceConfig {
            listener,
            scope,
            database,
            runtime,
        })
    }
}

#[cfg(test)]
mod tests {
    use {super::CommonServiceConfig, crate::Resolvable, serde::Deserialize, std::time::Duration};

    /// A service configuration as a service crate would define it: common sections flattened to
    /// the top level of the file, plus a service-specific section alongside them.
    #[derive(Clone, Debug, Deserialize)]
    struct TestServiceConfig {
        #[serde(flatten)]
        common: CommonServiceConfig,

        signing: TestSigningConfig,
    }

    #[derive(Clone, Debug, Deserialize)]
    struct TestSigningConfig {
        key_id: String,
    }

    #[test]
    fn test_flattened_service_config() {
        let config: TestServiceConfig = toml::from_str(
            r#"
[scope]
region = "us-east-1"

[database]
url = "postgresql://localhost/scratchstack"
connection_timeout = "30s"

[runtime]
threads = 2

[signing]
key_id = "test-key"
"#,
        )
        .unwrap();

        assert!(config.common.listener.is_none());
        assert_eq!(config.common.scope.region.as_deref(), Some("us-east-1"));
        assert_eq!(config.common.database.connection_timeout, Some(Duration::from_secs(30)));
        assert_eq!(config.signing.key_id, "test-key");

        let resolved = config.common.resolve().unwrap();
        assert_eq!(resolved.scope.region, "us-east-1");
        assert_eq!(resolved.database.url, "postgresql://localhost/scratchstack");
        assert_eq!(resolved.runtime.threads, 2);
    }
}
