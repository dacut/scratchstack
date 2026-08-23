//! Configuration common to all Scratchstack services.
use {
    crate::{
        ConfigError, DatabaseConfig, HttpListenerConfig, Resolvable, ResolvedDatabaseConfig,
        ResolvedHttpListenerConfig, ResolvedRuntimeConfig, ResolvedScopeConfig, RuntimeConfig, ScopeConfig,
    },
    bon::Builder,
    serde::Deserialize,
};

/// Configuration schema common to all Scratchstack services.
///
/// Service configuration types embed this via `#[serde(flatten)]` so the common sections appear
/// at the top level of the service's configuration file alongside any service-specific sections.
///
/// This struct is `#[non_exhaustive]`: outside this crate it must be built with
/// [`CommonServiceConfig::builder`] rather than struct literal syntax, so that adding a field stays a
/// non-breaking change. The fields remain public for reading.
///
/// ```compile_fail,E0639
/// # use scratchstack_config::CommonServiceConfig;
/// let _ = CommonServiceConfig {
///     listener: None,
/// };
/// ```
#[derive(Builder, Clone, Debug, Deserialize)]
#[non_exhaustive]
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
///
/// This struct is `#[non_exhaustive]`: outside this crate it must be built with
/// [`ResolvedCommonServiceConfig::builder`] rather than struct literal syntax, so that adding a field stays a
/// non-breaking change. The fields remain public for reading.
///
/// ```compile_fail,E0639
/// # use scratchstack_config::ResolvedCommonServiceConfig;
/// let _ = ResolvedCommonServiceConfig {
///     runtime: todo!(),
/// };
/// ```
#[derive(Builder, Clone, Debug)]
#[non_exhaustive]
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
    use {
        super::CommonServiceConfig,
        crate::{
            DatabaseConfig, HttpListenerConfig, Resolvable, ResolvedScopeConfig, RuntimeConfig, ScopeConfig, TlsConfig,
        },
        serde::Deserialize,
        std::time::Duration,
    };

    #[test]
    fn smoke_builders() {
        let scope = ScopeConfig::builder().region("us-east-1").build();
        assert_eq!(scope.region.as_deref(), Some("us-east-1"));
        assert!(scope.partition.is_none());

        let db = DatabaseConfig::builder().url("postgresql://localhost/x").port(5432u16).build();
        assert_eq!(db.url.as_deref(), Some("postgresql://localhost/x"));

        let listener = HttpListenerConfig::builder().port(8080u16).build();
        assert_eq!(listener.port(), 8080);

        let rt = RuntimeConfig::builder().threads(4usize).build();
        let common = CommonServiceConfig::builder().scope(scope).database(db).runtime(rt).listener(listener).build();
        assert_eq!(common.runtime.resolve().unwrap().threads, 4);

        let tls = TlsConfig::builder().certificate_chain_file("/tmp/c.pem").private_key_file("/tmp/k.pem").build();
        assert_eq!(tls.certificate_chain_file, "/tmp/c.pem");

        let rscope = ResolvedScopeConfig::builder().partition("aws").region("us-east-1").build();
        assert_eq!(rscope.partition, "aws");
    }

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
