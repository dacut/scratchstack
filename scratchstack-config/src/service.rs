//! Top-level configuration for a Scratchstack deployment.
//!
//! A deployment is described by a single configuration file holding the process-global runtime
//! settings, a set of named databases, a `defaults` section inherited by every service, and one
//! section per service:
//!
//! ```toml
//! [runtime]
//! threads = 20
//!
//! [defaults.scope]
//! partition = "local"
//! region = "local"
//!
//! [database.primary]
//! host = "localhost"
//! database = "scratchstack_iam"
//!
//! [iam]
//! database_ref = "primary"
//!
//! [iam.listener]
//! port = 7401
//! ```
//!
//! Service sections inherit `listener` and `scope` settings from `defaults`, overriding
//! individual values. `runtime` is deliberately not inheritable: one process runs one Tokio
//! runtime, so a per-service override could not be honored.
//!
//! Two services naming the same database are expected to share a single connection pool; callers
//! build one pool per distinct [`ResolvedServiceConfig::database_name`] rather than one per
//! service.

use {
    crate::{
        ConfigError, DatabaseConfig, HttpListenerConfig, Resolvable, ResolvedDatabaseConfig,
        ResolvedHttpListenerConfig, ResolvedRuntimeConfig, ResolvedScopeConfig, RuntimeConfig, ScopeConfig,
        read_config_file,
    },
    bon::Builder,
    serde::Deserialize,
    std::{collections::HashMap, path::Path},
};

/// The database a service connects to when its section does not name one.
pub const DEFAULT_DATABASE_NAME: &str = "default";

/// Settings inherited by every service section.
///
/// A service section overrides individual values from this section; anything it leaves unset is
/// taken from here. Note that a listener `port` set here would be inherited by every service and
/// leave all but one of them unable to bind, so ports belong in the service sections.
///
/// This struct is `#[non_exhaustive]`: outside this crate it must be built with
/// [`DefaultsConfig::builder`] rather than struct literal syntax, so that adding a field stays a
/// non-breaking change. The fields remain public for reading.
///
/// ```compile_fail,E0639
/// # use scratchstack_config::DefaultsConfig;
/// let _ = DefaultsConfig {
///     scope: None,
/// };
/// ```
#[derive(Builder, Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct DefaultsConfig {
    /// HTTP listener settings inherited by each service.
    #[serde(default)]
    pub listener: Option<HttpListenerConfig>,

    /// Cloud scope settings inherited by each service.
    #[serde(default)]
    pub scope: Option<ScopeConfig>,
}

/// Configuration for a single Scratchstack service.
///
/// This struct is `#[non_exhaustive]`: outside this crate it must be built with
/// [`ServiceConfig::builder`] rather than struct literal syntax, so that adding a field stays a
/// non-breaking change. The fields remain public for reading.
///
/// ```compile_fail,E0639
/// # use scratchstack_config::ServiceConfig;
/// let _ = ServiceConfig {
///     scope: None,
/// };
/// ```
#[derive(Builder, Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ServiceConfig {
    /// Whether this service is enabled. Defaults to `true`.
    #[builder(default = true)]
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// The name of the database this service connects to, from the `database` table. Defaults to
    /// [`DEFAULT_DATABASE_NAME`].
    #[builder(into)]
    #[serde(default)]
    pub database_ref: Option<String>,

    /// HTTP listener settings for this service, overriding the defaults section.
    #[serde(default)]
    pub listener: Option<HttpListenerConfig>,

    /// Cloud scope settings for this service, overriding the defaults section.
    #[serde(default)]
    pub scope: Option<ScopeConfig>,
}

/// The default value for the enabled attribute of a service section.
#[inline(always)]
fn default_enabled() -> bool {
    true
}

/// Top-level configuration for a Scratchstack deployment.
///
/// Service sections are collected by name rather than declared as fields, so that one
/// configuration file can describe every service regardless of which of them a given binary was
/// built with. Use [`ScratchstackConfig::validate_service_names`] to reject names no service in
/// the project claims.
///
/// This struct is `#[non_exhaustive]`: outside this crate it must be built with
/// [`ScratchstackConfig::builder`] rather than struct literal syntax, so that adding a field stays
/// a non-breaking change. The fields remain public for reading.
///
/// ```compile_fail,E0639
/// # use scratchstack_config::ScratchstackConfig;
/// let _ = ScratchstackConfig {
///     runtime: None,
/// };
/// ```
#[derive(Builder, Clone, Debug, Default, Deserialize)]
#[non_exhaustive]
pub struct ScratchstackConfig {
    /// The databases available to services, keyed by name.
    #[serde(default)]
    pub database: HashMap<String, DatabaseConfig>,

    /// Settings inherited by every service section.
    #[serde(default)]
    pub defaults: Option<DefaultsConfig>,

    /// Process-global runtime settings.
    #[serde(default)]
    pub runtime: Option<RuntimeConfig>,

    /// Per-service settings, keyed by service name.
    ///
    /// This collects every top-level table that is not one of the fields above, so an
    /// unrecognized name lands here rather than failing to deserialize.
    #[serde(flatten)]
    pub services: HashMap<String, ServiceConfig>,
}

/// Resolved configuration for a single Scratchstack service.
///
/// This struct is `#[non_exhaustive]`: outside this crate it must be built with
/// [`ResolvedServiceConfig::builder`] rather than struct literal syntax, so that adding a field
/// stays a non-breaking change. The fields remain public for reading.
///
/// ```compile_fail,E0639
/// # use scratchstack_config::ResolvedServiceConfig;
/// let _ = ResolvedServiceConfig {
///     database_name: "default".to_string(),
/// };
/// ```
#[derive(Builder, Clone, Debug)]
#[non_exhaustive]
pub struct ResolvedServiceConfig {
    /// Whether this service is enabled. Defaults to `true`.
    #[builder(default = true)]
    pub enabled: bool,

    /// The resolved database this service connects to.
    pub database: ResolvedDatabaseConfig,

    /// The name of the database this service connects to.
    ///
    /// Services naming the same database are expected to share one connection pool, so callers
    /// key their pools on this rather than on the service name.
    #[builder(into)]
    pub database_name: String,

    /// The resolved HTTP listener settings for this service.
    pub listener: ResolvedHttpListenerConfig,

    /// The resolved cloud scope for this service.
    pub scope: ResolvedScopeConfig,
}

impl ScratchstackConfig {
    /// Reads the Scratchstack configuration from a file.
    pub fn read_file(path: &Path) -> Result<Self, ConfigError> {
        read_config_file(path)
    }

    /// Resolve the process-global runtime settings, applying defaults if the file omits them.
    pub fn resolve_runtime(&self) -> Result<ResolvedRuntimeConfig, ConfigError> {
        self.runtime.clone().unwrap_or_default().resolve()
    }

    /// Resolve the configuration for the service named `name`, returning `None` if the
    /// configuration has no section for it.
    ///
    /// `default_port` is the port the service listens on when neither its own section nor the
    /// defaults section specifies one.
    pub fn resolve_service(&self, name: &str, default_port: u16) -> Result<Option<ResolvedServiceConfig>, ConfigError> {
        let Some(service) = self.services.get(name) else {
            return Ok(None);
        };

        let defaults = self.defaults.clone().unwrap_or_default();

        // Start from the inherited settings and let the service's own values override them.
        let mut listener = defaults.listener.unwrap_or_default();
        if let Some(service_listener) = &service.listener {
            listener.update_from(service_listener);
        }

        let mut scope = defaults.scope.unwrap_or_default();
        if let Some(service_scope) = &service.scope {
            scope.update_from(service_scope);
        }

        let database_name = service.database_ref.as_deref().unwrap_or(DEFAULT_DATABASE_NAME);
        let Some(database) = self.database.get(database_name) else {
            let mut defined: Vec<&str> = self.database.keys().map(String::as_str).collect();
            defined.sort_unstable();
            let defined = if defined.is_empty() {
                "none are defined".to_string()
            } else {
                format!("defined databases: {}", defined.join(", "))
            };
            return Err(ConfigError::InvalidConfig(format!(
                "Service '{name}' references database '{database_name}', but {defined}"
            )));
        };

        Ok(Some(ResolvedServiceConfig {
            enabled: service.enabled,
            database: database.resolve()?,
            database_name: database_name.to_string(),
            listener: listener.resolve_with_default_port(default_port)?,
            scope: scope.resolve()?,
        }))
    }

    /// Verify that every service section names a service this project knows about.
    ///
    /// `known` must list every service the project implements, not merely those the running
    /// binary was built with, so that one configuration file can serve every build variant. A
    /// name outside that list is a typo and is rejected.
    pub fn validate_service_names(&self, known: &[&str]) -> Result<(), ConfigError> {
        let mut unknown: Vec<&str> =
            self.services.keys().map(String::as_str).filter(|name| !known.contains(name)).collect();

        if unknown.is_empty() {
            return Ok(());
        }

        unknown.sort_unstable();
        let mut known = known.to_vec();
        known.sort_unstable();

        Err(ConfigError::InvalidConfig(format!(
            "Configuration contains unknown service section(s): {}; known services: {}",
            unknown.join(", "),
            known.join(", ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{DefaultsConfig, ScratchstackConfig, ServiceConfig},
        crate::{
            DatabaseConfig, HttpListenerConfig, Resolvable, ResolvedScopeConfig, RuntimeConfig, ScopeConfig, TlsConfig,
        },
        std::{
            net::{IpAddr, Ipv4Addr},
            time::Duration,
        },
    };

    /// A deployment file exercising every section: process-global runtime, inherited defaults,
    /// a named database, and two services that share it on different ports.
    const DEPLOYMENT: &str = r#"
[runtime]
threads = 20

[defaults.scope]
partition = "local"
region = "local"

[defaults.listener]
address = "127.0.0.1"

[database.default]
database = "scratchstack_iam"
host = "localhost"
port = 7154
connection_timeout = "1s"

[iam]
database_ref = "default"

[iam.listener]
port = 7401

[sts]

[sts.scope]
region = "us-east-1"
"#;

    fn deployment() -> ScratchstackConfig {
        toml::from_str(DEPLOYMENT).expect("failed to parse deployment configuration")
    }

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
        assert_eq!(rt.resolve().unwrap().threads, 4);

        let tls = TlsConfig::builder().certificate_chain_file("/tmp/c.pem").private_key_file("/tmp/k.pem").build();
        assert_eq!(tls.certificate_chain_file, "/tmp/c.pem");

        let rscope = ResolvedScopeConfig::builder().partition("aws").region("us-east-1").build();
        assert_eq!(rscope.partition, "aws");

        let service = ServiceConfig::builder().database_ref("primary").build();
        assert_eq!(service.database_ref.as_deref(), Some("primary"));

        let defaults = DefaultsConfig::builder().scope(scope).build();
        assert!(defaults.listener.is_none());
    }

    #[test]
    fn deployment_file_parses_into_sections() {
        let config = deployment();
        assert_eq!(config.runtime.as_ref().and_then(|r| r.resolve().ok()).map(|r| r.threads), Some(20));
        assert_eq!(config.database.len(), 1);
        assert_eq!(config.database["default"].connection_timeout, Some(Duration::from_secs(1)));

        // Service sections are collected by name, not declared as fields.
        let mut services: Vec<&str> = config.services.keys().map(String::as_str).collect();
        services.sort_unstable();
        assert_eq!(services, vec!["iam", "sts"]);
    }

    #[test]
    fn service_inherits_defaults_and_applies_its_own_overrides() {
        let config = deployment();

        let iam = config.resolve_service("iam", 7401).unwrap().expect("iam section missing");
        // Address inherited from defaults, port from the service's own section.
        assert_eq!(iam.listener.socket_addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(iam.listener.socket_addr.port(), 7401);
        // Scope fully inherited.
        assert_eq!(iam.scope.partition, "local");
        assert_eq!(iam.scope.region, "local");

        let sts = config.resolve_service("sts", 7400).unwrap().expect("sts section missing");
        // No listener section at all: address still inherited, port falls back to the default.
        assert_eq!(sts.listener.socket_addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(sts.listener.socket_addr.port(), 7400);
        // Partition inherited, region overridden by the service.
        assert_eq!(sts.scope.partition, "local");
        assert_eq!(sts.scope.region, "us-east-1");
    }

    /// Services naming the same database report the same name, so a caller can key one shared
    /// connection pool on it rather than opening one pool per service.
    #[test]
    fn services_sharing_a_database_report_the_same_name() {
        let config = deployment();
        let iam = config.resolve_service("iam", 7401).unwrap().unwrap();
        let sts = config.resolve_service("sts", 7400).unwrap().unwrap();

        assert_eq!(iam.database_name, "default");
        assert_eq!(sts.database_name, "default");
        assert_eq!(iam.database.url, sts.database.url);
    }

    #[test]
    fn absent_service_section_resolves_to_none() {
        let config = deployment();
        assert!(config.resolve_service("elb", 7402).unwrap().is_none());
    }

    #[test]
    fn unknown_database_reference_is_rejected() {
        let config: ScratchstackConfig = toml::from_str(
            r#"
[defaults.scope]
region = "local"

[database.primary]
database = "scratchstack_iam"

[iam]
database_ref = "secondary"
"#,
        )
        .unwrap();

        let e = config.resolve_service("iam", 7401).expect_err("expected an unknown-database error");
        let message = e.to_string();
        assert!(message.contains("secondary"), "{message}");
        assert!(message.contains("primary"), "{message}");
    }

    /// A binary built without a service still has to accept a file describing it, so validation
    /// runs against every service the project implements rather than the compiled-in ones.
    #[test]
    fn service_names_are_validated_against_the_project_wide_list() {
        let config = deployment();
        config.validate_service_names(&["iam", "sts"]).expect("known services should validate");
        config.validate_service_names(&["iam", "sts", "elb"]).expect("extra known services are fine");

        let e = config.validate_service_names(&["iam"]).expect_err("expected an unknown-service error");
        assert!(e.to_string().contains("sts"), "{e}");
    }

    #[test]
    fn typos_inside_a_service_section_are_rejected() {
        let result: Result<ScratchstackConfig, _> = toml::from_str(
            r#"
[iam]
databse_ref = "default"
"#,
        );
        assert!(result.is_err(), "expected a deserialization error for the misspelled key");
    }
}
