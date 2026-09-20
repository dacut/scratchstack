//! Runtime configuration types.
use {
    crate::{Resolvable, error::ConfigError},
    bon::Builder,
    serde::Deserialize,
};

/// The default number of threads to use if none is specified.
const DEFAULT_THREADS: usize = 1;

/// Runtime configuration for a service.
///
/// To create a `RuntimeConfig` instance programmatically, use
/// [`RuntimeConfig::builder()`][RuntimeConfig::builder].
#[derive(Builder, Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    /// The number of threads to use for the service. If unspecified, defaults to the number of
    /// cores on the machine.
    #[serde(default)]
    threads: Option<usize>,
}

/// Resolved runtime configuration for a service.
///
/// This is typically obtained by calling [`resolve()`][RuntimeConfig::resolve] on a
/// [`RuntimeConfig`] instance.
#[derive(Builder, Clone, Copy, Debug)]
#[non_exhaustive]
pub struct ResolvedRuntimeConfig {
    /// The number of threads to use for the service.
    pub threads: usize,
}

impl Resolvable for RuntimeConfig {
    type Resolved = ResolvedRuntimeConfig;

    fn resolve(&self) -> Result<Self::Resolved, ConfigError> {
        let threads = self.threads.unwrap_or(DEFAULT_THREADS);

        Ok(ResolvedRuntimeConfig {
            threads,
        })
    }
}
