//! Runtime configuration types.
use {
    crate::{Resolvable, error::ConfigError},
    serde::Deserialize,
};

/// The default number of threads to use if none is specified.
const DEFAULT_THREADS: usize = 1;

/// Runtime configuration for a service.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    /// The number of threads to use for the service. If unspecified, defaults to the number of
    /// cores on the machine.
    #[serde(default)]
    threads: Option<usize>,
}

/// Resolved runtime configuration for a service.
#[derive(Clone, Copy, Debug)]
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
