//! Runtime configuration types.
use {
    crate::{Resolvable, error::ConfigError},
    bon::Builder,
    serde::Deserialize,
};

/// The default number of threads to use if none is specified.
const DEFAULT_THREADS: usize = 1;

/// Runtime configuration for a service.
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
/// This struct is `#[non_exhaustive]`: outside this crate it must be built with
/// [`ResolvedRuntimeConfig::builder`] rather than struct literal syntax, so that adding a field stays a
/// non-breaking change. The fields remain public for reading.
///
/// ```compile_fail,E0639
/// # use scratchstack_config::ResolvedRuntimeConfig;
/// let _ = ResolvedRuntimeConfig {
///     threads: 4,
/// };
/// ```
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
