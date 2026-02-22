use {
    crate::{ConfigError, ServiceConfig},
    serde::Deserialize,
    std::{fmt::Debug, fs::File, io::Read, path::Path},
    toml::from_slice as toml_from_slice,
};

/// The configuration data for the server, as specified by the user. This allows for optional fields and references
/// to files for things like TLS certificates and keys.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub service: Option<ServiceConfig>,
}

impl Config {
    pub fn read_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        match File::open(path) {
            Err(e) => Err(ConfigError::IO(e)),
            Ok(mut file) => {
                let metadata = file.metadata()?;
                let mut raw = Vec::with_capacity(metadata.len() as usize);
                file.read_to_end(&mut raw)?;
                toml_from_slice(&raw).map_err(Into::into)
            }
        }
    }
}
