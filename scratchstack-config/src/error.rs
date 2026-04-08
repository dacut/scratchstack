use {
    rustls::Error as TlsError,
    std::{
        error::Error,
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        io::Error as IOError,
        net::AddrParseError,
        str::Utf8Error,
    },
    toml::de::Error as TomlDeError,
};

/// Errors that can occur when reading or resolving the configuration.
#[derive(Debug)]
pub enum ConfigError {
    /// An error occurred while deserializing the configuration from TOML.
    DeserError(TomlDeError),

    /// An I/O error occurred while reading a file referenced in the configuration.
    IO(IOError),

    /// The configuration is invalid for some reason not covered by a more specific error variant.
    InvalidConfig(String),

    /// The TLS configuration is invalid, such as an invalid certificate or private key, or a
    /// failure to set up the TLS configuration.
    InvalidTlsConfig(TlsConfigErrorKind),

    /// The database configuration is invalid, such as an invalid hostname or a missing
    /// password.
    InvalidDatabaseConfig(DatabaseConfigErrorKind),

    /// An address specified in the configuration is invalid.
    InvalidAddress(AddrParseError),

    /// The partition specified in the configuration is invalid.
    InvalidPartition,

    /// The port specified in the configuration is invalid.
    InvalidPort,

    /// The region specified in the configuration is invalid.
    InvalidRegion,
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match &self {
            Self::DeserError(e) => write!(f, "Deserialization error: {e}"),
            Self::IO(e) => write!(f, "I/O error: {e}"),
            Self::InvalidConfig(msg) => write!(f, "Invalid config: {msg}"),
            Self::InvalidTlsConfig(e) => write!(f, "Invalid TLS configuration: {e}"),
            Self::InvalidDatabaseConfig(e) => write!(f, "Invalid database configuration: {e}"),
            Self::InvalidAddress(e) => write!(f, "Invalid address: {e}"),
            Self::InvalidPartition => write!(f, "Invalid partition"),
            Self::InvalidPort => write!(f, "Invalid port"),
            Self::InvalidRegion => write!(f, "Invalid region"),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::IO(e) => Some(e),
            Self::DeserError(e) => Some(e),
            Self::InvalidTlsConfig(TlsConfigErrorKind::TlsSetupFailed(e)) => Some(e),
            Self::InvalidDatabaseConfig(DatabaseConfigErrorKind::InvalidPasswordFileEncoding(_, e)) => Some(e),
            Self::InvalidAddress(e) => Some(e),
            _ => None,
        }
    }
}

impl From<AddrParseError> for ConfigError {
    fn from(e: AddrParseError) -> Self {
        ConfigError::InvalidAddress(e)
    }
}

impl From<DatabaseConfigErrorKind> for ConfigError {
    fn from(e: DatabaseConfigErrorKind) -> Self {
        ConfigError::InvalidDatabaseConfig(e)
    }
}

impl From<IOError> for ConfigError {
    fn from(e: IOError) -> Self {
        ConfigError::IO(e)
    }
}

impl From<TlsConfigErrorKind> for ConfigError {
    fn from(e: TlsConfigErrorKind) -> Self {
        ConfigError::InvalidTlsConfig(e)
    }
}

impl From<TomlDeError> for ConfigError {
    fn from(e: TomlDeError) -> Self {
        ConfigError::DeserError(e)
    }
}

#[derive(Debug)]
pub enum DatabaseConfigErrorKind {
    InvalidPasswordFileEncoding(String, Utf8Error),
    MissingPassword,
}

impl Display for DatabaseConfigErrorKind {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match &self {
            Self::InvalidPasswordFileEncoding(s, e) => write!(f, "Invalid password file encoding: {s}: {e}"),
            Self::MissingPassword => {
                write!(f, "Database URL specifies a password placeholder but a password was not supplied")
            }
        }
    }
}

#[derive(Debug)]
pub enum TlsConfigErrorKind {
    TlsSetupFailed(TlsError),
    InvalidCertificate,
    InvalidPrivateKey,
}

impl Display for TlsConfigErrorKind {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match &self {
            TlsConfigErrorKind::TlsSetupFailed(e) => {
                write!(f, "Invalid TLS configuration: {e}")
            }
            TlsConfigErrorKind::InvalidCertificate => {
                write!(f, "Invalid certificate")
            }
            TlsConfigErrorKind::InvalidPrivateKey => {
                write!(f, "Invalid private key")
            }
        }
    }
}
