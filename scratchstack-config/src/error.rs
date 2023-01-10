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

#[derive(Debug)]
pub enum ConfigError {
    DeserError(TomlDeError),
    IO(IOError),
    InvalidConfig(String),
    InvalidTlsConfig(TlsConfigErrorKind),
    InvalidDatabaseConfig(DatabaseConfigErrorKind),
    InvalidAddress(AddrParseError),
    InvalidPartition,
    InvalidPort,
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
            Self::IO(ref e) => Some(e),
            Self::DeserError(e) => Some(e),
            Self::InvalidTlsConfig(ref e) => match e {
                TlsConfigErrorKind::InvalidBase64Encoding(e) => Some(e),
                TlsConfigErrorKind::TlsSetupFailed(e) => Some(e),
                _ => None,
            },
            Self::InvalidDatabaseConfig(DatabaseConfigErrorKind::InvalidPasswordFileEncoding(_, e)) => Some(e),
            Self::InvalidAddress(ref e) => Some(e),
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
            Self::InvalidPasswordFileEncoding(s, ref e) => write!(f, "Invalid password file encoding: {s}: {e}"),
            Self::MissingPassword => {
                write!(
                    f,
                    "Database URL specifies a password placeholder but a password was not supplied"
                )
            }
        }
    }
}

#[derive(Debug)]
pub enum TlsConfigErrorKind {
    InvalidBase64Encoding(base64::DecodeError),
    TlsSetupFailed(TlsError),
    InvalidCertificate,
    InvalidPrivateKey,
}

impl Display for TlsConfigErrorKind {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match &self {
            TlsConfigErrorKind::InvalidBase64Encoding(e) => {
                write!(f, "Invalid base64 encoding: {e}")
            }
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
