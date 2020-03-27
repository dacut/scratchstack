use std::error::Error;
use std::fmt;
use std::fs::{File, read};
use std::io::{BufReader, Error as IOError};
use std::path::Path;    

use bb8_postgres::PostgresConnectionManager;
use humantime::parse_duration;
use native_tls::{Certificate, Error as NativeTlsError, TlsConnector};
use postgres_native_tls::MakeTlsConnector;
use serde::Deserialize;
use serde_json;
use tokio_postgres::config::Config as PostgresConfig;
use tokio_postgres::config::SslMode;
use tokio_postgres::tls::NoTls;

pub enum ConnectionManager {
    NoTls(PostgresConnectionManager<NoTls>),
    Tls(PostgresConnectionManager<MakeTlsConnector>),
}

#[derive(Clone, Deserialize, Debug)]
pub struct Config {
    #[serde(rename(deserialize = "Port"))]
    pub port: Option<u16>,

    #[serde(rename(deserialize = "Address"))]
    pub address: Option<String>,

    #[serde(rename(deserialize = "Database"))]
    pub database: DatabaseConfig,
}

impl Config {
    pub fn read_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        match File::open(path) {
            Err(e) => Err(ConfigError{
                kind: ConfigErrorKind::IO(e),
            }),
            Ok(file) => {
                let reader = BufReader::new(file);
                match serde_json::from_reader(reader) {
                    Ok(config) => Ok(config),
                    Err(e) => Err(ConfigError{
                        kind: ConfigErrorKind::JSONDeserializationError(e),
                    }),
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum ConfigErrorKind {
    IO(IOError),
    JSONDeserializationError(serde_json::error::Error),
    InvalidDatabaseConfiguration(DatabaseConfigError),
}

#[derive(Debug)]
pub struct ConfigError {
    pub kind: ConfigErrorKind,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.kind {
            ConfigErrorKind::IO(e) => {
                write!(f, "I/O error: {}", e)
            }
            ConfigErrorKind::JSONDeserializationError(e) => {
                write!(f, "JSON deserialization error: {}", e)
            }
            ConfigErrorKind::InvalidDatabaseConfiguration(e) => {
                write!(f, "Invalid database configuration: {}", e)
            }
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self.kind {
            ConfigErrorKind::IO(ref e) => Some(e),
            ConfigErrorKind::JSONDeserializationError(ref e) => Some(e),
            ConfigErrorKind::InvalidDatabaseConfiguration(ref e) => Some(e),
        }
    }
}

impl From<IOError> for ConfigError {
    fn from(e: IOError) -> Self {
        ConfigError {
            kind: ConfigErrorKind::IO(e),
        }
    }
}

impl From<serde_json::error::Error> for ConfigError {
    fn from(e: serde_json::error::Error) -> Self {
        ConfigError {
            kind: ConfigErrorKind::JSONDeserializationError(e),
        }
    }
}

impl From<DatabaseConfigError> for ConfigError {
    fn from(e: DatabaseConfigError) -> Self {
        ConfigError {
            kind: ConfigErrorKind::InvalidDatabaseConfiguration(e)
        }
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct DatabaseConfig {
    #[serde(rename(deserialize = "Host"))]
    pub host: Option<String>,

    #[serde(rename(deserialize = "Port"))]
    pub port: Option<u16>,

    #[serde(rename(deserialize = "UnixSocketPath"))]
    pub unix_socket_path: Option<String>,

    #[serde(rename(deserialize = "Username"))]
    pub username: String,

    #[serde(rename(deserialize = "Password"))]
    pub password: Option<String>,

    #[serde(rename(deserialize = "PasswordFile"))]
    pub password_file: Option<String>,

    #[serde(rename(deserialize = "DatabaseName"))]
    pub database_name: Option<String>,

    #[serde(rename(deserialize = "ApplicationName"))]
    pub application_name: Option<String>,

    #[serde(rename(deserialize = "ConnectionTimeout"))]
    pub connect_timeout_str: Option<String>,

    #[serde(rename(deserialize = "KeepalivePeriod"))]
    pub keepalive_period_str: Option<String>,

    #[serde(rename(deserialize = "SSLMode"))]
    pub ssl_mode: Option<String>,

    #[serde(rename(deserialize = "RootCertificateFile"))]
    pub root_certificate_file: Option<String>,
}

#[derive(Debug)]
pub enum DatabaseConfigErrorKind {
    IO(IOError),
    InvalidSSLMode(String),
    RootCertificateNotSpecified,
    InvalidCertificate(NativeTlsError),
    InvalidConnectionTimeout(String),
    InvalidKeepalivePeriod(String),
}

#[derive(Debug)]
pub struct DatabaseConfigError {
    pub kind: DatabaseConfigErrorKind,
}

impl Error for DatabaseConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self.kind {
            DatabaseConfigErrorKind::IO(ref e) => Some(e),
            DatabaseConfigErrorKind::InvalidCertificate(ref e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for DatabaseConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.kind {
            DatabaseConfigErrorKind::IO(ref e) => {
                write!(f, "I/O error: {}", e)
            }
            DatabaseConfigErrorKind::InvalidSSLMode(mode) => {
                write!(f, "Invalid SSL mode specified: {}", mode)
            }
            DatabaseConfigErrorKind::RootCertificateNotSpecified => {
                write!(f, "RootCertificateFile must be specified")
            }
            DatabaseConfigErrorKind::InvalidCertificate(e) => {
                write!(f, "Invalid certificate: {}", e)
            }
            DatabaseConfigErrorKind::InvalidConnectionTimeout(s) => {
                write!(f, "Invalid ConnectionTimeout: {}", s)
            }
            DatabaseConfigErrorKind::InvalidKeepalivePeriod(s) => {
                write!(f, "Invalid KeepalivePeriod: {}", s)
            }
        }
    }
}

impl From<IOError> for DatabaseConfigError {
    fn from(e: IOError) -> Self {
        DatabaseConfigError {
            kind: DatabaseConfigErrorKind::IO(e),
        }
    }
}

impl From<NativeTlsError> for DatabaseConfigError {
    fn from(e: NativeTlsError) -> Self {
        DatabaseConfigError {
            kind: DatabaseConfigErrorKind::InvalidCertificate(e)
        }
    }
}

impl DatabaseConfig {
    pub fn to_postgres_config(&self) -> Result<PostgresConfig, DatabaseConfigError> {
        let mut c = tokio_postgres::config::Config::new();

        if let Some(host) = &self.host {
            c.host(&host);
        }

        if let Some(port) = self.port {
            c.port(port);
        }

        if let Some(unix_socket_path) = &self.unix_socket_path {
            c.host_path(&unix_socket_path);
        }

        c.user(&self.username);

        if let Some(password) = &self.password {
            c.password(&password);
        } else if let Some(password_file) = &self.password_file {
            match read(&password_file) {
                Ok(password) => { c.password(&password); }
                Err(e) => return Err(DatabaseConfigError{kind: DatabaseConfigErrorKind::IO(e)}),
            }
        }

        if let Some(database_name) = &self.database_name {
            c.dbname(&database_name);
        }

        if let Some(application_name) = &self.application_name {
            c.application_name(&application_name);
        }

        if let Some(connect_timeout_str) = &self.connect_timeout_str {
            match parse_duration(connect_timeout_str) {
                Ok(connect_timeout) => { c.connect_timeout(connect_timeout); }
                Err(_) => return Err(DatabaseConfigError {
                    kind: DatabaseConfigErrorKind::InvalidConnectionTimeout(connect_timeout_str.to_string()),
                }),
            }
        }

        if let Some(keepalive_period_str) = &self.keepalive_period_str {
            match parse_duration(keepalive_period_str) {
                Ok(keepalive_period) => { c.keepalives_idle(keepalive_period); }
                Err(_) => return Err(DatabaseConfigError {
                    kind: DatabaseConfigErrorKind::InvalidKeepalivePeriod(keepalive_period_str.to_string()),
                }),
            }
        }

        if let Some(ssl_mode_str) = &self.ssl_mode {
            let ssl_mode = match ssl_mode_str.as_ref() {
                "Disable" => SslMode::Disable,
                "Require" => SslMode::Require,
                _ => return Err(DatabaseConfigError{
                    kind: DatabaseConfigErrorKind::InvalidSSLMode(ssl_mode_str.to_string()),
                }),
            };

            c.ssl_mode(ssl_mode);
        }

        Ok(c)
    }

    pub fn to_connection_manager(&self) -> Result<ConnectionManager, DatabaseConfigError> {
        let db_config = self.to_postgres_config()?;
        match db_config.get_ssl_mode() {
            SslMode::Prefer | SslMode::Require => {
                match &self.root_certificate_file {
                    None => Err(DatabaseConfigError {
                        kind: DatabaseConfigErrorKind::RootCertificateNotSpecified,
                    }),
                    Some(filename) => {
                        let cert_bytes = read(filename)?;
                        let cert = Certificate::from_pem(&cert_bytes)?;
                        let connector = TlsConnector::builder()
                            .add_root_certificate(cert)
                            .build()?;
                        Ok(
                            ConnectionManager::Tls(
                                PostgresConnectionManager::new(
                                    db_config, MakeTlsConnector::new(connector))
                            )
                        )
                    }
                }
            }
            _ => Ok(
                ConnectionManager::NoTls(PostgresConnectionManager::new(db_config, NoTls))
            ),
        }
    }    
}
