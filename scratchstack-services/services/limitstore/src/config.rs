use std::error::Error;
use std::fmt;
use std::fs::{File, read};
use std::io::{BufRead, BufReader, Error as IOError};
use std::path::Path;    

use base64;
use bb8_postgres::PostgresConnectionManager;
use humantime::parse_duration;
use native_tls::{Certificate, Error as NativeTlsError, TlsConnector};
use postgres_native_tls::MakeTlsConnector;
use rustls;
use rustls::NoClientAuth;
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

    #[serde(rename(deserialize = "TLS"))]
    pub tls: Option<TLSConfig>,

    #[serde(rename(deserialize = "Threads"))]
    pub threads: Option<usize>,

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
    InvalidTLSConfiguration(TLSConfigError),
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
            ConfigErrorKind::InvalidTLSConfiguration(e) => {
                write!(f, "Invalid TLS configuration: {}", e)
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
            ConfigErrorKind::InvalidTLSConfiguration(ref e) => Some(e),
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

impl From<TLSConfigError> for ConfigError {
    fn from(e: TLSConfigError) -> Self {
        ConfigError {
            kind: ConfigErrorKind::InvalidTLSConfiguration(e),
        }
    }
}

impl From<DatabaseConfigError> for ConfigError {
    fn from(e: DatabaseConfigError) -> Self {
        ConfigError {
            kind: ConfigErrorKind::InvalidDatabaseConfiguration(e),
        }
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct TLSConfig {
    #[serde(rename(deserialize = "CertificateChainFile"))]
    certificate_chain_file: String,

    #[serde(rename(deserialize = "PrivateKeyFile"))]
    private_key_file: String,
}

impl TLSConfig {
    pub fn to_server_config(&self) -> Result<rustls::ServerConfig, TLSConfigError> {
        let mut sc = rustls::ServerConfig::new(NoClientAuth::new());
        
        let cert_file = File::open(&self.certificate_chain_file)?;
        let mut reader = BufReader::new(cert_file);
        let certs = read_certs(&mut reader)?;
        if certs.len() == 0 {
            return Err(TLSConfigError { kind: TLSConfigErrorKind::InvalidCertificate });
        }

        let private_key_file = File::open(&self.private_key_file)?;
        let mut reader = BufReader::new(private_key_file);
        let mut private_keys = read_rsa_private_keys(&mut reader)?;
        if private_keys.len() != 1 {
            return Err(TLSConfigError { kind: TLSConfigErrorKind::InvalidPrivateKey });
        }
        let private_key = private_keys.remove(0);

        sc.set_single_cert(certs, private_key)?;
        Ok(sc)
    }
}


/// Extract and decode all PEM sections from `rd`, which begin with `start_mark`
/// and end with `end_mark`.  Apply the functor `f` to each decoded buffer,
/// and return a Vec of `f`'s return values.
/// 
/// Originally from rustls::pemfile::extract, modified to return errors.
fn extract_cert_or_key<A>(
    rd: &mut dyn BufRead,
    start_mark: &str,
    end_mark: &str,
    f: &dyn Fn(Vec<u8>) -> A)
-> Result<Vec<A>, TLSConfigError> {
    let mut ders = Vec::new();
    let mut b64buf = String::new();
    let mut take_base64 = false;

    let mut raw_line = Vec::<u8>::new();
    loop {
        raw_line.clear();
        let len = rd.read_until(b'\n', &mut raw_line)?;

        if len == 0 {
            return Ok(ders);
        }

        let line = String::from_utf8_lossy(&raw_line);

        if line.starts_with(start_mark) {
            take_base64 = true;
            continue;
        }

        if line.starts_with(end_mark) {
            take_base64 = false;
            let der = base64::decode(&b64buf)?;
            ders.push(f(der));
            b64buf = String::new();
            continue;
        }

        if take_base64 {
            b64buf.push_str(line.trim());
        }
    }
}

/// Extract all the certificates from rd, and return a vec of `rustls::Certificate`s
/// containing the der-format contents.
/// 
/// Originally from rustls::pemfile::certs, modified to return errors.
fn read_certs(rd: &mut dyn BufRead) -> Result<Vec<rustls::Certificate>, TLSConfigError> {
    extract_cert_or_key(
        rd,
        "-----BEGIN CERTIFICATE-----",
        "-----END CERTIFICATE-----",
        &|v| rustls::Certificate(v))
}

/// Extract all RSA private keys from rd, and return a vec of `rustls::PrivateKey`s
/// containing the der-format contents.
/// 
/// Originally from rustls::pemfile::rsa_private_keys, modified to return errors.
fn read_rsa_private_keys(rd: &mut dyn BufRead) -> Result<Vec<rustls::PrivateKey>, TLSConfigError> {
    extract_cert_or_key(
        rd,
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----END RSA PRIVATE KEY-----",
        &|v| rustls::PrivateKey(v))
}

#[derive(Debug)]
pub enum TLSConfigErrorKind {
    IO(IOError),
    InvalidBase64Encoding(base64::DecodeError),
    InvalidTLSConfiguration(rustls::TLSError),
    InvalidCertificate,
    InvalidPrivateKey,
}

#[derive(Debug)]
pub struct TLSConfigError {
    kind: TLSConfigErrorKind,
}

impl Error for TLSConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self.kind {
            TLSConfigErrorKind::IO(ref e) => Some(e),
            TLSConfigErrorKind::InvalidBase64Encoding(ref e) => Some(e),
            TLSConfigErrorKind::InvalidTLSConfiguration(ref e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for TLSConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.kind {
            TLSConfigErrorKind::IO(e) => {
                write!(f, "I/O error: {}", e)
            }
            TLSConfigErrorKind::InvalidBase64Encoding(e) => {
                write!(f, "Invalid base64 encoding: {}", e)
            }
            TLSConfigErrorKind::InvalidTLSConfiguration(e) => {
                write!(f, "Invalid TLS configuration: {}", e)
            }
            TLSConfigErrorKind::InvalidCertificate => {
                write!(f, "Invalid certificate")
            }
            TLSConfigErrorKind::InvalidPrivateKey => {
                write!(f, "Invalid private key")
            }
        }
    }
}

impl From<IOError> for TLSConfigError {
    fn from(e: IOError) -> Self {
        TLSConfigError {
            kind: TLSConfigErrorKind::IO(e),
        }
    }
}

impl From<base64::DecodeError> for TLSConfigError {
    fn from(e: base64::DecodeError) -> Self {
        TLSConfigError {
            kind: TLSConfigErrorKind::InvalidBase64Encoding(e),
        }
    }
}

impl From<rustls::TLSError> for TLSConfigError {
    fn from(e: rustls::TLSError) -> Self {
        TLSConfigError {
            kind: TLSConfigErrorKind::InvalidTLSConfiguration(e),
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
                Err(e) => return Err(DatabaseConfigError{
                    kind: DatabaseConfigErrorKind::IO(e),
                }),
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
                    kind: DatabaseConfigErrorKind::InvalidConnectionTimeout(
                        connect_timeout_str.to_string()),
                }),
            }
        }

        if let Some(keepalive_period_str) = &self.keepalive_period_str {
            match parse_duration(keepalive_period_str) {
                Ok(keepalive_period) => { c.keepalives_idle(keepalive_period); }
                Err(_) => return Err(DatabaseConfigError {
                    kind: DatabaseConfigErrorKind::InvalidKeepalivePeriod(
                        keepalive_period_str.to_string()),
                }),
            }
        }

        if let Some(ssl_mode_str) = &self.ssl_mode {
            let ssl_mode = match ssl_mode_str.as_ref() {
                "Disable" => SslMode::Disable,
                "Require" => SslMode::Require,
                _ => return Err(DatabaseConfigError{
                    kind: DatabaseConfigErrorKind::InvalidSSLMode(
                        ssl_mode_str.to_string()),
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
                ConnectionManager::NoTls(
                    PostgresConnectionManager::new(db_config, NoTls))
            ),
        }
    }    
}
