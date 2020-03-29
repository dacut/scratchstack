use core::fmt::Debug;
use std::error::Error;
use std::fmt;
use std::fs::{File, read};
use std::io::{BufRead, BufReader, Error as IOError};
use std::net::AddrParseError;
use std::path::Path;
use std::str::Utf8Error;

use base64;
use diesel::r2d2::{Builder, ManageConnection};
use humantime::parse_duration;
use rustls;
use rustls::NoClientAuth;
use serde::Deserialize;
use serde_json;

#[derive(Clone, Deserialize, Debug)]
pub struct Config {
    #[serde(rename(deserialize = "Port"))]
    pub port: Option<u16>,

    #[serde(rename(deserialize = "Address"))]
    pub address: Option<String>,

    #[serde(rename(deserialize = "Region"))]
    pub region: String,

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
    InvalidAddress(AddrParseError),
    InvalidPort,
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
            ConfigErrorKind::InvalidAddress(e) => {
                write!(f, "Invalid address: {}", e)
            }
            ConfigErrorKind::InvalidPort => {
                write!(f, "Invalid port")
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
            ConfigErrorKind::InvalidAddress(ref e) => Some(e),
            _ => None,
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

impl From<AddrParseError> for ConfigError {
    fn from(e: AddrParseError) -> Self {
        ConfigError {
            kind: ConfigErrorKind::InvalidAddress(e),
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
    #[serde(rename(deserialize = "URL"))]
    pub url: String,

    #[serde(rename(deserialize = "Password"))]
    pub password: Option<String>,

    #[serde(rename(deserialize = "PasswordFile"))]
    pub password_file: Option<String>,

    #[serde(rename(deserialize = "PoolSize"))]
    pub pool_size: Option<u32>,

    #[serde(rename(deserialize = "PoolMinIdle"))]
    pub pool_min_idle: Option<u32>,

    #[serde(rename(deserialize = "ConnectTimeout"))]
    pub connect_timeout_str: Option<String>,

    #[serde(rename(deserialize = "MaxLifetime"))]
    pub max_lifetime_str: Option<String>,

    #[serde(rename(deserialize = "IdleTimeout"))]
    pub idle_timeout_str: Option<String>,
}

#[derive(Debug)]
pub enum DatabaseConfigErrorKind {
    IO(IOError),
    InvalidPasswordFileEncoding(String, Utf8Error),
    InvalidConnectionTimeout(String),
    InvalidKeepalivePeriod(String),
    InvalidMaxLifetime(String),
    InvalidIdleTimeout(String),
}

#[derive(Debug)]
pub struct DatabaseConfigError {
    pub kind: DatabaseConfigErrorKind,
}

impl Error for DatabaseConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self.kind {
            DatabaseConfigErrorKind::IO(ref e) => Some(e),
            DatabaseConfigErrorKind::InvalidPasswordFileEncoding(_, ref e) => Some(e),
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
            DatabaseConfigErrorKind::InvalidPasswordFileEncoding(s, ref e) => {
                write!(f, "Invalid password file encoding: {}: {}", s, e)
            }
            DatabaseConfigErrorKind::InvalidConnectionTimeout(s) => {
                write!(f, "Invalid ConnectionTimeout: {}", s)
            }
            DatabaseConfigErrorKind::InvalidKeepalivePeriod(s) => {
                write!(f, "Invalid KeepalivePeriod: {}", s)
            }
            DatabaseConfigErrorKind::InvalidMaxLifetime(s) => {
                write!(f, "Invalid MaxLifetime: {}", s)
            }
            DatabaseConfigErrorKind::InvalidIdleTimeout(s) => {
                write!(f, "Invalid IdleTimeout: {}", s)
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

impl DatabaseConfig {
    pub fn get_postgres_url(&self) -> Result<String, DatabaseConfigError> {
        let url = self.url.clone();

        let url = if let Some(password) = &self.password {
            url.replace("${password}", password)
        } else if let Some(password_file) = &self.password_file {
            match read(&password_file) {
                Ok(password_u8) => match std::str::from_utf8(&password_u8) {
                    Ok(password) => url.replace("${password}", password),
                    Err(e) => return Err(DatabaseConfigError {
                        kind: DatabaseConfigErrorKind::InvalidPasswordFileEncoding(
                            password_file.to_string(), e),
                    }),
                }
                Err(e) => return Err(DatabaseConfigError {
                    kind: DatabaseConfigErrorKind::IO(e),
                }),
            }
        } else {
            url
        };

        Ok(url)
    }

    pub fn get_pool_builder<M: ManageConnection>(&self) -> Result<Builder<M>, DatabaseConfigError> {
        let mut pb = Builder::new();

        if let Some(pool_size) = self.pool_size {
            pb = pb.max_size(pool_size);
        }

        if let Some(pool_min_idle) = self.pool_min_idle {
            pb = pb.min_idle(Some(pool_min_idle));
        }

        if let Some(max_lifetime_str) = &self.max_lifetime_str {
            match parse_duration(max_lifetime_str) {
                Ok(max_lifetime) => {
                    pb = pb.max_lifetime(Some(max_lifetime));
                }
                Err(_) => return Err(DatabaseConfigError {
                    kind: DatabaseConfigErrorKind::InvalidMaxLifetime(
                        max_lifetime_str.to_string()),
                }),
            }
        }

        if let Some(idle_timeout_str) = &self.idle_timeout_str {
            match parse_duration(idle_timeout_str) {
                Ok(idle_timeout) => {
                    pb = pb.idle_timeout(Some(idle_timeout));
                }
                Err(_) => return Err(DatabaseConfigError {
                    kind: DatabaseConfigErrorKind::InvalidIdleTimeout(
                        idle_timeout_str.to_string()),
                }),
            }
        }

        if let Some(connect_timeout_str) = &self.connect_timeout_str {
            match parse_duration(connect_timeout_str) {
                Ok(connect_timeout) => {
                    pb = pb.connection_timeout(connect_timeout);
                }
                Err(_) => return Err(DatabaseConfigError {
                    kind: DatabaseConfigErrorKind::InvalidConnectionTimeout(
                        connect_timeout_str.to_string()),
                }),
            }
        }

        Ok(pb)
    }
}
