use std::{
    error::Error,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    fs::{read, File},
    io::{BufRead, BufReader, Error as IOError},
    net::{AddrParseError, IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    str::Utf8Error,
    time::Duration,
};

use base64;
use diesel::{
    pg::PgConnection,
    r2d2::{Builder as PoolBuilder, ConnectionManager, ManageConnection, Pool, PoolError},
};
use hyper::Error as HyperError;
use log::{debug, error, info};
use rustls::{Certificate, Error as TLSError, PrivateKey, ServerConfig};
use serde::Deserialize;
use serde_json;
use tokio_rustls::rustls::ServerConfig as TlsServerConfig;

const DEFAULT_PORT: u16 = 8080;

#[inline]
const fn get_default_port() -> u16 {
    DEFAULT_PORT
}

#[inline]
const fn get_default_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[inline]
const fn get_default_threads() -> usize {
    1
}

fn get_default_partition() -> String {
    "aws".into()
}

/// The configuration data for the server, as specified by the user. This allows for optional fields and references
/// to files for things like TLS certificates and keys.
#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(rename = "Port", default = "get_default_port")]
    pub port: u16,

    #[serde(rename = "Address", default = "get_default_address")]
    pub address: IpAddr,

    #[serde(rename = "Partition", default = "get_default_partition")]
    pub partition: String,

    #[serde(rename = "Region")]
    pub region: String,

    #[serde(rename = "TLS", default)]
    pub tls: Option<TlsConfig>,

    #[serde(rename = "Threads", default = "get_default_threads")]
    pub threads: usize,

    #[serde(rename = "Database")]
    pub database: DatabaseConfig,
}

impl Config {
    pub fn read_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        match File::open(path) {
            Err(e) => Err(ConfigError::IO(e)),
            Ok(file) => {
                let reader = BufReader::new(file);
                match serde_json::from_reader(reader) {
                    Ok(config) => Ok(config),
                    Err(e) => Err(ConfigError::JSONDeserializationError(e)),
                }
            }
        }
    }

    pub fn resolve(self) -> Result<ResolvedConfig, ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::InvalidPort);
        }

        if self.partition.len() == 0 {
            return Err(ConfigError::InvalidPartition);
        }

        if self.region.len() == 0 {
            return Err(ConfigError::InvalidRegion);
        }

        let tls_config = match &self.tls {
            None => None,
            Some(c) => Some(c.to_server_config()?),
        };

        let pool = self.database.get_pool()?;
        Ok(ResolvedConfig {
            address: SocketAddr::new(self.address, self.port),
            partition: self.partition,
            region: self.region,
            threads: self.threads,
            tls: tls_config,
            pool: pool,
        })
    }
}

/// The resolved configuration: optional values have been replaced
pub struct ResolvedConfig {
    pub address: SocketAddr,
    pub partition: String,
    pub region: String,
    pub threads: usize,
    pub tls: Option<TlsServerConfig>,
    pub pool: Pool<ConnectionManager<PgConnection>>,
}

impl Debug for ResolvedConfig {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "ResolvedConfig{{address={:?}, region={:?}, threads={:?}, ",
            self.address, self.region, self.threads
        )?;
        match self.tls {
            None => write!(f, "tls=None, ")?,
            Some(ref _tsc) => write!(f, "tls=Some(ServerConfig), ")?,
        }
        write!(
            f,
            "pool=Pool{{state={:?}, max_size={:?}, min_idle={:?}, test_on_check_out={:?}, max_lifetime={:?}, \
            idle_timeout={:?}, connection_timeout={:?}}}}}",
            self.pool.state(),
            self.pool.max_size(),
            self.pool.min_idle(),
            self.pool.test_on_check_out(),
            self.pool.max_lifetime(),
            self.pool.idle_timeout(),
            self.pool.connection_timeout()
        )
    }
}

#[derive(Debug)]
pub enum ConfigError {
    DatabasePoolError(PoolError),
    HTTPServerError(HyperError),
    IO(IOError),
    JSONDeserializationError(serde_json::error::Error),
    InvalidTlsConfiguration(TlsConfigError),
    InvalidDatabaseConfiguration(DatabaseConfigError),
    InvalidAddress(AddrParseError),
    InvalidPartition,
    InvalidPort,
    InvalidRegion,
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match &self {
            Self::DatabasePoolError(e) => {
                write!(f, "Database pool error: {}", e)
            }
            Self::HTTPServerError(e) => write!(f, "HTTP server error: {}", e),
            Self::IO(e) => write!(f, "I/O error: {}", e),
            Self::JSONDeserializationError(e) => {
                write!(f, "JSON deserialization error: {}", e)
            }
            Self::InvalidTlsConfiguration(e) => {
                write!(f, "Invalid TLS configuration: {}", e)
            }
            Self::InvalidDatabaseConfiguration(e) => {
                write!(f, "Invalid database configuration: {}", e)
            }
            Self::InvalidAddress(e) => write!(f, "Invalid address: {}", e),
            Self::InvalidPartition => write!(f, "Invalid partition"),
            Self::InvalidPort => write!(f, "Invalid port"),
            Self::InvalidRegion => write!(f, "Invalid region"),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::DatabasePoolError(ref e) => Some(e),
            Self::HTTPServerError(ref e) => Some(e),
            Self::IO(ref e) => Some(e),
            Self::JSONDeserializationError(ref e) => Some(e),
            Self::InvalidTlsConfiguration(ref e) => Some(e),
            Self::InvalidDatabaseConfiguration(ref e) => Some(e),
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

impl From<DatabaseConfigError> for ConfigError {
    fn from(e: DatabaseConfigError) -> Self {
        ConfigError::InvalidDatabaseConfiguration(e)
    }
}

impl From<HyperError> for ConfigError {
    fn from(e: HyperError) -> Self {
        ConfigError::HTTPServerError(e)
    }
}

impl From<IOError> for ConfigError {
    fn from(e: IOError) -> Self {
        ConfigError::IO(e)
    }
}

impl From<PoolError> for ConfigError {
    fn from(e: PoolError) -> Self {
        ConfigError::DatabasePoolError(e)
    }
}

impl From<serde_json::error::Error> for ConfigError {
    fn from(e: serde_json::error::Error) -> Self {
        ConfigError::JSONDeserializationError(e)
    }
}

impl From<TlsConfigError> for ConfigError {
    fn from(e: TlsConfigError) -> Self {
        ConfigError::InvalidTlsConfiguration(e)
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct TlsConfig {
    #[serde(rename(deserialize = "CertificateChainFile"))]
    certificate_chain_file: String,

    #[serde(rename(deserialize = "PrivateKeyFile"))]
    private_key_file: String,
}

impl TlsConfig {
    /// Resolve files referenced in the TLS configuration to actual certificates and keys.
    pub fn to_server_config(&self) -> Result<ServerConfig, TlsConfigError> {
        let builder = ServerConfig::builder().with_safe_defaults().with_no_client_auth();

        let cert_file = File::open(&self.certificate_chain_file)?;
        let mut reader = BufReader::new(cert_file);
        let certs = read_certs(&mut reader)?;
        if certs.len() == 0 {
            return Err(TlsConfigError {
                kind: TlsConfigErrorKind::InvalidCertificate,
            });
        }

        let private_key_file = File::open(&self.private_key_file)?;
        let mut reader = BufReader::new(private_key_file);
        let mut private_keys = read_rsa_private_keys(&mut reader)?;
        if private_keys.len() != 1 {
            return Err(TlsConfigError {
                kind: TlsConfigErrorKind::InvalidPrivateKey,
            });
        }
        let private_key = private_keys.remove(0);

        Ok(builder.with_single_cert(certs, private_key)?)
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
    f: &dyn Fn(Vec<u8>) -> A,
) -> Result<Vec<A>, TlsConfigError> {
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
fn read_certs(rd: &mut dyn BufRead) -> Result<Vec<Certificate>, TlsConfigError> {
    extract_cert_or_key(rd, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", &|v| {
        Certificate(v)
    })
}

/// Extract all RSA private keys from rd, and return a vec of `rustls::PrivateKey`s
/// containing the der-format contents.
///
/// Originally from rustls::pemfile::rsa_private_keys, modified to return errors.
fn read_rsa_private_keys(rd: &mut dyn BufRead) -> Result<Vec<PrivateKey>, TlsConfigError> {
    extract_cert_or_key(
        rd,
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----END RSA PRIVATE KEY-----",
        &|v| PrivateKey(v),
    )
}

#[derive(Debug)]
pub enum TlsConfigErrorKind {
    IO(IOError),
    InvalidBase64Encoding(base64::DecodeError),
    InvalidTlsConfiguration(TLSError),
    InvalidCertificate,
    InvalidPrivateKey,
}

#[derive(Debug)]
pub struct TlsConfigError {
    kind: TlsConfigErrorKind,
}

impl Error for TlsConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self.kind {
            TlsConfigErrorKind::IO(ref e) => Some(e),
            TlsConfigErrorKind::InvalidBase64Encoding(ref e) => Some(e),
            TlsConfigErrorKind::InvalidTlsConfiguration(ref e) => Some(e),
            _ => None,
        }
    }
}

impl Display for TlsConfigError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match &self.kind {
            TlsConfigErrorKind::IO(e) => {
                write!(f, "I/O error: {}", e)
            }
            TlsConfigErrorKind::InvalidBase64Encoding(e) => {
                write!(f, "Invalid base64 encoding: {}", e)
            }
            TlsConfigErrorKind::InvalidTlsConfiguration(e) => {
                write!(f, "Invalid TLS configuration: {}", e)
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

impl From<IOError> for TlsConfigError {
    fn from(e: IOError) -> Self {
        TlsConfigError {
            kind: TlsConfigErrorKind::IO(e),
        }
    }
}

impl From<base64::DecodeError> for TlsConfigError {
    fn from(e: base64::DecodeError) -> Self {
        TlsConfigError {
            kind: TlsConfigErrorKind::InvalidBase64Encoding(e),
        }
    }
}

impl From<TLSError> for TlsConfigError {
    fn from(e: TLSError) -> Self {
        TlsConfigError {
            kind: TlsConfigErrorKind::InvalidTlsConfiguration(e),
        }
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct DatabaseConfig {
    #[serde(rename = "URL")]
    pub url: String,

    #[serde(rename = "Password", default)]
    pub password: Option<String>,

    #[serde(rename = "PasswordFile", default)]
    pub password_file: Option<String>,

    #[serde(rename = "PoolSize", default)]
    pub pool_size: Option<u32>,

    #[serde(rename = "PoolMinIdle", default)]
    pub pool_min_idle: Option<u32>,

    #[serde(rename = "ConnectionTimeout", with = "humantime_serde", default)]
    pub connection_timeout: Option<Duration>,

    #[serde(rename = "MaxLifetime", with = "humantime_serde", default)]
    pub max_lifetime: Option<Duration>,

    #[serde(rename = "IdleTimeout", with = "humantime_serde", default)]
    pub idle_timeout: Option<Duration>,
}

#[derive(Debug)]
pub enum DatabaseConfigError {
    IO(IOError, Option<String>),
    InvalidPasswordFileEncoding(String, Utf8Error),
    MissingPassword,
    Pool(PoolError),
}

impl Error for DatabaseConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::IO(ref e, _) => Some(e),
            Self::InvalidPasswordFileEncoding(_, ref e) => Some(e),
            Self::Pool(ref e) => Some(e),
            _ => None,
        }
    }
}

impl Display for DatabaseConfigError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match &self {
            Self::IO(ref e, maybe_filename) => match maybe_filename {
                None => write!(f, "I/O error: {}", e),
                Some(filename) => write!(f, "{}: {}", filename, e),
            },
            Self::InvalidPasswordFileEncoding(s, ref e) => write!(f, "Invalid password file encoding: {}: {}", s, e),
            Self::MissingPassword => write!(
                f,
                "Database URL specifies a password placeholder but a password was not supplied"
            ),
            Self::Pool(ref e) => write!(f, "Pool error: {}", e),
        }
    }
}

impl From<IOError> for DatabaseConfigError {
    fn from(e: IOError) -> Self {
        DatabaseConfigError::IO(e, None)
    }
}

impl From<PoolError> for DatabaseConfigError {
    fn from(e: PoolError) -> Self {
        DatabaseConfigError::Pool(e)
    }
}

impl DatabaseConfig {
    pub fn get_postgres_url(&self) -> Result<String, DatabaseConfigError> {
        let url = self.url.clone();

        if let Some(password) = &self.password {
            debug!("Database password specified in config file -- replacing occurrences in URL");
            Ok(url.replace("${password}", password))
        } else if let Some(password_file) = &self.password_file {
            debug!("Database password file specified.");
            match read(&password_file) {
                Ok(password_u8) => match std::str::from_utf8(&password_u8) {
                    Ok(password) => {
                        info!(
                            "Successfully read database password file {}; replacing URL",
                            password_file
                        );
                        let password = password.trim();
                        Ok(url.replace("${password}", password))
                    }
                    Err(e) => {
                        error!("Found non-UTF-8 characters in database password file {}", password_file);
                        Err(DatabaseConfigError::InvalidPasswordFileEncoding(
                            password_file.to_string(),
                            e,
                        ))
                    }
                },
                Err(e) => {
                    error!("Failed to open database password file {}: {}", password_file, e);
                    Err(DatabaseConfigError::IO(e, Some(password_file.to_string())))
                }
            }
        } else if url.contains("${password}") {
            error!(
                "Found password placeholder '${{password}}' in database URL but no password was supplied: {}",
                url
            );
            Err(DatabaseConfigError::MissingPassword)
        } else {
            Ok(url)
        }
    }

    pub fn get_pool_builder<M: ManageConnection>(&self) -> Result<PoolBuilder<M>, DatabaseConfigError> {
        let mut pb = PoolBuilder::new();

        if let Some(pool_size) = self.pool_size {
            pb = pb.max_size(pool_size);
        }

        if let Some(pool_min_idle) = self.pool_min_idle {
            pb = pb.min_idle(Some(pool_min_idle));
        }

        pb = pb.max_lifetime(self.max_lifetime);
        pb = pb.idle_timeout(self.idle_timeout);

        if let Some(connection_timeout) = self.connection_timeout {
            pb = pb.connection_timeout(connection_timeout);
        }

        Ok(pb)
    }

    pub fn get_pool(&self) -> Result<Pool<ConnectionManager<PgConnection>>, DatabaseConfigError> {
        let url = self.get_postgres_url()?;
        let cm = ConnectionManager::<PgConnection>::new(url);
        let pb = self.get_pool_builder()?;
        Ok(pb.build(cm)?)
    }
}
