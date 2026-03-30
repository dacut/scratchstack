use {
    crate::error::{ConfigError, DatabaseConfigErrorKind},
    log::{debug, error},
    pct_str::{PctString, UriReserved},
    serde::Deserialize,
    sqlx::{any::Any as AnyDB, pool::PoolOptions},
    std::{fmt::Debug, time::Duration},
    tokio::fs::read,
};

fn pct_encode(s: &str) -> String {
    PctString::encode(s.chars(), UriReserved::Any).as_str().to_string()
}

/// Database configuration for a service.
#[derive(Clone, Deserialize, Debug)]
pub struct DatabaseConfig {
    /// The database URL to connect to. If the URL contains the placeholder `${password}`, then either
    /// `password` or `password_file` must be specified to provide a value for the placeholder.
    ///
    /// If other fields are specified, they will override that portion of the URL.
    ///
    /// If unspecified, the URL will be constructed from other fields in this configuration.
    pub url: Option<String>,

    /// The database host to connect to. This can also be a directory on Unix systems, in which
    /// case a Unix socket will be used to connect to the database instead of TCP.
    ///
    /// If not specified, defaults to `/tmp`.
    pub host: Option<String>,

    /// The database port to connect to.
    ///
    /// If not specified, defaults to the standard PostgreSQL port (5432).
    pub port: Option<u16>,

    /// The database username to connect as. Used only if `url` is not specified.
    ///
    /// If not specified, defaults to the current system user.
    pub username: Option<String>,

    /// The password to use when connecting to the database. Used only if `url` is not specified or
    /// if `url` contains the `${password}` placeholder.
    ///
    /// If not specified, no password will be used when connecting to the database.
    #[serde(default)]
    pub password: Option<String>,

    /// The path to a file containing the database password. Used only if `url` is not specified or
    /// if `url` contains the `${password}` placeholder.
    ///
    /// If not specified, no password will be used when connecting to the database.
    #[serde(default)]
    pub password_file: Option<String>,

    /// The database to connect to. Used only if `url` is not specified.
    ///
    /// If not specified, the `scratchstack` database will be used.
    pub database: Option<String>,

    /// Maximum number of connections to maintain in the pool.
    #[serde(default)]
    pub max_connections: Option<u32>,

    /// Minimum number of connections to maintain in the pool.
    #[serde(default)]
    pub min_connections: Option<u32>,

    /// Timeout for acquiring a connection from the pool.
    #[serde(with = "humantime_serde", default)]
    pub connection_timeout: Option<Duration>,

    /// Maximum lifetime of a connection in the pool.
    #[serde(with = "humantime_serde", default)]
    pub max_lifetime: Option<Duration>,

    /// Idle timeout for connections in the pool.
    #[serde(with = "humantime_serde", default)]
    pub idle_timeout: Option<Duration>,

    /// Whether to test connections for liveness before acquiring them from the pool.
    #[serde(default)]
    pub test_before_acquire: Option<bool>,
}

impl DatabaseConfig {
    /// Returns the database URL to connect to.
    ///
    /// If the `url` field is specified, it is returned with any `${password}` placeholders replaced
    /// by the value from `password` or `password_file`.
    ///
    /// If `url` is not specified, a URL is constructed from the other fields in this configuration.
    pub async fn get_database_url(&self) -> Result<String, ConfigError> {
        if let Some(url) = &self.url {
            if url.contains("${password}") {
                if let Some(password) = &self.password {
                    Ok(url.replace("${password}", password))
                } else if self.password_file.is_some() {
                    let password = self.get_password_from_file().await?;
                    Ok(url.replace("${password}", &password))
                } else {
                    error!("Found password placeholder '${{password}}' in database URL but no password was supplied");
                    Err(DatabaseConfigErrorKind::MissingPassword.into())
                }
            } else {
                Ok(url.clone())
            }
        } else {
            self.construct_url().await
        }
    }

    /// Cosntruct a database URL from the other fields in this configuration. This is used when
    /// `url` is not specified.
    ///
    /// # Panics
    /// Panics if the `url` field has been specified.
    async fn construct_url(&self) -> Result<String, ConfigError> {
        assert!(self.url.is_none(), "Cannot construct database URL when 'url' field is specified");
        const URL_PREFIX: &str = "postgresql://";

        let mut result = String::new();
        result.push_str(URL_PREFIX);
        if let Some(username) = &self.username {
            result.push_str(&pct_encode(username));

            if let Some(password) = &self.password {
                result.push(':');
                result.push_str(&pct_encode(password));
            } else if self.password_file.is_some() {
                let password = self.get_password_from_file().await?;
                result.push(':');
                result.push_str(&pct_encode(&password));
            }

            result.push('@');
        }

        if let Some(host) = &self.host {
            result.push_str(&pct_encode(host));
        } else {
            result.push_str("localhost");
        }

        if let Some(port) = self.port {
            result.push(':');
            result.push_str(&port.to_string());
        }

        if let Some(database) = &self.database {
            result.push('/');
            result.push_str(&pct_encode(database));
        } else {
            result.push_str("/scratchstack");
        }

        Ok(result)
    }

    /// Returns the password from a password file.
    ///
    /// # Panics
    /// Panics if `password_file` is None.
    async fn get_password_from_file(&self) -> Result<String, ConfigError> {
        let password_file = self.password_file.as_ref().unwrap();

        match read(password_file).await {
            Ok(password_u8) => match std::str::from_utf8(&password_u8) {
                Ok(password) => {
                    debug!("Successfully read database password file {password_file}");
                    Ok(password.trim().to_string())
                }
                Err(e) => {
                    error!("Found non-UTF-8 characters in database password file {password_file}");
                    Err(DatabaseConfigErrorKind::InvalidPasswordFileEncoding(password_file.to_string(), e).into())
                }
            },
            Err(e) => {
                error!("Failed to open database password file {password_file}: {e}");
                Err(ConfigError::IO(e))
            }
        }
    }

    pub fn get_pool_options(&self) -> Result<PoolOptions<AnyDB>, ConfigError> {
        let options = PoolOptions::<AnyDB>::new();
        let options = options.max_lifetime(self.max_lifetime);
        let mut options = options.idle_timeout(self.idle_timeout);

        if let Some(size) = self.max_connections {
            options = options.max_connections(size);
        }

        if let Some(size) = self.min_connections {
            options = options.min_connections(size);
        }

        if let Some(duration) = self.connection_timeout {
            options = options.acquire_timeout(duration);
        }

        if let Some(b) = self.test_before_acquire {
            options = options.test_before_acquire(b);
        }

        Ok(options)
    }

    pub async fn resolve(&self) -> Result<ResolvedDatabaseConfig, ConfigError> {
        let url = self.get_database_url().await?;
        let pool_options = self.get_pool_options()?;

        Ok(ResolvedDatabaseConfig {
            url,
            pool_options,
        })
    }
}

#[derive(Debug)]
pub struct ResolvedDatabaseConfig {
    pub url: String,
    pub pool_options: PoolOptions<AnyDB>,
}
