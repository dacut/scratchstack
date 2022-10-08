use {
    crate::error::{ConfigError, DatabaseConfigErrorKind},
    log::{debug, error, info},
    serde::Deserialize,
    sqlx::{any::Any as AnyDB, pool::PoolOptions},
    std::{fmt::Debug, fs::read, time::Duration},
};

#[derive(Clone, Deserialize, Debug)]
pub struct DatabaseConfig {
    pub url: String,

    #[serde(default)]
    pub password: Option<String>,

    #[serde(default)]
    pub password_file: Option<String>,

    #[serde(default)]
    pub max_connections: Option<u32>,

    #[serde(default)]
    pub min_connections: Option<u32>,

    #[serde(with = "humantime_serde", default)]
    pub connection_timeout: Option<Duration>,

    #[serde(with = "humantime_serde", default)]
    pub max_lifetime: Option<Duration>,

    #[serde(with = "humantime_serde", default)]
    pub idle_timeout: Option<Duration>,

    #[serde(default)]
    pub test_before_acquire: Option<bool>,
}

impl DatabaseConfig {
    pub fn get_database_url(&self) -> Result<String, ConfigError> {
        let url = self.url.clone();

        if let Some(password) = &self.password {
            debug!("Database password specified in config file -- replacing occurrences in URL");
            Ok(url.replace("${password}", password))
        } else if let Some(password_file) = &self.password_file {
            debug!("Database password file specified.");
            match read(password_file) {
                Ok(password_u8) => match std::str::from_utf8(&password_u8) {
                    Ok(password) => {
                        info!("Successfully read database password file {}; replacing URL", password_file);
                        let password = password.trim();
                        Ok(url.replace("${password}", password))
                    }
                    Err(e) => {
                        error!("Found non-UTF-8 characters in database password file {}", password_file);
                        Err(DatabaseConfigErrorKind::InvalidPasswordFileEncoding(password_file.to_string(), e).into())
                    }
                },
                Err(e) => {
                    error!("Failed to open database password file {}: {}", password_file, e);
                    Err(ConfigError::IO(e))
                }
            }
        } else if url.contains("${password}") {
            error!("Found password placeholder '${{password}}' in database URL but no password was supplied: {}", url);
            Err(DatabaseConfigErrorKind::MissingPassword.into())
        } else {
            Ok(url)
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

    pub fn resolve(&self) -> Result<ResolvedDatabaseConfig, ConfigError> {
        let url = self.get_database_url()?;
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
