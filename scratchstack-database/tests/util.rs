//! Utility functions and types for testing the `scratchstack-database` crate.
use {
    log,
    postgresql_commands::Settings as _,
    postgresql_embedded::{
        Error as PgError, PostgreSQL, SettingsBuilder as PgSettingsBuilder, Status as PgStatus, VersionReq,
    },
    rand::random_range,
    scratchstack_database::connection_url,
    std::fmt::Debug,
    tempfile::{TempDir, tempdir},
};

/// A temporary PostgreSQL database instance for testing.
pub struct TempDatabase {
    /// The underlying embedded PostgreSQL database.
    ///
    /// This *must* be before `base_dir` so that it is dropped before the temporary directory is deleted.
    pub database: PostgreSQL,

    /// The temporary directory used for the database's data directory.
    #[allow(dead_code)]
    pub base_dir: TempDir,

    /// The bootstrap password for the database, which is randomly generated on creation.
    #[allow(dead_code)]
    pub bootstrap_password: String,
}

/// Subset of characters to use when generating random passwords for testing.
///
/// PostgreSQL allows more characters than these in passwords, but these are sufficient for testing and avoid issues
/// with characters that may need to be escaped in URLs.
pub const PASSWORD_CHARSET: &[u8] = br#"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$*+,-./^_`|~"#;

/// The version of PostgreSQL to use for testing.
pub const DB_VERSION: &str = "18.3";

/// The initial username to use for connecting to the database before creating a scratchstack user.
pub const BOOTSTRAP_USER: &str = "postgres";

/// The port to use for the temporary PostgreSQL database. We use a non-standard port to avoid conflicts with any
/// existing PostgreSQL instances that may be running on the default port.
pub const DB_PORT: u16 = 7715;

pub fn generate_password(length: usize) -> String {
    let mut result = String::with_capacity(length);

    for _ in 0..length {
        let index = random_range(0..PASSWORD_CHARSET.len());
        let c = PASSWORD_CHARSET[index] as char;
        result.push(c);
    }

    result
}

impl TempDatabase {
    /// Create a new temporary PostgreSQL database instance.
    pub async fn new() -> Result<Self, PgError> {
        let base_dir = tempdir().expect("Failed to create temporary directory");
        let bootstrap_password: String = generate_password(32);

        let settings = PgSettingsBuilder::new()
            .version(VersionReq::parse(DB_VERSION).expect("Failed to parse database version requirement"))
            .temporary(true)
            .host("127.0.0.1")
            .port(DB_PORT)
            .password(&bootstrap_password)
            .build();

        let database = PostgreSQL::new(settings);

        Ok(Self {
            database,
            base_dir,
            bootstrap_password,
        })
    }

    /// Return the settings used for the temporary database instance.
    #[allow(dead_code)]
    #[inline]
    pub fn settings(&self) -> &postgresql_embedded::Settings {
        self.database.settings()
    }

    /// Return the status of the temporary database instance.
    #[allow(dead_code)]
    #[inline]
    pub fn status(&self) -> PgStatus {
        self.database.status()
    }

    /// Set up the temporary database instance by initializing the data directory and performing any necessary configuration.
    #[allow(dead_code)]
    #[inline]
    pub async fn setup(&mut self) -> Result<(), PgError> {
        log::info!("Setting up PostgreSQL database");
        self.database.setup().await
    }

    /// Start the temporary database instance by launching the PostgreSQL server process.
    #[allow(dead_code)]
    #[inline]
    pub async fn start(&mut self) -> Result<(), PgError> {
        log::info!("Starting PostgreSQL database");
        self.database.start().await
    }

    /// Stop the temporary database instance by shutting down the PostgreSQL server process.
    #[allow(dead_code)]
    #[inline]
    pub async fn stop(&self) -> Result<(), PgError> {
        log::info!("Stopping PostgreSQL database");
        self.database.stop().await
    }

    /// Create a new database with the given name in the temporary PostgreSQL instance.
    #[allow(dead_code)]
    #[inline]
    pub async fn create_database<S>(&self, database_name: S) -> Result<(), PgError>
    where
        S: AsRef<str> + Debug,
    {
        let database_name = database_name.as_ref();
        log::info!("Creating database '{database_name}'");
        self.database.create_database(database_name).await
    }

    /// Drop the database with the given name from the temporary PostgreSQL instance.
    #[allow(dead_code)]
    #[inline]
    pub async fn drop_database<S>(&self, database_name: S) -> Result<(), PgError>
    where
        S: AsRef<str> + Debug,
    {
        let database_name = database_name.as_ref();
        log::info!("Dropping database '{database_name}'");
        self.database.drop_database(database_name).await
    }

    /// Check if a database with the given name exists in the temporary PostgreSQL instance.
    #[allow(dead_code)]
    #[inline]
    pub async fn database_exists<S>(&self, database_name: S) -> Result<bool, PgError>
    where
        S: AsRef<str> + Debug,
    {
        self.database.database_exists(database_name).await
    }

    /// Get a connection URL for connecting to the temporary PostgreSQL instance using the bootstrap user.
    #[allow(dead_code)]
    #[inline]
    pub fn bootstrap_url(&self) -> String {
        connection_url(
            Some(BOOTSTRAP_USER),
            Some(&self.bootstrap_password),
            Some(self.settings().get_host().to_str().expect("Host should be a valid string")),
            Some(self.settings().get_port()),
            Some("postgres"),
        )
    }
}
