//! Utility functions and types for testing the `scratchstack-database` crate.
use {
    crate::ConnectionUrlBuilder,
    log,
    postgresql_commands::Settings as _,
    postgresql_embedded::{
        Error as PgError, PostgreSQL, SettingsBuilder as PgSettingsBuilder, Status as PgStatus, VersionReq,
    },
    rand::random_range,
    sqlx::{
        ConnectOptions as _, Error as SqlxError, Row as _,
        postgres::{PgConnectOptions, PgConnection, PgPoolOptions},
        query,
    },
    std::{fmt::Debug, time::Duration},
    tempfile::{TempDir, tempdir},
    tokio::{fs::File, io::AsyncReadExt as _, net::TcpListener},
};

async fn find_open_port() -> u16 {
    loop {
        let port = random_range(1024u16..65535u16);
        if TcpListener::bind(("127.0.0.1", port)).await.is_ok() {
            return port;
        }
    }
}

/// Quote an identifier for use in a PostgreSQL DDL statement.
///
/// This returns the identifier surrounded by double quotes, with any double quotes in the identifier escaped by doubling them.
pub fn pg_quote_ident(ident: &str) -> String {
    let escaped = ident.replace('"', "\"\"");
    format!("\"{}\"", escaped)
}

/// Quote a literal for use in a PostgreSQL DDL statement.
///
/// This returns the literal surrounded by single quotes, with any single quotes in the literal escaped by doubling them.
pub fn pg_quote_literal(literal: &str) -> String {
    let escaped = literal.replace('\'', "''");
    format!("'{}'", escaped)
}

/// Create a database if it does not already exist.
///
/// The connection must be made as a superuser, typically on the postgres database.
///
/// This function avoids errors that may occur if the database already exists.
pub async fn create_database_if_not_exists(conn: &mut PgConnection, db_name: &str) -> Result<(), SqlxError> {
    let present = query("SELECT COUNT(1) FROM pg_catalog.pg_database WHERE datname = $1")
        .bind(db_name)
        .fetch_one(&mut *conn)
        .await?
        .try_get::<i64, _>(0)?;

    if present == 0 {
        log::info!("Creating database {db_name}");
        let sql = format!("CREATE DATABASE {}", pg_quote_ident(db_name));
        query(&sql).execute(&mut *conn).await?;
        log::info!("Created database {db_name}");
    }

    Ok(())
}

/// Create a user if it does not already exist.
///
/// The connection must be made as a superuser, typically on the postgres database.
///
/// This function avoids errors that may occur if the user already exists.
pub async fn create_user_if_not_exists(
    conn: &mut PgConnection,
    username: &str,
    password: &str,
) -> Result<(), SqlxError> {
    let present = query("SELECT COUNT(1) FROM pg_catalog.pg_roles WHERE rolname = $1")
        .bind(username)
        .fetch_one(&mut *conn)
        .await?
        .try_get::<i64, _>(0)?;

    if present == 0 {
        // No; create the user.
        log::info!("Creating database role for user {username}");
        let sql = format!(
            "CREATE ROLE {} WITH LOGIN NOSUPERUSER CREATEDB NOCREATEROLE NOINHERIT NOREPLICATION PASSWORD {}",
            pg_quote_ident(username),
            pg_quote_literal(password),
        );
        query(&sql).bind(username).execute(&mut *conn).await?;
        log::info!("Created database role for user {username}");
    } else {
        log::info!("Database role for user {username} already exists");
    }

    Ok(())
}

/// Allow DDL permissions to be granted to a user on a database.
pub async fn grant_ddl_permissions(conn: &mut PgConnection, db_name: &str, username: &str) -> Result<(), SqlxError> {
    let sql = format!(
        "GRANT CREATE, TEMPORARY, CONNECT ON DATABASE {} TO {} WITH GRANT OPTION",
        pg_quote_ident(db_name),
        pg_quote_ident(username)
    );
    query(&sql).bind(username).execute(&mut *conn).await?;
    log::info!("Granted DDL permissions to user {username} on database {db_name}");
    Ok(())
}

/// The current state of the temporary database instance.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TempDatabaseState {
    /// The database instance has been created but not set up yet. The data directory has not been initialized and the
    /// PostgreSQL server process is not running.
    #[default]
    Created,

    /// The database instance has been set up by initializing the data directory and performing any necessary
    /// configuration, but the PostgreSQL server process is not running.
    SetUp,

    /// The database instance is fully set up and the PostgreSQL server process is running, but the database has not
    /// been bootstrapped by creating a `scratchstack` user and an `iam` database.
    RunningNotBootstrapped,

    /// The database instance is fully set up, the PostgreSQL server process is running, and the database has been
    /// bootstrapped by creating a `scratchstack` user and an `iam` database.
    RunningBootstrapped,

    /// The database instance is fully set up and the database has been bootstrapped by creating a `scratchstack` user
    /// and an `iam` database, but has been stopped by shutting down the PostgreSQL server process.
    Stopped,
}

/// A temporary PostgreSQL database instance for testing.
pub struct TempDatabase {
    /// The underlying embedded PostgreSQL database.
    ///
    /// This *must* be before `base_dir` so that it is dropped before the temporary directory is deleted.
    database: PostgreSQL,

    /// The temporary directory used for the database's data directory.
    #[allow(dead_code)]
    base_dir: TempDir,

    /// The bootstrap password for the database, which is randomly generated on creation.
    #[allow(dead_code)]
    bootstrap_password: String,

    /// The scratchstack user password for the database (randomly generated)
    scratchstack_password: String,

    /// The current state of the database.
    state: TempDatabaseState,
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
        let scratchstack_password = generate_password(32);
        let port = find_open_port().await;

        let settings = PgSettingsBuilder::new()
            .version(VersionReq::parse(DB_VERSION).expect("Failed to parse database version requirement"))
            .temporary(true)
            .port(port)
            .password(&bootstrap_password)
            .build();

        let database = PostgreSQL::new(settings);

        Ok(Self {
            database,
            base_dir,
            bootstrap_password,
            scratchstack_password,
            state: TempDatabaseState::Created,
        })
    }

    /// Return the bootstrap password for the database, which is randomly generated on creation.
    #[inline]
    pub fn bootstrap_password(&self) -> &str {
        &self.bootstrap_password
    }

    /// Return the scratchstack user password for the database, which is randomly generated during bootstrapping.
    #[inline]
    pub fn scratchstack_password(&self) -> &str {
        &self.scratchstack_password
    }

    /// Return the settings used for the temporary database instance.
    #[inline]
    pub fn settings(&self) -> &postgresql_embedded::Settings {
        self.database.settings()
    }

    /// Return the status of the temporary database instance.
    #[inline]
    pub fn status(&self) -> PgStatus {
        self.database.status()
    }

    /// Set up the temporary database instance by initializing the data directory and performing any necessary
    /// configuration.
    pub async fn setup(&mut self) -> Result<(), PgError> {
        if self.state == TempDatabaseState::Created {
            log::info!("Setting up PostgreSQL database");
            self.database.setup().await?;
            self.state = TempDatabaseState::SetUp;
        } else {
            log::info!("PostgreSQL database is already set up; current state is {:?}", self.state);
        }

        Ok(())
    }

    /// Start the temporary database.
    ///
    /// This sets up the temporary database instance (if it hasn't already been set up) by initializing the data
    /// directory and performing any necessary configuration, then starts the database server process.
    pub async fn start(&mut self) -> Result<(), PgError> {
        if self.state == TempDatabaseState::Created {
            self.setup().await?;
            assert_eq!(self.state, TempDatabaseState::SetUp, "Database state should be SetUp after setup");
        }

        match self.state {
            TempDatabaseState::Created => unreachable!("Database should have been set up in the previous step"),
            TempDatabaseState::SetUp => {
                log::info!("Starting PostgreSQL database");
                self.do_start().await?;
                self.state = TempDatabaseState::RunningNotBootstrapped;
            }
            TempDatabaseState::Stopped => {
                log::info!("Starting PostgreSQL database");
                self.do_start().await?;
                self.state = TempDatabaseState::RunningBootstrapped;
            }
            TempDatabaseState::RunningNotBootstrapped | TempDatabaseState::RunningBootstrapped => {
                log::info!("PostgreSQL database is already running; current state is {:?}", self.state);
            }
        }

        Ok(())
    }

    async fn do_start(&mut self) -> Result<(), PgError> {
        match self.database.start().await {
            Ok(()) => Ok(()),
            Err(e) => {
                let start_log = self.settings().data_dir.join("start.log");
                match File::open(&start_log).await {
                    Ok(mut f) => {
                        let mut contents = String::new();
                        if let Err(e) = f.read_to_string(&mut contents).await {
                            log::error!("Failed to read start log: {e}");
                        } else {
                            log::error!("PostgreSQL start log:\n{contents}");
                        }
                    }
                    Err(e) => log::error!("Failed to open start log {}: {}", start_log.display(), e),
                }

                Err(e)
            }
        }
    }

    /// Bootstrap the database by setting up a `scratchstack` user with a randomly generated
    /// password and creating a database named `iam` owned by the `scratchstack` user.
    pub async fn bootstrap(&mut self) -> Result<(), PgError> {
        if self.state == TempDatabaseState::Stopped {
            self.start().await?;
            assert_eq!(
                self.state,
                TempDatabaseState::RunningBootstrapped,
                "Database state should be RunningBootstrapped after starting from Stopped state"
            );
            return Ok(());
        }

        if self.state == TempDatabaseState::RunningBootstrapped {
            log::info!("PostgreSQL database is already bootstrapped; current state is {:?}", self.state);
            return Ok(());
        }

        if matches!(self.state, TempDatabaseState::Created | TempDatabaseState::SetUp) {
            self.start().await?;
            assert_eq!(
                self.state,
                TempDatabaseState::RunningNotBootstrapped,
                "Database state should be RunningNotBootstrapped after starting"
            );
        }

        assert_eq!(
            self.state,
            TempDatabaseState::RunningNotBootstrapped,
            "Database should be running but not bootstrapped before bootstrapping"
        );

        let settings = self.settings();
        let mut c = PgConnectOptions::new()
            .port(settings.port)
            .username(BOOTSTRAP_USER)
            .password(&self.bootstrap_password)
            .connect()
            .await?;

        query(&format!(
            "CREATE ROLE scratchstack NOSUPERUSER CREATEDB NOCREATEROLE LOGIN PASSWORD '{}'",
            self.scratchstack_password
        ))
        .execute(&mut c)
        .await
        .expect("Failed to create role in PostgreSQL database");

        query("CREATE DATABASE iam OWNER scratchstack")
            .execute(&mut c)
            .await
            .expect("Failed to create database in PostgreSQL database");
        self.state = TempDatabaseState::RunningBootstrapped;

        Ok(())
    }

    /// Stop the temporary database instance by shutting down the PostgreSQL server process.
    pub async fn stop(&mut self) -> Result<(), PgError> {
        match self.state {
            TempDatabaseState::Created | TempDatabaseState::SetUp | TempDatabaseState::Stopped => {
                log::info!("PostgreSQL database is not running; current state is {:?}", self.state);
            }
            TempDatabaseState::RunningNotBootstrapped => {
                log::info!("Stopping PostgreSQL database");
                self.database.stop().await?;
                self.state = TempDatabaseState::SetUp;
            }
            TempDatabaseState::RunningBootstrapped => {
                log::info!("Stopping PostgreSQL database");
                self.database.stop().await?;
                self.state = TempDatabaseState::Stopped;
            }
        }
        log::info!("Stopping PostgreSQL database");

        Ok(())
    }

    /// Returns a PostgreSQL connection pool for the scratchstack user.
    pub async fn get_scratchstack_pool(&self) -> Result<sqlx::PgPool, SqlxError> {
        let conn_options = PgConnectOptions::new()
            .port(self.settings().get_port())
            .username("scratchstack")
            .password(&self.scratchstack_password)
            .database("iam");

        PgPoolOptions::new()
            .min_connections(1)
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(conn_options)
            .await
    }

    /// Get a connection URL for connecting to the temporary PostgreSQL instance using the bootstrap user.
    pub fn bootstrap_url(&self) -> String {
        ConnectionUrlBuilder::default()
            .username(BOOTSTRAP_USER)
            .password(&self.bootstrap_password)
            .host(self.settings().get_host().to_str().expect("Host should be a valid string"))
            .port(self.settings().get_port())
            .database("postgres")
            .build()
    }
}
