use {
    log,
    pct_str::{PctString, UriReserved},
    postgresql_commands::Settings as _,
    postgresql_embedded::{
        Error as PgError, PostgreSQL, SettingsBuilder as PgSettingsBuilder, Status as PgStatus, VersionReq,
    },
    rand::random_range,
    scratchstack_database::model::iam,
    sqlx::{ConnectOptions, postgres::{PgConnectOptions, PgPoolOptions}, query},
    std::{env, fmt::Debug, time::Duration},
    tempfile::{TempDir, tempdir},
};

struct TempDatabase {
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
}

const PASSWORD_CHARSET: &[u8] = br#"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$*+,-./^_`|~"#;

const DB_VERSION: &str = "18.3";

const BOOTSTRAP_USER: &str = "postgres";
const DB_PORT: u16 = 7715;

#[allow(dead_code)]
fn connection_url(
    username: impl AsRef<str>,
    password: impl AsRef<str>,
    host: impl AsRef<str>,
    port: u16,
    database: impl AsRef<str>,
) -> String {
    let username_esc = PctString::encode(username.as_ref().chars(), UriReserved::Any);
    let bootstrap_password_esc = PctString::encode(password.as_ref().chars(), UriReserved::Any);
    let database = database.as_ref();
    if database.is_empty() {
        format!("postgres://{}:{}@{}:{}", username_esc, bootstrap_password_esc, host.as_ref(), port)
    } else {
        format!("postgres://{}:{}@{}:{}/{}", username_esc, bootstrap_password_esc, host.as_ref(), port, database)
    }
}

fn generate_password(length: usize) -> String {
    let mut result = String::with_capacity(length);

    for _ in 0..length {
        let index = random_range(0..PASSWORD_CHARSET.len());
        let c = PASSWORD_CHARSET[index] as char;
        result.push(c);
    }

    result
}

impl TempDatabase {
    async fn new() -> Result<Self, PgError> {
        let base_dir = tempdir().expect("Failed to create temporary directory");
        let bootstrap_password: String = generate_password(32);
        let install_dir = env::var("HOME").expect("HOME environment variable not set") + "/.theseus/postgresql/18.3.0";

        let settings = PgSettingsBuilder::new()
            .version(VersionReq::parse(DB_VERSION).expect("Failed to parse database version requirement"))
            .installation_dir(install_dir)
            .temporary(true)
            .host("127.0.0.1")
            .port(DB_PORT)
            .password(&bootstrap_password)
            .trust_installation_dir(true)
            .build();

        let database = PostgreSQL::new(settings);

        Ok(Self {
            database,
            base_dir,
            bootstrap_password,
        })
    }

    #[allow(dead_code)]
    #[inline]
    fn settings(&self) -> &postgresql_embedded::Settings {
        self.database.settings()
    }

    #[allow(dead_code)]
    #[inline]
    fn status(&self) -> PgStatus {
        self.database.status()
    }

    #[allow(dead_code)]
    #[inline]
    async fn setup(&mut self) -> Result<(), PgError> {
        log::info!("Setting up PostgreSQL database");
        self.database.setup().await
    }

    #[allow(dead_code)]
    #[inline]
    async fn start(&mut self) -> Result<(), PgError> {
        log::info!("Starting PostgreSQL database");
        self.database.start().await
    }

    #[allow(dead_code)]
    #[inline]
    async fn stop(&self) -> Result<(), PgError> {
        log::info!("Stopping PostgreSQL database");
        self.database.stop().await
    }

    #[allow(dead_code)]
    #[inline]
    async fn create_database<S>(&self, database_name: S) -> Result<(), PgError>
    where
        S: AsRef<str> + Debug,
    {
        let database_name = database_name.as_ref();
        log::info!("Creating database '{database_name}'");
        self.database.create_database(database_name).await
    }

    #[allow(dead_code)]
    #[inline]
    async fn drop_database<S>(&self, database_name: S) -> Result<(), PgError>
    where
        S: AsRef<str> + Debug,
    {
        let database_name = database_name.as_ref();
        log::info!("Dropping database '{database_name}'");
        self.database.drop_database(database_name).await
    }

    #[allow(dead_code)]
    #[inline]
    async fn database_exists<S>(&self, database_name: S) -> Result<bool, PgError>
    where
        S: AsRef<str> + Debug,
    {
        self.database.database_exists(database_name).await
    }

    #[allow(dead_code)]
    #[inline]
    fn bootstrap_url(&self) -> String {
        connection_url(
            BOOTSTRAP_USER,
            &self.bootstrap_password,
            self.settings().get_host().to_str().expect("Host should be a valid string"),
            self.settings().get_port(),
            "postgres",
        )
    }
}

/// Test all of the features of the database.
///
/// We do this instead of more granular testing because the database we're running against is typically stateful.
#[test_log::test(tokio::test)]
async fn test_database() {
    let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
    assert_ne!(database.settings().get_port(), 0, "Database port should be non-zero");
    database.setup().await.expect("Failed to set up PostgreSQL database");
    database.start().await.expect("Failed to start PostgreSQL database");
    let settings = database.settings();

    let mut bootstrap = PgConnectOptions::new()
        .host(&settings.host)
        .host("127.0.0.1")
        .port(settings.port)
        .username(BOOTSTRAP_USER)
        .password(&database.bootstrap_password)
        .connect()
        .await
        .expect("Failed to connect to PostgreSQL database with ConnectOptions");
    let password = generate_password(32);

    query(&format!("CREATE ROLE scratchstack NOSUPERUSER CREATEDB NOCREATEROLE LOGIN PASSWORD '{password}'"))
        .execute(&mut bootstrap)
        .await
        .expect("Failed to create role in PostgreSQL database");
    query("CREATE DATABASE iam OWNER scratchstack")
        .execute(&mut bootstrap)
        .await
        .expect("Failed to create database in PostgreSQL database");
    drop(bootstrap);

    let url = connection_url("scratchstack", &password, "127.0.0.1", settings.port, "iam");

    let pool = PgPoolOptions::new()
        .min_connections(1)
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&url)
        .await
        .expect("Failed to connect to PostgreSQL database");

    let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
    iam::MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
    iam::MIGRATOR.undo(&mut *c, 0).await.expect("Failed to undo database migrations");
}
