//! Database loading and dumping utilities.
use {
    pct_str::{PctString, UriReserved},
    std::env::var,
    sqlx::postgres::PgConnection,
    tower::BoxError,
};

/// Trait that allows a model object to be dumped from a database.
#[cfg(feature = "load")]
pub trait Dumpable: Sized {
    /// Dump a table containing the specified objects from the database.
    fn dump_from(
        database: &mut PgConnection,
    ) -> impl std::future::Future<Output = Result<Vec<Self>, sqlx::Error>>;
}

/// Trait that allows a model object to be loaded into a database.
#[cfg(feature = "load")]
pub trait Loadable {
    /// Load the model object into the database.
    ///
    /// On success, returns the number of records inserted into the database.
    fn load_into(
        &self,
        conn: &mut PgConnection,
    ) -> impl std::future::Future<Output = Result<usize, sqlx::Error>>;
}

/// Create a database URL from environment variables.
///
/// The environment variables used are determined by the `env_prefix` parameter.
///
/// If `<env_prefix>_DATABASE_URL` is set, it will be returned directly. Otherwise:
/// * The host will be obtained from `<env_prefix>_DATABASE_HOST`, defaulting to `localhost` if not
///   set.
/// * The port will be obtained from `<env_prefix>_DATABASE_PORT`, defaulting to `default_port` if
///   not set.
/// * The user will be obtained from `<env_prefix>_DATABASE_USER`, defaulting to `default_user` if
///   not set.
/// * The password will be obtained from `<env_prefix>_DATABASE_PASSWORD`. If this is not set, an
///   error will be returned.
///
/// The resulting URL will be in the format `postgres://<user>:<password>@<host>:<port>/<database>`.
/// The user and password will be percent-encoded to ensure that special characters are properly
/// escaped.
pub fn database_url_from_env(
    env_prefix: impl AsRef<str>,
    default_database: impl Into<String>,
    default_user: impl Into<String>,
    default_port: u16,
) -> Result<String, BoxError> {
    let env_prefix = env_prefix.as_ref();

    let url_env = format!("{env_prefix}_DATABASE_URL");
    let host_env = format!("{env_prefix}_DATABASE_HOST");
    let port_env = format!("{env_prefix}_DATABASE_PORT");
    let db_env = format!("{env_prefix}_DB");
    let user_env = format!("{env_prefix}_DATABASE_USER");
    let password_env = format!("{env_prefix}_DATABASE_PASSWORD");

    // If there's a prefix_DATABASE_URL environment variable set, use it.
    if let Ok(url) = var(url_env)
        && !url.is_empty()
    {
        return Ok(url);
    }

    // Otherwise, obtain this from individual environment variables.
    let host = var(host_env).unwrap_or_else(|_| "localhost".to_string());
    let port = if let Ok(port) = var(&port_env) {
        port.parse::<u16>()
            .map_err(|_| format!("{port_env} environment variable must be a valid port number from 1-65535"))?
    } else {
        default_port
    };
    let user = PctString::encode(var(user_env).unwrap_or_else(|_| default_user.into()).chars(), UriReserved::Any);
    let Some(password) = var(&password_env).ok() else {
        return Err(format!("{password_env} environment variable not set").into());
    };
    let password = PctString::encode(password.chars(), UriReserved::Any);
    let database = var(db_env).unwrap_or_else(|_| default_database.into());

    Ok(format!("postgres://{}:{}@{}:{}/{}", user, password, host, port, database))
}
