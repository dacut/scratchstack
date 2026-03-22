//! Database loading and dumping utilities.
use {
    pct_str::{PctString, UriReserved},
    sqlx::postgres::PgConnection,
};

/// Trait that allows a model object to be dumped from a database.
#[cfg(feature = "load")]
pub trait Dumpable: Sized {
    /// Dump a table containing the specified objects from the database.
    fn dump_from(database: &mut PgConnection) -> impl std::future::Future<Output = Result<Vec<Self>, sqlx::Error>>;
}

/// Trait that allows a model object to be loaded into a database.
#[cfg(feature = "load")]
pub trait Loadable {
    /// Load the model object into the database.
    ///
    /// On success, returns the number of records inserted into the database.
    fn load_into(&self, conn: &mut PgConnection) -> impl std::future::Future<Output = Result<usize, sqlx::Error>>;
}

/// Create a database URL from command line arguments.
pub fn connection_url(
    username: Option<impl AsRef<str>>,
    password: Option<impl AsRef<str>>,
    host: Option<impl AsRef<str>>,
    port: Option<u16>,
    database: Option<impl AsRef<str>>,
) -> String {
    let mut result = "postgres://".to_string();
    if let Some(username) = username {
        let username_encoded = PctString::encode(username.as_ref().chars(), UriReserved::Any);
        result.push_str(username_encoded.as_str());

        if let Some(password) = password {
            let password_encoded = PctString::encode(password.as_ref().chars(), UriReserved::Any);
            result.push(':');
            result.push_str(password_encoded.as_str());
        }

        result.push('@');
    }

    if let Some(host) = host {
        result.push_str(host.as_ref());
    } else {
        result.push_str("localhost");
    }

    if let Some(port) = port {
        result.push(':');
        result.push_str(port.to_string().as_str());
    }

    if let Some(database) = database {
        result.push('/');
        result.push_str(database.as_ref());
    }

    result
}
