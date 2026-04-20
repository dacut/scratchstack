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

/// Create a connection URL programmatically.
#[derive(Clone, Debug, Default)]
pub struct ConnectionUrlBuilder {
    username: Option<String>,
    password: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    database: Option<String>,
}

impl ConnectionUrlBuilder {
    /// Set the username component of the connection URL.
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set the password component of the connection URL.
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Set the host component of the connection URL.
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Set the port component of the connection URL.
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the database component of the connection URL.
    pub fn database(mut self, database: impl Into<String>) -> Self {
        self.database = Some(database.into());
        self
    }

    /// Build the connection URL string.
    pub fn build(self) -> String {
        let mut result = "postgres://".to_string();
        if let Some(username) = self.username {
            let username_encoded = PctString::encode(username.chars(), UriReserved::Any);
            result.push_str(username_encoded.as_str());

            if let Some(password) = self.password {
                let password_encoded = PctString::encode(password.chars(), UriReserved::Any);
                result.push(':');
                result.push_str(password_encoded.as_str());
            }

            result.push('@');
        }

        if let Some(host) = self.host {
            let host_encoded = PctString::encode(host.chars(), UriReserved::Any);
            result.push_str(host_encoded.as_str());
        } else {
            result.push_str("localhost");
        }

        if let Some(port) = self.port {
            result.push(':');
            result.push_str(port.to_string().as_str());
        }

        if let Some(database) = self.database {
            let database_encoded = PctString::encode(database.chars(), UriReserved::Any);
            result.push('/');
            result.push_str(database_encoded.as_str());
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username_at_sign_encoded() {
        // '@' would break host parsing if unencoded.
        let url = ConnectionUrlBuilder::default().username("user@example").build();
        assert_eq!(url, "postgres://user%40example@localhost");
    }

    #[test]
    fn test_username_colon_encoded() {
        // ':' would be mistaken for the user/password separator if unencoded.
        let url = ConnectionUrlBuilder::default().username("user:name").build();
        assert_eq!(url, "postgres://user%3Aname@localhost");
    }

    #[test]
    fn test_password_special_chars_encoded() {
        // '@' and ':' in the password would break URL parsing if unencoded.
        let url = ConnectionUrlBuilder::default().username("alice").password("p@ss:word").build();
        assert_eq!(url, "postgres://alice:p%40ss%3Aword@localhost"); // codeql[rust/hard-coded-cryptographic-value]
    }

    #[test]
    fn test_host_directory_path_encoded() {
        // Unix socket directory paths contain '/' which must be percent-encoded so
        // they are not interpreted as the URL path component.
        let url = ConnectionUrlBuilder::default().host("/var/run/postgresql").build();
        assert_eq!(url, "postgres://%2Fvar%2Frun%2Fpostgresql");
    }

    #[test]
    fn test_host_directory_path_with_credentials_and_database() {
        let url = ConnectionUrlBuilder::default()
            .username("alice")
            .password("secret") // codeql[rust/hard-coded-cryptographic-value]
            .host("/var/run/postgresql")
            .database("mydb")
            .build();
        assert_eq!(url, "postgres://alice:secret@%2Fvar%2Frun%2Fpostgresql/mydb");
    }

    #[test]
    fn test_database_name_encoded() {
        // '/' and '?' in a database name must be percent-encoded.
        let url = ConnectionUrlBuilder::default().database("my/db?name").build();
        assert_eq!(url, "postgres://localhost/my%2Fdb%3Fname");
    }
}
