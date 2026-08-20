//! Scratchstack database schema and models
#![warn(clippy::all)]
#![allow(clippy::manual_range_contains)]
#![deny(
    missing_docs,
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_html_tags,
    rustdoc::private_intra_doc_links,
    rustdoc::unescaped_backticks
)]
#![cfg_attr(doc, feature(doc_cfg))]

use {
    pct_str::{PctString, UriReserved},
    scratchstack_core::RequestId,
    scratchstack_pagination::{
        FixedKeyService, OperationPaginator, ScratchstackOperationMetadata, ScratchstackServiceMetadata,
    },
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        types::error::{InternalFailure as IamInternalFailure, ValidationError as IamValidationError},
    },
    scratchstack_shapes_sts::error_meta::Error as StsError,
    serde::Serialize,
    sqlx::postgres::PgTransaction,
};

/// Account-related database operations.
pub mod account;

/// Constants used across database operations.
pub mod constants;

/// Group-related database operations.
pub mod group;

/// IAM identifier parsing and construction utilities.
pub mod id;

/// Database migration utilities.
pub mod migrate;

/// Partition-related database operations.
pub mod partition;

/// Path-related utilities.
pub mod path;

/// Policy-related database operations.
pub mod policy;

/// Role-related database operations.
pub mod role;

/// Session token encryption key-related database operations.
pub mod session_token_encryption_key;

/// Tag-related utilities.
pub mod tag;

/// User-related database operations.
pub mod user;

#[cfg(feature = "gsk-direct")]
mod gsk_direct;
#[cfg(feature = "gsk-direct")]
pub use gsk_direct::*;

/// Database utilities.
#[cfg(feature = "utils")]
pub mod utils;

/// Create a connection URL programmatically.
#[derive(Clone, Debug, Default)]
pub struct ConnectionUrlBuilder {
    username: Option<String>,
    password: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    database: Option<String>,
}

/// Trait that all request types implement to be executed and return a response.
pub trait RequestExecutor {
    /// The type of response returned by this request.
    type Response: Serialize + Send + 'static;

    /// The type of error returned by this request.
    type Error: Send + 'static;

    /// Execute the request and return the response. The transaction is not committed, so any
    /// returned results are subject to the transaction being committed. Do **not** use results
    /// until the commit has been completed.
    ///
    /// `request_id` is the id of the service request that triggered this operation; it is stamped
    /// on every error returned so callers can correlate a failure with the service logs.
    fn execute(
        &self,
        tx: &mut PgTransaction<'_>,
        request_id: RequestId,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>>;
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

/// Constrain the `max_items` parameter for a list operation to be between 1 and 1000, inclusive, or
/// return a validation error. If `max_items` is `None`, return the default of 100.
pub(crate) fn constrain_max_items(max_items: Option<i32>, request_id: RequestId) -> Result<usize, IamValidationError> {
    if let Some(max_items) = max_items {
        if max_items <= 0 {
            let message = "max_items must be a positive integer.".to_string();
            Err(IamValidationError::builder().message(message).request_id(request_id).build())
        } else if max_items > 1000 {
            let message = "max_items must be at most 1000.".to_string();
            Err(IamValidationError::builder().message(message).request_id(request_id).build())
        } else {
            Ok(max_items as usize)
        }
    } else {
        Ok(100)
    }
}

/// Construct a generic `InternalFailure` with the standard internal-failure message. Use
/// this for every "unexpected database/builder/etc. error" call site — never leak
/// underlying details to the caller (those go to the log).
pub(crate) fn internal_failure(request_id: RequestId) -> IamInternalFailure {
    IamInternalFailure::builder().message(constants::MSG_INTERNAL_FAILURE).request_id(request_id).build()
}

/// Construct an `OperationPaginator` for an IAM operation.
pub(crate) fn make_iam_paginator(
    partition: &str,
    operation_name: &'static str,
    request_id: RequestId,
) -> Result<OperationPaginator<FixedKeyService, FixedKeyService>, IamError> {
    let service_metadata = ScratchstackServiceMetadata::new(partition.to_string(), "", constants::SERVICE_ID_IAM);
    let operation_metadata = ScratchstackOperationMetadata::new(constants::IAM_API_VERSION, operation_name);
    OperationPaginator::new_fixed_key(
        &service_metadata,
        &operation_metadata,
        constants::IAM_PAGINATION_KEY_ID,
        *constants::IAM_PAGINATION_KEY,
    )
    .map_err(|e| {
        log::error!("Failed to create paginator for {operation_name}: {e}");
        internal_failure(request_id).into()
    })
}

/// Construct an `OperationPaginator` for an STS operation.
///
/// TODO: Remove if we don't need this.
#[allow(dead_code)]
pub(crate) fn make_paginator_sts(
    partition: &str,
    operation_name: &'static str,
    request_id: RequestId,
) -> Result<OperationPaginator<FixedKeyService, FixedKeyService>, StsError> {
    let service_metadata = ScratchstackServiceMetadata::new(partition.to_string(), "", constants::SERVICE_ID_STS);
    let operation_metadata = ScratchstackOperationMetadata::new(constants::STS_API_VERSION, operation_name);
    OperationPaginator::new_fixed_key(
        &service_metadata,
        &operation_metadata,
        constants::STS_PAGINATION_KEY_ID,
        *constants::STS_PAGINATION_KEY,
    )
    .map_err(|e| {
        log::error!("Failed to create paginator for {operation_name}: {e}");
        internal_failure(request_id).into()
    })
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
