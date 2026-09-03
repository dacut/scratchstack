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
        types::error::{
            InternalFailure as IamInternalFailure, InvalidInputException as IamInvalidInput,
            ValidationError as IamValidationError,
        },
    },
    scratchstack_shapes_sts::error_meta::Error as StsError,
    serde::{Serialize, de::DeserializeOwned},
    sqlx::postgres::PgTransaction,
};

pub mod account;
pub mod authz;
pub mod constants;
pub mod group;
pub mod id;
pub mod migrate;
pub mod partition;
pub mod path;
pub mod policy;
pub mod role;
pub mod session_token_encryption_key;
pub mod tag;
pub mod user;

#[cfg(feature = "gsk-direct")]
mod gsk_direct;
#[cfg(feature = "gsk-direct")]
pub use gsk_direct::*;

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
    ///
    /// A password is emitted only alongside a username. It occupies the second half of the URL's
    /// userinfo field, so without a username there is nowhere in the URL to put it. Setting one
    /// without the other drops it and logs a warning rather than failing: the URL that results
    /// connects with no credential at all, which a trust-authenticated server will accept, and a
    /// caller who meant to supply a password would otherwise have no sign that it went nowhere.
    ///
    /// An unset host becomes `localhost`. An unset port or database is left out entirely, so the
    /// server's defaults apply.
    ///
    /// Every component is percent-encoded, so a username, password, host or database name
    /// containing `@`, `:`, `/` or `?` cannot break the URL apart -- which is what lets a Unix
    /// socket directory be passed as the host.
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
        } else if self.password.is_some() {
            log::warn!("A password was set on a connection URL with no username; it is not part of the URL");
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

/// Decrypt the pagination token `token` a request asks to continue from, as the marker type `T`
/// describing where the previous page stopped.
///
/// A token that will not decrypt is the caller's to fix rather than ours: it is one this service
/// never issued, one issued for a different operation, or one altered on its way back. Most often
/// it is a client-side pagination token -- several SDKs and the AWS CLI hand out a token of their
/// own that wraps the marker, and passing that back in place of the marker lands here. None of
/// that is a server fault, so it is reported as invalid input rather than as an internal failure,
/// which tells the caller what it can do about it and keeps a routine client mistake out of the
/// error log.
///
/// What actually went wrong with the token goes to the log at debug level and no further: a caller
/// learns that the token is not one it may continue from, and nothing about the key or the
/// operation metadata it failed against.
pub(crate) async fn decrypt_pagination_token<T: DeserializeOwned>(
    paginator: &OperationPaginator<FixedKeyService, FixedKeyService>,
    token: &str,
    operation_name: &'static str,
    request_id: RequestId,
) -> Result<T, IamInvalidInput> {
    paginator.decrypt_token(token).await.map_err(|e| {
        log::debug!("{request_id}: Failed to decrypt pagination token for {operation_name}: {e}");
        IamInvalidInput::builder()
            .message(format!("The pagination marker is not valid for {operation_name}."))
            .request_id(request_id)
            .build()
    })
}

/// Records an internal failure, logging the detail and returning an error that does not carry it.
///
/// Use this for every "unexpected database/builder/etc. error" call site. The caller receives the
/// fixed [`constants::MSG_INTERNAL_FAILURE`] and nothing more; everything passed here goes to the
/// log and nowhere else. The request id comes first, separated by a semicolon, and is stamped on
/// both the log entry and the returned error -- it is what ties a caller's complaint to the
/// logged detail.
///
/// Takes `format!`-style arguments after the semicolon:
///
/// ```text
/// internal_failure!(request_id; "Failed to fetch managed policy tags: {e}")
/// ```
///
/// It evaluates to an [`IamInternalFailure`], so a call site needing the enclosing error enum
/// adds `.into()` exactly as it would around the bare error.
///
/// This is a macro rather than a function taking the same arguments so that the log entry is
/// attributed to the operation that failed rather than to one line in this file, which is what
/// `RUST_LOG` module filtering and the file and line in the log record both key on. Fusing the
/// two steps is the point: an internal failure that reached a caller with nothing in the log to
/// explain it is the failure mode this guards against.
macro_rules! internal_failure {
    ($request_id:expr; $($arg:tt)+) => {{
        let request_id = $request_id;
        ::log::error!("{}: {}", request_id, ::std::format_args!($($arg)+));
        $crate::new_internal_failure(request_id)
    }};
}
pub(crate) use internal_failure;

/// Implementation detail of [`internal_failure!`]. Builds the error *without* logging; reaching
/// this directly would produce an internal failure that no log entry explains.
pub(crate) fn new_internal_failure(request_id: RequestId) -> IamInternalFailure {
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
    .map_err(|e| internal_failure!(request_id; "Failed to create paginator for {operation_name}: {e}").into())
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
    .map_err(|e| internal_failure!(request_id; "Failed to create paginator for {operation_name}: {e}").into())
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

    #[test_log::test]
    fn internal_failure_keeps_the_detail_out_of_the_error() {
        let request_id = RequestId::new();
        let detail = "connection to 10.0.0.1 refused";
        let e = internal_failure!(request_id; "Database query failed: {detail}");

        // The detail went to the log and nowhere else; the caller gets the fixed message, and
        // the request id that ties its complaint to that log entry.
        assert_eq!(e.message.as_deref(), Some(constants::MSG_INTERNAL_FAILURE));
        assert_eq!(e.request_id, Some(request_id.to_string()));
    }

    #[test]
    fn test_password_without_username_is_dropped() {
        // A password lives in the second half of the userinfo field, so there is nowhere to put
        // it without a username. It is dropped, and `build` logs that it was.
        let url = ConnectionUrlBuilder::default()
            .password("secret") // codeql[rust/hard-coded-cryptographic-value]
            .host("db.example")
            .database("mydb")
            .build();
        assert_eq!(url, "postgres://db.example/mydb");
        assert!(!url.contains("secret"), "the dropped password must not appear anywhere in {url}");
    }

    #[test]
    fn test_unset_host_defaults_to_localhost() {
        assert_eq!(ConnectionUrlBuilder::default().build(), "postgres://localhost");
        assert_eq!(ConnectionUrlBuilder::default().database("mydb").build(), "postgres://localhost/mydb");
    }

    #[test]
    fn test_unset_port_and_database_are_omitted() {
        // Left out rather than defaulted, so the server's own defaults apply.
        let url = ConnectionUrlBuilder::default().username("alice").host("db.example").build();
        assert_eq!(url, "postgres://alice@db.example");
    }

    #[test]
    fn test_database_name_encoded() {
        // '/' and '?' in a database name must be percent-encoded.
        let url = ConnectionUrlBuilder::default().database("my/db?name").build();
        assert_eq!(url, "postgres://localhost/my%2Fdb%3Fname");
    }
}
