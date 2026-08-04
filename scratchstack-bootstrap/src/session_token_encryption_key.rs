//! Scratchstack bootstrap session token encryption key subcommands
use {
    crate::{Cli, Runnable, execute_in_transaction, internal_failure},
    chrono::{DateTime, Utc},
    clap::Parser,
    log::error,
    scratchstack_cli_utils::{ShorthandValue, parse_shorthand},
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreateSessionTokenEncryptionKeyRequest, CreateSessionTokenEncryptionKeyResponse,
            GetSessionTokenEncryptionKeyRequest, GetSessionTokenEncryptionKeyResponse,
            ListSessionTokenEncryptionKeysRequest, ListSessionTokenEncryptionKeysResponse,
            UpdateSessionTokenEncryptionKeyRequest, UpdateSessionTokenEncryptionKeyResponse,
        },
        types::{ListSessionTokenEncryptionKeysFilter, error::ValidationError},
    },
    std::ffi::OsString,
};

/// Create a new session token encryption key.
#[derive(Debug, Parser)]
pub(crate) struct CreateSessionTokenEncryptionKeyCommand {
    /// The encryption algorithm used to encrypt the session token. The only valid value is `AES256-GCM`.
    #[clap(long)]
    encryption_algorithm: Option<scratchstack_shapes_iam::types::SessionTokenEncryptionAlgorithm>,

    /// The date and time when the key can be used to encrypt session tokens.
    #[clap(long)]
    issue_valid_from: DateTime<Utc>,

    /// The date and time when the key can no longer be used to encrypt session tokens.
    #[clap(long)]
    issue_expires_at: Option<DateTime<Utc>>,

    /// The date and time when key can no longer be used to decrypt session tokens.
    #[clap(long)]
    accept_expires_at: Option<DateTime<Utc>>,
}

/// Get information about a session token encryption key.
#[derive(Debug, Parser)]
pub(crate) struct GetSessionTokenEncryptionKeyCommand {
    /// The unique identifier of the session token encryption key to retrieve.
    #[clap(long)]
    pub session_token_encryption_key_id: String,
}

/// List session token encryption keys.
#[derive(Debug, Parser)]
pub(crate) struct ListSessionTokenEncryptionKeysCommand {
    /// Filters to apply when listing session token encryption keys. Each filter is a
    /// `Name=<filter-name>,Values=<filter-values>` structure.
    ///
    /// Valid filter names are `issue-valid-from-start-time`, `issue-valid-from-end-time`,
    /// `issue-expires-at-start-time`, `issue-expires-at-end-time`, `accept-expires-at-start-time`,
    /// and `accept-expires-at-end-time`. The corresponding filter values are RFC3339 timestamps.
    #[clap(long, num_args = 1..)]
    pub filters: Vec<String>,

    /// The maximum number of session token encryption keys to include in the response.
    #[clap(long)]
    pub max_items: Option<i32>,

    /// A marker for paginating the list of session token encryption keys. If the response from a previous
    /// ListSessionTokenEncryptionKeys request was truncated, the response will include a marker that
    /// you can use in a subsequent ListSessionTokenEncryptionKeys request to retrieve the next set of
    /// session token encryption keys.
    #[clap(long)]
    pub marker: Option<String>,
}

/// Update the expiration windows of an existing session token encryption key. Any field left
/// unspecified retains its current value.
#[derive(Debug, Parser)]
pub(crate) struct UpdateSessionTokenEncryptionKeyCommand {
    /// The unique identifier of the session token encryption key to update.
    #[clap(long)]
    pub session_token_encryption_key_id: String,

    /// The date and time when the key can be used to encrypt session tokens.
    #[clap(long)]
    pub issue_valid_from: Option<DateTime<Utc>>,

    /// The date and time when the key can no longer be used to encrypt session tokens.
    #[clap(long)]
    pub issue_expires_at: Option<DateTime<Utc>>,

    /// The date and time when key can no longer be used to decrypt session tokens.
    #[clap(long)]
    pub accept_expires_at: Option<DateTime<Utc>>,
}

impl Runnable for CreateSessionTokenEncryptionKeyCommand {
    type Result = CreateSessionTokenEncryptionKeyResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = CreateSessionTokenEncryptionKeyRequest::builder()
            .issue_valid_from(self.issue_valid_from)
            .set_encryption_algorithm(self.encryption_algorithm)
            .set_issue_expires_at(self.issue_expires_at)
            .set_accept_expires_at(self.accept_expires_at)
            .build()
            .map_err(|e| {
                error!("Failed to build CreateSessionTokenEncryptionKeyRequest: {e}");
                internal_failure()
            })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for GetSessionTokenEncryptionKeyCommand {
    type Result = GetSessionTokenEncryptionKeyResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = GetSessionTokenEncryptionKeyRequest::builder()
            .session_token_encryption_key_id(self.session_token_encryption_key_id.clone())
            .build()
            .map_err(|e| {
                error!("Failed to build GetSessionTokenEncryptionKeyRequest: {e}");
                internal_failure()
            })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListSessionTokenEncryptionKeysCommand {
    type Result = ListSessionTokenEncryptionKeysResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let filters = list_session_token_encryption_keys_filters_from_shorthand(&self.filters)?;
        let request = ListSessionTokenEncryptionKeysRequest::builder()
            .set_filters(filters)
            .set_max_items(self.max_items)
            .set_marker(self.marker.clone())
            .build()
            .map_err(|e| {
                error!("Failed to build ListSessionTokenEncryptionKeysRequest: {e}");
                internal_failure()
            })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for UpdateSessionTokenEncryptionKeyCommand {
    type Result = UpdateSessionTokenEncryptionKeyResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = UpdateSessionTokenEncryptionKeyRequest::builder()
            .session_token_encryption_key_id(self.session_token_encryption_key_id.clone())
            .set_issue_valid_from(self.issue_valid_from)
            .set_issue_expires_at(self.issue_expires_at)
            .set_accept_expires_at(self.accept_expires_at)
            .build()
            .map_err(|e| {
                error!("Failed to build UpdateSessionTokenEncryptionKeyRequest: {e}");
                internal_failure()
            })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

/// Convert a list of shorthand values to a `Vec<ListSessionTokenEncryptionKeysFilter>`.
pub(crate) fn list_session_token_encryption_keys_filters_from_shorthand(
    values: &[impl AsRef<str>],
) -> Result<Vec<ListSessionTokenEncryptionKeysFilter>, IamError> {
    let mut filters = Vec::with_capacity(values.len());

    for value in values {
        let value = value.as_ref();
        let parsed = parse_shorthand(value).map_err(|e| {
            IamError::from(ValidationError::builder().message(format!("Invalid filter format: {value:?}: {e}")).build())
        })?;

        match parsed {
            ShorthandValue::List(values) => {
                for value in values {
                    let ShorthandValue::Map(map) = value else {
                        return Err(ValidationError::builder()
                            .message(format!(
                                "Invalid filter format: {value:?}. Filters must be JSON objects with 'Name' and 'Values' fields"
                            ))
                            .build()
                            .into());
                    };
                    let filter = filter_from_shorthand(&map)?;
                    filters.push(filter);
                }
            }
            ShorthandValue::Map(map) => {
                let filter = filter_from_shorthand(&map)?;
                filters.push(filter);
            }
            _ => {
                return Err(ValidationError::builder()
                    .message(format!(
                        "Invalid filter format: {value:?}. Filters must be in the format 'Name=n,Values=v1,v2' or a JSON object with 'Name' and 'Values' fields"))
                        .build()
                        .into());
            }
        };
    }

    Ok(filters)
}

/// Convert a map of keys to shorthand values to a [`ListSessionTokenEncryptionKeysFilter`].
fn filter_from_shorthand(
    map: &std::collections::HashMap<String, ShorthandValue>,
) -> Result<ListSessionTokenEncryptionKeysFilter, IamError> {
    ListSessionTokenEncryptionKeysFilter::try_from(map).map_err(|e| {
        IamError::from(ValidationError::builder().message(format!("Invalid filter format: {map:?}: {e}")).build())
    })
}
