//! Scratchstack bootstrap session token encryption key subcommands
use {
    crate::{Cli, Runnable, execute_in_transaction},
    chrono::{DateTime, Utc},
    clap::Parser,
    scratchstack_cli_utils::{ShorthandValue, parse_shorthand},
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreateSessionTokenEncryptionKeyRequest, CreateSessionTokenEncryptionKeyResponse,
            ListSessionTokenEncryptionKeysRequest, ListSessionTokenEncryptionKeysResponse,
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

impl Runnable for CreateSessionTokenEncryptionKeyCommand {
    type Result = CreateSessionTokenEncryptionKeyResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let mut request = CreateSessionTokenEncryptionKeyRequest::builder().issue_valid_from(self.issue_valid_from);
        if let Some(encryption_algorithm) = self.encryption_algorithm {
            request = request.encryption_algorithm(encryption_algorithm);
        }
        if let Some(issue_expires_at) = self.issue_expires_at {
            request = request.issue_expires_at(issue_expires_at);
        }
        if let Some(accept_expires_at) = self.accept_expires_at {
            request = request.accept_expires_at(accept_expires_at);
        }
        let request = request.build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListSessionTokenEncryptionKeysCommand {
    type Result = ListSessionTokenEncryptionKeysResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let filters = list_session_token_encryption_keys_filters_from_shorthand(&self.filters)?;
        let mut request = ListSessionTokenEncryptionKeysRequest::builder().filters(filters);
        if let Some(max_items) = self.max_items {
            request = request.max_items(max_items);
        }
        if let Some(marker) = &self.marker {
            request = request.marker(marker.clone());
        }
        let request = request.build()?;
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
        let parsed = parse_shorthand(value)
            .map_err(|e| {
                IamError::from(
                    ValidationError::builder().message(format!("Invalid filter format: {value:?}: {e}")).build(),
                )
            })
            .map_err(|e| {
                ValidationError::builder().message(format!("Invalid filter format: {value:?}: {e}")).build()
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
