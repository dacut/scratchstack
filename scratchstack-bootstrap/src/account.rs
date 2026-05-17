//! Scratchstack bootsrap account subcommands
use {
    crate::{Cli, Runnable, execute_in_transaction},
    clap::Parser,
    scratchstack_cli_utils::{ShorthandValue, parse_shorthand},
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{CreateAccountRequest, CreateAccountResponse, ListAccountsRequest, ListAccountsResponse},
        types::{ListAccountsFilter, ListAccountsFilterName, error::ValidationError},
    },
    std::{collections::HashMap, ffi::OsString, str::FromStr as _},
};

/// Create a new account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct CreateAccountCommand {
    /// The unique identifier of the organization to create the account in.
    ///
    /// This is currently unsupported and must not be specified.
    #[clap(long)]
    pub organization_id: Option<String>,

    /// The unique identifier for this account.
    ///
    /// This is usually omitted; the service will select a random unused account id, but this can be
    /// used to specify a particular account id to create.
    ///
    /// The account id must be a 12-digit number.
    #[clap(long)]
    pub account_id: Option<String>,

    /// Email address associated with the account.
    #[clap(long)]
    pub email: Option<String>,

    /// The account alias to assign to the account.
    #[clap(long)]
    pub account_alias: Option<String>,
}

/// List accounts in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct ListAccountsCommand {
    /// Filters to apply when listing accounts.
    #[clap(long, num_args = 1..)]
    pub filters: Vec<String>,

    /// The maximum number of accounts to return.
    #[clap(long)]
    pub max_items: Option<u32>,

    /// The token to use for pagination.
    #[clap(long)]
    pub marker: Option<String>,
}

impl Runnable for CreateAccountCommand {
    type Result = CreateAccountResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<CreateAccountResponse, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let mut builder =
            CreateAccountRequest::builder().email(self.email.clone()).account_alias(self.account_alias.clone());
        if let Some(organization_id) = &self.organization_id {
            builder = builder.organization_id(organization_id.clone());
        }
        if let Some(account_id) = &self.account_id {
            builder = builder.account_id(account_id.clone());
        }

        let request = builder.build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListAccountsCommand {
    type Result = ListAccountsResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<ListAccountsResponse, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let mut builder = ListAccountsRequest::builder();
        let mut filters = Vec::with_capacity(self.filters.len());

        for filter in &self.filters {
            let parsed = parse_shorthand(filter).map_err(|e| {
                IamError::from(
                    ValidationError::builder().message(format!("Invalid filter format: {filter}: {e}")).build(),
                )
            })?;
            match parsed {
                ShorthandValue::List(values) => {
                    for value in values {
                        let ShorthandValue::Map(value) = value else {
                            return Err(ValidationError::builder()
                                .message(format!(
                                    "Invalid filter format: {filter}. Filters must be in the format 'key=value' or 'key=value1,value2,...'"
                                ))
                                .build()
                                .into());
                        };
                        filters = list_accounts_filter_from_shorthand(&value)?;
                    }
                }
                ShorthandValue::Map(value) => {
                    filters.extend(list_accounts_filter_from_shorthand(&value)?);
                }
                _ => {
                    return Err(ValidationError::builder()
                        .message(format!(
                            "Invalid filter format: {filter}. Filters must be in the format 'key=value' or 'key=value1,value2,...'"
                        ))
                        .build()
                        .into());
                }
            }
        }

        builder = builder.filters(filters);
        if let Some(max_items) = self.max_items {
            builder = builder.max_items(max_items as i32);
        }
        if let Some(marker) = &self.marker {
            builder = builder.marker(marker.clone());
        }

        let request = builder.build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

fn list_accounts_filter_from_shorthand(
    map: &HashMap<String, ShorthandValue>,
) -> Result<Vec<ListAccountsFilter>, IamError> {
    let mut result = Vec::new();
    for (name, values) in map {
        let name = ListAccountsFilterName::from_str(name).map_err(|e| {
            IamError::from(ValidationError::builder().message(format!("Invalid filter key: {name}: {e}")).build())
        })?;
        let values = match values {
            ShorthandValue::Scalar(s) => vec![s.clone()],
            ShorthandValue::List(l) => l
                .iter()
                .map(|v| {
                    if let ShorthandValue::Scalar(s) = v {
                        Ok(s.clone())
                    } else {
                        Err(IamError::from(
                            ValidationError::builder()
                                .message(format!(
                                    "Invalid filter value: {v:?}. Filter values must be strings or lists of strings"
                                ))
                                .build(),
                        ))
                    }
                })
                .collect::<Result<Vec<String>, IamError>>()?,
            _ => {
                return Err(ValidationError::builder()
                    .message(format!(
                        "Invalid filter value: {values:?}. Filter values must be strings or lists of strings"
                    ))
                    .build()
                    .into());
            }
        };
        result.push(ListAccountsFilter {
            name,
            values,
        });
    }

    Ok(result)
}
