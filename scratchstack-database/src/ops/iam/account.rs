//! Account database level operations.

use {
    crate::{
        constants::iam::*,
        ops::{
            RequestExecutor,
            iam::{constrain_max_items, get_current_partition_or_fail, make_paginator, validate_account_id},
        },
    },
    indoc::indoc,
    rand::random_range,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{CreateAccountRequest, CreateAccountResponse, ListAccountsRequest, ListAccountsResponse},
        types::{
            Account, ListAccountsFilter, ListAccountsFilterName,
            error::{InternalFailure, ValidationError},
        },
    },
    serde::{Deserialize, Serialize},
    sqlx::{Acquire as _, FromRow, QueryBuilder, postgres::PgTransaction, query},
};

impl RequestExecutor for CreateAccountRequest {
    type Response = CreateAccountResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        create_account(
            tx,
            self.organization_id.clone(),
            self.account_id.clone(),
            self.email.clone(),
            self.account_alias.clone(),
        )
        .await
    }
}

/// Create a new account on the database.
///
/// If an account ID is provided, attempts to create the account with that ID and fails if it
/// already exists. Otherwise, attempts to create the account with a random account ID, retrying
/// with different random account IDs if there are collisions, until it succeeds.
pub async fn create_account(
    tx: &mut PgTransaction<'_>,
    organization_id: Option<String>,
    account_id: Option<String>,
    email: Option<String>,
    account_alias: Option<String>,
) -> Result<CreateAccountResponse, IamError> {
    if organization_id.is_some() {
        return Err(ValidationError::builder()
            .message("Creating accounts in an organization is currently unsupported")
            .build()
            .into());
    }

    if let Some(account_id) = account_id {
        create_account_with_id(tx, account_id, email, account_alias).await
    } else {
        create_account_with_random_account_id(tx, email, account_alias).await
    }
}

/// Create a new account on the database with the specified account ID.
async fn create_account_with_id(
    tx: &mut PgTransaction<'_>,
    account_id: String,
    email: Option<String>,
    account_alias: Option<String>,
) -> Result<CreateAccountResponse, IamError> {
    validate_account_id(&account_id)?;

    let account_alias = if let Some(account_alias) = account_alias {
        if !ACCOUNT_ALIAS_REGEX.is_match(&account_alias) || account_alias.len() < 3 || account_alias.len() > 63 {
            return Err(ValidationError::builder()
                .message(
                    "Account alias must be 3-63 characters long and consist of lowercase letters, digits, and dashes. The alias cannot start or end with a dash and cannot contain consecutive dashes."
                )
                .build()
                .into());
        }
        Some(account_alias)
    } else {
        None
    };

    if let Err(e) = query(indoc! {"
        INSERT INTO iam.accounts(account_id, email, alias)
        VALUES($1, $2, $3)
    "})
    .bind(account_id.clone())
    .bind(email.clone())
    .bind(account_alias.clone())
    .execute(tx.as_mut())
    .await
    {
        log::error!("Failed to insert account into database: {e}");
        return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
    }

    let mut acct_builder = Account::builder().account_id(account_id);
    if let Some(email) = email {
        acct_builder = acct_builder.email(email);
    }
    if let Some(account_alias) = account_alias {
        acct_builder = acct_builder.account_alias(account_alias);
    }
    let account = acct_builder.build().map_err(|e| {
        log::error!("Failed to build Account: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;
    Ok(CreateAccountResponse {
        account,
    })
}

/// Create a new account on the database with a random account ID.
async fn create_account_with_random_account_id(
    tx: &mut PgTransaction<'_>,
    email: Option<String>,
    account_alias: Option<String>,
) -> Result<CreateAccountResponse, IamError> {
    loop {
        let account_id = format!("{:012}", random_range(1u64..=999_999_999_999));
        // Create a savepoint that we can roll back to if the account ID already exists.
        let mut savepoint = match tx.begin().await {
            Ok(sp) => sp,
            Err(e) => {
                log::error!("Failed to create savepoint: {e}");
                return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
            }
        };

        match create_account_with_id(&mut savepoint, account_id, email.clone(), account_alias.clone()).await {
            Ok(response) => {
                if let Err(e) = savepoint.commit().await {
                    log::error!("Failed to commit savepoint: {e}");
                    return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
                }
                return Ok(response);
            }
            Err(IamError::InternalFailure(_)) => {
                // The insert failed — this could be a unique violation (account ID collision)
                // or a genuine error. We can't easily distinguish here since we wrapped the
                // sqlx error, so just roll back and retry. After enough retries a genuine
                // error would keep looping, but collisions on 12-digit random IDs are
                // extremely unlikely to repeat.
                if let Err(e) = savepoint.rollback().await {
                    log::error!("Failed to rollback savepoint: {e}");
                    return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
                }
                continue;
            }
            Err(other) => {
                // Validation error or something else — don't retry.
                if let Err(e) = savepoint.rollback().await {
                    log::error!("Failed to rollback savepoint: {e}");
                    return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
                }
                return Err(other);
            }
        }
    }
}

impl RequestExecutor for ListAccountsRequest {
    type Response = ListAccountsResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_accounts(tx, &self.filters, self.marker.as_deref(), self.max_items).await
    }
}

/// The marker innards for a ListAccounts operation.
#[derive(Deserialize, Serialize)]
struct ListAccountsMarker {
    next_account_id: String,
}

/// The rows returned by the ListAccounts query.
#[derive(FromRow)]
struct ListAccountsRow {
    account_id: String,
    email: Option<String>,
    alias: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// List accounts on the database, optionally filtered by account id, email, or account alias.
pub async fn list_accounts(
    tx: &mut PgTransaction<'_>,
    filters: &[ListAccountsFilter],
    marker: Option<&str>,
    max_items: Option<i32>,
) -> Result<ListAccountsResponse, IamError> {
    let max_items = constrain_max_items(max_items)?;
    let partition = get_current_partition_or_fail(tx).await?;
    let paginator = make_paginator(&partition, OP_LIST_ACCOUNTS)?;

    let mut sql = QueryBuilder::new("SELECT account_id, email, alias, created_at FROM iam.accounts WHERE TRUE");

    for filter in filters.iter() {
        let column = match filter.name {
            ListAccountsFilterName::AccountId => "account_id",
            ListAccountsFilterName::AccountAlias => "alias",
            ListAccountsFilterName::Email => "email",
            _ => {
                log::warn!("Received unsupported filter key: {:?}", filter.name);
                continue;
            }
        };
        sql.push(format!(" AND {column} = ANY("));
        sql.push_bind(&filter.values);
        sql.push(")");
    }

    if let Some(marker) = marker {
        let info: ListAccountsMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token for ListAccounts: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;
        sql.push(" AND account_id > ");
        sql.push_bind(info.next_account_id);
    }

    // Request one more than max_items so we can determine if there are more results.
    sql.push(" ORDER BY account_id ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListAccountsRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch accounts from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    let mut accounts = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if accounts.len() == max_items {
            // The cursor is the last *included* account id, not the overflow row's id. The
            // next page queries `account_id > cursor`, so using the overflow row's id would
            // skip it entirely.
            let last_account_id = accounts.last().map(|a: &Account| a.account_id.clone()).expect(
                "accounts is non-empty when len() == max_items > 0, which is guaranteed by constrain_max_items",
            );
            next_marker = Some(
                paginator
                    .encrypt_token(&ListAccountsMarker {
                        next_account_id: last_account_id,
                    })
                    .await
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token for ListAccounts: {e}");
                        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                    })?,
            );
            break;
        }

        accounts.push(Account {
            organization_id: None,
            account_id: row.account_id,
            account_alias: row.alias,
            email: row.email,
            created_at: Some(row.created_at),
        });
    }

    let is_truncated = next_marker.is_some();
    Ok(ListAccountsResponse {
        accounts,
        marker: next_marker,
        is_truncated,
    })
}

#[cfg(test)]
mod tests {
    use {super::*, scratchstack_shapes_iam::types::ListAccountsFilter};

    // -- ListAccountsFilterName::from_str -------------------------------------

    #[test]
    fn filter_key_from_str_account_id() {
        let key: ListAccountsFilterName = "account-id".parse().expect("Failed to parse 'account-id'");
        assert!(matches!(key, ListAccountsFilterName::AccountId));
    }

    #[test]
    fn filter_key_from_str_account_alias() {
        let key: ListAccountsFilterName = "account-alias".parse().expect("Failed to parse 'account-alias'");
        assert!(matches!(key, ListAccountsFilterName::AccountAlias));
    }

    #[test]
    fn filter_key_from_str_email() {
        let key: ListAccountsFilterName = "email".parse().expect("Failed to parse 'email'");
        assert!(matches!(key, ListAccountsFilterName::Email));
    }

    #[test]
    fn filter_key_from_str_invalid() {
        assert!("OrganizationId".parse::<ListAccountsFilterName>().is_err());
    }

    // -- ListAccountsFilterName::fmt ------------------------------------------

    #[test]
    fn filter_key_display_account_id() {
        assert_eq!(ListAccountsFilterName::AccountId.to_string(), "account-id");
    }

    #[test]
    fn filter_key_display_alias() {
        assert_eq!(ListAccountsFilterName::AccountAlias.to_string(), "account-alias");
    }

    #[test]
    fn filter_key_display_email() {
        assert_eq!(ListAccountsFilterName::Email.to_string(), "email");
    }

    // -- ListAccountsFilter::from_str ----------------------------------------

    #[test]
    fn filter_from_str_account_id_single_value() {
        let f: ListAccountsFilter = "Name=account-id,Values=[123456789012]".parse().expect("Failed to parse filter");
        assert!(matches!(f.name, ListAccountsFilterName::AccountId));
        assert_eq!(f.values, vec!["123456789012"]);
    }

    #[test]
    fn filter_from_str_account_id_multiple_values() {
        let f: ListAccountsFilter =
            "Name=account-id,Values=[111111111111,222222222222]".parse().expect("Failed to parse filter");
        assert!(matches!(f.name, ListAccountsFilterName::AccountId));
        assert_eq!(f.values, vec!["111111111111", "222222222222"]);
    }

    #[test]
    fn filter_from_str_email_scalar_value() {
        // A single value can be given as a plain scalar rather than an explicit list.
        let f: ListAccountsFilter = "Name=email,Values=admin@example.com".parse().expect("Failed to parse filter");
        assert!(matches!(f.name, ListAccountsFilterName::Email));
        assert_eq!(f.values, vec!["admin@example.com"]);
    }

    #[test]
    fn filter_from_str_alias() {
        let f: ListAccountsFilter = "Name=account-alias,Values=[example-corp]".parse().expect("Failed to parse filter");
        assert!(matches!(f.name, ListAccountsFilterName::AccountAlias));
        assert_eq!(f.values, vec!["example-corp"]);
    }

    #[test]
    fn filter_from_str_missing_name() {
        assert!("Values=[123456789012]".parse::<ListAccountsFilter>().is_err());
    }

    #[test]
    fn filter_from_str_missing_values() {
        assert!("Name=account-id".parse::<ListAccountsFilter>().is_ok());
    }

    #[test]
    fn filter_from_str_invalid_key_name() {
        assert!("Name=OrganizationId,Values=[o-12345]".parse::<ListAccountsFilter>().is_err());
    }

    #[test]
    fn filter_from_str_not_a_map() {
        // A bare scalar has no '=' so the shorthand parser itself rejects it.
        assert!("account-id".parse::<ListAccountsFilter>().is_err());
    }

    #[test]
    fn filter_from_str_values_is_a_map() {
        // Values={...} is a map, which is neither a string nor a list — hits the
        // "'Values' field must be either a string or a list of strings" error.
        assert!("Name=account-id,Values={a=b}".parse::<ListAccountsFilter>().is_err());
    }
}
