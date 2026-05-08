//! Account database level operations.

use {
    crate::{
        constants::iam::*,
        ops::{
            RequestExecutor,
            iam::{constrain_max_items, validate_account_id},
        },
    },
    anyhow::{Result as AnyResult, bail},
    base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD},
    indoc::indoc,
    rand::random_range,
    scratchstack_shapes_iam::{
        operation::{CreateAccountRequest, CreateAccountResponse, ListAccountsRequest, ListAccountsResponse},
        types::{Account, ListAccountsFilterName},
    },
    sqlx::{
        Acquire as _, Row as _,
        error::{Error as SqlxError, ErrorKind as SqlxErrorKind},
        postgres::PgTransaction,
        query,
    },
};

impl RequestExecutor for CreateAccountRequest {
    type Response = CreateAccountResponse;
    type Error = anyhow::Error; // FIXME

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> AnyResult<Self::Response> {
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
) -> AnyResult<CreateAccountResponse> {
    if organization_id.is_some() {
        bail!("Creating accounts in an organization is currently unsupported");
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
) -> AnyResult<CreateAccountResponse> {
    validate_account_id(&account_id)?;

    let account_alias = if let Some(account_alias) = account_alias {
        if !ACCOUNT_ALIAS_REGEX.is_match(&account_alias) || account_alias.len() < 3 || account_alias.len() > 63 {
            bail!(
                "Account alias must be 3-63 characters long and consist of lowercase letters, digits, and dashes. The alias cannot start or end with a dash and cannot contain consecutive dashes."
            );
        }
        Some(account_alias)
    } else {
        None
    };

    query(indoc! {"
        INSERT INTO iam.accounts(account_id, email, alias)
        VALUES($1, $2, $3)
    "})
    .bind(account_id.clone())
    .bind(email.clone())
    .bind(account_alias.clone())
    .execute(tx.as_mut())
    .await?;
    let mut acct_builder = Account::builder().account_id(account_id);
    if let Some(email) = email {
        acct_builder = acct_builder.email(email);
    }
    if let Some(account_alias) = account_alias {
        acct_builder = acct_builder.account_alias(account_alias);
    }
    let account = acct_builder.build()?;
    Ok(CreateAccountResponse {
        account,
    })
}

/// Create a new account on the database with a random account ID.
async fn create_account_with_random_account_id(
    tx: &mut PgTransaction<'_>,
    email: Option<String>,
    account_alias: Option<String>,
) -> AnyResult<CreateAccountResponse> {
    loop {
        let account_id = format!("{:012}", random_range(1u64..=999_999_999_999));
        // Create a savepoint that we can roll back to if the account ID already exists.
        let mut savepoint = tx.begin().await?;

        match create_account_with_id(&mut savepoint, account_id, email.clone(), account_alias.clone()).await {
            Ok(account_id) => {
                savepoint.commit().await?;
                return Ok(account_id);
            }
            Err(e) => match e.downcast::<SqlxError>() {
                Ok(sqlx_error) => {
                    if let SqlxError::Database(ref dbe) = sqlx_error
                        && dbe.kind() == SqlxErrorKind::UniqueViolation
                    {
                        // Account ID already exists, try again with a different random account ID.
                        savepoint.rollback().await?;
                        continue;
                    }

                    log::error!("Failed to create account with random account id: {sqlx_error}");
                    savepoint.rollback().await?;
                    return Err(sqlx_error.into());
                }
                Err(other) => {
                    log::error!("Failed to create account with random account id: {other}");
                    savepoint.rollback().await?;
                    return Err(other);
                }
            },
        }
    }
}

impl RequestExecutor for ListAccountsRequest {
    type Response = ListAccountsResponse;
    type Error = anyhow::Error; // FIXME

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> AnyResult<Self::Response> {
        let mut sql = "SELECT account_id, email, alias, created_at FROM iam.accounts WHERE 1=1".to_string();
        let mut filter_bindings = Vec::with_capacity(self.filters.len());
        let max_items = constrain_max_items(self.max_items)?;
        let mut next_id: usize = 1;

        if !self.filters.is_empty() {
            for filter in self.filters.iter() {
                sql.push_str(" AND ");

                match filter.name {
                    ListAccountsFilterName::AccountId => sql.push_str(&format!("account_id = ANY(${})", next_id)),
                    ListAccountsFilterName::AccountAlias => sql.push_str(&format!("alias = ANY(${})", next_id)),
                    ListAccountsFilterName::Email => sql.push_str(&format!("email = ANY(${})", next_id)),
                    _ => log::warn!("Received unsupported filter key: {:?}", filter.name),
                }
                filter_bindings.push(&filter.values);
                next_id += 1;
            }
        }

        let mut prev_account_id = None;

        if let Some(marker) = self.marker.clone()
            && !marker.is_empty()
        {
            let version = marker.as_bytes()[0];
            if version == b'1' {
                // Version 1 tokens are just the account id to start after,
                // encoded in base64.
                if let Ok(previous_account_id_bytes) = URL_SAFE_NO_PAD.decode(&marker[1..])
                    && let Ok(previous_account_id_str) = String::from_utf8(previous_account_id_bytes)
                {
                    sql.push_str(&format!(" AND account_id > ${}", next_id));
                    next_id += 1;
                    prev_account_id = Some(previous_account_id_str.clone());
                }
            }
        }

        sql.push_str(&format!(" ORDER BY account_id LIMIT ${}", next_id));

        let mut q = query(&sql);
        for values in filter_bindings.into_iter() {
            q = q.bind(values);
        }

        if let Some(prev_account_id) = prev_account_id {
            q = q.bind(prev_account_id);
        }

        q = q.bind(max_items as i64 + 1); // Request one more than max items so we can determine if there are more results.

        let rows = q.fetch_all(tx.as_mut()).await?;
        let mut accounts = Vec::new();
        let mut has_more = false;

        for row in rows {
            let account_id: String = row.try_get(0)?;
            let email = row.try_get(1)?;
            let account_alias = row.try_get(2)?;
            let created_at = row.try_get(3)?;

            if accounts.len() == max_items {
                // The overflow row confirms there are more results; don't include it.
                has_more = true;
                break;
            }

            accounts.push(Account {
                organization_id: None,
                account_id,
                account_alias,
                email,
                created_at,
            });
        }

        // The cursor is the last *included* account ID, not the overflow row's ID.
        // The next page queries `account_id > cursor`, so using the overflow row's ID
        // would skip it entirely.
        let marker = if has_more {
            accounts.last().map(|a| format!("1{}", URL_SAFE_NO_PAD.encode(a.account_id.as_bytes())))
        } else {
            None
        };
        let is_truncated = marker.is_some();

        Ok(ListAccountsResponse {
            accounts,
            marker,
            is_truncated,
        })
    }
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
