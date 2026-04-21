//! Account database level operations.

use {
    crate::{
        constants::iam::*,
        model::iam::Account,
        ops::{RequestExecutor, iam::validate_account_id},
    },
    anyhow::{Error as AnyError, Result as AnyResult, anyhow, bail},
    base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD},
    indoc::indoc,
    rand::random_range,
    scratchstack_shapes_iam::shorthand::Value as ShorthandValue,
    serde::{Deserialize, Serialize},
    sqlx::{
        Acquire as _, Row as _,
        error::{Error as SqlxError, ErrorKind as SqlxErrorKind},
        postgres::PgTransaction,
        query,
    },
    std::{
        cmp::min,
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

/// Parameters to create a new account on the Scratchstack IAM database.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct CreateAccountRequest {
    /// The organization id to create the account in. This is currently unsupported and must be
    /// `None`. In the future, this can be used to specify an organization to create the account in.
    #[cfg_attr(feature = "clap", arg(long))]
    pub organization_id: Option<String>,

    /// The account id to create. This is usually unspecified, which will return a random
    /// unused account id, but this can be used to specify a particular account id to create.
    /// The account id must be a 12-digit number.
    #[cfg_attr(feature = "clap", arg(long))]
    pub account_id: Option<String>,

    /// Email address associated with the account.
    #[cfg_attr(feature = "clap", arg(long))]
    pub email: Option<String>,

    /// Unique alias for the account. This must be a string of length 3 to 63 characters consisting
    /// of ASCII lowercase letters, digits, and dashes. The alias cannot start or finish with a
    /// dash and cannot contain consecutive dashes.
    #[cfg_attr(feature = "clap", arg(long))]
    pub alias: Option<String>,
}

/// Result of creating an account, which is returned as JSON in the API response.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct CreateAccountResponse {
    /// The organization id that the account was created in. This is currently always `None`, but
    /// in the future, this will be used to specify the organization that the account was created
    /// in.
    pub organization_id: Option<String>,

    /// The account id of the newly created account.
    pub account_id: String,

    /// Email address associated with the account.
    pub email: Option<String>,

    /// Unique alias for the account.
    pub alias: Option<String>,
}

impl RequestExecutor for CreateAccountRequest {
    type Response = CreateAccountResponse;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> AnyResult<Self::Response> {
        if self.organization_id.is_some() {
            bail!("Creating accounts in an organization is currently unsupported");
        }

        if let Some(account_id) = &self.account_id {
            create_account(tx, account_id.clone(), self.email.clone(), self.alias.clone()).await
        } else {
            create_account_with_random_account_id(tx, self.email.clone(), self.alias.clone()).await
        }
    }
}

/// Create a new account on the database.
async fn create_account(
    tx: &mut PgTransaction<'_>,
    account_id: String,
    email: Option<String>,
    alias: Option<String>,
) -> AnyResult<CreateAccountResponse> {
    validate_account_id(&account_id)?;

    let alias = if let Some(alias) = alias {
        if !ACCOUNT_ALIAS_REGEX.is_match(&alias) || alias.len() < 3 || alias.len() > 63 {
            bail!(
                "Account alias must be 3-63 characters long and consist of lowercase letters, digits, and dashes. The alias cannot start or end with a dash and cannot contain consecutive dashes."
            );
        }
        Some(alias)
    } else {
        None
    };

    query(indoc! {"
        INSERT INTO iam.accounts(account_id, email, alias)
        VALUES($1, $2, $3)
    "})
    .bind(account_id.clone())
    .bind(email.clone())
    .bind(alias.clone())
    .execute(tx.as_mut())
    .await?;
    Ok(CreateAccountResponse {
        organization_id: None,
        account_id,
        email,
        alias,
    })
}

/// Create a new account on the database with a random account ID.
async fn create_account_with_random_account_id(
    tx: &mut PgTransaction<'_>,
    email: Option<String>,
    alias: Option<String>,
) -> AnyResult<CreateAccountResponse> {
    loop {
        let account_id = format!("{:012}", random_range(1u64..=999_999_999_999));
        // Create a savepoint that we can roll back to if the account ID already exists.
        let mut savepoint = tx.begin().await?;

        match create_account(&mut savepoint, account_id, email.clone(), alias.clone()).await {
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

/// Parameters to list accounts on the Scratchstack IAM database.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct ListAccountsRequest {
    /// Filters to apply to the list accounts operation.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "clap", arg(long = "filters", num_args = 1.., ))]
    pub filters: Vec<ListAccountsFilter>,

    /// Maximum number of results to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "clap", arg(long))]
    pub max_items: Option<usize>,

    /// Starting token for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "clap", arg(long))]
    pub next_token: Option<String>,
}

impl RequestExecutor for ListAccountsRequest {
    type Response = ListAccountsResponse;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> AnyResult<Self::Response> {
        let mut sql = "SELECT account_id, email, alias, created_at FROM iam.accounts WHERE 1=1".to_string();
        let mut filter_bindings = Vec::with_capacity(self.filters.len());
        let max_items = min(self.max_items.unwrap_or(100), 100);
        let mut next_id: usize = 1;

        if !self.filters.is_empty() {
            for filter in self.filters.iter() {
                sql.push_str(" AND ");

                match filter.name {
                    ListAccountsFilterKey::AccountId => sql.push_str(&format!("account_id = ANY(${})", next_id)),
                    ListAccountsFilterKey::Alias => sql.push_str(&format!("alias = ANY(${})", next_id)),
                    ListAccountsFilterKey::Email => sql.push_str(&format!("email = ANY(${})", next_id)),
                }
                filter_bindings.push(&filter.values);
                next_id += 1;
            }
        }

        let mut prev_account_id = None;

        if let Some(token) = self.next_token.clone()
            && !token.is_empty()
        {
            let version = token.as_bytes()[0];
            if version == b'1' {
                // Version 1 tokens are just the account id to start after,
                // encoded in base64.
                if let Ok(previous_account_id_bytes) = URL_SAFE_NO_PAD.decode(&token[1..])
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
            let alias = row.try_get(2)?;
            let created_at = row.try_get(3)?;

            if accounts.len() == max_items {
                // The overflow row confirms there are more results; don't include it.
                has_more = true;
                break;
            }

            accounts.push(Account {
                account_id,
                alias,
                email,
                created_at,
            });
        }

        // The cursor is the last *included* account ID, not the overflow row's ID.
        // The next page queries `account_id > cursor`, so using the overflow row's ID
        // would skip it entirely.
        let next_token = if has_more {
            accounts.last().map(|a| format!("1{}", URL_SAFE_NO_PAD.encode(a.account_id.as_bytes())))
        } else {
            None
        };

        Ok(ListAccountsResponse {
            accounts,
            next_token,
        })
    }
}

/// Response for the ListAccounts operation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct ListAccountsResponse {
    /// The accounts matching the filters, if any were provided.
    pub accounts: Vec<Account>,

    /// The token to use to retrieve the next page of results, or `None` if there are no more results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
}

/// Filter to apply to the list accounts operation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct ListAccountsFilter {
    /// The name of the filter to apply.
    pub name: ListAccountsFilterKey,

    /// The allowed values for the filter.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
}

impl FromStr for ListAccountsFilter {
    type Err = AnyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = ShorthandValue::from_str(s)?;
        // The shorthand grammar's top-level production always returns a Map; a
        // Scalar or List can only appear as nested values, never at the top level.
        let ShorthandValue::Map(obj) = value else {
            unreachable!("shorthand top-level parse always returns a Map");
        };

        let name = obj.get("Name").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("Missing 'Name' field in filter"))?;

        let name = ListAccountsFilterKey::from_str(name)?;

        let values = obj.get("Values").ok_or_else(|| anyhow!("Missing 'Values' field in filter"))?;

        if let Some(values) = values.as_list() {
            let values = values.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect();
            Ok(ListAccountsFilter {
                name,
                values,
            })
        } else if let Some(values) = values.as_str() {
            let values = vec![values.to_string()];
            Ok(ListAccountsFilter {
                name,
                values,
            })
        } else {
            bail!("'Values' field in filter must be either a string or a list of strings")
        }
    }
}

/// Allowed keys for ListAccountsFilter.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[non_exhaustive]
pub enum ListAccountsFilterKey {
    /// Filter by the account ID.
    AccountId,

    /// Filter by the account alias.
    Alias,

    /// Filter by the account email.
    Email,
}

impl FromStr for ListAccountsFilterKey {
    type Err = AnyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "AccountId" | "account-id" => Ok(ListAccountsFilterKey::AccountId),
            "Alias" | "alias" => Ok(ListAccountsFilterKey::Alias),
            "Email" | "email" => Ok(ListAccountsFilterKey::Email),
            _ => bail!("Invalid filter key: {s}"),
        }
    }
}

impl Display for ListAccountsFilterKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ListAccountsFilterKey::AccountId => write!(f, "AccountId"),
            ListAccountsFilterKey::Alias => write!(f, "Alias"),
            ListAccountsFilterKey::Email => write!(f, "Email"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- ListAccountsFilterKey::from_str -------------------------------------

    #[test]
    fn filter_key_from_str_account_id_pascal() {
        let key: ListAccountsFilterKey = "AccountId".parse().expect("Failed to parse 'AccountId'");
        assert!(matches!(key, ListAccountsFilterKey::AccountId));
    }

    #[test]
    fn filter_key_from_str_account_id_kebab() {
        let key: ListAccountsFilterKey = "account-id".parse().expect("Failed to parse 'account-id'");
        assert!(matches!(key, ListAccountsFilterKey::AccountId));
    }

    #[test]
    fn filter_key_from_str_alias_pascal() {
        let key: ListAccountsFilterKey = "Alias".parse().expect("Failed to parse 'Alias'");
        assert!(matches!(key, ListAccountsFilterKey::Alias));
    }

    #[test]
    fn filter_key_from_str_alias_lower() {
        let key: ListAccountsFilterKey = "alias".parse().expect("Failed to parse 'alias'");
        assert!(matches!(key, ListAccountsFilterKey::Alias));
    }

    #[test]
    fn filter_key_from_str_email_pascal() {
        let key: ListAccountsFilterKey = "Email".parse().expect("Failed to parse 'Email'");
        assert!(matches!(key, ListAccountsFilterKey::Email));
    }

    #[test]
    fn filter_key_from_str_email_lower() {
        let key: ListAccountsFilterKey = "email".parse().expect("Failed to parse 'email'");
        assert!(matches!(key, ListAccountsFilterKey::Email));
    }

    #[test]
    fn filter_key_from_str_invalid() {
        assert!("OrganizationId".parse::<ListAccountsFilterKey>().is_err());
    }

    // -- ListAccountsFilterKey::fmt ------------------------------------------

    #[test]
    fn filter_key_display_account_id() {
        assert_eq!(ListAccountsFilterKey::AccountId.to_string(), "AccountId");
    }

    #[test]
    fn filter_key_display_alias() {
        assert_eq!(ListAccountsFilterKey::Alias.to_string(), "Alias");
    }

    #[test]
    fn filter_key_display_email() {
        assert_eq!(ListAccountsFilterKey::Email.to_string(), "Email");
    }

    // -- ListAccountsFilter::from_str ----------------------------------------

    #[test]
    fn filter_from_str_account_id_single_value() {
        let f: ListAccountsFilter = "Name=AccountId,Values=[123456789012]".parse().expect("Failed to parse filter");
        assert!(matches!(f.name, ListAccountsFilterKey::AccountId));
        assert_eq!(f.values, vec!["123456789012"]);
    }

    #[test]
    fn filter_from_str_account_id_multiple_values() {
        let f: ListAccountsFilter =
            "Name=AccountId,Values=[111111111111,222222222222]".parse().expect("Failed to parse filter");
        assert!(matches!(f.name, ListAccountsFilterKey::AccountId));
        assert_eq!(f.values, vec!["111111111111", "222222222222"]);
    }

    #[test]
    fn filter_from_str_email_scalar_value() {
        // A single value can be given as a plain scalar rather than an explicit list.
        let f: ListAccountsFilter = "Name=Email,Values=admin@example.com".parse().expect("Failed to parse filter");
        assert!(matches!(f.name, ListAccountsFilterKey::Email));
        assert_eq!(f.values, vec!["admin@example.com"]);
    }

    #[test]
    fn filter_from_str_alias() {
        let f: ListAccountsFilter = "Name=Alias,Values=[example-corp]".parse().expect("Failed to parse filter");
        assert!(matches!(f.name, ListAccountsFilterKey::Alias));
        assert_eq!(f.values, vec!["example-corp"]);
    }

    #[test]
    fn filter_from_str_missing_name() {
        assert!("Values=[123456789012]".parse::<ListAccountsFilter>().is_err());
    }

    #[test]
    fn filter_from_str_missing_values() {
        assert!("Name=AccountId".parse::<ListAccountsFilter>().is_err());
    }

    #[test]
    fn filter_from_str_invalid_key_name() {
        assert!("Name=OrganizationId,Values=[o-12345]".parse::<ListAccountsFilter>().is_err());
    }

    #[test]
    fn filter_from_str_not_a_map() {
        // A bare scalar has no '=' so the shorthand parser itself rejects it.
        assert!("AccountId".parse::<ListAccountsFilter>().is_err());
    }

    #[test]
    fn filter_from_str_values_is_a_map() {
        // Values={...} is a map, which is neither a string nor a list — hits the
        // "'Values' field must be either a string or a list of strings" error.
        assert!("Name=AccountId,Values={a=b}".parse::<ListAccountsFilter>().is_err());
    }
}
