//! ListAccounts database operation
use {
    crate::{
        constants::iam::*,
        ops::{
            RequestExecutor,
            iam::{constrain_max_items, get_current_partition_or_fail, make_paginator},
        },
    },
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListAccountsRequest, ListAccountsResponse},
        types::{Account, ListAccountsFilter, ListAccountsFilterName, error::InternalFailure},
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, postgres::PgTransaction},
};

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
    use super::*;

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
