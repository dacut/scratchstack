//! ListAccounts database level operation.

use {
    crate::{model::iam::Account, ops::RequestExecutor},
    anyhow::{Error as AnyError, Result as AnyResult, anyhow},
    base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD},
    scratchstack_shapes::shorthand::Value as ShorthandValue,
    serde::{Deserialize, Serialize},
    sqlx::{Row as _, postgres::PgTransaction, query},
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

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
        list_accounts(tx, self).await
    }
}

/// List accounts in the database, applying the provided filters if any.
async fn list_accounts(tx: &mut PgTransaction<'_>, request: &ListAccountsRequest) -> AnyResult<ListAccountsResponse> {
    let mut sql = "SELECT account_id, email, alias, created_at FROM iam.accounts WHERE 1=1".to_string();
    let mut filter_bindings = Vec::with_capacity(request.filters.len());
    let max_items = request.max_items.unwrap_or(100);
    let mut next_id: usize = 1;

    if !request.filters.is_empty() {
        for filter in request.filters.iter() {
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

    if let Some(token) = request.next_token.clone()
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
    let mut last_account_id = None;

    for row in rows {
        let account_id: String = row.try_get(0)?;
        let email = row.try_get(1)?;
        let alias = row.try_get(2)?;
        let created_at = row.try_get(3)?;

        if accounts.len() == max_items {
            last_account_id = Some(account_id.clone());
            break;
        }

        accounts.push(Account {
            account_id,
            alias,
            email,
            created_at,
        });
    }

    let next_token = last_account_id.map(|id| format!("1{}", URL_SAFE_NO_PAD.encode(id.as_bytes())));

    Ok(ListAccountsResponse {
        accounts,
        next_token,
    })
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
        if let ShorthandValue::Map(obj) = value {
            let name =
                obj.get("Name").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("Missing 'Name' field in filter"))?;

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
                Err(anyhow!("'Values' field in filter must be either a string or a list of strings"))
            }
        } else {
            Err(anyhow!("Expected an object for filter"))
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
            _ => Err(anyhow!("Invalid filter key: {s}")),
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
