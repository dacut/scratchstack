//! ListUserPolicies database operation
use {
    crate::{
        RequestExecutor,
        constants::iam::*,
        iam::{
            constrain_max_items, get_current_partition_or_fail, make_paginator, validate_account_id, validate_user_name,
        },
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListUserPoliciesInternalRequest, ListUserPoliciesResponse},
        types::error::{InternalFailure, NoSuchEntityException},
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for ListUserPoliciesInternalRequest {
    type Response = ListUserPoliciesResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_user_policies(tx, &self.account_id, &self.user_name, self.marker.as_deref(), self.max_items).await
    }
}

/// The marker innards for a ListUserPolicies operation.
#[derive(Deserialize, Serialize)]
struct ListUserPoliciesMarker {
    next_policy_name_lower: String,
}

/// The rows returned by the ListUserPolicies query.
#[derive(FromRow)]
struct ListUserPoliciesRow {
    policy_name_lower: String,
    policy_name_cased: String,
}

/// List the names of inline policies attached to a user. Returns NoSuchEntity if the user does
/// not exist.
pub async fn list_user_policies(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
) -> Result<ListUserPoliciesResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;
    let max_items = constrain_max_items(max_items)?;
    let partition = get_current_partition_or_fail(tx).await?;

    let user_id: String = match query(indoc! {"
            SELECT user_id
            FROM iam.users
            WHERE account_id = $1 AND user_name_lower = $2
        "})
    .bind(account_id)
    .bind(user_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The user with name {user_name} cannot be found."))
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up user in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    let paginator = make_paginator(&partition, OP_LIST_USER_POLICIES)?;

    let mut sql = QueryBuilder::new(indoc! {"
        SELECT policy_name_lower, policy_name_cased
        FROM iam.user_inline_policies
        WHERE user_id = "});
    sql.push_bind(user_id);

    if let Some(marker) = marker {
        let m: ListUserPoliciesMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token for ListUserPolicies: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;
        sql.push("\nAND policy_name_lower >= ");
        sql.push_bind(m.next_policy_name_lower);
    }

    sql.push("\nORDER BY policy_name_lower ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListUserPoliciesRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch user inline policies from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    let mut results: Vec<String> = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if results.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListUserPoliciesMarker {
                        next_policy_name_lower: row.policy_name_lower,
                    })
                    .await
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token for ListUserPolicies: {e}");
                        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                    })?,
            );
            break;
        }

        results.push(row.policy_name_cased);
    }

    let mut builder = ListUserPoliciesResponse::builder();
    builder = builder.policy_names(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(Some(true)).marker(Some(next_marker));
    }

    builder.build().map_err(|e| {
        log::error!("Failed to build ListUserPoliciesResponse: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })
}
