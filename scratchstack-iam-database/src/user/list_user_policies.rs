//! ListUserPolicies database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, constrain_max_items, decrypt_pagination_token,
        internal_failure, make_iam_paginator, partition::get_current_partition_or_fail, user::validate_user_name,
    },
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListUserPoliciesInternalRequest, ListUserPoliciesResponse},
        types::error::NoSuchEntityException,
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for ListUserPoliciesInternalRequest {
    type Response = ListUserPoliciesResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        list_user_policies(tx, &self.account_id, &self.user_name, self.marker.as_deref(), self.max_items, request_id)
            .await
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
    request_id: RequestId,
) -> Result<ListUserPoliciesResponse, IamError> {
    validate_account_id(account_id, request_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name, request_id)?;
    let max_items = constrain_max_items(max_items, request_id)?;
    let partition = get_current_partition_or_fail(tx, request_id).await?;

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
                .request_id(request_id)
                .build()
                .into());
        }
        Err(e) => {
            return Err(internal_failure!(request_id; "Failed to look up user in database: {e}").into());
        }
    };

    let paginator = make_iam_paginator(&partition, OP_LIST_USER_POLICIES, request_id)?;

    let mut sql = QueryBuilder::new(indoc! {"
        SELECT policy_name_lower, policy_name_cased
        FROM iam.user_inline_policies
        WHERE user_id = "});
    sql.push_bind(user_id);

    if let Some(marker) = marker {
        let m: ListUserPoliciesMarker =
            decrypt_pagination_token(&paginator, marker, OP_LIST_USER_POLICIES, request_id).await?;
        sql.push("\nAND policy_name_lower >= ");
        sql.push_bind(m.next_policy_name_lower);
    }

    sql.push("\nORDER BY policy_name_lower ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql
        .build_query_as::<ListUserPoliciesRow>()
        .fetch_all(tx.as_mut())
        .await
        .map_err(|e| internal_failure!(request_id; "Failed to fetch user inline policies from database: {e}"))?;

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
                        internal_failure!(request_id; "Failed to encrypt pagination token for ListUserPolicies: {e}")
                    })?,
            );
            break;
        }

        results.push(row.policy_name_cased);
    }

    let mut builder = ListUserPoliciesResponse::builder();
    builder = builder.set_policy_names(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(true).marker(next_marker);
    }

    builder.build().map_err(|e| internal_failure!(request_id; "Failed to build ListUserPoliciesResponse: {e}").into())
}
