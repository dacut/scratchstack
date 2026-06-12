//! ListAttachedUserPolicies database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, constrain_max_items, internal_failure,
        make_iam_paginator, partition::get_current_partition_or_fail, path::validate_path_prefix,
        policy::build_policy_arn, user::validate_user_name,
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListAttachedUserPoliciesInternalRequest, ListAttachedUserPoliciesResponse},
        types::{AttachedPolicy, error::NoSuchEntityException},
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for ListAttachedUserPoliciesInternalRequest {
    type Response = ListAttachedUserPoliciesResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_attached_user_policies(
            tx,
            &self.account_id,
            &self.user_name,
            self.marker.as_deref(),
            self.max_items,
            self.path_prefix.as_deref(),
        )
        .await
    }
}

/// The marker innards for a ListAttachedUserPolicies operation.
#[derive(Deserialize, Serialize)]
struct ListAttachedUserPoliciesMarker {
    next_policy_name_lower: String,
    next_managed_policy_id: String,
}

/// The rows returned by the ListAttachedUserPolicies query.
#[derive(FromRow)]
struct ListAttachedPolicyRow {
    managed_policy_id: String,
    account_id: String,
    managed_policy_name_cased: String,
    managed_policy_name_lower: String,
    path: String,
}

/// List managed policies attached to a user in the database.
pub async fn list_attached_user_policies(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
    path_prefix: Option<&str>,
) -> Result<ListAttachedUserPoliciesResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;
    if let Some(path_prefix) = path_prefix {
        validate_path_prefix(path_prefix)?;
    }
    let max_items = constrain_max_items(max_items)?;
    let partition = get_current_partition_or_fail(tx).await?;

    // Look up the user_id, returning NoSuchEntity if the user doesn't exist.
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
            return Err(internal_failure().into());
        }
    };

    let paginator = make_iam_paginator(&partition, OP_LIST_ATTACHED_USER_POLICIES)?;

    let mut sql = QueryBuilder::new(
        r#"
        SELECT mp.managed_policy_id, mp.account_id, mp.managed_policy_name_cased,
            mp.managed_policy_name_lower, mp.path
        FROM iam.user_attached_policies uap
        INNER JOIN iam.managed_policies mp ON uap.managed_policy_id = mp.managed_policy_id
        WHERE uap.user_id =
    "#,
    );
    sql.push_bind(&user_id);

    if let Some(path_prefix) = path_prefix {
        sql.push(" AND mp.path LIKE ");
        sql.push_bind(format!("{}%", path_prefix.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")));
    }

    if let Some(marker) = marker {
        let info: ListAttachedUserPoliciesMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token for ListAttachedUserPolicies: {e}");
            internal_failure()
        })?;
        sql.push(" AND (mp.managed_policy_name_lower, mp.managed_policy_id) >= (");
        sql.push_bind(info.next_policy_name_lower);
        sql.push(", ");
        sql.push_bind(info.next_managed_policy_id);
        sql.push(")");
    }

    // Request one more than max_items so we can determine if there are more results.
    sql.push(" ORDER BY mp.managed_policy_name_lower ASC, mp.managed_policy_id ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListAttachedPolicyRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch attached user policies from database: {e}");
        internal_failure()
    })?;

    let mut results: Vec<AttachedPolicy> = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if results.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListAttachedUserPoliciesMarker {
                        next_policy_name_lower: row.managed_policy_name_lower,
                        next_managed_policy_id: row.managed_policy_id,
                    })
                    .await
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token for ListAttachedUserPolicies: {e}");
                        internal_failure()
                    })?,
            );
            break;
        }

        let arn = build_policy_arn(&partition, &row.account_id, &row.path, &row.managed_policy_name_cased)?;
        results.push(
            AttachedPolicy::builder()
                .policy_arn(Some(arn.to_string()))
                .policy_name(Some(row.managed_policy_name_cased))
                .build()
                .map_err(|e| {
                    log::error!("Failed to construct AttachedPolicy: {e}");
                    internal_failure()
                })?,
        );
    }

    let mut builder = ListAttachedUserPoliciesResponse::builder();
    builder = builder.attached_policies(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(Some(true)).marker(Some(next_marker));
    }

    builder.build().map_err(|e| {
        log::error!("Failed to build ListAttachedUserPoliciesResponse: {e}");
        internal_failure().into()
    })
}
