//! ListAttachedGroupPolicies database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, constrain_max_items, decrypt_pagination_token,
        group::validate_group_name, internal_failure, make_iam_paginator, partition::get_current_partition_or_fail,
        path::validate_path_prefix, policy::build_policy_arn,
    },
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListAttachedGroupPoliciesInternalRequest, ListAttachedGroupPoliciesResponse},
        types::{AttachedPolicy, error::NoSuchEntityException},
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for ListAttachedGroupPoliciesInternalRequest {
    type Response = ListAttachedGroupPoliciesResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        list_attached_group_policies(
            tx,
            &self.account_id,
            &self.group_name,
            self.marker.as_deref(),
            self.max_items,
            self.path_prefix.as_deref(),
            request_id,
        )
        .await
    }
}

/// The marker innards for a ListAttachedGroupPolicies operation.
#[derive(Deserialize, Serialize)]
struct ListAttachedGroupPoliciesMarker {
    next_policy_name_lower: String,
    next_managed_policy_id: String,
}

/// The rows returned by the ListAttachedGroupPolicies query.
#[derive(FromRow)]
struct ListAttachedGroupPolicyRow {
    managed_policy_id: String,
    account_id: String,
    managed_policy_name_cased: String,
    managed_policy_name_lower: String,
    path: String,
}

/// List managed policies attached to a group in the database.
pub async fn list_attached_group_policies(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    group_name: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
    path_prefix: Option<&str>,
    request_id: RequestId,
) -> Result<ListAttachedGroupPoliciesResponse, IamError> {
    validate_account_id(account_id, request_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_group_name(group_name, request_id)?;
    if let Some(path_prefix) = path_prefix {
        validate_path_prefix(path_prefix, request_id)?;
    }
    let max_items = constrain_max_items(max_items, request_id)?;
    let partition = get_current_partition_or_fail(tx, request_id).await?;

    // Look up the group_id, returning NoSuchEntity if the group doesn't exist.
    let group_id: String = match query(indoc! {"
            SELECT group_id
            FROM iam.groups
            WHERE account_id = $1 AND group_name_lower = $2
        "})
    .bind(account_id)
    .bind(group_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The group with name {group_name} cannot be found."))
                .request_id(request_id)
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up group in database: {e}");
            return Err(internal_failure(request_id).into());
        }
    };

    let paginator = make_iam_paginator(&partition, OP_LIST_ATTACHED_GROUP_POLICIES, request_id)?;

    let mut sql = QueryBuilder::new(
        r#"
        SELECT mp.managed_policy_id, mp.account_id, mp.managed_policy_name_cased,
            mp.managed_policy_name_lower, mp.path
        FROM iam.group_attached_policies gap
        INNER JOIN iam.managed_policies mp ON gap.managed_policy_id = mp.managed_policy_id
        WHERE gap.group_id =
    "#,
    );
    sql.push_bind(&group_id);

    if let Some(path_prefix) = path_prefix {
        sql.push(" AND mp.path LIKE ");
        sql.push_bind(format!("{}%", path_prefix.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")));
    }

    if let Some(marker) = marker {
        let info: ListAttachedGroupPoliciesMarker =
            decrypt_pagination_token(&paginator, marker, OP_LIST_ATTACHED_GROUP_POLICIES, request_id).await?;
        sql.push(" AND (mp.managed_policy_name_lower, mp.managed_policy_id) >= (");
        sql.push_bind(info.next_policy_name_lower);
        sql.push(", ");
        sql.push_bind(info.next_managed_policy_id);
        sql.push(")");
    }

    sql.push(" ORDER BY mp.managed_policy_name_lower ASC, mp.managed_policy_id ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListAttachedGroupPolicyRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch attached group policies from database: {e}");
        internal_failure(request_id)
    })?;

    let mut results: Vec<AttachedPolicy> = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if results.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListAttachedGroupPoliciesMarker {
                        next_policy_name_lower: row.managed_policy_name_lower,
                        next_managed_policy_id: row.managed_policy_id,
                    })
                    .await
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token for ListAttachedGroupPolicies: {e}");
                        internal_failure(request_id)
                    })?,
            );
            break;
        }

        let arn = build_policy_arn(&partition, &row.account_id, &row.path, &row.managed_policy_name_cased, request_id)?;
        results.push(
            AttachedPolicy::builder()
                .policy_arn(arn.to_string())
                .policy_name(row.managed_policy_name_cased)
                .build()
                .map_err(|e| {
                    log::error!("Failed to construct AttachedPolicy: {e}");
                    internal_failure(request_id)
                })?,
        );
    }

    let mut builder = ListAttachedGroupPoliciesResponse::builder();
    builder = builder.set_attached_policies(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(true).marker(next_marker);
    }

    builder.build().map_err(|e| {
        log::error!("Failed to build ListAttachedGroupPoliciesResponse: {e}");
        internal_failure(request_id).into()
    })
}
