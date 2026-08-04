//! ListPolicyVersions database operation
use {
    crate::{
        RequestExecutor, constants::*, constrain_max_items, internal_failure, make_iam_paginator,
        partition::get_current_partition_or_fail, policy::parse_policy_arn,
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    log::error,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListPolicyVersionsRequest, ListPolicyVersionsResponse},
        types::{PolicyVersion, error::NoSuchEntityException},
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, postgres::PgTransaction, query_as},
};

impl RequestExecutor for ListPolicyVersionsRequest {
    type Response = ListPolicyVersionsResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_policy_versions(tx, &self.policy_arn, self.marker.as_deref(), self.max_items).await
    }
}

/// List versions of a managed policy by ARN.
pub async fn list_policy_versions(
    tx: &mut PgTransaction<'_>,
    policy_arn: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
) -> Result<ListPolicyVersionsResponse, IamError> {
    /// The marker innards for a ListPolicyVersions operation.
    #[derive(Deserialize, Serialize)]
    struct ListPolicyVersionsMarker {
        next_version: i64,
    }

    /// The row returned by the initial query to the iam.policies table to get the managed_policy_id
    /// and default_version for the requested policy ARN.
    #[derive(FromRow)]
    struct PolicyRow {
        managed_policy_id: String,
        default_version: i64,
    }

    /// The rows returned by the ListPolicyVersions operation.
    #[derive(FromRow)]
    struct ListPolicyVersionsRow {
        managed_policy_version: i64,
        created_at: DateTime<Utc>,
    }

    let parts = parse_policy_arn(policy_arn)?;
    let policy_account_id = match parts.account_id() {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let max_items = constrain_max_items(max_items)?;
    let partition = get_current_partition_or_fail(tx).await?;

    let paginator = make_iam_paginator(&partition, OP_LIST_POLICY_VERSIONS)?;

    // Look up the policy to get managed_policy_id and default_version.
    let policy_row: PolicyRow = query_as(indoc! {"
            SELECT managed_policy_id, default_version
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(policy_account_id)
    .bind(parts.resource_path())
    .bind(parts.resource_name_lower())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        error!("Failed to query managed policy from database: {e}");
        internal_failure()
    })?
    .ok_or_else(|| NoSuchEntityException::builder().message(format!("Policy {policy_arn} was not found.")).build())?;

    let mut sql = QueryBuilder::new(
        r#"
        SELECT managed_policy_version, created_at
        FROM iam.managed_policy_versions
        WHERE managed_policy_id =
    "#,
    );
    sql.push_bind(&policy_row.managed_policy_id);

    if let Some(marker) = marker {
        let info: ListPolicyVersionsMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            error!("Failed to decrypt pagination token for ListPolicyVersions: {e}");
            internal_failure()
        })?;
        sql.push(" AND managed_policy_version <= ");
        sql.push_bind(info.next_version);
    }

    sql.push(" ORDER BY managed_policy_version DESC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListPolicyVersionsRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        error!("Failed to fetch managed policy versions from database: {e}");
        internal_failure()
    })?;

    let mut versions: Vec<PolicyVersion> = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if versions.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListPolicyVersionsMarker {
                        next_version: row.managed_policy_version,
                    })
                    .await
                    .map_err(|e| {
                        error!("Failed to encrypt pagination token for ListPolicyVersions: {e}");
                        internal_failure()
                    })?,
            );
            break;
        }

        versions.push(
            PolicyVersion::builder()
                .create_date(row.created_at)
                .is_default_version(row.managed_policy_version == policy_row.default_version)
                .version_id(format!("v{}", row.managed_policy_version))
                .build()
                .map_err(|e| {
                    error!("Failed to build PolicyVersion: {e}");
                    internal_failure()
                })?,
        );
    }

    Ok(ListPolicyVersionsResponse::builder()
        .set_versions(versions)
        .is_truncated(next_marker.is_some())
        .set_marker(next_marker)
        .build()
        .map_err(|e| {
            error!("Failed to build ListPolicyVersionsResponse: {e}");
            internal_failure()
        })?)
}
