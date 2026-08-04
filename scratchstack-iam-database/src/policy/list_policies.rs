//! ListPolicies database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, constrain_max_items, internal_failure,
        make_iam_paginator, partition::get_current_partition_or_fail, path::validate_path_prefix,
        policy::build_policy_arn,
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    log::error,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListPoliciesInternalRequest, ListPoliciesResponse},
        types::{Policy, PolicyScopeType, PolicyUsageType, error::ValidationError},
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, postgres::PgTransaction, query_as},
    std::{cmp::min, collections::BTreeMap},
};

impl RequestExecutor for ListPoliciesInternalRequest {
    type Response = ListPoliciesResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_policies(
            tx,
            &self.account_id,
            self.marker.as_deref(),
            self.max_items,
            self.only_attached,
            self.path_prefix.as_deref(),
            self.policy_usage_filter.as_ref(),
            self.scope.as_ref(),
        )
        .await
    }
}

/// List managed policies in an account, optionally including AWS-managed policies.
#[allow(clippy::too_many_arguments)]
pub async fn list_policies(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
    only_attached: Option<bool>,
    path_prefix: Option<&str>,
    policy_usage_filter: Option<&PolicyUsageType>,
    scope: Option<&PolicyScopeType>,
) -> Result<ListPoliciesResponse, IamError> {
    /// The marker innards for a ListPolicies operation.
    #[derive(Deserialize, Serialize)]
    struct ListPoliciesMarker {
        next_account_id: String,
        next_managed_policy_id: String,
    }

    /// The rows returned by the ListPolicies operation.
    #[derive(FromRow)]
    struct ListPoliciesRow {
        managed_policy_id: String,
        account_id: String,
        managed_policy_name_cased: String,
        path: String,
        default_version: i64,
        deprecated: bool,
        created_at: DateTime<Utc>,
        update_date: DateTime<Utc>,
    }

    /// The rows returned for attachment counts.
    #[derive(FromRow)]
    struct AttachmentCountRow {
        managed_policy_id: String,
        attachment_count: i64,
    }

    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    if let Some(path_prefix) = path_prefix {
        validate_path_prefix(path_prefix)?;
    }
    let max_items = constrain_max_items(max_items)?;
    let partition = get_current_partition_or_fail(tx).await?;

    let paginator = make_iam_paginator(&partition, OP_LIST_POLICIES)?;

    let mut sql = QueryBuilder::new(
        r#"
        SELECT managed_policy_id, account_id, managed_policy_name_cased, path, default_version,
            deprecated, created_at, update_date
        FROM iam.managed_policies
        WHERE
    "#,
    );

    let scope = scope.unwrap_or(&PolicyScopeType::All);
    match scope {
        PolicyScopeType::Aws => {
            sql.push("account_id = ");
            sql.push_bind(AWS_ACCOUNT_ID_NUMERIC);
        }
        PolicyScopeType::Local => {
            sql.push("account_id = ");
            sql.push_bind(account_id);
        }
        PolicyScopeType::All => {
            sql.push("(account_id = ");
            sql.push_bind(account_id);
            sql.push(" OR account_id = ");
            sql.push_bind(AWS_ACCOUNT_ID_NUMERIC);
            sql.push(")");
        }
        other => {
            return Err(ValidationError::builder().message(format!("Unsupported Scope value: {other}")).build().into());
        }
    }

    if let Some(path_prefix) = path_prefix {
        sql.push(" AND path LIKE ");
        sql.push_bind(format!("{}%", path_prefix.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")));
    }

    // "Attached" here means "attached to a user/group/role in the caller's account". The
    // subqueries join back to the owning entity tables so attachments to entities in other
    // accounts don't leak through.
    let needs_permissions_policy_filter =
        only_attached == Some(true) || policy_usage_filter == Some(&PolicyUsageType::PermissionsPolicy);
    if needs_permissions_policy_filter {
        push_attached_in_account_filter(&mut sql, account_id);
    }

    if let Some(filter) = policy_usage_filter {
        match filter {
            PolicyUsageType::PermissionsPolicy => {}
            PolicyUsageType::PermissionsBoundary => {
                push_pb_in_account_filter(&mut sql, account_id);
            }
            other => {
                return Err(ValidationError::builder()
                    .message(format!("Unsupported PolicyUsageFilter value: {other}"))
                    .build()
                    .into());
            }
        }
    }

    if let Some(marker) = marker {
        let info: ListPoliciesMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            error!("Failed to decrypt pagination token for ListPolicies: {e}");
            internal_failure()
        })?;
        sql.push(" AND (account_id, managed_policy_id) >= (");
        sql.push_bind(info.next_account_id);
        sql.push(", ");
        sql.push_bind(info.next_managed_policy_id);
        sql.push(")");
    }

    sql.push(" ORDER BY account_id ASC, managed_policy_id ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListPoliciesRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        error!("Failed to fetch managed policies from database: {e}");
        internal_failure()
    })?;

    let mut results: BTreeMap<String, Policy> = BTreeMap::new();
    let mut next_marker = None;

    for row in rows.into_iter() {
        if results.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListPoliciesMarker {
                        next_account_id: row.account_id,
                        next_managed_policy_id: row.managed_policy_id,
                    })
                    .await
                    .map_err(|e| {
                        error!("Failed to encrypt pagination token for ListPolicies: {e}");
                        internal_failure()
                    })?,
            );
            break;
        }

        let arn = build_policy_arn(&partition, &row.account_id, &row.path, &row.managed_policy_name_cased)?;
        let policy_id = format!("{}{}", IamResourceType::ManagedPolicy.as_str(), row.managed_policy_id);
        let policy = Policy::builder()
            .arn(arn.to_string())
            .create_date(row.created_at)
            .default_version_id(format!("v{}", row.default_version))
            .is_attachable(!row.deprecated)
            .path(row.path)
            .policy_id(policy_id)
            .policy_name(row.managed_policy_name_cased)
            .update_date(row.update_date)
            .build()
            .map_err(|e| {
                error!("Failed to build Policy: {e}");
                internal_failure()
            })?;
        results.insert(row.managed_policy_id, policy);
    }

    // This will be very, very many for AWS policies, will overflow the resulting i32, and will
    // take an extremely long time. Skip it for AWS policies by only doing it when listing a single
    // account's policies.
    if account_id != AWS_ACCOUNT_ID_NUMERIC {
        // Retrieve the attachment count for each of the policies in the result set.
        let attachment_rows: Vec<AttachmentCountRow> = query_as(indoc! {"
            SELECT mp.managed_policy_id,
                (SELECT COUNT(*) FROM iam.user_attached_policies WHERE managed_policy_id = mp.managed_policy_id) +
                (SELECT COUNT(*) FROM iam.group_attached_policies WHERE managed_policy_id = mp.managed_policy_id) +
                (SELECT COUNT(*) FROM iam.role_attached_policies WHERE managed_policy_id = mp.managed_policy_id)
                AS attachment_count
            FROM iam.managed_policies mp
            WHERE mp.managed_policy_id = ANY($1)
        "})
        .bind(results.keys().cloned().collect::<Vec<String>>())
        .fetch_all(tx.as_mut())
        .await
        .map_err(|e| {
            error!("Failed to fetch policy attachment counts from database: {e}");
            internal_failure()
        })?;
        for row in attachment_rows.into_iter() {
            let attachment_count = min(row.attachment_count, i32::MAX as i64) as i32;

            if let Some(policy) = results.get_mut(&row.managed_policy_id) {
                policy.attachment_count = Some(attachment_count);
            }
        }

        // Retrieve the permissions boundary usage count for each of the policies in the result set.
        let permissions_boundary_usage_rows: Vec<AttachmentCountRow> = query_as(indoc! {"
            SELECT mp.managed_policy_id,
                (SELECT COUNT(*) FROM iam.users
                 WHERE account_id = $2 AND permissions_boundary_managed_policy_id = mp.managed_policy_id) +
                (SELECT COUNT(*) FROM iam.roles
                 WHERE account_id = $2 AND permissions_boundary_managed_policy_id = mp.managed_policy_id)
                AS attachment_count
            FROM iam.managed_policies mp
            WHERE mp.managed_policy_id = ANY($1)
        "})
        .bind(results.keys().cloned().collect::<Vec<String>>())
        .bind(account_id)
        .fetch_all(tx.as_mut())
        .await
        .map_err(|e| {
            error!("Failed to fetch policy permissions boundary usage counts from database: {e}");
            internal_failure()
        })?;
        for row in permissions_boundary_usage_rows.into_iter() {
            let usage_count = min(row.attachment_count, i32::MAX as i64) as i32;

            if let Some(policy) = results.get_mut(&row.managed_policy_id) {
                policy.permissions_boundary_usage_count = Some(usage_count);
            }
        }
    }

    let policies = results.into_values().collect::<Vec<_>>();

    Ok(ListPoliciesResponse::builder()
        .set_policies(policies)
        .is_truncated(next_marker.is_some())
        .set_marker(next_marker)
        .build()
        .map_err(|e| {
            error!("Failed to build ListPoliciesResponse: {e}");
            internal_failure()
        })?)
}

/// Append a ListPolicies filter restricting results to policies attached to a user, group, or
/// role in `account_id`. The join back to the entity tables prevents attachments to entities in
/// other accounts from leaking through.
fn push_attached_in_account_filter(sql: &mut QueryBuilder<sqlx::Postgres>, account_id: &str) {
    sql.push(" AND managed_policy_id IN (SELECT uap.managed_policy_id FROM iam.user_attached_policies uap ");
    sql.push("JOIN iam.users u ON u.user_id = uap.user_id WHERE u.account_id = ");
    sql.push_bind(account_id);
    sql.push(" UNION ALL SELECT gap.managed_policy_id FROM iam.group_attached_policies gap ");
    sql.push("JOIN iam.groups g ON g.group_id = gap.group_id WHERE g.account_id = ");
    sql.push_bind(account_id);
    sql.push(" UNION ALL SELECT rap.managed_policy_id FROM iam.role_attached_policies rap ");
    sql.push("JOIN iam.roles r ON r.role_id = rap.role_id WHERE r.account_id = ");
    sql.push_bind(account_id);
    sql.push(")");
}

/// Append a ListPolicies filter restricting results to policies used as a permissions boundary
/// by a user or role in `account_id`.
fn push_pb_in_account_filter(sql: &mut QueryBuilder<sqlx::Postgres>, account_id: &str) {
    sql.push(" AND managed_policy_id IN (");
    sql.push("SELECT permissions_boundary_managed_policy_id FROM iam.users WHERE account_id = ");
    sql.push_bind(account_id);
    sql.push(" AND permissions_boundary_managed_policy_id IS NOT NULL");
    sql.push(" UNION ALL SELECT permissions_boundary_managed_policy_id FROM iam.roles WHERE account_id = ");
    sql.push_bind(account_id);
    sql.push(" AND permissions_boundary_managed_policy_id IS NOT NULL)");
}
