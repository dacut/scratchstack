//! ListRoles database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, constrain_max_items, decrypt_pagination_token,
        internal_failure, make_iam_paginator, partition::get_current_partition_or_fail, path::validate_path_prefix,
        policy::build_policy_arn, role::role_arn_resource,
    },
    chrono::{DateTime, Utc},
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListRolesInternalRequest, ListRolesResponse},
        types::{AttachedPermissionsBoundary, PermissionsBoundaryAttachmentType, Role, Tag},
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, postgres::PgTransaction},
};

impl RequestExecutor for ListRolesInternalRequest {
    type Response = ListRolesResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        list_roles(
            tx,
            &self.account_id,
            self.marker.as_deref(),
            self.max_items,
            self.path_prefix.as_deref(),
            request_id,
        )
        .await
    }
}

/// The marker innards for a ListRoles operation.
#[derive(Deserialize, Serialize)]
struct ListRolesMarker {
    next_role_name_lower: String,
}

/// The rows returned by the ListRoles query. The `pb_*` columns come from a LEFT JOIN against
/// iam.managed_policies on permissions_boundary_managed_policy_id, so the join keeps the row even
/// when a role has no PB and the projection avoids the N+1 lookup per role.
#[derive(FromRow)]
struct ListRolesRow {
    role_id: String,
    role_name_lower: String,
    role_name_cased: String,
    path: String,
    permissions_boundary_managed_policy_id: Option<String>,
    description: Option<String>,
    assume_role_policy_document: String,
    max_session_duration: Option<i32>,
    created_at: DateTime<Utc>,
    pb_account_id: Option<String>,
    pb_path: Option<String>,
    pb_name_cased: Option<String>,
}

/// List roles in the account. Each result carries the same Role projection produced by GetRole,
/// minus the tag list (consistent with AWS ListRoles, which omits tags from the per-role payload).
pub async fn list_roles(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
    path_prefix: Option<&str>,
    request_id: RequestId,
) -> Result<ListRolesResponse, IamError> {
    validate_account_id(account_id, request_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    if let Some(path_prefix) = path_prefix {
        validate_path_prefix(path_prefix, request_id)?;
    }
    let max_items = constrain_max_items(max_items, request_id)?;
    let partition = get_current_partition_or_fail(tx, request_id).await?;

    let paginator = make_iam_paginator(&partition, OP_LIST_ROLES, request_id)?;

    let mut sql = QueryBuilder::new(
        r#"
        SELECT r.role_id, r.role_name_lower, r.role_name_cased, r.path,
            r.permissions_boundary_managed_policy_id, r.description, r.assume_role_policy_document,
            r.max_session_duration, r.created_at,
            pb.account_id AS pb_account_id, pb.path AS pb_path,
            pb.managed_policy_name_cased AS pb_name_cased
        FROM iam.roles r
        LEFT JOIN iam.managed_policies pb
            ON pb.managed_policy_id = r.permissions_boundary_managed_policy_id
        WHERE r.account_id =
    "#,
    );
    sql.push_bind(account_id);

    if let Some(path_prefix) = path_prefix {
        sql.push(" AND r.path LIKE ");
        sql.push_bind(format!("{}%", path_prefix.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")));
    }

    if let Some(marker) = marker {
        let info: ListRolesMarker = decrypt_pagination_token(&paginator, marker, OP_LIST_ROLES, request_id).await?;
        sql.push(" AND r.role_name_lower >= ");
        sql.push_bind(info.next_role_name_lower);
    }

    // Request one more than max_items so we can determine if there are more results.
    sql.push(" ORDER BY r.role_name_lower ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListRolesRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch roles from database: {e}");
        internal_failure(request_id)
    })?;

    let mut results: Vec<Role> = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if results.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListRolesMarker {
                        next_role_name_lower: row.role_name_lower,
                    })
                    .await
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token for ListRoles: {e}");
                        internal_failure(request_id)
                    })?,
            );
            break;
        }

        let arn = Arn::builder()
            .partition(partition.clone())
            .service(SERVICE_KEY_IAM)
            .account_id(account_id)
            .resource(role_arn_resource(&row.path, &row.role_name_cased))
            .build()
            .map_err(|e| {
                log::error!("Failed to construct ARN for role: {e}");
                internal_failure(request_id)
            })?;

        let permissions_boundary = if let Some(pb_id) = row.permissions_boundary_managed_policy_id.as_deref() {
            // The FK on permissions_boundary_managed_policy_id guarantees the joined row exists,
            // so a missing pb_account_id/pb_path/pb_name_cased here indicates DB corruption.
            let (pb_account_id, pb_path, pb_name_cased) =
                match (row.pb_account_id.as_deref(), row.pb_path.as_deref(), row.pb_name_cased.as_deref()) {
                    (Some(pb_account_id), Some(pb_path), Some(pb_name_cased)) => {
                        (pb_account_id, pb_path, pb_name_cased)
                    }
                    _ => {
                        log::error!("Role references missing permissions boundary managed policy ID: {pb_id}");
                        return Err(internal_failure(request_id).into());
                    }
                };

            // The boundary is named by the account owning the policy, not by the account owning
            // the role: an AWS-managed policy serving as a boundary belongs to the AWS account.
            let pb_arn = build_policy_arn(&partition, pb_account_id, pb_path, pb_name_cased, request_id)?;

            Some(
                AttachedPermissionsBoundary::builder()
                    .permissions_boundary_arn(pb_arn.to_string())
                    .permissions_boundary_type(PermissionsBoundaryAttachmentType::Policy)
                    .build()
                    .map_err(|e| {
                        log::error!("Failed to construct permissions boundary for role: {e}");
                        internal_failure(request_id)
                    })?,
            )
        } else {
            None
        };

        results.push(
            Role::builder()
                .arn(arn.to_string())
                .assume_role_policy_document(row.assume_role_policy_document)
                .create_date(row.created_at)
                .set_description(row.description)
                .set_max_session_duration(row.max_session_duration)
                .path(row.path)
                .set_permissions_boundary(permissions_boundary)
                .role_id(format!("{}{}", IamResourceType::Role.as_str(), row.role_id))
                .role_name(row.role_name_cased)
                .set_tags(Vec::<Tag>::new())
                .build()
                .map_err(|e| {
                    log::error!("Failed to construct role object: {e}");
                    internal_failure(request_id)
                })?,
        );
    }

    let mut builder = ListRolesResponse::builder();
    builder = builder.set_roles(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(true).marker(next_marker);
    }

    builder.build().map_err(|e| {
        log::error!("Failed to build ListRolesResponse: {e}");
        internal_failure(request_id).into()
    })
}
