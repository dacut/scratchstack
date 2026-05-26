//! ListRoles database operation
use {
    crate::{
        RequestExecutor,
        constants::iam::*,
        iam::{
            build_policy_arn, constrain_max_items, get_current_partition_or_fail, make_paginator, role_arn_resource,
            validate_account_id, validate_path_prefix,
        },
    },
    chrono::{DateTime, Utc},
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListRolesInternalRequest, ListRolesResponse},
        types::{AttachedPermissionsBoundary, PermissionsBoundaryAttachmentType, Role, Tag, error::InternalFailure},
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, postgres::PgTransaction},
};

impl RequestExecutor for ListRolesInternalRequest {
    type Response = ListRolesResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_roles(tx, &self.account_id, self.marker.as_deref(), self.max_items, self.path_prefix.as_deref()).await
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
) -> Result<ListRolesResponse, IamError> {
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

    let paginator = make_paginator(&partition, OP_LIST_ROLES)?;

    let mut sql = QueryBuilder::new(
        r#"
        SELECT r.role_id, r.role_name_lower, r.role_name_cased, r.path,
            r.permissions_boundary_managed_policy_id, r.description, r.assume_role_policy_document,
            r.max_session_duration, r.created_at,
            pb.path AS pb_path, pb.managed_policy_name_cased AS pb_name_cased
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
        let info: ListRolesMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token for ListRoles: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;
        sql.push(" AND r.role_name_lower >= ");
        sql.push_bind(info.next_role_name_lower);
    }

    // Request one more than max_items so we can determine if there are more results.
    sql.push(" ORDER BY r.role_name_lower ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListRolesRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch roles from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
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
                        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
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
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?;

        let permissions_boundary = if let Some(pb_id) = row.permissions_boundary_managed_policy_id.as_deref() {
            // The FK on permissions_boundary_managed_policy_id guarantees the joined row exists,
            // so a missing pb_path/pb_name_cased here indicates DB corruption.
            let (pb_path, pb_name_cased) = match (row.pb_path, row.pb_name_cased) {
                (Some(p), Some(n)) => (p, n),
                _ => {
                    log::error!("Role references missing permissions boundary managed policy ID: {pb_id}");
                    return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
                }
            };
            let pb_arn = build_policy_arn(&partition, account_id, &pb_path, &pb_name_cased)?;

            Some(
                AttachedPermissionsBoundary::builder()
                    .permissions_boundary_arn(Some(pb_arn.to_string()))
                    .permissions_boundary_type(Some(PermissionsBoundaryAttachmentType::Policy))
                    .build()
                    .map_err(|e| {
                        log::error!("Failed to construct permissions boundary for role: {e}");
                        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                    })?,
            )
        } else {
            None
        };

        results.push(
            Role::builder()
                .arn(arn.to_string())
                .assume_role_policy_document(Some(row.assume_role_policy_document))
                .create_date(row.created_at)
                .description(row.description)
                .max_session_duration(row.max_session_duration)
                .path(row.path)
                .permissions_boundary(permissions_boundary)
                .role_id(format!("{}{}", IamResourceType::Role.as_str(), row.role_id))
                .role_name(row.role_name_cased)
                .tags(Vec::<Tag>::new())
                .build()
                .map_err(|e| {
                    log::error!("Failed to construct role object: {e}");
                    IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                })?,
        );
    }

    let mut builder = ListRolesResponse::builder();
    builder = builder.roles(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(Some(true)).marker(Some(next_marker));
    }

    builder.build().map_err(|e| {
        log::error!("Failed to build ListRolesResponse: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })
}
