//! ListUsers database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, constrain_max_items, decrypt_pagination_token,
        internal_failure, make_iam_paginator, partition::get_current_partition_or_fail, path::validate_path_prefix,
        policy::build_policy_arn, user::user_arn_resource,
    },
    chrono::{DateTime, Utc},
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListUsersInternalRequest, ListUsersResponse},
        types::{AttachedPermissionsBoundary, PermissionsBoundaryAttachmentType, User},
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, postgres::PgTransaction},
};

impl RequestExecutor for ListUsersInternalRequest {
    type Response = ListUsersResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        list_users(
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

/// The marker innards for a ListUsers operation.
#[derive(Deserialize, Serialize)]
struct ListUsersMarker {
    next_user_name: String,
}

/// The rows returned by the ListUsers query. The `pb_*` columns come from a LEFT JOIN against
/// iam.managed_policies on permissions_boundary_managed_policy_id, so the join keeps the row even
/// when a user has no PB and the projection avoids the N+1 lookup per user.
#[derive(FromRow)]
struct ListUsersRow {
    user_id: String,
    user_name_lower: String,
    user_name_cased: String,
    path: String,
    permissions_boundary_managed_policy_id: Option<String>,
    created_at: DateTime<Utc>,
    pb_account_id: Option<String>,
    pb_path: Option<String>,
    pb_name_cased: Option<String>,
}

/// List users on the database.
pub async fn list_users(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
    path_prefix: Option<&str>,
    request_id: RequestId,
) -> Result<ListUsersResponse, IamError> {
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

    let paginator = make_iam_paginator(&partition, OP_LIST_USERS, request_id)?;

    let mut sql = QueryBuilder::new(
        r#"
        SELECT u.user_id, u.user_name_lower, u.user_name_cased, u.path,
            u.permissions_boundary_managed_policy_id, u.created_at,
            pb.account_id AS pb_account_id, pb.path AS pb_path,
            pb.managed_policy_name_cased AS pb_name_cased
        FROM iam.users u
        LEFT JOIN iam.managed_policies pb
            ON pb.managed_policy_id = u.permissions_boundary_managed_policy_id
        WHERE u.account_id =
    "#,
    );
    sql.push_bind(account_id);

    if let Some(path_prefix) = path_prefix {
        sql.push(" AND u.path LIKE ");
        sql.push_bind(format!("{}%", path_prefix.replace('%', "\\%").replace('_', "\\_")));
    }

    if let Some(marker) = marker {
        let info: ListUsersMarker = decrypt_pagination_token(&paginator, marker, OP_LIST_USERS, request_id).await?;
        sql.push(" AND u.user_name_lower >= ");
        sql.push_bind(info.next_user_name);
    }

    // Request one more than max_items so we can determine if there are more results.
    sql.push(" ORDER BY u.user_name_lower ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql
        .build_query_as::<ListUsersRow>()
        .fetch_all(tx.as_mut())
        .await
        .map_err(|e| internal_failure!(request_id; "Failed to fetch users from database: {e}"))?;
    let mut results = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if results.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListUsersMarker {
                        next_user_name: row.user_name_lower,
                    })
                    .await
                    .map_err(
                        |e| internal_failure!(request_id; "Failed to encrypt pagination token for ListUsers: {e}"),
                    )?,
            );
            break;
        }

        let arn = Arn::builder()
            .partition(partition.clone())
            .service(SERVICE_KEY_IAM)
            .account_id(account_id)
            .resource(user_arn_resource(&row.path, &row.user_name_cased))
            .build()
            .map_err(|e| internal_failure!(request_id; "Failed to construct ARN for user: {e}"))?;

        let permissions_boundary = if let Some(pb_id) = row.permissions_boundary_managed_policy_id.as_deref() {
            // The FK on permissions_boundary_managed_policy_id guarantees the joined row exists,
            // so a missing pb_account_id/pb_path/pb_name_cased here indicates DB corruption.
            let (pb_account_id, pb_path, pb_name_cased) = match (
                row.pb_account_id.as_deref(),
                row.pb_path.as_deref(),
                row.pb_name_cased.as_deref(),
            ) {
                (Some(pb_account_id), Some(pb_path), Some(pb_name_cased)) => (pb_account_id, pb_path, pb_name_cased),
                _ => {
                    return Err(internal_failure!(request_id; "User references missing permissions boundary managed policy ID: {pb_id}").into());
                }
            };

            // The boundary is named by the account owning the policy, not by the account owning
            // the user: an AWS-managed policy serving as a boundary belongs to the AWS account.
            let pb_arn = build_policy_arn(&partition, pb_account_id, pb_path, pb_name_cased, request_id)?;

            Some(
                AttachedPermissionsBoundary::builder()
                    .permissions_boundary_arn(pb_arn.to_string())
                    .permissions_boundary_type(PermissionsBoundaryAttachmentType::Policy)
                    .build()
                    .map_err(
                        |e| internal_failure!(request_id; "Failed to construct permissions boundary for user: {e}"),
                    )?,
            )
        } else {
            None
        };

        results.push(
            User::builder()
                .arn(arn.to_string())
                .create_date(row.created_at)
                .path(row.path)
                .user_id(format!("{}{}", IamResourceType::User.as_str(), row.user_id))
                .user_name(row.user_name_cased)
                .set_permissions_boundary(permissions_boundary)
                .build()
                .map_err(|e| internal_failure!(request_id; "Failed to construct user object: {e}"))?,
        );
    }

    let mut builder = ListUsersResponse::builder();
    builder = builder.set_users(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(true).marker(next_marker);
    }

    builder.build().map_err(|e| internal_failure!(request_id; "Failed to build ListUsersResponse: {e}").into())
}
