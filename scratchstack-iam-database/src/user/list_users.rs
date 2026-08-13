//! ListUsers database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, constrain_max_items, internal_failure,
        make_iam_paginator, partition::get_current_partition_or_fail, path::validate_path_prefix,
    },
    chrono::{DateTime, Utc},
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
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

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_users(tx, &self.account_id, self.marker.as_deref(), self.max_items, self.path_prefix.as_deref()).await
    }
}

/// The marker innards for a ListUsers operation.
#[derive(Deserialize, Serialize)]
struct ListUsersMarker {
    next_user_name: String,
}

/// The rows returned by the ListUsers query.
#[derive(FromRow)]
struct ListUsersRow {
    user_id: String,
    user_name_lower: String,
    user_name_cased: String,
    path: String,
    permissions_boundary_managed_policy_id: Option<String>,
    created_at: DateTime<Utc>,
}

/// List users on the database.
pub async fn list_users(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
    path_prefix: Option<&str>,
) -> Result<ListUsersResponse, IamError> {
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

    let paginator = make_iam_paginator(&partition, OP_LIST_USERS)?;

    let mut sql = QueryBuilder::new(
        r#"
        SELECT user_id, user_name_lower, user_name_cased, path,
        permissions_boundary_managed_policy_id, created_at
        FROM iam.users
        WHERE account_id =
    "#,
    );
    sql.push_bind(account_id);

    if let Some(path_prefix) = path_prefix {
        sql.push(" AND PATH LIKE ");
        sql.push_bind(format!("{}%", path_prefix.replace('%', "\\%").replace('_', "\\_")));
    }

    if let Some(marker) = marker {
        let info: ListUsersMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token for ListUsers: {e}");
            internal_failure()
        })?;
        sql.push(" AND user_name_lower >= ");
        sql.push_bind(info.next_user_name);
    }

    // Request one more than max_items so we can determine if there are more results.
    sql.push(" ORDER BY user_name_lower ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListUsersRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch users from database: {e}");
        internal_failure()
    })?;
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
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token for ListUsers: {e}");
                        internal_failure()
                    })?,
            );
            break;
        }

        let arn = Arn::builder()
            .partition(partition.clone())
            .service("iam")
            .account_id(account_id)
            .resource(format!("user/{}", row.user_name_cased))
            .build()
            .map_err(|e| {
                log::error!("Failed to construct ARN for user: {e}");
                internal_failure()
            })?;

        let permissions_boundary = if let Some(pb_id) = row.permissions_boundary_managed_policy_id {
            // FIXME: The ARN here is incorrect; we need to translate the managed policy ID back into
            // its path and name.
            log::warn!(
                "Permissions boundary ARN for user is incorrect because we don't have the policy name and path available"
            );
            let arn = format!("arn:{partition}:{SERVICE_KEY_IAM}::{account_id}:{ARN_RESOURCE_TYPE_POLICY}/{pb_id}");
            Some(
                AttachedPermissionsBoundary::builder()
                    .permissions_boundary_arn(arn)
                    .permissions_boundary_type(PermissionsBoundaryAttachmentType::Policy)
                    .build()
                    .map_err(|e| {
                        log::error!("Failed to construct permissions boundary for user: {e}");
                        internal_failure()
                    })?,
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
                .map_err(|e| {
                    log::error!("Failed to construct user object: {e}");
                    internal_failure()
                })?,
        );
    }

    let mut builder = ListUsersResponse::builder();
    builder = builder.set_users(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(true).marker(next_marker);
    }

    builder.build().map_err(|e| {
        log::error!("Failed to build ListUsersResponse: {e}");
        internal_failure().into()
    })
}
