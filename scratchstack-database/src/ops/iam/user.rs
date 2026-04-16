//! User database level operations.

use {
    crate::{
        constants::iam::*,
        model::iam::IamId,
        ops::{RequestExecutor, iam::get_current_partition_or_fail},
    },
    anyhow::{Result as AnyResult, anyhow, bail},
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_pagination::{OperationPaginator, ScratchstackOperationMetadata, ScratchstackServiceMetadata},
    scratchstack_shapes::iam::{
        AttachedPermissionsBoundary, CreateUserInternalRequest, CreateUserResponse, ListUsersInternalRequest,
        ListUsersResponse, PermissionsBoundaryType, Tag, User,
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for CreateUserInternalRequest {
    type Response = CreateUserResponse;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> anyhow::Result<Self::Response> {
        create_user(tx, self.account_id(), self.user_name(), self.path(), self.permissions_boundary(), self.tags())
            .await
    }
}

/// Create a new user on the database.
pub async fn create_user(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    path: &str,
    permissions_boundary: Option<&Arn>,
    tags: &[Tag],
) -> AnyResult<CreateUserResponse> {
    let partition = get_current_partition_or_fail(tx).await?;

    // If a permissions boundary was specified, look it up and verify that it exists. We need the actual IAM
    // identifier for the boundary, not just the ARN.
    let permissions_boundary_id = if let Some(permissions_boundary) = permissions_boundary {
        let resource = permissions_boundary.resource();
        if !resource.starts_with(ARN_RESOURCE_PREFIX_POLICY) {
            bail!("Permissions boundary ARN must have a resource that starts with \"policy/\"");
        }

        let account_id = match account_id {
            AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
            account_id => account_id,
        };
        let policy_path_and_name = &resource[6..];
        let name_start = policy_path_and_name.rfind('/').map(|i| i + 1).unwrap_or(0);
        let policy_path = &policy_path_and_name[..name_start];
        let policy_name = policy_path_and_name[name_start..].to_ascii_lowercase();
        let results = query(indoc! {"
                SELECT managed_policy_id
                FROM iam.managed_policies
                WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
            "})
        .bind(account_id)
        .bind(policy_path)
        .bind(policy_name)
        .fetch_all(tx.as_mut())
        .await?;
        if results.is_empty() {
            bail!("Permissions boundary policy does not exist");
        }
        if results.len() > 1 {
            bail!(
                "Multiple permissions boundary policies found with the same name and path; this is a database integrity error"
            );
        }

        let mp_id: &str = results[0].try_get(0)?;
        Some(mp_id.to_string())
    } else {
        None
    };

    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let user_id = IamId::new(IamResourceType::User, account_id.parse().unwrap()).to_string();

    let result = query(indoc! {"
            INSERT INTO iam.users(
                account_id, user_id, path, user_name_lower, user_name_cased,
                permissions_boundary_managed_policy_id)
            VALUES($1, $2, $3, $4, $5, $6)
            RETURNING created_at
        "})
    .bind(account_id)
    .bind(user_id[4..].to_string())
    .bind(path)
    .bind(user_name.to_ascii_lowercase())
    .bind(user_name)
    .bind(permissions_boundary_id)
    .fetch_one(tx.as_mut())
    .await?;
    let created_at: chrono::DateTime<chrono::Utc> = result.try_get(0)?;

    for tag in tags {
        let key_cased = tag.key();
        let key_lower = key_cased.to_ascii_lowercase();
        let value = tag.value();

        query(indoc! {"
                INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value)
                VALUES($1, $2, $3, $4)
            "})
        .bind(user_id[4..].to_string())
        .bind(key_lower)
        .bind(key_cased)
        .bind(value)
        .execute(tx.as_mut())
        .await?;
    }

    let arn = Arn::builder()
        .partition(partition)
        .service(SERVICE_KEY_IAM)
        .account_id(account_id)
        .resource(format!("{ARN_RESOURCE_PREFIX_USER}{user_name}"))
        .build()?;

    let permissions_boundary = if let Some(pb) = permissions_boundary {
        Some(
            AttachedPermissionsBoundary::builder()
                .permissions_boundary_arn(pb.clone())
                .permissions_boundary_type(PermissionsBoundaryType::Policy)
                .build()?,
        )
    } else {
        None
    };

    let user = User::builder()
        .arn(arn)
        .create_date(created_at)
        .path(path)
        .user_id(user_id)
        .user_name(user_name)
        .permissions_boundary(permissions_boundary)
        .build()?;

    Ok(CreateUserResponse::builder().user(user).build()?)
}

impl RequestExecutor for ListUsersInternalRequest {
    type Response = ListUsersResponse;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> AnyResult<Self::Response> {
        list_users(tx, self.account_id(), self.marker(), self.max_items(), self.path_prefix()).await
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
    max_items: Option<usize>,
    path_prefix: Option<&str>,
) -> AnyResult<ListUsersResponse> {
    let partition = get_current_partition_or_fail(tx).await?;

    // Create the paginator for this operation.
    let service_metadata = ScratchstackServiceMetadata::new(partition.clone(), "", SERVICE_ID_IAM);
    let operation_metadata = ScratchstackOperationMetadata::new(IAM_API_VERSION, OP_LIST_USERS);
    let paginator =
        OperationPaginator::new_fixed_key(&service_metadata, &operation_metadata, PAGINATION_KEY_ID, *PAGINATION_KEY)
            .map_err(|e| anyhow!("Failed to create paginator for ListUsers: {e}"))?;

    let max_items = max_items.unwrap_or(100).clamp(1, 1000);

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
        let info: ListUsersMarker = paginator
            .decrypt_token(marker)
            .await
            .map_err(|e| anyhow!("Failed to decrypt pagination token for ListUsers: {e}"))?;
        sql.push(" AND user_name_lower >= ");
        sql.push_bind(info.next_user_name);
    }

    // Request one more than max_items so we can determine if there are more results.
    sql.push(" ORDER BY user_name_lower ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListUsersRow>().fetch_all(tx.as_mut()).await?;
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
                    .map_err(|e| anyhow!("Failed to encrypt pagination token for ListUsers: {e}"))?,
            );
            break;
        }

        let arn = Arn::builder()
            .partition(partition.clone())
            .service("iam")
            .account_id(account_id)
            .resource(format!("user/{}", row.user_name_cased))
            .build()?;

        let permissions_boundary = if let Some(pb_id) = row.permissions_boundary_managed_policy_id {
            // FIXME: The ARN here is incorrect; we need to translate the managed policy ID back into
            // its path and name.
            log::warn!(
                "Permissions boundary ARN for user {} is incorrect because we don't have the policy name and path available",
                row.user_name_cased
            );
            Some(
                AttachedPermissionsBoundary::builder()
                    .permissions_boundary_arn(
                        Arn::builder()
                            .partition(partition.clone())
                            .service(SERVICE_KEY_IAM)
                            .account_id(account_id)
                            .resource(format!("{ARN_RESOURCE_PREFIX_POLICY}{pb_id}"))
                            .build()?,
                    )
                    .permissions_boundary_type(PermissionsBoundaryType::Policy)
                    .build()?,
            )
        } else {
            None
        };

        results.push(
            User::builder()
                .arn(arn)
                .create_date(row.created_at)
                .path(row.path)
                .user_id(format!("{}{}", IamResourceType::User.as_str(), row.user_id))
                .user_name(row.user_name_cased)
                .permissions_boundary(permissions_boundary)
                .build()?,
        );
    }

    let mut builder = ListUsersResponse::builder();
    builder.users(results);
    if let Some(next_marker) = next_marker {
        builder.is_truncated(true).marker(Some(next_marker));
    }

    Ok(builder.build()?)
}
