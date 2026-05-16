//! User database level operations.
use {
    crate::{
        constants::iam::*,
        model::iam::IamId,
        ops::{
            RequestExecutor,
            iam::{
                constrain_max_items, get_current_partition_or_fail, get_permissions_boundary_id, validate_account_id,
                validate_path, validate_path_prefix, validate_tag_key, validate_tag_value, validate_user_name,
            },
        },
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_pagination::{OperationPaginator, ScratchstackOperationMetadata, ScratchstackServiceMetadata},
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreateUserInternalRequest, CreateUserResponse, DeleteUserInternalRequest, ListUserTagsInternalRequest,
            ListUserTagsResponse, ListUsersInternalRequest, ListUsersResponse, TagUserInternalRequest,
            UntagUserInternalRequest, UpdateUserInternalRequest,
        },
        types::{
            AttachedPermissionsBoundary, PermissionsBoundaryAttachmentType, Tag, User,
            error::{InternalFailure, NoSuchEntityException, ValidationError},
        },
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for CreateUserInternalRequest {
    type Response = CreateUserResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        create_user(
            tx,
            &self.account_id,
            &self.user_name,
            self.path.as_deref(),
            self.permissions_boundary.as_deref(),
            &self.tags,
        )
        .await
    }
}

/// Create a new user on the database.
pub async fn create_user(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    path: Option<&str>,
    permissions_boundary: Option<&str>,
    tags: &[Tag],
) -> Result<CreateUserResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let path = path.unwrap_or("/");
    validate_path(path)?;
    validate_user_name(user_name)?;

    for tag in tags {
        validate_tag_key(&tag.key)?;
        validate_tag_value(&tag.value)?;
    }

    // Generate a new user id for this user.
    let user_id = IamId::new(IamResourceType::User, account_id.parse().unwrap()).to_string();
    let partition = get_current_partition_or_fail(tx).await?;

    // If a permissions boundary was specified, look it up and verify that it exists. We need the actual IAM
    // identifier for the boundary, not just the ARN.
    let permissions_boundary_id = if let Some(permissions_boundary) = permissions_boundary {
        Some(get_permissions_boundary_id(tx, account_id, permissions_boundary).await?)
    } else {
        None
    };

    let result = match query(indoc! {"
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
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to insert user into database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };
    let created_at: chrono::DateTime<chrono::Utc> = match result.try_get(0) {
        Ok(created_at) => created_at,
        Err(e) => {
            log::error!("Failed to get created_at from database row: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    for tag in tags {
        let key_cased = tag.key.as_str();
        let key_lower = key_cased.to_ascii_lowercase();
        let value = tag.value.as_str();

        if let Err(e) = query(indoc! {"
                INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value)
                VALUES($1, $2, $3, $4)
            "})
        .bind(user_id[4..].to_string())
        .bind(key_lower)
        .bind(key_cased)
        .bind(value)
        .execute(tx.as_mut())
        .await
        {
            log::error!("Failed to insert user tag into database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    }

    let arn = match Arn::builder()
        .partition(partition)
        .service(SERVICE_KEY_IAM)
        .account_id(account_id)
        .resource(format!("{ARN_RESOURCE_PREFIX_USER}{user_name}"))
        .build()
    {
        Ok(arn) => arn,
        Err(e) => {
            log::error!("Failed to construct ARN for new user: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    let permissions_boundary = if let Some(pb) = permissions_boundary {
        Some(
            AttachedPermissionsBoundary::builder()
                .permissions_boundary_arn(Some(pb.to_string()))
                .permissions_boundary_type(Some(PermissionsBoundaryAttachmentType::Policy))
                .build()
                .map_err(|e| {
                    log::error!("Failed to construct permissions boundary for new user: {e}");
                    InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
                })?,
        )
    } else {
        None
    };

    let user = User::builder()
        .arn(arn.to_string())
        .create_date(created_at)
        .path(path.to_string())
        .tags(tags.to_vec())
        .user_id(user_id)
        .user_name(user_name.to_string())
        .permissions_boundary(permissions_boundary)
        .build()
        .map_err(|e| {
            log::error!("Failed to construct user object for new user: {e}");
            InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
        })?;

    Ok(CreateUserResponse::builder().user(Some(user)).build().unwrap())
}

impl RequestExecutor for DeleteUserInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        delete_user(tx, &self.account_id, &self.user_name).await
    }
}

/// Delete a user from the database.
pub async fn delete_user(tx: &mut PgTransaction<'_>, account_id: &str, user_name: &str) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;

    let result = match query(indoc! {"
            DELETE FROM iam.users
            WHERE account_id = $1 AND user_name_lower = $2
        "})
    .bind(account_id)
    .bind(user_name.to_lowercase())
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to delete user from database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if result.rows_affected() == 0 {
        Err(NoSuchEntityException::builder()
            .message(format!("The user with name {user_name} cannot be found."))
            .build()
            .into())
    } else {
        Ok(())
    }
}

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

    // Create the paginator for this operation.
    let service_metadata = ScratchstackServiceMetadata::new(partition.clone(), "", SERVICE_ID_IAM);
    let operation_metadata = ScratchstackOperationMetadata::new(IAM_API_VERSION, OP_LIST_USERS);
    let paginator =
        OperationPaginator::new_fixed_key(&service_metadata, &operation_metadata, PAGINATION_KEY_ID, *PAGINATION_KEY)
            .map_err(|e| {
            log::error!("Failed to create paginator for ListUsers: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;

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
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;
        sql.push(" AND user_name_lower >= ");
        sql.push_bind(info.next_user_name);
    }

    // Request one more than max_items so we can determine if there are more results.
    sql.push(" ORDER BY user_name_lower ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListUsersRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch users from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
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
                        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
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
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?;

        let permissions_boundary = if let Some(pb_id) = row.permissions_boundary_managed_policy_id {
            // FIXME: The ARN here is incorrect; we need to translate the managed policy ID back into
            // its path and name.
            log::warn!(
                "Permissions boundary ARN for user is incorrect because we don't have the policy name and path available"
            );
            let arn = format!("arn:{partition}:{SERVICE_KEY_IAM}::{account_id}:{ARN_RESOURCE_PREFIX_POLICY}{pb_id}");
            Some(
                AttachedPermissionsBoundary::builder()
                    .permissions_boundary_arn(Some(arn))
                    .permissions_boundary_type(Some(PermissionsBoundaryAttachmentType::Policy))
                    .build()
                    .map_err(|e| {
                        log::error!("Failed to construct permissions boundary for user: {e}");
                        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
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
                .permissions_boundary(permissions_boundary)
                .build()
                .map_err(|e| {
                    log::error!("Failed to construct user object: {e}");
                    IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                })?,
        );
    }

    let mut builder = ListUsersResponse::builder();
    builder = builder.users(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(Some(true)).marker(Some(next_marker));
    }

    builder.build().map_err(|e| {
        log::error!("Failed to build ListUsersResponse: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })
}

impl RequestExecutor for ListUserTagsInternalRequest {
    type Response = ListUserTagsResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_user_tags(tx, &self.account_id, &self.user_name, self.marker.as_deref(), self.max_items).await
    }
}

/// The marker innards for a ListUserTags operation.
#[derive(Deserialize, Serialize)]
struct ListUserTagsMarker {
    next_key_lower: String,
}

/// The rows returned by the ListUserTags query.
#[derive(FromRow)]
struct ListUserTagsRow {
    key_cased: String,
    value: String,
}

/// List the tags for a user from the database.
pub async fn list_user_tags(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
) -> Result<ListUserTagsResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;
    let user_name_lower = user_name.to_lowercase();
    let max_items = constrain_max_items(max_items)?;
    let partition = get_current_partition_or_fail(tx).await?;

    let user_exists = query(indoc! {"
        SELECT 1
        FROM iam.users
        WHERE account_id = $1 AND user_name_lower = $2
        LIMIT 1
    "})
    .bind(account_id)
    .bind(&user_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to check if user exists in database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;
    if user_exists.is_none() {
        return Err(NoSuchEntityException::builder()
            .message(format!("The user with name {user_name} cannot be found."))
            .build()
            .into());
    }

    // Create the paginator for this operation.
    let service_metadata = ScratchstackServiceMetadata::new(partition.clone(), "", SERVICE_ID_IAM);
    let operation_metadata = ScratchstackOperationMetadata::new(IAM_API_VERSION, OP_LIST_USER_TAGS);
    let paginator =
        OperationPaginator::new_fixed_key(&service_metadata, &operation_metadata, PAGINATION_KEY_ID, *PAGINATION_KEY)
            .map_err(|e| {
            log::error!("Failed to create paginator for ListUserTags: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;

    let mut sql = QueryBuilder::new(
        r#"
        SELECT key_cased, value
        FROM iam.user_tags t
        INNER JOIN iam.users u
        ON t.user_id = u.user_id
        WHERE u.account_id =
        "#,
    );
    sql.push_bind(account_id);
    sql.push(" AND u.user_name_lower = ");
    sql.push_bind(user_name_lower);

    if let Some(marker) = marker {
        let m: ListUserTagsMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token for ListUserTags: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;
        sql.push(" AND t.key_lower >= ");
        sql.push_bind(m.next_key_lower);
    }

    // Request one more than max_items so we can determine if there are more results.
    sql.push(" ORDER BY t.key_lower ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListUserTagsRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch user tags from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;
    let mut results = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if results.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListUserTagsMarker {
                        next_key_lower: row.key_cased.to_lowercase(),
                    })
                    .await
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token for ListUserTags: {e}");
                        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                    })?,
            );
            break;
        }

        results.push(Tag::builder().key(row.key_cased).value(row.value).build().map_err(|e| {
            log::error!("Failed to construct tag object: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?);
    }

    let mut builder = ListUserTagsResponse::builder();
    builder = builder.tags(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(Some(true)).marker(Some(next_marker));
    }

    builder.build().map_err(|e| {
        log::error!("Failed to build ListUserTagsResponse: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })
}

impl RequestExecutor for TagUserInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        tag_user(tx, &self.account_id, &self.user_name, &self.tags).await
    }
}

/// Add or update tags on a user in the database.
pub async fn tag_user(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    tags: &[Tag],
) -> Result<(), IamError> {
    if tags.is_empty() {
        return Err(ValidationError::builder().message("At least one tag must be provided.").build().into());
    }

    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;

    for tag in tags {
        validate_tag_key(&tag.key)?;
        validate_tag_value(&tag.value)?;
    }

    // Verify the user exists and get the user_id.
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
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    for tag in tags {
        let key_cased = tag.key.as_str();
        let key_lower = key_cased.to_ascii_lowercase();
        let value = tag.value.as_str();

        if let Err(e) = query(indoc! {"
                INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value)
                VALUES($1, $2, $3, $4)
                ON CONFLICT (user_id, key_lower)
                DO UPDATE SET key_cased = EXCLUDED.key_cased, value = EXCLUDED.value
            "})
        .bind(&user_id)
        .bind(key_lower)
        .bind(key_cased)
        .bind(value)
        .execute(tx.as_mut())
        .await
        {
            log::error!("Failed to insert/update user tag in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    }

    Ok(())
}

impl RequestExecutor for UpdateUserInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        update_user(tx, &self.account_id, &self.user_name, self.new_user_name.as_deref(), self.new_path.as_deref())
            .await
    }
}

/// Update a user on the database.
pub async fn update_user(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    new_user_name: Option<&str>,
    new_path: Option<&str>,
) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;
    let user_name_lower = user_name.to_lowercase();

    let (new_user_name_cased, new_user_name_lower) = if let Some(new_user_name) = new_user_name {
        validate_user_name(new_user_name)?;
        (Some(new_user_name), Some(new_user_name.to_lowercase()))
    } else {
        (None, None)
    };

    if let Some(new_path) = new_path {
        validate_path(new_path)?;
    }

    let result = match query(indoc! {"
        UPDATE iam.users
        SET user_name_lower = COALESCE($3, user_name_lower),
            user_name_cased = COALESCE($4, user_name_cased),
            path = COALESCE($5, path)
        WHERE account_id = $1 AND user_name_lower = $2
    "})
    .bind(account_id)
    .bind(&user_name_lower)
    .bind(new_user_name_lower)
    .bind(new_user_name_cased)
    .bind(new_path)
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to update user in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if result.rows_affected() == 0 {
        Err(NoSuchEntityException::builder()
            .message(format!("The user with name {user_name} cannot be found."))
            .build()
            .into())
    } else {
        Ok(())
    }
}

impl RequestExecutor for UntagUserInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        untag_user(tx, &self.account_id, &self.user_name, &self.tag_keys).await
    }
}

/// Remove tags from a user in the database.
pub async fn untag_user(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    tag_keys: &[String],
) -> Result<(), IamError> {
    if tag_keys.is_empty() {
        return Err(ValidationError::builder().message("At least one tag key must be provided.").build().into());
    }

    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;

    for key in tag_keys {
        validate_tag_key(key)?;
    }

    // Verify the user exists and get the user_id.
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
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    for key in tag_keys {
        let key_lower = key.to_ascii_lowercase();

        if let Err(e) = query(indoc! {"
                DELETE FROM iam.user_tags
                WHERE user_id = $1 AND key_lower = $2
            "})
        .bind(&user_id)
        .bind(key_lower)
        .execute(tx.as_mut())
        .await
        {
            log::error!("Failed to delete user tag from database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    }

    Ok(())
}
