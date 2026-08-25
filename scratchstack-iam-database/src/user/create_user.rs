//! CreateUser database operation
use {
    crate::{
        RequestExecutor,
        account::validate_account_id,
        constants::*,
        id::IamId,
        internal_failure,
        partition::get_current_partition_or_fail,
        path::validate_path,
        policy::get_permissions_boundary_id,
        tag::{validate_tag_key, validate_tag_keys_unique, validate_tag_value},
        user::{is_user_name_unique_violation, user_arn_resource, validate_user_name},
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{CreateUserInternalRequest, CreateUserResponse},
        types::{
            AttachedPermissionsBoundary, PermissionsBoundaryAttachmentType, Tag, User,
            error::EntityAlreadyExistsException,
        },
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for CreateUserInternalRequest {
    type Response = CreateUserResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        create_user(
            tx,
            &self.account_id,
            &self.user_name,
            self.path.as_deref(),
            self.permissions_boundary.as_deref(),
            &self.tags,
            request_id,
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
    request_id: RequestId,
) -> Result<CreateUserResponse, IamError> {
    validate_account_id(account_id, request_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let path = path.unwrap_or("/");
    validate_path(path, request_id)?;
    validate_user_name(user_name, request_id)?;

    for tag in tags {
        validate_tag_key(&tag.key, request_id)?;
        validate_tag_value(&tag.value, request_id)?;
    }

    // Two tags with the same key would collide on the user_tags primary key, which is keyed on the
    // lower-cased key. That is the caller asking for two values for one tag, so reject it here
    // rather than letting the insert below fail as though something had gone wrong on our side.
    validate_tag_keys_unique(tags.iter().map(|tag| tag.key.as_str()), request_id)?;

    // Generate a new user id for this user.
    let user_id = IamId::new(IamResourceType::User, account_id.parse().unwrap()).to_string();
    let partition = get_current_partition_or_fail(tx, request_id).await?;

    // If a permissions boundary was specified, look it up and verify that it exists. We need the actual IAM
    // identifier for the boundary, not just the ARN.
    let permissions_boundary_id = if let Some(permissions_boundary) = permissions_boundary {
        Some(get_permissions_boundary_id(tx, account_id, permissions_boundary, request_id).await?)
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
            // Only a violation of the user-name constraint means the account already has a user
            // with this name; names are compared case-insensitively, so the collision is on the
            // lower-cased name rather than the one the caller spelled. The table can also raise a
            // unique violation on the user_id primary key, which is a generated-id collision
            // rather than anything the caller did, and falls through to the internal failure
            // below.
            if is_user_name_unique_violation(&e) {
                let message = format!("User with name {user_name} already exists.");
                return Err(EntityAlreadyExistsException::builder()
                    .message(message)
                    .request_id(request_id)
                    .build()
                    .into());
            }
            log::error!("Failed to insert user into database: {e}");
            return Err(internal_failure(request_id).into());
        }
    };
    let created_at: DateTime<Utc> = match result.try_get(0) {
        Ok(created_at) => created_at,
        Err(e) => {
            log::error!("Failed to get created_at from database row: {e}");
            return Err(internal_failure(request_id).into());
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
            return Err(internal_failure(request_id).into());
        }
    }

    let arn = match Arn::builder()
        .partition(partition)
        .service(SERVICE_KEY_IAM)
        .account_id(account_id)
        .resource(user_arn_resource(path, user_name))
        .build()
    {
        Ok(arn) => arn,
        Err(e) => {
            log::error!("Failed to construct ARN for new user: {e}");
            return Err(internal_failure(request_id).into());
        }
    };

    let permissions_boundary = if let Some(pb) = permissions_boundary {
        Some(
            AttachedPermissionsBoundary::builder()
                .permissions_boundary_arn(pb.to_string())
                .permissions_boundary_type(PermissionsBoundaryAttachmentType::Policy)
                .build()
                .map_err(|e| {
                    log::error!("Failed to construct permissions boundary for new user: {e}");
                    internal_failure(request_id)
                })?,
        )
    } else {
        None
    };

    let user = User::builder()
        .arn(arn.to_string())
        .create_date(created_at)
        .path(path.to_string())
        .set_tags(tags.to_vec())
        .user_id(user_id)
        .user_name(user_name.to_string())
        .set_permissions_boundary(permissions_boundary)
        .build()
        .map_err(|e| {
            log::error!("Failed to construct user object for new user: {e}");
            internal_failure(request_id)
        })?;

    Ok(CreateUserResponse::builder().user(user).build().unwrap())
}
