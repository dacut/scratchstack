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
        tag::{validate_tag_key, validate_tag_value},
        user::{user_arn_resource, validate_user_name},
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    log::error,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{CreateUserInternalRequest, CreateUserResponse},
        types::{AttachedPermissionsBoundary, PermissionsBoundaryAttachmentType, Tag, User},
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
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
            error!("Failed to insert user into database: {e}");
            return Err(internal_failure().into());
        }
    };
    let created_at: DateTime<Utc> = match result.try_get(0) {
        Ok(created_at) => created_at,
        Err(e) => {
            error!("Failed to get created_at from database row: {e}");
            return Err(internal_failure().into());
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
            error!("Failed to insert user tag into database: {e}");
            return Err(internal_failure().into());
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
            error!("Failed to construct ARN for new user: {e}");
            return Err(internal_failure().into());
        }
    };

    let permissions_boundary = if let Some(pb) = permissions_boundary {
        Some(
            AttachedPermissionsBoundary::builder()
                .permissions_boundary_arn(pb)
                .permissions_boundary_type(PermissionsBoundaryAttachmentType::Policy)
                .build()
                .map_err(|e| {
                    error!("Failed to construct AttachedPermissionsBoundary: {e}");
                    internal_failure()
                })?,
        )
    } else {
        None
    };

    let user = User::builder()
        .arn(arn)
        .create_date(created_at)
        .path(path)
        .set_tags(tags)
        .user_id(user_id)
        .user_name(user_name.to_string())
        .set_permissions_boundary(permissions_boundary)
        .build()
        .map_err(|e| {
            error!("Failed to construct User: {e}");
            internal_failure()
        })?;

    Ok(CreateUserResponse::builder().user(user).build().map_err(|e| {
        error!("Failed to construct CreateUserResponse: {e}");
        internal_failure()
    })?)
}
