//! GetUser database operation
use {
    crate::{
        constants::iam::*,
        ops::{
            RequestExecutor,
            iam::{
                build_policy_arn, get_current_partition_or_fail, user::user_arn_resource, validate_account_id,
                validate_user_name,
            },
        },
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{GetUserInternalRequest, GetUserResponse},
        types::{
            AttachedPermissionsBoundary, PermissionsBoundaryAttachmentType, Tag, User,
            error::{InternalFailure, NoSuchEntityException, ValidationError},
        },
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for GetUserInternalRequest {
    type Response = GetUserResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        get_user(tx, &self.account_id, self.user_name.as_deref()).await
    }
}

/// Get a user from the database.
pub async fn get_user(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: Option<&str>,
) -> Result<GetUserResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };

    let user_name = user_name.ok_or_else(|| {
        // If no user name is provided, this would normally default to the calling user,
        // but at the database level we require it.
        IamError::from(ValidationError::builder().message("UserName is required").build())
    })?;
    validate_user_name(user_name)?;
    let user_name_lower = user_name.to_lowercase();

    let partition = get_current_partition_or_fail(tx).await?;

    let row = query(indoc! {"
            SELECT user_id, user_name_cased, path, permissions_boundary_managed_policy_id, created_at
            FROM iam.users
            WHERE account_id = $1 AND user_name_lower = $2
        "})
    .bind(account_id)
    .bind(&user_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch user from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    let row = row.ok_or_else(|| {
        IamError::from(
            NoSuchEntityException::builder()
                .message(format!("The user with name {user_name} cannot be found."))
                .build(),
        )
    })?;

    let user_id: String = row.get(0);
    let user_name_cased: String = row.get(1);
    let path: String = row.get(2);
    let permissions_boundary_id: Option<String> = row.get(3);
    let created_at: DateTime<Utc> = row.get(4);

    let arn = Arn::builder()
        .partition(partition.clone())
        .service(SERVICE_KEY_IAM)
        .account_id(account_id)
        .resource(user_arn_resource(&path, &user_name_cased))
        .build()
        .map_err(|e| {
            log::error!("Failed to construct ARN for user: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;

    let permissions_boundary = if let Some(pb_id) = permissions_boundary_id {
        let pb_row = query(indoc! {"
                SELECT path, managed_policy_name_cased
                FROM iam.managed_policies
                WHERE managed_policy_id = $1
            "})
        .bind(&pb_id)
        .fetch_optional(tx.as_mut())
        .await
        .map_err(|e| {
            log::error!("Failed to fetch permissions boundary managed policy from database: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;

        let pb_row = pb_row.ok_or_else(|| {
            log::error!("User references missing permissions boundary managed policy ID: {pb_id}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;

        let pb_path: String = pb_row.get(0);
        let pb_name_cased: String = pb_row.get(1);
        let pb_arn = build_policy_arn(&partition, account_id, &pb_path, &pb_name_cased)?;

        Some(
            AttachedPermissionsBoundary::builder()
                .permissions_boundary_arn(Some(pb_arn.to_string()))
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

    // Fetch tags for this user.
    let tag_rows = query(indoc! {"
            SELECT key_cased, value
            FROM iam.user_tags
            WHERE user_id = $1
            ORDER BY key_lower ASC
        "})
    .bind(&user_id)
    .fetch_all(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch user tags from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    let mut tags = Vec::with_capacity(tag_rows.len());
    for tag_row in tag_rows {
        let key: String = tag_row.get(0);
        let value: String = tag_row.get(1);
        tags.push(Tag::builder().key(key).value(value).build().map_err(|e| {
            log::error!("Failed to construct tag object: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?);
    }

    let user = User::builder()
        .arn(arn.to_string())
        .create_date(created_at)
        .path(path)
        .tags(tags)
        .user_id(format!("{}{}", IamResourceType::User.as_str(), user_id))
        .user_name(user_name_cased)
        .permissions_boundary(permissions_boundary)
        .build()
        .map_err(|e| {
            log::error!("Failed to construct user object: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;

    Ok(GetUserResponse::builder().user(user).build().unwrap())
}
