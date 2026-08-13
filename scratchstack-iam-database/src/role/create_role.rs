//! CreateRole databse operation
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
        role::{role_arn_resource, validate_role_name},
        tag::{validate_tag_key, validate_tag_value},
    },
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{CreateRoleInternalRequest, CreateRoleResponse},
        types::{AttachedPermissionsBoundary, PermissionsBoundaryAttachmentType, Role, Tag, error::ValidationError},
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for CreateRoleInternalRequest {
    type Response = CreateRoleResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        create_role(
            tx,
            &self.account_id,
            &self.role_name,
            &self.assume_role_policy_document,
            self.description.as_deref(),
            self.max_session_duration,
            self.path.as_deref(),
            self.permissions_boundary.as_deref(),
            &self.tags,
        )
        .await
    }
}

/// Create a new role on the database.
#[allow(clippy::too_many_arguments)]
pub async fn create_role(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
    assume_role_policy_document: &str,
    description: Option<&str>,
    max_session_duration: Option<i32>,
    path: Option<&str>,
    permissions_boundary: Option<&str>,
    tags: &[Tag],
) -> Result<CreateRoleResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let path = path.unwrap_or("/");
    validate_path(path)?;
    validate_role_name(role_name)?;
    if let Some(max_session_duration) = max_session_duration
        && (max_session_duration < 3600 || max_session_duration > 43200)
    {
        let message = "Maximum session duration must be between 3600 and 43200 seconds.".to_string();
        return Err(ValidationError::builder().message(message).build().into());
    }

    for tag in tags {
        validate_tag_key(&tag.key)?;
        validate_tag_value(&tag.value)?;
    }

    // Generate a new role id for this role.
    let role_id = IamId::new(IamResourceType::Role, account_id.parse().unwrap()).to_string();
    let partition = get_current_partition_or_fail(tx).await?;

    // If a permissions boundary was specified, look it up and verify that it exists.
    let permissions_boundary_id = if let Some(permissions_boundary) = permissions_boundary {
        Some(get_permissions_boundary_id(tx, account_id, permissions_boundary).await?)
    } else {
        None
    };

    let result = match query(indoc! {"
            INSERT INTO iam.roles(
                account_id, role_id, path, role_name_lower, role_name_cased,
                permissions_boundary_managed_policy_id, description, assume_role_policy_document,
                max_session_duration)
            VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING created_at
        "})
    .bind(account_id)
    .bind(role_id[4..].to_string())
    .bind(path)
    .bind(role_name.to_ascii_lowercase())
    .bind(role_name)
    .bind(permissions_boundary_id)
    .bind(description)
    .bind(assume_role_policy_document)
    .bind(max_session_duration)
    .fetch_one(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to insert role into database: {e}");
            return Err(internal_failure().into());
        }
    };
    let created_at: chrono::DateTime<chrono::Utc> = match result.try_get(0) {
        Ok(created_at) => created_at,
        Err(e) => {
            log::error!("Failed to get created_at from database row: {e}");
            return Err(internal_failure().into());
        }
    };

    for tag in tags {
        let key_cased = tag.key.as_str();
        let key_lower = key_cased.to_ascii_lowercase();
        let value = tag.value.as_str();

        if let Err(e) = query(indoc! {"
                INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value)
                VALUES($1, $2, $3, $4)
            "})
        .bind(role_id[4..].to_string())
        .bind(key_lower)
        .bind(key_cased)
        .bind(value)
        .execute(tx.as_mut())
        .await
        {
            log::error!("Failed to insert role tag into database: {e}");
            return Err(internal_failure().into());
        }
    }

    let arn = match Arn::builder()
        .partition(partition)
        .service(SERVICE_KEY_IAM)
        .account_id(account_id)
        .resource(role_arn_resource(path, role_name))
        .build()
    {
        Ok(arn) => arn,
        Err(e) => {
            log::error!("Failed to construct ARN for new role: {e}");
            return Err(internal_failure().into());
        }
    };

    let permissions_boundary = if let Some(pb) = permissions_boundary {
        Some(
            AttachedPermissionsBoundary::builder()
                .permissions_boundary_arn(pb.to_string())
                .permissions_boundary_type(PermissionsBoundaryAttachmentType::Policy)
                .build()
                .map_err(|e| {
                    log::error!("Failed to construct permissions boundary for new role: {e}");
                    internal_failure()
                })?,
        )
    } else {
        None
    };

    let role = Role::builder()
        .arn(arn.to_string())
        .assume_role_policy_document(assume_role_policy_document.to_string())
        .create_date(created_at)
        .set_description(description.map(|d| d.to_string()))
        .set_max_session_duration(max_session_duration)
        .path(path.to_string())
        .set_permissions_boundary(permissions_boundary)
        .role_id(role_id)
        .role_name(role_name.to_string())
        .set_tags(tags.to_vec())
        .build()
        .map_err(|e| {
            log::error!("Failed to construct role object for new role: {e}");
            internal_failure()
        })?;

    Ok(CreateRoleResponse::builder().role(role).build().unwrap())
}
