//! GetRole database operation
use {
    crate::{
        RequestExecutor,
        constants::iam::*,
        iam::{
            build_policy_arn, get_current_partition_or_fail, internal_failure, role_arn_resource, validate_account_id,
            validate_role_name,
        },
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{GetRoleInternalRequest, GetRoleResponse},
        types::{
            AttachedPermissionsBoundary, PermissionsBoundaryAttachmentType, Role, Tag, error::NoSuchEntityException,
        },
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for GetRoleInternalRequest {
    type Response = GetRoleResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        get_role(tx, &self.account_id, &self.role_name).await
    }
}

/// Get a role from the database, including its tags, permissions boundary, and trust policy.
pub async fn get_role(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
) -> Result<GetRoleResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name)?;
    let role_name_lower = role_name.to_lowercase();

    let partition = get_current_partition_or_fail(tx).await?;

    let row = query(indoc! {"
            SELECT role_id, role_name_cased, path, permissions_boundary_managed_policy_id,
                description, assume_role_policy_document, max_session_duration, created_at
            FROM iam.roles
            WHERE account_id = $1 AND role_name_lower = $2
        "})
    .bind(account_id)
    .bind(&role_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch role from database: {e}");
        internal_failure()
    })?;

    let row = row.ok_or_else(|| {
        NoSuchEntityException::builder().message(format!("The role with name {role_name} cannot be found.")).build()
    })?;

    let role_id: String = row.get(0);
    let role_name_cased: String = row.get(1);
    let path: String = row.get(2);
    let permissions_boundary_id: Option<String> = row.get(3);
    let description: Option<String> = row.get(4);
    let assume_role_policy_document: String = row.get(5);
    let max_session_duration: Option<i32> = row.get(6);
    let created_at: DateTime<Utc> = row.get(7);

    let arn = Arn::builder()
        .partition(partition.clone())
        .service(SERVICE_KEY_IAM)
        .account_id(account_id)
        .resource(role_arn_resource(&path, &role_name_cased))
        .build()
        .map_err(|e| {
            log::error!("Failed to construct ARN for role: {e}");
            internal_failure()
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
            internal_failure()
        })?;

        let pb_row = pb_row.ok_or_else(|| {
            log::error!("Role references missing permissions boundary managed policy ID: {pb_id}");
            internal_failure()
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
                    log::error!("Failed to construct permissions boundary for role: {e}");
                    internal_failure()
                })?,
        )
    } else {
        None
    };

    let tag_rows = query(indoc! {"
            SELECT key_cased, value
            FROM iam.role_tags
            WHERE role_id = $1
            ORDER BY key_lower ASC
        "})
    .bind(&role_id)
    .fetch_all(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch role tags from database: {e}");
        internal_failure()
    })?;

    let mut tags = Vec::with_capacity(tag_rows.len());
    for tag_row in tag_rows {
        let key: String = tag_row.get(0);
        let value: String = tag_row.get(1);
        tags.push(Tag::builder().key(key).value(value).build().map_err(|e| {
            log::error!("Failed to construct tag object: {e}");
            internal_failure()
        })?);
    }

    let role = Role::builder()
        .arn(arn.to_string())
        .assume_role_policy_document(Some(assume_role_policy_document))
        .create_date(created_at)
        .description(description)
        .max_session_duration(max_session_duration)
        .path(path)
        .permissions_boundary(permissions_boundary)
        .role_id(format!("{}{}", IamResourceType::Role.as_str(), role_id))
        .role_name(role_name_cased)
        .tags(tags)
        .build()
        .map_err(|e| {
            log::error!("Failed to construct role object: {e}");
            internal_failure()
        })?;

    GetRoleResponse::builder().role(role).build().map_err(|e| {
        log::error!("Failed to construct get role response object: {e}");
        internal_failure().into()
    })
}
