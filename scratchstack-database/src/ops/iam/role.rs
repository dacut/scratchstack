//! Role database level operations.
use {
    crate::{
        constants::iam::*,
        model::iam::IamId,
        ops::{
            RequestExecutor,
            iam::{
                build_policy_arn, constrain_max_items, get_current_partition_or_fail, get_permissions_boundary_id,
                make_paginator, parse_policy_arn, validate_account_id, validate_path, validate_path_prefix,
                validate_role_name, validate_tag_key, validate_tag_value,
            },
        },
    },
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            AttachRolePolicyInternalRequest, CreateRoleInternalRequest, CreateRoleResponse, DeleteRoleInternalRequest,
            DetachRolePolicyInternalRequest, ListAttachedRolePoliciesInternalRequest, ListAttachedRolePoliciesResponse,
        },
        types::{
            AttachedPermissionsBoundary, AttachedPolicy, PermissionsBoundaryAttachmentType, Role, Tag,
            error::{DeleteConflictException, InternalFailure, NoSuchEntityException, ValidationError},
        },
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, Row as _, postgres::PgTransaction, query, query_as},
};

impl RequestExecutor for AttachRolePolicyInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        attach_role_policy(tx, &self.account_id, &self.role_name, &self.policy_arn).await
    }
}

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
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
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
                    log::error!("Failed to construct permissions boundary for new role: {e}");
                    InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
                })?,
        )
    } else {
        None
    };

    let role = Role::builder()
        .arn(arn.to_string())
        .assume_role_policy_document(Some(assume_role_policy_document.to_string()))
        .create_date(created_at)
        .description(description.map(|d| d.to_string()))
        .max_session_duration(max_session_duration)
        .path(path.to_string())
        .permissions_boundary(permissions_boundary)
        .role_id(role_id)
        .role_name(role_name.to_string())
        .tags(tags.to_vec())
        .build()
        .map_err(|e| {
            log::error!("Failed to construct role object for new role: {e}");
            InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
        })?;

    Ok(CreateRoleResponse::builder().role(role).build().unwrap())
}

fn role_arn_resource(path: &str, role_name: &str) -> String {
    let resource_path = path.trim_matches('/');
    if resource_path.is_empty() {
        format!("{ARN_RESOURCE_PREFIX_ROLE}{role_name}")
    } else {
        format!("{ARN_RESOURCE_PREFIX_ROLE}{resource_path}/{role_name}")
    }
}

/// Attach a managed policy to a role in the database.
pub async fn attach_role_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
    policy_arn: &str,
) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name)?;

    let parts = parse_policy_arn(policy_arn)?;
    if parts.account_id != account_id && parts.account_id != AWS_ACCOUNT_ID_NUMERIC {
        return Err(NoSuchEntityException::builder()
            .message(format!("Policy {policy_arn} was not found."))
            .build()
            .into());
    }

    // Look up the managed_policy_id.
    let managed_policy_id: String = match query(indoc! {"
            SELECT managed_policy_id
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(&parts.account_id)
    .bind(&parts.policy_path)
    .bind(&parts.policy_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("Policy {policy_arn} was not found."))
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up managed policy in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    // Look up the role_id.
    let role_id: String = match query(indoc! {"
            SELECT role_id
            FROM iam.roles
            WHERE account_id = $1 AND role_name_lower = $2
        "})
    .bind(account_id)
    .bind(role_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The role with name {role_name} cannot be found."))
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up role in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if let Err(e) = query(indoc! {"
            INSERT INTO iam.role_attached_policies(role_id, managed_policy_id)
            VALUES($1, $2)
            ON CONFLICT (role_id, managed_policy_id) DO NOTHING
        "})
    .bind(&role_id)
    .bind(&managed_policy_id)
    .execute(tx.as_mut())
    .await
    {
        log::error!("Failed to attach policy to role in database: {e}");
        return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
    }

    Ok(())
}

impl RequestExecutor for DeleteRoleInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        delete_role(tx, &self.account_id, &self.role_name).await
    }
}

/// Delete a role from the database. The role must have no attached managed policies and no inline
/// policies. Role tags are removed via FK cascade.
pub async fn delete_role(tx: &mut PgTransaction<'_>, account_id: &str, role_name: &str) -> Result<(), IamError> {
    /// The row returned by the lookup query against iam.roles.
    #[derive(FromRow)]
    struct RoleRow {
        role_id: String,
    }

    /// The row returned by the conflict-check aggregation. Each column counts one class of
    /// attachment that AWS requires to be cleared before DeleteRole succeeds.
    #[derive(FromRow)]
    struct ConflictCountsRow {
        attached_policies: i64,
        inline_policies: i64,
    }

    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name)?;

    // Lock the role row so a concurrent AttachRolePolicy / PutRolePolicy can't slip in between the
    // conflict checks and the DELETE.
    let role_row: RoleRow = match query_as(indoc! {"
            SELECT role_id
            FROM iam.roles
            WHERE account_id = $1 AND role_name_lower = $2
            FOR UPDATE
        "})
    .bind(account_id)
    .bind(role_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The role with name {role_name} cannot be found."))
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up role in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    let counts: ConflictCountsRow = match query_as(indoc! {"
            SELECT
                (SELECT COUNT(*) FROM iam.role_attached_policies WHERE role_id = $1)
                    AS attached_policies,
                (SELECT COUNT(*) FROM iam.role_inline_policies WHERE role_id = $1)
                    AS inline_policies
        "})
    .bind(&role_row.role_id)
    .fetch_one(tx.as_mut())
    .await
    {
        Ok(row) => row,
        Err(e) => {
            log::error!("Failed to query DeleteRole conflict counts from database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if counts.attached_policies > 0 {
        let message = format!(
            "Cannot delete role {role_name}: the role has {} attached managed policies. You must detach all managed policies before deleting the role.",
            counts.attached_policies
        );
        return Err(DeleteConflictException::builder().message(message).build().into());
    }

    if counts.inline_policies > 0 {
        let message = format!(
            "Cannot delete role {role_name}: the role has {} inline policies. You must delete all inline policies before deleting the role.",
            counts.inline_policies
        );
        return Err(DeleteConflictException::builder().message(message).build().into());
    }

    // FK cascade handles role_tags. The unchanged role_attached_policies / role_inline_policies
    // FKs act as a backstop: if a concurrent transaction managed to slip an attachment in despite
    // the FOR UPDATE row lock, the DELETE would fail with a FK violation rather than corrupt state.
    if let Err(e) = query(indoc! {"
            DELETE FROM iam.roles
            WHERE role_id = $1
        "})
    .bind(&role_row.role_id)
    .execute(tx.as_mut())
    .await
    {
        if let sqlx::Error::Database(db_err) = &e
            && db_err.code().as_deref() == Some("23503")
        {
            let message =
                format!("Cannot delete role {role_name} because it has attached managed policies or inline policies.");
            return Err(DeleteConflictException::builder().message(message).build().into());
        }

        log::error!("Failed to delete role from database: {e}");
        return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
    }

    Ok(())
}

impl RequestExecutor for DetachRolePolicyInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        detach_role_policy(tx, &self.account_id, &self.role_name, &self.policy_arn).await
    }
}

/// Detach a managed policy from a role in the database.
pub async fn detach_role_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
    policy_arn: &str,
) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name)?;

    let parts = parse_policy_arn(policy_arn)?;
    if parts.account_id != account_id && parts.account_id != AWS_ACCOUNT_ID_NUMERIC {
        return Err(NoSuchEntityException::builder()
            .message(format!("Policy {policy_arn} was not found."))
            .build()
            .into());
    }

    // Look up the managed_policy_id.
    let managed_policy_id: String = match query(indoc! {"
            SELECT managed_policy_id
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(&parts.account_id)
    .bind(&parts.policy_path)
    .bind(&parts.policy_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("Policy {policy_arn} was not found."))
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up managed policy in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    // Look up the role_id.
    let role_id: String = match query(indoc! {"
            SELECT role_id
            FROM iam.roles
            WHERE account_id = $1 AND role_name_lower = $2
        "})
    .bind(account_id)
    .bind(role_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The role with name {role_name} cannot be found."))
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up role in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    let result = match query(indoc! {"
            DELETE FROM iam.role_attached_policies
            WHERE role_id = $1 AND managed_policy_id = $2
        "})
    .bind(&role_id)
    .bind(&managed_policy_id)
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to detach policy from role in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if result.rows_affected() == 0 {
        return Err(NoSuchEntityException::builder()
            .message(format!("Policy {policy_arn} was not found attached to role {role_name}."))
            .build()
            .into());
    }

    Ok(())
}

impl RequestExecutor for ListAttachedRolePoliciesInternalRequest {
    type Response = ListAttachedRolePoliciesResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_attached_role_policies(
            tx,
            &self.account_id,
            &self.role_name,
            self.marker.as_deref(),
            self.max_items,
            self.path_prefix.as_deref(),
        )
        .await
    }
}

/// The marker innards for a ListAttachedRolePolicies operation.
#[derive(Deserialize, Serialize)]
struct ListAttachedRolePoliciesMarker {
    next_policy_name_lower: String,
    next_managed_policy_id: String,
}

/// The rows returned by the ListAttachedRolePolicies query.
#[derive(FromRow)]
struct ListAttachedRolePolicyRow {
    managed_policy_id: String,
    account_id: String,
    managed_policy_name_cased: String,
    managed_policy_name_lower: String,
    path: String,
}

/// List managed policies attached to a role in the database.
pub async fn list_attached_role_policies(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
    path_prefix: Option<&str>,
) -> Result<ListAttachedRolePoliciesResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name)?;
    if let Some(path_prefix) = path_prefix {
        validate_path_prefix(path_prefix)?;
    }
    let max_items = constrain_max_items(max_items)?;
    let partition = get_current_partition_or_fail(tx).await?;

    // Look up the role_id, returning NoSuchEntity if the role doesn't exist.
    let role_id: String = match query(indoc! {"
            SELECT role_id
            FROM iam.roles
            WHERE account_id = $1 AND role_name_lower = $2
        "})
    .bind(account_id)
    .bind(role_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The role with name {role_name} cannot be found."))
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up role in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    let paginator = make_paginator(&partition, OP_LIST_ATTACHED_ROLE_POLICIES)?;

    let mut sql = QueryBuilder::new(
        r#"
        SELECT mp.managed_policy_id, mp.account_id, mp.managed_policy_name_cased,
            mp.managed_policy_name_lower, mp.path
        FROM iam.role_attached_policies rap
        INNER JOIN iam.managed_policies mp ON rap.managed_policy_id = mp.managed_policy_id
        WHERE rap.role_id =
    "#,
    );
    sql.push_bind(&role_id);

    if let Some(path_prefix) = path_prefix {
        sql.push(" AND mp.path LIKE ");
        sql.push_bind(format!("{}%", path_prefix.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")));
    }

    if let Some(marker) = marker {
        let info: ListAttachedRolePoliciesMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token for ListAttachedRolePolicies: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;
        sql.push(" AND (mp.managed_policy_name_lower, mp.managed_policy_id) >= (");
        sql.push_bind(info.next_policy_name_lower);
        sql.push(", ");
        sql.push_bind(info.next_managed_policy_id);
        sql.push(")");
    }

    sql.push(" ORDER BY mp.managed_policy_name_lower ASC, mp.managed_policy_id ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListAttachedRolePolicyRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch attached role policies from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    let mut results: Vec<AttachedPolicy> = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if results.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListAttachedRolePoliciesMarker {
                        next_policy_name_lower: row.managed_policy_name_lower,
                        next_managed_policy_id: row.managed_policy_id,
                    })
                    .await
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token for ListAttachedRolePolicies: {e}");
                        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                    })?,
            );
            break;
        }

        let arn = build_policy_arn(&partition, &row.account_id, &row.path, &row.managed_policy_name_cased)?;
        results.push(
            AttachedPolicy::builder()
                .policy_arn(Some(arn.to_string()))
                .policy_name(Some(row.managed_policy_name_cased))
                .build()
                .map_err(|e| {
                    log::error!("Failed to construct AttachedPolicy: {e}");
                    IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                })?,
        );
    }

    let mut builder = ListAttachedRolePoliciesResponse::builder();
    builder = builder.attached_policies(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(Some(true)).marker(Some(next_marker));
    }

    builder.build().map_err(|e| {
        log::error!("Failed to build ListAttachedRolePoliciesResponse: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })
}
