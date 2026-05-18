//! Policy-level database operations.
use {
    crate::{
        constants::iam::*,
        model::iam::IamId,
        ops::{
            RequestExecutor,
            iam::{
                constrain_max_items, get_current_partition_or_fail, validate_account_id, validate_path,
                validate_path_prefix, validate_policy_name, validate_tag_key, validate_tag_value,
            },
        },
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aspen::Policy as AspenPolicy,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_pagination::{
        FixedKeyService, OperationPaginator, ScratchstackOperationMetadata, ScratchstackServiceMetadata,
    },
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreatePolicyInternalRequest, CreatePolicyResponse, CreatePolicyVersionRequest, CreatePolicyVersionResponse,
            DeletePolicyVersionRequest, GetPolicyRequest, GetPolicyResponse, GetPolicyVersionRequest,
            GetPolicyVersionResponse, ListPoliciesInternalRequest, ListPoliciesResponse, ListPolicyVersionsRequest,
            ListPolicyVersionsResponse, SetDefaultPolicyVersionRequest, TagPolicyRequest, UntagPolicyRequest,
        },
        types::{
            Policy, PolicyScopeType, PolicyUsageType, PolicyVersion, Tag,
            error::{
                DeleteConflictException, InternalFailure, LimitExceededException, MalformedPolicyDocumentException,
                NoSuchEntityException, ValidationError,
            },
        },
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, Row as _, postgres::PgTransaction, query, query_as},
    std::{cmp::min, collections::HashMap, str::FromStr as _},
};

impl RequestExecutor for CreatePolicyInternalRequest {
    type Response = CreatePolicyResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        create_policy(
            tx,
            &self.account_id,
            &self.policy_name,
            &self.policy_document,
            self.description.as_deref(),
            self.path.as_deref(),
            &self.tags,
        )
        .await
    }
}

/// Create a new managed policy on the database.
pub async fn create_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    policy_name: &str,
    policy_document: &str,
    description: Option<&str>,
    path: Option<&str>,
    tags: &[Tag],
) -> Result<CreatePolicyResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let path = path.unwrap_or("/");
    validate_path(path)?;
    validate_policy_name(policy_name)?;

    // Validate the policy document is valid Aspen JSON.
    if let Err(e) = AspenPolicy::from_str(policy_document) {
        let message = format!("Invalid policy document: {e}");
        return Err(MalformedPolicyDocumentException::builder().message(message).build().into());
    }

    for tag in tags {
        validate_tag_key(&tag.key)?;
        validate_tag_value(&tag.value)?;
    }

    // Generate a new managed policy id.
    let policy_id = IamId::new(IamResourceType::ManagedPolicy, account_id.parse().unwrap()).to_string();
    let partition = get_current_partition_or_fail(tx).await?;

    let result = match query(indoc! {"
            INSERT INTO iam.managed_policies(
                managed_policy_id, account_id, managed_policy_name_lower, managed_policy_name_cased,
                path, default_version, deprecated, latest_version, description)
            VALUES($1, $2, $3, $4, $5, 1, false, 1, $6)
            RETURNING created_at
        "})
    .bind(&policy_id[4..])
    .bind(account_id)
    .bind(policy_name.to_ascii_lowercase())
    .bind(policy_name)
    .bind(path)
    .bind(description)
    .fetch_one(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to insert managed policy into database: {e}");
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

    // Insert the initial policy version.
    if let Err(e) = query(indoc! {"
            INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document)
            VALUES($1, 1, $2)
        "})
    .bind(&policy_id[4..])
    .bind(policy_document)
    .execute(tx.as_mut())
    .await
    {
        log::error!("Failed to insert managed policy version into database: {e}");
        return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
    }

    // Insert tags.
    for tag in tags {
        let key_cased = tag.key.as_str();
        let key_lower = key_cased.to_ascii_lowercase();
        let value = tag.value.as_str();

        if let Err(e) = query(indoc! {"
                INSERT INTO iam.managed_policy_tags(managed_policy_id, key_lower, key_cased, value)
                VALUES($1, $2, $3, $4)
            "})
        .bind(&policy_id[4..])
        .bind(key_lower)
        .bind(key_cased)
        .bind(value)
        .execute(tx.as_mut())
        .await
        {
            log::error!("Failed to insert managed policy tag into database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    }

    let arn = match Arn::builder()
        .partition(partition)
        .service(SERVICE_KEY_IAM)
        .account_id(account_id)
        .resource(policy_arn_resource(path, policy_name))
        .build()
    {
        Ok(arn) => arn,
        Err(e) => {
            log::error!("Failed to construct ARN for new managed policy: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    let policy = Policy::builder()
        .arn(Some(arn.to_string()))
        .attachment_count(Some(0))
        .create_date(Some(created_at))
        .default_version_id(Some("v1".to_string()))
        .description(description.map(|d| d.to_string()))
        .is_attachable(Some(true))
        .path(Some(path.to_string()))
        .permissions_boundary_usage_count(Some(0))
        .policy_id(Some(policy_id))
        .policy_name(Some(policy_name.to_string()))
        .tags(tags.to_vec())
        .build()
        .map_err(|e| {
            log::error!("Failed to construct policy object for new managed policy: {e}");
            InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
        })?;

    Ok(CreatePolicyResponse {
        policy: Some(policy),
    })
}

impl RequestExecutor for CreatePolicyVersionRequest {
    type Response = CreatePolicyVersionResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        create_policy_version(tx, &self.policy_arn, &self.policy_document, self.set_as_default).await
    }
}

/// Create a new version for an existing managed policy.
pub async fn create_policy_version(
    tx: &mut PgTransaction<'_>,
    policy_arn: &str,
    policy_document: &str,
    set_as_default: Option<bool>,
) -> Result<CreatePolicyVersionResponse, IamError> {
    /// The row returned by the initial query to the iam.policies table to get the managed_policy_id
    /// and latest_version for the requested policy ARN.
    #[derive(FromRow)]
    struct PolicyRow {
        managed_policy_id: String,
        latest_version: i64,
    }

    // Parse the policy ARN.
    let arn = match Arn::from_str(policy_arn) {
        Ok(arn) => arn,
        Err(e) => {
            log::info!("Failed to parse policy ARN: {e}");
            return Err(ValidationError::builder().message("Invalid policy ARN".to_string()).build().into());
        }
    };

    let resource = arn.resource();
    if !resource.starts_with(ARN_RESOURCE_PREFIX_POLICY) {
        return Err(ValidationError::builder()
            .message("Policy ARN must have a resource that starts with \"policy/\"".to_string())
            .build()
            .into());
    }

    let account_id = arn.account_id();
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        other => other,
    };

    // Extract path and name from the resource.
    let policy_path_and_name = &resource[ARN_RESOURCE_PREFIX_POLICY.len()..];
    let name_start = policy_path_and_name.rfind('/').map(|i| i + 1).unwrap_or(0);
    let policy_name_lower = policy_path_and_name[name_start..].to_ascii_lowercase();
    let policy_path = if name_start == 0 {
        "/".to_string()
    } else {
        format!("/{}", &policy_path_and_name[..name_start])
    };

    // Validate the policy document is valid Aspen JSON.
    if let Err(e) = AspenPolicy::from_str(policy_document) {
        let message = format!("Invalid policy document: {e}");
        return Err(MalformedPolicyDocumentException::builder().message(message).build().into());
    }

    // Look up the policy and get its current latest_version.
    let policy_row: PolicyRow = match query_as(indoc! {"
            SELECT managed_policy_id, latest_version
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(account_id)
    .bind(&policy_path)
    .bind(&policy_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            let message = format!("Policy {policy_arn} does not exist or is not attachable.");
            return Err(NoSuchEntityException::builder().message(message).build().into());
        }
        Err(e) => {
            log::error!("Failed to query managed policy from database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    // AWS limits managed policies to 5 versions.
    let new_version = policy_row.latest_version + 1;
    if new_version > MAX_POLICY_VERSIONS {
        let message = format!(
            "A managed policy can have up to {MAX_POLICY_VERSIONS} versions. Before you create a new version, you must delete an existing version."
        );
        return Err(LimitExceededException::builder().message(message).build().into());
    }

    let set_as_default = set_as_default.unwrap_or(false);

    // Insert the new policy version.
    let version_row = match query(indoc! {"
            INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document)
            VALUES($1, $2, $3)
            RETURNING created_at
        "})
    .bind(&policy_row.managed_policy_id)
    .bind(new_version)
    .bind(policy_document)
    .fetch_one(tx.as_mut())
    .await
    {
        Ok(row) => row,
        Err(e) => {
            log::error!("Failed to insert managed policy version into database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    let created_at: chrono::DateTime<chrono::Utc> = version_row.try_get(0).map_err(|e| {
        log::error!("Failed to get created_at from database row: {e}");
        InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
    })?;

    // Update latest_version and update_date (and default_version if set_as_default).
    let update_query = if set_as_default {
        query(indoc! {"
                UPDATE iam.managed_policies
                SET latest_version = $1, default_version = $1, update_date = $3
                WHERE managed_policy_id = $2
            "})
        .bind(new_version)
        .bind(&policy_row.managed_policy_id)
        .bind(created_at)
    } else {
        query(indoc! {"
                UPDATE iam.managed_policies
                SET latest_version = $1, update_date = $3
                WHERE managed_policy_id = $2
            "})
        .bind(new_version)
        .bind(&policy_row.managed_policy_id)
        .bind(created_at)
    };

    if let Err(e) = update_query.execute(tx.as_mut()).await {
        log::error!("Failed to update managed policy latest_version: {e}");
        return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
    }

    let version_id = format!("v{new_version}");
    let policy_version = PolicyVersion::builder()
        .create_date(Some(created_at))
        .document(Some(policy_document.to_string()))
        .is_default_version(Some(set_as_default))
        .version_id(Some(version_id))
        .build()
        .map_err(|e| {
            log::error!("Failed to construct PolicyVersion object: {e}");
            InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
        })?;

    Ok(CreatePolicyVersionResponse {
        policy_version: Some(policy_version),
    })
}

impl RequestExecutor for DeletePolicyVersionRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        delete_policy_version(tx, &self.policy_arn, &self.version_id).await
    }
}

/// Delete a non-default version of a managed policy.
pub async fn delete_policy_version(
    tx: &mut PgTransaction<'_>,
    policy_arn: &str,
    version_id: &str,
) -> Result<(), IamError> {
    /// The row returned by the query to the iam.policies table to get the managed_policy_id,
    /// default_version, and latest_version for the requested policy ARN.
    #[derive(FromRow)]
    struct PolicyRow {
        managed_policy_id: String,
        default_version: i64,
        latest_version: i64,
    }

    let parts = parse_policy_arn(policy_arn)?;

    // Parse the numeric portion of the version id. The Smithy regex enforces
    // ^v[1-9][0-9]*(\.[A-Za-z0-9-]*)?$, so version_id always starts with 'v' followed by digits
    // and optionally a '.suffix'. We accept the input defensively in case the builder is bypassed.
    let version_number = parse_policy_version_id(version_id).ok_or_else(|| {
        IamError::from(ValidationError::builder().message(format!("Invalid policy version id: {version_id}")).build())
    })?;

    // Lock the managed_policies row to prevent a race in which another transaction sets the
    // default version to the one being deleted between our default-version check and the delete.
    let policy_row: PolicyRow = match query_as(indoc! {"
            SELECT managed_policy_id, default_version, latest_version
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
            FOR UPDATE
        "})
    .bind(&parts.account_id)
    .bind(&parts.policy_path)
    .bind(&parts.policy_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            let message = format!("Policy {policy_arn} was not found.");
            return Err(NoSuchEntityException::builder().message(message).build().into());
        }
        Err(e) => {
            log::error!("Failed to query managed policy from database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if version_number == policy_row.default_version {
        let message = "Cannot delete the default version of a policy. To delete the default version, you must first set another version as the default.".to_string();
        return Err(DeleteConflictException::builder().message(message).build().into());
    }

    let result = match query(indoc! {"
            DELETE FROM iam.managed_policy_versions
            WHERE managed_policy_id = $1 AND managed_policy_version = $2
        "})
    .bind(&policy_row.managed_policy_id)
    .bind(version_number)
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to delete managed policy version from database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if result.rows_affected() == 0 {
        let message = format!("Policy {policy_arn} version {version_id} was not found.");
        return Err(NoSuchEntityException::builder().message(message).build().into());
    }

    // If we just removed the latest version, the denormalized update_date is now stale. Recompute
    // it from the remaining versions. (No COALESCE: the default version can't be deleted, so at
    // least one version always remains.) This runs only on the rare path of deleting the latest
    // version; non-latest deletes leave update_date alone, matching the existing latest_version
    // laziness.
    if version_number == policy_row.latest_version
        && let Err(e) = query(indoc! {"
                UPDATE iam.managed_policies
                SET update_date = (
                    SELECT MAX(created_at)
                    FROM iam.managed_policy_versions
                    WHERE managed_policy_id = $1
                )
                WHERE managed_policy_id = $1
            "})
        .bind(&policy_row.managed_policy_id)
        .execute(tx.as_mut())
        .await
    {
        log::error!("Failed to recompute managed policy update_date: {e}");
        return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
    }

    Ok(())
}

impl RequestExecutor for GetPolicyRequest {
    type Response = GetPolicyResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        get_policy(tx, &self.policy_arn).await
    }
}

/// Get details for a single managed policy by ARN.
pub async fn get_policy(tx: &mut PgTransaction<'_>, policy_arn: &str) -> Result<GetPolicyResponse, IamError> {
    /// The row returned by the query to the iam.policies table to get details for the requested
    /// policy ARN.
    #[derive(FromRow)]
    struct PolicyRow {
        managed_policy_id: String,
        managed_policy_name_cased: String,
        path: String,
        default_version: i64,
        deprecated: bool,
        description: Option<String>,
        created_at: DateTime<Utc>,
        update_date: DateTime<Utc>,
    }

    let parts = parse_policy_arn(policy_arn)?;
    let partition = get_current_partition_or_fail(tx).await?;

    let policy_row: PolicyRow = query_as(indoc! {"
            SELECT managed_policy_id, managed_policy_name_cased, path, default_version, deprecated,
                description, created_at, update_date
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(&parts.account_id)
    .bind(&parts.policy_path)
    .bind(&parts.policy_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to query managed policy from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?
    .ok_or_else(|| {
        IamError::from(NoSuchEntityException::builder().message(format!("Policy {policy_arn} was not found.")).build())
    })?;

    let arn = build_policy_arn(&partition, &parts.account_id, &policy_row.path, &policy_row.managed_policy_name_cased)?;
    let tags = fetch_policy_tags(tx, &policy_row.managed_policy_id).await?;
    let attachment_count = if parts.account_id == AWS_ACCOUNT_ID_NUMERIC {
        None
    } else {
        Some(get_policy_attachment_count(tx, &policy_row.managed_policy_id).await?)
    };
    let permissions_boundary_usage_count = if parts.account_id == AWS_ACCOUNT_ID_NUMERIC {
        None
    } else {
        Some(get_policy_permissions_boundary_usage_count(tx, &policy_row.managed_policy_id).await?)
    };

    let policy = Policy::builder()
        .arn(Some(arn.to_string()))
        .attachment_count(attachment_count)
        .create_date(Some(policy_row.created_at))
        .default_version_id(Some(format!("v{}", policy_row.default_version)))
        .description(policy_row.description)
        .is_attachable(Some(!policy_row.deprecated))
        .path(Some(policy_row.path))
        .permissions_boundary_usage_count(permissions_boundary_usage_count)
        .policy_id(Some(format!("{}{}", IamResourceType::ManagedPolicy.as_str(), policy_row.managed_policy_id)))
        .policy_name(Some(policy_row.managed_policy_name_cased))
        .update_date(Some(policy_row.update_date))
        .tags(tags)
        .build()?;
    Ok(GetPolicyResponse {
        policy: Some(policy),
    })
}

impl RequestExecutor for GetPolicyVersionRequest {
    type Response = GetPolicyVersionResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        get_policy_version(tx, &self.policy_arn, &self.version_id).await
    }
}

/// Get a specific version of a managed policy by ARN.
pub async fn get_policy_version(
    tx: &mut PgTransaction<'_>,
    policy_arn: &str,
    version_id: &str,
) -> Result<GetPolicyVersionResponse, IamError> {
    /// The row returned by the query to the iam.policies and iam.policy_versions tables to get details for the
    /// requested policy ARN and version id.
    #[derive(FromRow)]
    struct PolicyVersionRow {
        default_version: i64,
        policy_document: String,
        created_at: DateTime<Utc>,
    }

    let parts = parse_policy_arn(policy_arn)?;
    let version_number = parse_policy_version_id(version_id).ok_or_else(|| {
        IamError::from(ValidationError::builder().message(format!("Invalid policy version id: {version_id}")).build())
    })?;

    let row: PolicyVersionRow = query_as(indoc! {"
            SELECT mp.default_version, mpv.policy_document, mpv.created_at
            FROM iam.managed_policies mp
            JOIN iam.managed_policy_versions mpv ON mp.managed_policy_id = mpv.managed_policy_id
            WHERE mp.account_id = $1 AND mp.path = $2 AND mp.managed_policy_name_lower = $3
                AND mpv.managed_policy_version = $4
        "})
    .bind(&parts.account_id)
    .bind(&parts.policy_path)
    .bind(&parts.policy_name_lower)
    .bind(version_number)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to query managed policy version from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?
    .ok_or_else(|| {
        IamError::from(
            NoSuchEntityException::builder()
                .message(format!("Policy {policy_arn} version {version_id} was not found."))
                .build(),
        )
    })?;

    let policy_version = PolicyVersion::builder()
        .create_date(Some(row.created_at))
        .document(Some(row.policy_document))
        .is_default_version(Some(version_number == row.default_version))
        .version_id(Some(format!("v{version_number}")))
        .build()
        .map_err(|e| {
            log::error!("Failed to construct PolicyVersion object: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;

    Ok(GetPolicyVersionResponse {
        policy_version: Some(policy_version),
    })
}

impl RequestExecutor for ListPoliciesInternalRequest {
    type Response = ListPoliciesResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_policies(
            tx,
            &self.account_id,
            self.marker.as_deref(),
            self.max_items,
            self.only_attached,
            self.path_prefix.as_deref(),
            self.policy_usage_filter.as_ref(),
            self.scope.as_ref(),
        )
        .await
    }
}

/// List managed policies in an account, optionally including AWS-managed policies.
#[allow(clippy::too_many_arguments)]
pub async fn list_policies(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
    only_attached: Option<bool>,
    path_prefix: Option<&str>,
    policy_usage_filter: Option<&PolicyUsageType>,
    scope: Option<&PolicyScopeType>,
) -> Result<ListPoliciesResponse, IamError> {
    /// The marker innards for a ListPolicies operation.
    #[derive(Deserialize, Serialize)]
    struct ListPoliciesMarker {
        next_account_id: String,
        next_managed_policy_id: String,
    }

    /// The rows returned by the ListPolicies operation.
    #[derive(FromRow)]
    struct ListPoliciesRow {
        managed_policy_id: String,
        account_id: String,
        managed_policy_name_cased: String,
        path: String,
        default_version: i64,
        deprecated: bool,
        created_at: DateTime<Utc>,
        update_date: DateTime<Utc>,
    }

    /// The rows returned for attachment counts.
    #[derive(FromRow)]
    struct AttachmentCountRow {
        managed_policy_id: String,
        attachment_count: i64,
    }

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

    let paginator = make_paginator(&partition, OP_LIST_POLICIES)?;

    let mut sql = QueryBuilder::new(
        r#"
        SELECT managed_policy_id, account_id, managed_policy_name_cased, path, default_version,
            deprecated, created_at, update_date
        FROM iam.managed_policies
        WHERE
    "#,
    );

    let scope = scope.unwrap_or(&PolicyScopeType::All);
    match scope {
        PolicyScopeType::Aws => {
            sql.push("account_id = ");
            sql.push_bind(AWS_ACCOUNT_ID_NUMERIC);
        }
        PolicyScopeType::Local => {
            sql.push("account_id = ");
            sql.push_bind(account_id);
        }
        PolicyScopeType::All => {
            sql.push("(account_id = ");
            sql.push_bind(account_id);
            sql.push(" OR account_id = ");
            sql.push_bind(AWS_ACCOUNT_ID_NUMERIC);
            sql.push(")");
        }
        other => {
            return Err(ValidationError::builder().message(format!("Unsupported Scope value: {other}")).build().into());
        }
    }

    if let Some(path_prefix) = path_prefix {
        sql.push(" AND path LIKE ");
        sql.push_bind(format!("{}%", path_prefix.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")));
    }

    // "Attached" here means "attached to a user/group/role in the caller's account". The
    // subqueries join back to the owning entity tables so attachments to entities in other
    // accounts don't leak through.
    if only_attached == Some(true) {
        push_attached_in_account_filter(&mut sql, account_id);
    }

    if let Some(filter) = policy_usage_filter {
        match filter {
            PolicyUsageType::PermissionsPolicy => {
                push_attached_in_account_filter(&mut sql, account_id);
            }
            PolicyUsageType::PermissionsBoundary => {
                push_pb_in_account_filter(&mut sql, account_id);
            }
            other => {
                return Err(ValidationError::builder()
                    .message(format!("Unsupported PolicyUsageFilter value: {other}"))
                    .build()
                    .into());
            }
        }
    }

    if let Some(marker) = marker {
        let info: ListPoliciesMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token for ListPolicies: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;
        sql.push(" AND (account_id, managed_policy_id) >= (");
        sql.push_bind(info.next_account_id);
        sql.push(", ");
        sql.push_bind(info.next_managed_policy_id);
        sql.push(")");
    }

    sql.push(" ORDER BY account_id ASC, managed_policy_id ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListPoliciesRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch managed policies from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    let mut results: HashMap<String, Policy> = HashMap::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if results.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListPoliciesMarker {
                        next_account_id: row.account_id,
                        next_managed_policy_id: row.managed_policy_id,
                    })
                    .await
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token for ListPolicies: {e}");
                        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                    })?,
            );
            break;
        }

        let arn = build_policy_arn(&partition, &row.account_id, &row.path, &row.managed_policy_name_cased)?;
        let policy_id = format!("{}{}", IamResourceType::ManagedPolicy.as_str(), row.managed_policy_id);
        let policy = Policy::builder()
            .arn(Some(arn.to_string()))
            .create_date(Some(row.created_at))
            .default_version_id(Some(format!("v{}", row.default_version)))
            .is_attachable(Some(!row.deprecated))
            .path(Some(row.path))
            .policy_id(policy_id.clone())
            .policy_name(Some(row.managed_policy_name_cased))
            .update_date(Some(row.update_date))
            .build()
            .map_err(|e| {
                log::error!("Failed to construct Policy object for ListPolicies result: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?;
        results.insert(row.managed_policy_id, policy);
    }

    // This will be very, very many for AWS policies, will overflow the resulting i32, and will
    // take an extremely long time. Skip it for AWS policies by only doing it when listing a single
    // account's policies.
    if account_id != AWS_ACCOUNT_ID_NUMERIC {
        // Retrieve the attachment count for each of the policies in the result set.
        let attachment_rows: Vec<AttachmentCountRow> = query_as(indoc! {"
            SELECT mp.managed_policy_id,
                (SELECT COUNT(*) FROM iam.user_attached_policies WHERE managed_policy_id = mp.managed_policy_id) +
                (SELECT COUNT(*) FROM iam.group_attached_policies WHERE managed_policy_id = mp.managed_policy_id) +
                (SELECT COUNT(*) FROM iam.role_attached_policies WHERE managed_policy_id = mp.managed_policy_id)
                AS attachment_count
            FROM iam.managed_policies mp
            WHERE mp.managed_policy_id = ANY($1)
        "})
        .bind(results.keys().cloned().collect::<Vec<String>>())
        .fetch_all(tx.as_mut())
        .await
        .map_err(|e| {
            log::error!("Failed to fetch policy attachment counts from database: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;
        for row in attachment_rows.into_iter() {
            let attachment_count = min(row.attachment_count, i32::MAX as i64) as i32;

            if let Some(policy) = results.get_mut(&row.managed_policy_id) {
                policy.attachment_count = Some(attachment_count);
            }
        }

        // Retrieve the permissions boundary usage count for each of the policies in the result set.
        let permissions_boundary_usage_rows: Vec<AttachmentCountRow> = query_as(indoc! {"
            SELECT mp.managed_policy_id,
                (SELECT COUNT(*) FROM iam.users WHERE permissions_boundary_managed_policy_id = mp.managed_policy_id) +
                (SELECT COUNT(*) FROM iam.roles WHERE permissions_boundary_managed_policy_id = mp.managed_policy_id)
                AS attachment_count
            FROM iam.managed_policies mp
            WHERE mp.managed_policy_id = ANY($1)
        "})
        .bind(results.keys().cloned().collect::<Vec<String>>())
        .fetch_all(tx.as_mut())
        .await
        .map_err(|e| {
            log::error!("Failed to fetch policy permissions boundary usage counts from database: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;
        for row in permissions_boundary_usage_rows.into_iter() {
            let usage_count = min(row.attachment_count, i32::MAX as i64) as i32;

            if let Some(policy) = results.get_mut(&row.managed_policy_id) {
                policy.permissions_boundary_usage_count = Some(usage_count);
            }
        }
    }

    Ok(ListPoliciesResponse {
        policies: results.into_values().collect(),
        is_truncated: Some(next_marker.is_some()),
        marker: next_marker,
    })
}

impl RequestExecutor for ListPolicyVersionsRequest {
    type Response = ListPolicyVersionsResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_policy_versions(tx, &self.policy_arn, self.marker.as_deref(), self.max_items).await
    }
}

/// List versions of a managed policy by ARN.
pub async fn list_policy_versions(
    tx: &mut PgTransaction<'_>,
    policy_arn: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
) -> Result<ListPolicyVersionsResponse, IamError> {
    /// The marker innards for a ListPolicyVersions operation.
    #[derive(Deserialize, Serialize)]
    struct ListPolicyVersionsMarker {
        next_version: i64,
    }

    /// The row returned by the initial query to the iam.policies table to get the managed_policy_id
    /// and default_version for the requested policy ARN.
    #[derive(FromRow)]
    struct PolicyRow {
        managed_policy_id: String,
        default_version: i64,
    }

    /// The rows returned by the ListPolicyVersions operation.
    #[derive(FromRow)]
    struct ListPolicyVersionsRow {
        managed_policy_version: i64,
        created_at: DateTime<Utc>,
    }

    let parts = parse_policy_arn(policy_arn)?;
    let max_items = constrain_max_items(max_items)?;
    let partition = get_current_partition_or_fail(tx).await?;

    let paginator = make_paginator(&partition, OP_LIST_POLICY_VERSIONS)?;

    // Look up the policy to get managed_policy_id and default_version.
    let policy_row: PolicyRow = query_as(indoc! {"
            SELECT managed_policy_id, default_version
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(&parts.account_id)
    .bind(&parts.policy_path)
    .bind(&parts.policy_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to query managed policy from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?
    .ok_or_else(|| {
        IamError::from(NoSuchEntityException::builder().message(format!("Policy {policy_arn} was not found.")).build())
    })?;

    let mut sql = QueryBuilder::new(
        r#"
        SELECT managed_policy_version, created_at
        FROM iam.managed_policy_versions
        WHERE managed_policy_id =
    "#,
    );
    sql.push_bind(&policy_row.managed_policy_id);

    if let Some(marker) = marker {
        let info: ListPolicyVersionsMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token for ListPolicyVersions: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;
        sql.push(" AND managed_policy_version <= ");
        sql.push_bind(info.next_version);
    }

    sql.push(" ORDER BY managed_policy_version DESC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListPolicyVersionsRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch managed policy versions from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    let mut versions: Vec<PolicyVersion> = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if versions.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListPolicyVersionsMarker {
                        next_version: row.managed_policy_version,
                    })
                    .await
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token for ListPolicyVersions: {e}");
                        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                    })?,
            );
            break;
        }

        versions.push(
            PolicyVersion::builder()
                .create_date(Some(row.created_at))
                .is_default_version(Some(row.managed_policy_version == policy_row.default_version))
                .version_id(Some(format!("v{}", row.managed_policy_version)))
                .build()
                .map_err(|e| {
                    log::error!("Failed to construct PolicyVersion object: {e}");
                    IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                })?,
        );
    }

    Ok(ListPolicyVersionsResponse {
        versions,
        is_truncated: Some(next_marker.is_some()),
        marker: next_marker,
    })
}

impl RequestExecutor for SetDefaultPolicyVersionRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        set_default_policy_version(tx, &self.policy_arn, &self.version_id).await
    }
}

/// Set the default version of a managed policy by ARN.
pub async fn set_default_policy_version(
    tx: &mut PgTransaction<'_>,
    policy_arn: &str,
    version_id: &str,
) -> Result<(), IamError> {
    /// The row returned by the query to the iam.policies table to get the managed_policy_id for
    /// the requested policy ARN.
    #[derive(FromRow)]
    struct PolicyRow {
        managed_policy_id: String,
    }

    let parts = parse_policy_arn(policy_arn)?;
    let version_number = parse_policy_version_id(version_id).ok_or_else(|| {
        IamError::from(ValidationError::builder().message(format!("Invalid policy version id: {version_id}")).build())
    })?;

    // Lock the managed_policies row FOR UPDATE to serialize against DeletePolicyVersion (which
    // also takes FOR UPDATE on this row). With this lock held, no concurrent transaction can
    // delete the version we're about to install as default before our commit lands.
    let policy_row: PolicyRow = query_as(indoc! {"
            SELECT managed_policy_id
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
            FOR UPDATE
        "})
    .bind(&parts.account_id)
    .bind(&parts.policy_path)
    .bind(&parts.policy_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to query managed policy from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?
    .ok_or_else(|| {
        IamError::from(NoSuchEntityException::builder().message(format!("Policy {policy_arn} was not found.")).build())
    })?;

    // Also lock the specific version row. This ensures a separate transaction can't delete this
    // version after we check it exists but before we set it as default.
    let version_exists = query(indoc! {"
            SELECT 1
            FROM iam.managed_policy_versions
            WHERE managed_policy_id = $1 AND managed_policy_version = $2
            FOR UPDATE
        "})
    .bind(&policy_row.managed_policy_id)
    .bind(version_number)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to query managed policy version from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    if version_exists.is_none() {
        return Err(NoSuchEntityException::builder()
            .message(format!("Policy {policy_arn} version {version_id} was not found."))
            .build()
            .into());
    }

    query(indoc! {"
            UPDATE iam.managed_policies
            SET default_version = $1
            WHERE managed_policy_id = $2
        "})
    .bind(version_number)
    .bind(&policy_row.managed_policy_id)
    .execute(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to update managed policy default_version: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    Ok(())
}

impl RequestExecutor for TagPolicyRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        tag_policy(tx, &self.policy_arn, &self.tags).await
    }
}

/// Add or update tags on a managed policy by ARN.
pub async fn tag_policy(tx: &mut PgTransaction<'_>, policy_arn: &str, tags: &[Tag]) -> Result<(), IamError> {
    if tags.is_empty() {
        return Err(ValidationError::builder().message("At least one tag must be provided.").build().into());
    }
    for tag in tags {
        validate_tag_key(&tag.key)?;
        validate_tag_value(&tag.value)?;
    }

    let parts = parse_policy_arn(policy_arn)?;
    let managed_policy_id = lookup_managed_policy_id(tx, &parts, policy_arn).await?;

    for tag in tags {
        let key_cased = tag.key.as_str();
        let key_lower = key_cased.to_ascii_lowercase();
        let value = tag.value.as_str();

        if let Err(e) = query(indoc! {"
                INSERT INTO iam.managed_policy_tags(managed_policy_id, key_lower, key_cased, value)
                VALUES($1, $2, $3, $4)
                ON CONFLICT (managed_policy_id, key_lower)
                DO UPDATE SET key_cased = EXCLUDED.key_cased, value = EXCLUDED.value,
                              updated_at = CURRENT_TIMESTAMP
            "})
        .bind(&managed_policy_id)
        .bind(key_lower)
        .bind(key_cased)
        .bind(value)
        .execute(tx.as_mut())
        .await
        {
            log::error!("Failed to insert/update managed policy tag: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    }

    Ok(())
}

impl RequestExecutor for UntagPolicyRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        untag_policy(tx, &self.policy_arn, &self.tag_keys).await
    }
}

/// Remove tags from a managed policy by ARN.
pub async fn untag_policy(tx: &mut PgTransaction<'_>, policy_arn: &str, tag_keys: &[String]) -> Result<(), IamError> {
    if tag_keys.is_empty() {
        return Err(ValidationError::builder().message("At least one tag key must be provided.").build().into());
    }
    for key in tag_keys {
        validate_tag_key(key)?;
    }

    let parts = parse_policy_arn(policy_arn)?;
    let managed_policy_id = lookup_managed_policy_id(tx, &parts, policy_arn).await?;

    for key in tag_keys {
        if let Err(e) = query(indoc! {"
                DELETE FROM iam.managed_policy_tags
                WHERE managed_policy_id = $1 AND key_lower = $2
            "})
        .bind(&managed_policy_id)
        .bind(key.to_ascii_lowercase())
        .execute(tx.as_mut())
        .await
        {
            log::error!("Failed to delete managed policy tag: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    }

    Ok(())
}

/// Parsed components of a policy ARN. `account_id` has the literal `aws` mapped to
/// `000000000000`.
struct PolicyArnParts {
    account_id: String,
    policy_path: String,
    policy_name_lower: String,
}

/// Parse a policy ARN and extract the account id, path, and lowercase policy name. Returns a
/// `ValidationError` if the ARN is unparseable or does not point at a `policy/` resource.
fn parse_policy_arn(policy_arn: &str) -> Result<PolicyArnParts, IamError> {
    let arn = Arn::from_str(policy_arn).map_err(|e| {
        log::info!("Failed to parse policy ARN: {e}");
        IamError::from(ValidationError::builder().message("Invalid policy ARN".to_string()).build())
    })?;

    let service = arn.service();
    if service != ARN_SERVICE_IAM {
        return Err(ValidationError::builder()
            .message("Policy ARN must have service \"iam\"".to_string())
            .build()
            .into());
    }

    if !arn.region().is_empty() {
        return Err(ValidationError::builder().message("Policy ARN must not have a region".to_string()).build().into());
    }

    let resource = arn.resource();
    if !resource.starts_with(ARN_RESOURCE_PREFIX_POLICY) {
        return Err(ValidationError::builder()
            .message("Policy ARN must have a resource that starts with \"policy/\"".to_string())
            .build()
            .into());
    }

    let account_id = match arn.account_id() {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC.to_string(),
        other => other.to_string(),
    };

    let policy_path_and_name = &resource[ARN_RESOURCE_PREFIX_POLICY.len()..];
    let name_start = policy_path_and_name.rfind('/').map(|i| i + 1).unwrap_or(0);
    let policy_name_lower = policy_path_and_name[name_start..].to_ascii_lowercase();
    let policy_path = if name_start == 0 {
        "/".to_string()
    } else {
        format!("/{}", &policy_path_and_name[..name_start])
    };

    Ok(PolicyArnParts {
        account_id,
        policy_path,
        policy_name_lower,
    })
}

/// Calculate the number of attachments for a policy by its managed_policy_id. This is the sum of
/// the number of user, group, and role attachments.
async fn get_policy_attachment_count(tx: &mut PgTransaction<'_>, managed_policy_id: &str) -> Result<i32, IamError> {
    let row = query(indoc! {"
            SELECT
                (SELECT COUNT(*) FROM iam.user_attached_policies WHERE managed_policy_id = $1) +
                (SELECT COUNT(*) FROM iam.group_attached_policies WHERE managed_policy_id = $1) +
                (SELECT COUNT(*) FROM iam.role_attached_policies WHERE managed_policy_id = $1)
                AS attachment_count
        "})
    .bind(managed_policy_id)
    .fetch_one(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to query attachment count for managed policy: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    row.try_get::<i64, _>(0)
        .map(|count| {
            if count > i32::MAX as i64 {
                i32::MAX
            } else {
                count as i32
            }
        })
        .map_err(|e| {
            log::error!("Failed to get attachment_count from database row: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })
}

/// Calculate the number of permissions boundary attachments for a policy by its managed_policy_id.
/// This is the sum of the number of user and role permissions boundary attachments.
async fn get_policy_permissions_boundary_usage_count(
    tx: &mut PgTransaction<'_>,
    managed_policy_id: &str,
) -> Result<i32, IamError> {
    let row = query(indoc! {"
            SELECT
                (SELECT COUNT(*) FROM iam.users WHERE permissions_boundary_managed_policy_id = $1) +
                (SELECT COUNT(*) FROM iam.roles WHERE permissions_boundary_managed_policy_id = $1)
                AS usage_count
        "})
    .bind(managed_policy_id)
    .fetch_one(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to query permissions boundary usage count for managed policy: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    row.try_get::<i64, _>("usage_count")
        .map(|count| {
            if count > i32::MAX as i64 {
                i32::MAX
            } else {
                count as i32
            }
        })
        .map_err(|e| {
            log::error!("Failed to get usage_count from database row: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })
}

/// Look up the `managed_policy_id` for a policy named by ARN; returns NoSuchEntity if not found.
async fn lookup_managed_policy_id(
    tx: &mut PgTransaction<'_>,
    parts: &PolicyArnParts,
    policy_arn: &str,
) -> Result<String, IamError> {
    query(indoc! {"
            SELECT managed_policy_id
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(&parts.account_id)
    .bind(&parts.policy_path)
    .bind(&parts.policy_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to query managed policy from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?
    .ok_or_else(|| {
        IamError::from(NoSuchEntityException::builder().message(format!("Policy {policy_arn} was not found.")).build())
    })?
    .try_get(0)
    .map_err(|e| {
        log::error!("Failed to get managed_policy_id from database row: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })
}

/// Fetch the tags attached to a managed policy.
async fn fetch_policy_tags(tx: &mut PgTransaction<'_>, managed_policy_id: &str) -> Result<Vec<Tag>, IamError> {
    /// The rows returned by the query to fetch managed policy tags.
    #[derive(FromRow)]
    struct PolicyTagRow {
        key_cased: String,
        value: String,
    }

    let rows: Vec<PolicyTagRow> = query_as(indoc! {"
            SELECT key_cased, value
            FROM iam.managed_policy_tags
            WHERE managed_policy_id = $1
            ORDER BY key_lower ASC
        "})
    .bind(managed_policy_id)
    .fetch_all(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch managed policy tags: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    let mut tags = Vec::with_capacity(rows.len());
    for row in rows.into_iter() {
        tags.push(Tag {
            key: row.key_cased,
            value: row.value,
        });
    }
    Ok(tags)
}

/// Construct a policy ARN from its components.
fn build_policy_arn(partition: &str, account_id: &str, path: &str, policy_name: &str) -> Result<Arn, IamError> {
    Arn::builder()
        .partition(partition)
        .service(SERVICE_KEY_IAM)
        .account_id(account_id)
        .resource(policy_arn_resource(path, policy_name))
        .build()
        .map_err(|e| {
            log::error!("Failed to construct ARN for managed policy: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })
}

/// Construct an `OperationPaginator` for a policy-related list operation.
fn make_paginator(
    partition: &str,
    operation_name: &'static str,
) -> Result<OperationPaginator<FixedKeyService, FixedKeyService>, IamError> {
    let service_metadata = ScratchstackServiceMetadata::new(partition.to_string(), "", SERVICE_ID_IAM);
    let operation_metadata = ScratchstackOperationMetadata::new(IAM_API_VERSION, operation_name);
    OperationPaginator::new_fixed_key(&service_metadata, &operation_metadata, PAGINATION_KEY_ID, *PAGINATION_KEY)
        .map_err(|e| {
            log::error!("Failed to create paginator for {operation_name}: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })
}

/// Append a ListPolicies filter restricting results to policies attached to a user, group, or
/// role in `account_id`. The join back to the entity tables prevents attachments to entities in
/// other accounts from leaking through.
fn push_attached_in_account_filter<'a>(sql: &mut QueryBuilder<'a, sqlx::Postgres>, account_id: &'a str) {
    sql.push(" AND managed_policy_id IN (SELECT uap.managed_policy_id FROM iam.user_attached_policies uap ");
    sql.push("JOIN iam.users u ON u.user_id = uap.user_id WHERE u.account_id = ");
    sql.push_bind(account_id);
    sql.push(" UNION ALL SELECT gap.managed_policy_id FROM iam.group_attached_policies gap ");
    sql.push("JOIN iam.groups g ON g.group_id = gap.group_id WHERE g.account_id = ");
    sql.push_bind(account_id);
    sql.push(" UNION ALL SELECT rap.managed_policy_id FROM iam.role_attached_policies rap ");
    sql.push("JOIN iam.roles r ON r.role_id = rap.role_id WHERE r.account_id = ");
    sql.push_bind(account_id);
    sql.push(")");
}

/// Append a ListPolicies filter restricting results to policies used as a permissions boundary
/// by a user or role in `account_id`.
fn push_pb_in_account_filter<'a>(sql: &mut QueryBuilder<'a, sqlx::Postgres>, account_id: &'a str) {
    sql.push(" AND managed_policy_id IN (");
    sql.push("SELECT permissions_boundary_managed_policy_id FROM iam.users WHERE account_id = ");
    sql.push_bind(account_id);
    sql.push(" AND permissions_boundary_managed_policy_id IS NOT NULL");
    sql.push(" UNION ALL SELECT permissions_boundary_managed_policy_id FROM iam.roles WHERE account_id = ");
    sql.push_bind(account_id);
    sql.push(" AND permissions_boundary_managed_policy_id IS NOT NULL)");
}

/// Parse a policy version id of the form `v<N>` or `v<N>.<suffix>` into its numeric portion.
/// Returns `None` if the input does not start with `v` followed by digits.
fn parse_policy_version_id(version_id: &str) -> Option<i64> {
    let digits = version_id.strip_prefix('v')?;
    let digits = digits.split('.').next().unwrap_or(digits);
    digits.parse::<i64>().ok().filter(|n| *n > 0)
}

fn policy_arn_resource(path: &str, policy_name: &str) -> String {
    let resource_path = path.trim_matches('/');
    if resource_path.is_empty() {
        format!("{ARN_RESOURCE_PREFIX_POLICY}{policy_name}")
    } else {
        format!("{ARN_RESOURCE_PREFIX_POLICY}{resource_path}/{policy_name}")
    }
}

/// Returns the policy id for the given permissions boundary ARN and account id, if it exists and is attachable.
/// Otherwise, returns an appropriate error.
pub async fn get_permissions_boundary_id(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    permissions_boundary: &str,
) -> Result<String, IamError> {
    let permissions_boundary = match Arn::from_str(permissions_boundary) {
        Ok(arn) => arn,
        Err(e) => {
            log::info!("Failed to parse permissions boundary ARN: {e}");
            let message = "Invalid permissions boundary ARN".to_string();

            return Err(ValidationError::builder().message(message).build().into());
        }
    };

    let resource = permissions_boundary.resource();
    if !resource.starts_with(ARN_RESOURCE_PREFIX_POLICY) {
        let message = "Permissions boundary ARN must have a resource that starts with \"policy/\"".to_string();
        return Err(ValidationError::builder().message(message).build().into());
    }

    let pb_account_id = permissions_boundary.account_id();
    let pb_account_id = if pb_account_id == AWS_ACCOUNT_ID {
        AWS_ACCOUNT_ID_NUMERIC
    } else if pb_account_id == account_id {
        account_id
    } else {
        let message = "Permissions boundary ARN must have an account ID that matches the request's account ID or 'aws'"
            .to_string();
        return Err(ValidationError::builder().message(message).build().into());
    };

    let policy_path_and_name = &resource[6..];
    let name_start = policy_path_and_name.rfind('/').map(|i| i + 1).unwrap_or(0);
    let policy_path = &policy_path_and_name[..name_start];
    let policy_name = policy_path_and_name[name_start..].to_ascii_lowercase();
    let results = match query(indoc! {"
            SELECT managed_policy_id
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(pb_account_id)
    .bind(policy_path)
    .bind(policy_name)
    .fetch_all(tx.as_mut())
    .await
    {
        Ok(results) => results,
        Err(e) => {
            log::error!("Failed to query permissions boundary from database: {e}");
            let message = "Internal failure".to_string();
            return Err(ValidationError::builder().message(message).build().into());
        }
    };

    if results.is_empty() {
        let message = format!("Scope ARN: {permissions_boundary} does not exist or is not attachable");
        let err = NoSuchEntityException::builder().message(message).build();
        return Err(err.into());
    }

    if results.len() > 1 {
        let message = "Multiple permissions boundary policies found with the same name and path; this is a database integrity error".to_string(
        );
        return Err(InternalFailure::builder().message(message).build().into());
    }

    let mp_id: &str = match results[0].try_get(0) {
        Ok(mp_id) => mp_id,
        Err(e) => {
            log::error!("Failed to get permissions boundary ID from database row: {e}");
            let message = "Internal failure".to_string();
            return Err(InternalFailure::builder().message(message).build().into());
        }
    };
    Ok(mp_id.to_string())
}
