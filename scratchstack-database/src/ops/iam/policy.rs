//! Policy-level database operations.
use {
    crate::{
        constants::iam::*,
        model::iam::IamId,
        ops::{
            RequestExecutor,
            iam::{
                get_current_partition_or_fail, validate_account_id, validate_path, validate_policy_name,
                validate_tag_key, validate_tag_value,
            },
        },
    },
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aspen::Policy as AspenPolicy,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreatePolicyInternalRequest, CreatePolicyResponse, CreatePolicyVersionRequest, CreatePolicyVersionResponse,
            DeletePolicyVersionRequest,
        },
        types::{
            PolicyVersion, Tag,
            error::{
                DeleteConflictException, InternalFailure, LimitExceededException, MalformedPolicyDocumentException,
                NoSuchEntityException, ValidationError,
            },
        },
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
    std::str::FromStr as _,
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

    let policy = scratchstack_shapes_iam::types::Policy::builder()
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

    Ok(CreatePolicyResponse::builder().policy(Some(policy)).build().unwrap())
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
    let row = match query(indoc! {"
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

    let managed_policy_id: &str = row.try_get(0).map_err(|e| {
        log::error!("Failed to get managed_policy_id from database row: {e}");
        InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
    })?;
    let latest_version: i64 = row.try_get(1).map_err(|e| {
        log::error!("Failed to get latest_version from database row: {e}");
        InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
    })?;

    // AWS limits managed policies to 5 versions.
    let new_version = latest_version + 1;
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
    .bind(managed_policy_id)
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

    // Update latest_version (and default_version if set_as_default).
    let update_query = if set_as_default {
        query(indoc! {"
                UPDATE iam.managed_policies
                SET latest_version = $1, default_version = $1
                WHERE managed_policy_id = $2
            "})
        .bind(new_version)
        .bind(managed_policy_id)
    } else {
        query(indoc! {"
                UPDATE iam.managed_policies
                SET latest_version = $1
                WHERE managed_policy_id = $2
            "})
        .bind(new_version)
        .bind(managed_policy_id)
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

    Ok(CreatePolicyVersionResponse::builder().policy_version(Some(policy_version)).build().unwrap())
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

    // Parse the numeric portion of the version id. The Smithy regex enforces
    // ^v[1-9][0-9]*(\.[A-Za-z0-9-]*)?$, so version_id always starts with 'v' followed by digits
    // and optionally a '.suffix'. We accept the input defensively in case the builder is bypassed.
    let version_number = parse_policy_version_id(version_id).ok_or_else(|| {
        IamError::from(ValidationError::builder().message(format!("Invalid policy version id: {version_id}")).build())
    })?;

    // Lock the managed_policies row to prevent a race in which another transaction sets the
    // default version to the one being deleted between our default-version check and the delete.
    let row = match query(indoc! {"
            SELECT managed_policy_id, default_version
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
            FOR UPDATE
        "})
    .bind(account_id)
    .bind(&policy_path)
    .bind(&policy_name_lower)
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

    let managed_policy_id: &str = row.try_get(0).map_err(|e| {
        log::error!("Failed to get managed_policy_id from database row: {e}");
        InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
    })?;
    let default_version: i64 = row.try_get(1).map_err(|e| {
        log::error!("Failed to get default_version from database row: {e}");
        InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
    })?;

    if version_number == default_version {
        let message = "Cannot delete the default version of a policy. To delete the default version, you must first set another version as the default.".to_string();
        return Err(DeleteConflictException::builder().message(message).build().into());
    }

    let result = match query(indoc! {"
            DELETE FROM iam.managed_policy_versions
            WHERE managed_policy_id = $1 AND managed_policy_version = $2
        "})
    .bind(managed_policy_id)
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

    Ok(())
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
