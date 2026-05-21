//! CreatePolicyVersion database operation
use {
    crate::{constants::iam::*, ops::RequestExecutor},
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aspen::Policy as AspenPolicy,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{CreatePolicyVersionRequest, CreatePolicyVersionResponse},
        types::{
            PolicyVersion,
            error::{
                InternalFailure, LimitExceededException, MalformedPolicyDocumentException, NoSuchEntityException,
                ValidationError,
            },
        },
    },
    sqlx::{FromRow, Row as _, postgres::PgTransaction, query, query_as},
    std::str::FromStr as _,
};

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
