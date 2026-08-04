//! CreatePolicyVersion database operation
use {
    crate::{RequestExecutor, constants::*, internal_failure},
    indoc::indoc,
    log::{error, info},
    scratchstack_arn::IamResourceArn,
    scratchstack_aspen::Policy as AspenPolicy,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{CreatePolicyVersionRequest, CreatePolicyVersionResponse},
        types::{
            PolicyVersion,
            error::{LimitExceededException, MalformedPolicyDocumentException, NoSuchEntityException, ValidationError},
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
    let arn = match IamResourceArn::from_str(policy_arn) {
        Ok(arn) => arn,
        Err(e) => {
            info!("Failed to parse policy ARN: {e}");
            return Err(ValidationError::builder().message("Invalid policy ARN".to_string()).build().into());
        }
    };

    if arn.resource_type() != ARN_RESOURCE_TYPE_POLICY {
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
    .bind(arn.resource_path())
    .bind(arn.resource_name_lower())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            let message = format!("Policy {policy_arn} does not exist or is not attachable.");
            return Err(NoSuchEntityException::builder().message(message).build().into());
        }
        Err(e) => {
            error!("Failed to query managed policy from database: {e}");
            return Err(internal_failure().into());
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
            error!("Failed to insert managed policy version into database: {e}");
            return Err(internal_failure().into());
        }
    };

    let created_at: chrono::DateTime<chrono::Utc> = version_row.try_get(0).map_err(|e| {
        error!("Failed to get created_at from database row: {e}");
        internal_failure()
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
        error!("Failed to update managed policy latest_version: {e}");
        return Err(internal_failure().into());
    }

    let version_id = format!("v{new_version}");
    let policy_version = PolicyVersion::builder()
        .create_date(created_at)
        .document(policy_document)
        .is_default_version(set_as_default)
        .version_id(version_id)
        .build()
        .map_err(|e| {
            error!("Failed to build PolicyVersion: {e}");
            internal_failure()
        })?;

    Ok(CreatePolicyVersionResponse::builder().policy_version(policy_version).build().map_err(|e| {
        error!("Failed to build CreatePolicyVersionResponse: {e}");
        internal_failure()
    })?)
}
