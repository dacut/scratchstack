//! GetPolicyVersion database operation
use {
    crate::{
        RequestExecutor,
        constants::*,
        internal_failure,
        policy::{parse_policy_arn, parse_policy_version_id},
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    log::error,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{GetPolicyVersionRequest, GetPolicyVersionResponse},
        types::{
            PolicyVersion,
            error::{NoSuchEntityException, ValidationError},
        },
    },
    sqlx::{FromRow, postgres::PgTransaction, query_as},
};

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
    let policy_account_id = match parts.account_id() {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let version_number = parse_policy_version_id(version_id).ok_or_else(|| {
        ValidationError::builder().message(format!("Invalid policy version id: {version_id}")).build()
    })?;

    let row: PolicyVersionRow = query_as(indoc! {"
            SELECT mp.default_version, mpv.policy_document, mpv.created_at
            FROM iam.managed_policies mp
            JOIN iam.managed_policy_versions mpv ON mp.managed_policy_id = mpv.managed_policy_id
            WHERE mp.account_id = $1 AND mp.path = $2 AND mp.managed_policy_name_lower = $3
                AND mpv.managed_policy_version = $4
        "})
    .bind(policy_account_id)
    .bind(parts.resource_path())
    .bind(parts.resource_name_lower())
    .bind(version_number)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        error!("Failed to query managed policy version from database: {e}");
        internal_failure()
    })?
    .ok_or_else(|| {
        NoSuchEntityException::builder()
            .message(format!("Policy {policy_arn} version {version_id} was not found."))
            .build()
    })?;

    let policy_version = PolicyVersion::builder()
        .create_date(row.created_at)
        .document(row.policy_document)
        .is_default_version(version_number == row.default_version)
        .version_id(format!("v{version_number}"))
        .build()
        .map_err(|e| {
            error!("Failed to build PolicyVersion: {e}");
            internal_failure()
        })?;

    Ok(GetPolicyVersionResponse::builder().policy_version(policy_version).build().map_err(|e| {
        error!("Failed to build GetPolicyVersionResponse: {e}");
        internal_failure()
    })?)
}
