//! SetDefaultPolicyVersion database operation
use {
    crate::{
        RequestExecutor,
        constants::*,
        internal_failure,
        policy::{parse_policy_arn, parse_policy_version_id},
    },
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::SetDefaultPolicyVersionRequest,
        types::error::{NoSuchEntityException, ValidationError},
    },
    sqlx::{FromRow, postgres::PgTransaction, query, query_as},
};

impl RequestExecutor for SetDefaultPolicyVersionRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        set_default_policy_version(tx, &self.policy_arn, &self.version_id, request_id).await
    }
}

/// Set the default version of a managed policy by ARN.
pub async fn set_default_policy_version(
    tx: &mut PgTransaction<'_>,
    policy_arn: &str,
    version_id: &str,
    request_id: RequestId,
) -> Result<(), IamError> {
    /// The row returned by the query to the iam.policies table to get the managed_policy_id for
    /// the requested policy ARN.
    #[derive(FromRow)]
    struct PolicyRow {
        managed_policy_id: String,
    }

    let parts = parse_policy_arn(policy_arn, request_id)?;
    let policy_account_id = match parts.account_id() {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let version_number = parse_policy_version_id(version_id).ok_or_else(|| {
        ValidationError::builder()
            .message(format!("Invalid policy version id: {version_id}"))
            .request_id(request_id)
            .build()
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
    .bind(policy_account_id)
    .bind(parts.resource_path())
    .bind(parts.resource_name_lower())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| internal_failure!(request_id; "Failed to query managed policy from database: {e}"))?
    .ok_or_else(|| {
        NoSuchEntityException::builder()
            .message(format!("Policy {policy_arn} was not found."))
            .request_id(request_id)
            .build()
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
    .map_err(|e| internal_failure!(request_id; "Failed to query managed policy version from database: {e}"))?;

    if version_exists.is_none() {
        return Err(NoSuchEntityException::builder()
            .message(format!("Policy {policy_arn} version {version_id} was not found."))
            .request_id(request_id)
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
    .map_err(|e| internal_failure!(request_id; "Failed to update managed policy default_version: {e}"))?;

    Ok(())
}
