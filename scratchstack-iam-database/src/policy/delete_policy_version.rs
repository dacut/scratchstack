//! DeletePolicyVersion database operation
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
        operation::DeletePolicyVersionRequest,
        types::error::{DeleteConflictException, NoSuchEntityException, ValidationError},
    },
    sqlx::{FromRow, postgres::PgTransaction, query, query_as},
};

impl RequestExecutor for DeletePolicyVersionRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        delete_policy_version(tx, &self.policy_arn, &self.version_id, request_id).await
    }
}

/// Delete a non-default version of a managed policy.
pub async fn delete_policy_version(
    tx: &mut PgTransaction<'_>,
    policy_arn: &str,
    version_id: &str,
    request_id: RequestId,
) -> Result<(), IamError> {
    /// The row returned by the query to the iam.policies table to get the managed_policy_id,
    /// default_version, and latest_version for the requested policy ARN.
    #[derive(FromRow)]
    struct PolicyRow {
        managed_policy_id: String,
        default_version: i64,
        latest_version: i64,
    }

    let parts = parse_policy_arn(policy_arn, request_id)?;
    let policy_account_id = match parts.account_id() {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };

    // Parse the numeric portion of the version id. The Smithy regex enforces
    // ^v[1-9][0-9]*(\.[A-Za-z0-9-]*)?$, so version_id always starts with 'v' followed by digits
    // and optionally a '.suffix'. We accept the input defensively in case the builder is bypassed.
    let version_number = parse_policy_version_id(version_id).ok_or_else(|| {
        ValidationError::builder()
            .message(format!("Invalid policy version id: {version_id}"))
            .request_id(request_id)
            .build()
    })?;

    // Lock the managed_policies row to prevent a race in which another transaction sets the
    // default version to the one being deleted between our default-version check and the delete.
    let policy_row: PolicyRow = match query_as(indoc! {"
            SELECT managed_policy_id, default_version, latest_version
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
            FOR UPDATE
        "})
    .bind(policy_account_id)
    .bind(parts.resource_path())
    .bind(parts.resource_name_lower())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            let message = format!("Policy {policy_arn} was not found.");
            return Err(NoSuchEntityException::builder().message(message).request_id(request_id).build().into());
        }
        Err(e) => {
            return Err(internal_failure!(request_id; "Failed to query managed policy from database: {e}").into());
        }
    };

    if version_number == policy_row.default_version {
        let message = "Cannot delete the default version of a policy. To delete the default version, you must first set another version as the default.".to_string();
        return Err(DeleteConflictException::builder().message(message).request_id(request_id).build().into());
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
            return Err(
                internal_failure!(request_id; "Failed to delete managed policy version from database: {e}").into()
            );
        }
    };

    if result.rows_affected() == 0 {
        let message = format!("Policy {policy_arn} version {version_id} was not found.");
        return Err(NoSuchEntityException::builder().message(message).request_id(request_id).build().into());
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
        return Err(internal_failure!(request_id; "Failed to recompute managed policy update_date: {e}").into());
    }

    Ok(())
}
