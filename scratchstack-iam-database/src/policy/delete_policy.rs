//! DeletePolicy database operation
use {
    crate::{RequestExecutor, constants::*, internal_failure, policy::parse_policy_arn},
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::DeletePolicyRequest,
        types::error::{DeleteConflictException, NoSuchEntityException},
    },
    sqlx::{FromRow, postgres::PgTransaction, query, query_as},
};

impl RequestExecutor for DeletePolicyRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        delete_policy(tx, &self.policy_arn, request_id).await
    }
}

/// Delete a managed policy. The policy must have no attachments to users, groups, or roles, must
/// not be used as a permissions boundary, and must have only the default version remaining (all
/// other versions must have been deleted via
/// [`delete_policy_version`][crate::policy::delete_policy_version] first). On success the
/// remaining default version and all tags are removed along with the policy via FK cascade.
///
/// # Errors
///
/// A [`NoSuchEntityException`] if no policy matches the ARN, and a [`DeleteConflictException`] if
/// one does but any of the conditions above is unmet. Those are checked before the delete, and
/// each says which condition it was and how many rows are holding the policy; a foreign-key
/// violation from the delete itself is reported the same way, for a row that arrived after the
/// checks ran.
pub async fn delete_policy(
    tx: &mut PgTransaction<'_>,
    policy_arn: &str,
    request_id: RequestId,
) -> Result<(), IamError> {
    /// The row returned by the lookup query against iam.managed_policies.
    #[derive(FromRow)]
    struct PolicyRow {
        managed_policy_id: String,
    }

    /// The row returned by the conflict-check aggregation. Each column is the count for one of
    /// the relations DeletePolicy needs to be empty before it can proceed.
    #[derive(FromRow)]
    struct ConflictCountsRow {
        user_attachments: i64,
        group_attachments: i64,
        role_attachments: i64,
        user_permissions_boundaries: i64,
        role_permissions_boundaries: i64,
        non_default_versions: i64,
    }

    let parts = parse_policy_arn(policy_arn, request_id)?;
    let account_id = match parts.account_id() {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };

    // Lock the parent row so a concurrent CreatePolicyVersion / attachment / permissions-boundary
    // assignment can't slip in between the conflict checks and the DELETE.
    let policy_row: PolicyRow = match query_as(indoc! {"
            SELECT managed_policy_id
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
            FOR UPDATE
        "})
    .bind(account_id)
    .bind(parts.resource_path())
    .bind(parts.resource_name_lower())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            let message = format!("Policy {policy_arn} was not found.");
            log::info!("{request_id}: {message}");
            return Err(NoSuchEntityException::builder().message(message).request_id(request_id).build().into());
        }
        Err(e) => {
            return Err(internal_failure!(request_id; "Failed to query managed policy from database: {e}").into());
        }
    };

    // Gather every blocking condition in a single round-trip. The default_version column is
    // excluded from the non_default_versions count so the remaining check is just "any other
    // version still around?"
    let counts: ConflictCountsRow = match query_as(indoc! {"
            SELECT
                (SELECT COUNT(*) FROM iam.user_attached_policies WHERE managed_policy_id = $1)
                    AS user_attachments,
                (SELECT COUNT(*) FROM iam.group_attached_policies WHERE managed_policy_id = $1)
                    AS group_attachments,
                (SELECT COUNT(*) FROM iam.role_attached_policies WHERE managed_policy_id = $1)
                    AS role_attachments,
                (SELECT COUNT(*) FROM iam.users WHERE permissions_boundary_managed_policy_id = $1)
                    AS user_permissions_boundaries,
                (SELECT COUNT(*) FROM iam.roles WHERE permissions_boundary_managed_policy_id = $1)
                    AS role_permissions_boundaries,
                (SELECT COUNT(*) FROM iam.managed_policy_versions mpv
                    JOIN iam.managed_policies mp ON mp.managed_policy_id = mpv.managed_policy_id
                    WHERE mpv.managed_policy_id = $1
                        AND mpv.managed_policy_version <> mp.default_version)
                    AS non_default_versions
        "})
    .bind(&policy_row.managed_policy_id)
    .fetch_one(tx.as_mut())
    .await
    {
        Ok(row) => row,
        Err(e) => {
            return Err(
                internal_failure!(request_id; "Failed to query DeletePolicy conflict counts from database: {e}").into(),
            );
        }
    };

    let attachment_total = counts.user_attachments + counts.group_attachments + counts.role_attachments;
    if attachment_total > 0 {
        let message = format!(
            "Cannot delete a policy attached to entities. The policy {policy_arn} is attached to {attachment_total} entities (users, groups, or roles)."
        );
        return Err(DeleteConflictException::builder().message(message).request_id(request_id).build().into());
    }

    let permissions_boundary_total = counts.user_permissions_boundaries + counts.role_permissions_boundaries;
    if permissions_boundary_total > 0 {
        let message = format!(
            "Cannot delete a policy used as a permissions boundary. The policy {policy_arn} is the permissions boundary for {permissions_boundary_total} entities (users or roles)."
        );
        return Err(DeleteConflictException::builder().message(message).request_id(request_id).build().into());
    }

    if counts.non_default_versions > 0 {
        let message = format!(
            "Cannot delete a policy with non-default versions. The policy {policy_arn} has {} non-default versions remaining. You must delete those versions before deleting the policy.",
            counts.non_default_versions
        );
        return Err(DeleteConflictException::builder().message(message).request_id(request_id).build().into());
    }

    // FK cascade handles managed_policy_versions (the default version) and managed_policy_tags.
    // The unchanged user/group/role_attached_policies FKs and the users/roles permissions-boundary
    // FKs act as a backstop: if a concurrent transaction managed to slip an attachment in despite
    // the FOR UPDATE row lock, the DELETE will fail with a FK violation rather than corrupt state.
    if let Err(e) = query(indoc! {"
            DELETE FROM iam.managed_policies
            WHERE managed_policy_id = $1
        "})
    .bind(&policy_row.managed_policy_id)
    .execute(tx.as_mut())
    .await
    {
        if let sqlx::Error::Database(db_err) = &e
            && db_err.code().as_deref() == Some("23503")
        {
            let message = format!(
                "Cannot delete policy {policy_arn} because it is attached to an entity or is set as a permissions boundary."
            );
            return Err(DeleteConflictException::builder().message(message).request_id(request_id).build().into());
        }

        return Err(internal_failure!(request_id; "Failed to delete managed policy from database: {e}").into());
    }

    Ok(())
}
