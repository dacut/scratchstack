//! DeleteRole database operation
use {
    crate::{
        constants::iam::*,
        ops::{
            RequestExecutor,
            iam::{validate_account_id, validate_role_name},
        },
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::DeleteRoleInternalRequest,
        types::error::{DeleteConflictException, InternalFailure, NoSuchEntityException},
    },
    sqlx::{FromRow, postgres::PgTransaction, query, query_as},
};

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

    // Race protection comes from the FOR UPDATE row lock above: a concurrent
    // AttachRolePolicy / PutRolePolicy needs a share lock on this iam.roles row to validate its
    // FK, so it blocks until we commit or rolls back if we delete first. role_tags,
    // role_attached_policies, and role_inline_policies all cascade on role_id, so this DELETE
    // takes any leftover rows with it.
    if let Err(e) = query(indoc! {"
            DELETE FROM iam.roles
            WHERE role_id = $1
        "})
    .bind(&role_row.role_id)
    .execute(tx.as_mut())
    .await
    {
        log::error!("Failed to delete role from database: {e}");
        return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
    }

    Ok(())
}
