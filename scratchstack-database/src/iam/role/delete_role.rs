//! DeleteRole database operation
use {
    crate::{
        RequestExecutor,
        constants::iam::*,
        iam::{validate_account_id, validate_role_name},
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::DeleteRoleInternalRequest,
        types::error::{DeleteConflictException, InternalFailure, NoSuchEntityException},
    },
    sqlx::{postgres::PgTransaction, query},
};

impl RequestExecutor for DeleteRoleInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        delete_role(tx, &self.account_id, &self.role_name).await
    }
}

/// Delete a role from the database. The role must have no remaining dependent resources
/// (attached managed policies, inline policies, etc.); a FK violation from the underlying DELETE
/// is surfaced as `DeleteConflictException`. Role tags are removed via FK cascade.
pub async fn delete_role(tx: &mut PgTransaction<'_>, account_id: &str, role_name: &str) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name)?;

    let result = match query(indoc! {"
            DELETE FROM iam.roles
            WHERE account_id = $1 AND role_name_lower = $2
        "})
    .bind(account_id)
    .bind(role_name.to_lowercase())
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            if let sqlx::Error::Database(db_err) = &e
                && db_err.code().as_deref() == Some("23503")
            {
                let message = format!(
                    "Cannot delete role {role_name} because it has attached managed policies, inline policies, or other dependent resources. You must remove them before deleting the role."
                );
                return Err(DeleteConflictException::builder().message(message).build().into());
            }
            log::error!("Failed to delete role from database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if result.rows_affected() == 0 {
        Err(NoSuchEntityException::builder()
            .message(format!("The role with name {role_name} cannot be found."))
            .build()
            .into())
    } else {
        Ok(())
    }
}
