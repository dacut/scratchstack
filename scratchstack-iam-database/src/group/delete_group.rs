//! DeleteGroup database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, group::validate_group_name, internal_failure,
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::DeleteGroupInternalRequest,
        types::error::{DeleteConflictException, NoSuchEntityException},
    },
    sqlx::{postgres::PgTransaction, query},
};

impl RequestExecutor for DeleteGroupInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        delete_group(tx, &self.account_id, &self.group_name).await
    }
}

/// Delete a group from the database. The group must have no remaining dependent resources
/// (attached managed policies, inline policies, etc.); a FK violation from the underlying DELETE
/// is surfaced as `DeleteConflictException`. Group memberships are removed via FK cascade.
pub async fn delete_group(tx: &mut PgTransaction<'_>, account_id: &str, group_name: &str) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_group_name(group_name)?;

    let result = match query(indoc! {"
            DELETE FROM iam.groups
            WHERE account_id = $1 AND group_name_lower = $2
        "})
    .bind(account_id)
    .bind(group_name.to_lowercase())
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            if let sqlx::Error::Database(db_err) = &e
                && db_err.code().as_deref() == Some("23503")
            {
                let message = format!(
                    "Cannot delete group {group_name} because it has attached managed policies, inline policies, or other dependent resources. You must remove them before deleting the group."
                );
                return Err(DeleteConflictException::builder().message(message).build().into());
            }
            log::error!("Failed to delete group from database: {e}");
            return Err(internal_failure().into());
        }
    };

    if result.rows_affected() == 0 {
        Err(NoSuchEntityException::builder()
            .message(format!("The group with name {group_name} cannot be found."))
            .build()
            .into())
    } else {
        Ok(())
    }
}
