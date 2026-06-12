//! DeleteUser database operation
use {
    crate::{RequestExecutor, account::validate_account_id, constants::*, internal_failure, user::validate_user_name},
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::DeleteUserInternalRequest,
        types::error::{DeleteConflictException, NoSuchEntityException},
    },
    sqlx::{postgres::PgTransaction, query},
};

impl RequestExecutor for DeleteUserInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        delete_user(tx, &self.account_id, &self.user_name).await
    }
}

/// Delete a user from the database. The user must have no remaining dependent resources
/// (attached managed policies, inline policies, etc.); a FK violation from the underlying DELETE
/// is surfaced as `DeleteConflictException`. User tags are removed via FK cascade.
pub async fn delete_user(tx: &mut PgTransaction<'_>, account_id: &str, user_name: &str) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;

    let result = match query(indoc! {"
            DELETE FROM iam.users
            WHERE account_id = $1 AND user_name_lower = $2
        "})
    .bind(account_id)
    .bind(user_name.to_lowercase())
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            if let sqlx::Error::Database(db_err) = &e
                && db_err.code().as_deref() == Some("23503")
            {
                let message = format!(
                    "Cannot delete user {user_name} because it has attached managed policies, inline policies, or other dependent resources. You must remove them before deleting the user."
                );
                return Err(DeleteConflictException::builder().message(message).build().into());
            }
            log::error!("Failed to delete user from database: {e}");
            return Err(internal_failure().into());
        }
    };

    if result.rows_affected() == 0 {
        Err(NoSuchEntityException::builder()
            .message(format!("The user with name {user_name} cannot be found."))
            .build()
            .into())
    } else {
        Ok(())
    }
}
