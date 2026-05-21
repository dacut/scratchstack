//! DeleteUser database operation
use {
    crate::{
        constants::iam::*,
        ops::{
            RequestExecutor,
            iam::{validate_account_id, validate_user_name},
        },
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::DeleteUserInternalRequest,
        types::error::{InternalFailure, NoSuchEntityException},
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

/// Delete a user from the database.
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
            log::error!("Failed to delete user from database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
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
