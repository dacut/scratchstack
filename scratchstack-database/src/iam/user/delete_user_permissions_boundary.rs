//! DeleteUserPermissionsBoundary database operation
use {
    crate::{
        RequestExecutor,
        constants::iam::*,
        iam::{internal_failure, validate_account_id, validate_user_name},
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError, operation::DeleteUserPermissionsBoundaryInternalRequest,
        types::error::NoSuchEntityException,
    },
    sqlx::{postgres::PgTransaction, query},
};

impl RequestExecutor for DeleteUserPermissionsBoundaryInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        delete_user_permissions_boundary(tx, &self.account_id, &self.user_name).await
    }
}

/// Clear the permissions boundary on a user. If the user exists but has no permissions boundary,
/// the call is a no-op (matches AWS DeleteUserPermissionsBoundary semantics). If the user does not
/// exist, returns NoSuchEntityException.
pub async fn delete_user_permissions_boundary(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;

    let result = match query(indoc! {"
            UPDATE iam.users
            SET permissions_boundary_managed_policy_id = NULL
            WHERE account_id = $1 AND user_name_lower = $2
        "})
    .bind(account_id)
    .bind(user_name.to_lowercase())
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to clear user permissions boundary in database: {e}");
            return Err(internal_failure().into());
        }
    };

    if result.rows_affected() == 0 {
        return Err(NoSuchEntityException::builder()
            .message(format!("The user with name {user_name} cannot be found."))
            .build()
            .into());
    }

    Ok(())
}
