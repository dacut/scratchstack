//! PutUserPermissionsBoundary database operation
use {
    crate::{
        RequestExecutor,
        constants::iam::*,
        iam::{get_permissions_boundary_id, internal_failure, validate_account_id, validate_user_name},
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError, operation::PutUserPermissionsBoundaryInternalRequest,
        types::error::NoSuchEntityException,
    },
    sqlx::{postgres::PgTransaction, query},
};

impl RequestExecutor for PutUserPermissionsBoundaryInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        put_user_permissions_boundary(tx, &self.account_id, &self.user_name, &self.permissions_boundary).await
    }
}

/// Set the permissions boundary on a user to the managed policy identified by the supplied ARN.
/// Replaces any previously-set boundary. Returns NoSuchEntityException if either the user or the
/// permissions boundary policy is missing.
pub async fn put_user_permissions_boundary(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    permissions_boundary: &str,
) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;

    let managed_policy_id = get_permissions_boundary_id(tx, account_id, permissions_boundary).await?;

    let result = match query(indoc! {"
            UPDATE iam.users
            SET permissions_boundary_managed_policy_id = $3
            WHERE account_id = $1 AND user_name_lower = $2
        "})
    .bind(account_id)
    .bind(user_name.to_lowercase())
    .bind(managed_policy_id)
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to set user permissions boundary in database: {e}");
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
