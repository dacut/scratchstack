//! DeleteRolePermissionsBoundary database operation
use {
    crate::{
        RequestExecutor,
        constants::iam::*,
        iam::{validate_account_id, validate_role_name},
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::DeleteRolePermissionsBoundaryInternalRequest,
        types::error::{InternalFailure, NoSuchEntityException},
    },
    sqlx::{postgres::PgTransaction, query},
};

impl RequestExecutor for DeleteRolePermissionsBoundaryInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        delete_role_permissions_boundary(tx, &self.account_id, &self.role_name).await
    }
}

/// Clear the permissions boundary on a role. If the role exists but has no permissions boundary,
/// the call is a no-op (matches AWS DeleteRolePermissionsBoundary semantics). If the role does not
/// exist, returns NoSuchEntityException.
pub async fn delete_role_permissions_boundary(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name)?;

    let result = match query(indoc! {"
            UPDATE iam.roles
            SET permissions_boundary_managed_policy_id = NULL
            WHERE account_id = $1 AND role_name_lower = $2
        "})
    .bind(account_id)
    .bind(role_name.to_lowercase())
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to clear role permissions boundary in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if result.rows_affected() == 0 {
        return Err(NoSuchEntityException::builder()
            .message(format!("The role with name {role_name} cannot be found."))
            .build()
            .into());
    }

    Ok(())
}
