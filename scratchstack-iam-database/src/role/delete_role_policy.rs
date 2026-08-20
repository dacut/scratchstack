//! DeleteRolePolicy database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, internal_failure, policy::validate_policy_name,
        role::validate_role_name,
    },
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError, operation::DeleteRolePolicyInternalRequest, types::error::NoSuchEntityException,
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for DeleteRolePolicyInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        delete_role_policy(tx, &self.account_id, &self.role_name, &self.policy_name, request_id).await
    }
}

/// Delete an inline policy from a role. Returns `NoSuchEntity` if either the role or the named
/// inline policy does not exist.
pub async fn delete_role_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
    policy_name: &str,
    request_id: RequestId,
) -> Result<(), IamError> {
    validate_account_id(account_id, request_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name, request_id)?;
    validate_policy_name(policy_name, request_id)?;

    let role_id: String = match query(indoc! {"
            SELECT role_id
            FROM iam.roles
            WHERE account_id = $1 AND role_name_lower = $2
        "})
    .bind(account_id)
    .bind(role_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The role with name {role_name} cannot be found."))
                .request_id(request_id)
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up role in database: {e}");
            return Err(internal_failure(request_id).into());
        }
    };

    let result = match query(indoc! {"
            DELETE FROM iam.role_inline_policies
            WHERE role_id = $1 AND policy_name_lower = $2
        "})
    .bind(&role_id)
    .bind(policy_name.to_ascii_lowercase())
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to delete role inline policy from database: {e}");
            return Err(internal_failure(request_id).into());
        }
    };

    if result.rows_affected() == 0 {
        return Err(NoSuchEntityException::builder()
            .message(format!("The inline policy {policy_name} was not found on role {role_name}."))
            .request_id(request_id)
            .build()
            .into());
    }

    Ok(())
}
