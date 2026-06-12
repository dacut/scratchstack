//! DeleteUserPolicy database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, internal_failure, policy::validate_policy_name,
        user::validate_user_name,
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError, operation::DeleteUserPolicyInternalRequest, types::error::NoSuchEntityException,
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for DeleteUserPolicyInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        delete_user_policy(tx, &self.account_id, &self.user_name, &self.policy_name).await
    }
}

/// Delete an inline policy from a user. Returns `NoSuchEntity` if either the user or the named
/// inline policy does not exist.
pub async fn delete_user_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    policy_name: &str,
) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;
    validate_policy_name(policy_name)?;

    let user_id: String = match query(indoc! {"
            SELECT user_id
            FROM iam.users
            WHERE account_id = $1 AND user_name_lower = $2
        "})
    .bind(account_id)
    .bind(user_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The user with name {user_name} cannot be found."))
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up user in database: {e}");
            return Err(internal_failure().into());
        }
    };

    let result = match query(indoc! {"
            DELETE FROM iam.user_inline_policies
            WHERE user_id = $1 AND policy_name_lower = $2
        "})
    .bind(&user_id)
    .bind(policy_name.to_ascii_lowercase())
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to delete user inline policy from database: {e}");
            return Err(internal_failure().into());
        }
    };

    if result.rows_affected() == 0 {
        return Err(NoSuchEntityException::builder()
            .message(format!("The inline policy {policy_name} was not found on user {user_name}."))
            .build()
            .into());
    }

    Ok(())
}
