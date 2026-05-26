//! DetachUserPolicy database operation
use {
    crate::{
        RequestExecutor,
        constants::iam::*,
        iam::{parse_policy_arn, validate_account_id, validate_user_name},
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::DetachUserPolicyInternalRequest,
        types::error::{InternalFailure, NoSuchEntityException},
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for DetachUserPolicyInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        detach_user_policy(tx, &self.account_id, &self.user_name, &self.policy_arn).await
    }
}

/// Detach a managed policy from a user in the database.
pub async fn detach_user_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    policy_arn: &str,
) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;

    let parts = parse_policy_arn(policy_arn)?;
    if parts.account_id != account_id && parts.account_id != AWS_ACCOUNT_ID_NUMERIC {
        return Err(NoSuchEntityException::builder()
            .message(format!("Policy {policy_arn} was not found."))
            .build()
            .into());
    }

    // Look up the managed_policy_id.
    let managed_policy_id: String = match query(indoc! {"
            SELECT managed_policy_id
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(&parts.account_id)
    .bind(&parts.policy_path)
    .bind(&parts.policy_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("Policy {policy_arn} was not found."))
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up managed policy in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    // Look up the user_id.
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
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    let result = match query(indoc! {"
            DELETE FROM iam.user_attached_policies
            WHERE user_id = $1 AND managed_policy_id = $2
        "})
    .bind(&user_id)
    .bind(&managed_policy_id)
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to detach policy from user in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if result.rows_affected() == 0 {
        return Err(NoSuchEntityException::builder()
            .message(format!("Policy {policy_arn} was not found attached to user {user_name}."))
            .build()
            .into());
    }

    Ok(())
}
