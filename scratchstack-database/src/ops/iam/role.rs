//! Role database level operations.
use {
    crate::{
        constants::iam::*,
        ops::{
            RequestExecutor,
            iam::{parse_policy_arn, validate_account_id, validate_role_name},
        },
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::AttachRolePolicyInternalRequest,
        types::error::{InternalFailure, NoSuchEntityException},
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for AttachRolePolicyInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        attach_role_policy(tx, &self.account_id, &self.role_name, &self.policy_arn).await
    }
}

/// Attach a managed policy to a role in the database.
pub async fn attach_role_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
    policy_arn: &str,
) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name)?;

    let parts = parse_policy_arn(policy_arn)?;

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

    // Look up the role_id.
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
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up role in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if let Err(e) = query(indoc! {"
            INSERT INTO iam.role_attached_policies(role_id, managed_policy_id)
            VALUES($1, $2)
            ON CONFLICT (role_id, managed_policy_id) DO NOTHING
        "})
    .bind(&role_id)
    .bind(&managed_policy_id)
    .execute(tx.as_mut())
    .await
    {
        log::error!("Failed to attach policy to role in database: {e}");
        return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
    }

    Ok(())
}
