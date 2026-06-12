//! DetachGroupPolicy database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, group::validate_group_name, internal_failure,
        policy::parse_policy_arn,
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError, operation::DetachGroupPolicyInternalRequest, types::error::NoSuchEntityException,
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for DetachGroupPolicyInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        detach_group_policy(tx, &self.account_id, &self.group_name, &self.policy_arn).await
    }
}

/// Detach a managed policy from a group in the database.
pub async fn detach_group_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    group_name: &str,
    policy_arn: &str,
) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_group_name(group_name)?;

    let parts = parse_policy_arn(policy_arn)?;
    if parts.account_id() != account_id && parts.account_id() != AWS_ACCOUNT_ID {
        return Err(NoSuchEntityException::builder()
            .message(format!("Policy {policy_arn} was not found."))
            .build()
            .into());
    }
    let policy_account_id = match parts.account_id() {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };

    // Look up the managed_policy_id.
    let managed_policy_id: String = match query(indoc! {"
            SELECT managed_policy_id
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(policy_account_id)
    .bind(parts.resource_path())
    .bind(parts.resource_name_lower())
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
            return Err(internal_failure().into());
        }
    };

    // Look up the group_id.
    let group_id: String = match query(indoc! {"
            SELECT group_id
            FROM iam.groups
            WHERE account_id = $1 AND group_name_lower = $2
        "})
    .bind(account_id)
    .bind(group_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The group with name {group_name} cannot be found."))
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up group in database: {e}");
            return Err(internal_failure().into());
        }
    };

    let result = match query(indoc! {"
            DELETE FROM iam.group_attached_policies
            WHERE group_id = $1 AND managed_policy_id = $2
        "})
    .bind(&group_id)
    .bind(&managed_policy_id)
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to detach policy from group in database: {e}");
            return Err(internal_failure().into());
        }
    };

    if result.rows_affected() == 0 {
        return Err(NoSuchEntityException::builder()
            .message(format!("Policy {policy_arn} was not found attached to group {group_name}."))
            .build()
            .into());
    }

    Ok(())
}
