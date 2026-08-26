//! AttachGroupPolicy database operation
use {
    crate::{
        RequestExecutor,
        account::validate_account_id,
        constants::*,
        group::validate_group_name,
        internal_failure,
        policy::{parse_policy_arn, resolve_policy_account_id},
    },
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError, operation::AttachGroupPolicyInternalRequest, types::error::NoSuchEntityException,
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for AttachGroupPolicyInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        attach_group_policy(tx, &self.account_id, &self.group_name, &self.policy_arn, request_id).await
    }
}

/// Attach a managed policy to a group in the database.
pub async fn attach_group_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    group_name: &str,
    policy_arn: &str,
    request_id: RequestId,
) -> Result<(), IamError> {
    validate_account_id(account_id, request_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_group_name(group_name, request_id)?;

    // Managed policies are not shared across accounts, so the ARN reaches this account's own
    // policies and the AWS-managed ones and nothing else.
    let parts = parse_policy_arn(policy_arn, request_id)?;
    let policy_account_id = resolve_policy_account_id(account_id, &parts, request_id)?;

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
                .request_id(request_id)
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up managed policy in database: {e}");
            return Err(internal_failure(request_id).into());
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
                .request_id(request_id)
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up group in database: {e}");
            return Err(internal_failure(request_id).into());
        }
    };

    if let Err(e) = query(indoc! {"
            INSERT INTO iam.group_attached_policies(group_id, managed_policy_id)
            VALUES($1, $2)
            ON CONFLICT (group_id, managed_policy_id) DO NOTHING
        "})
    .bind(&group_id)
    .bind(&managed_policy_id)
    .execute(tx.as_mut())
    .await
    {
        log::error!("Failed to attach policy to group in database: {e}");
        return Err(internal_failure(request_id).into());
    }

    Ok(())
}
