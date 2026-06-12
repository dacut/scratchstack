//! GetGroupPolicy database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, group::validate_group_name, internal_failure,
        policy::validate_policy_name,
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{GetGroupPolicyInternalRequest, GetGroupPolicyResponse},
        types::error::NoSuchEntityException,
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for GetGroupPolicyInternalRequest {
    type Response = GetGroupPolicyResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        get_group_policy(tx, &self.account_id, &self.group_name, &self.policy_name).await
    }
}

/// Retrieve the document of an inline policy attached to a group. Returns `NoSuchEntity` if the
/// group or the named inline policy does not exist.
pub async fn get_group_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    group_name: &str,
    policy_name: &str,
) -> Result<GetGroupPolicyResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_group_name(group_name)?;
    validate_policy_name(policy_name)?;

    let group_row = query(indoc! {"
            SELECT group_id, group_name_cased
            FROM iam.groups
            WHERE account_id = $1 AND group_name_lower = $2
        "})
    .bind(account_id)
    .bind(group_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to look up group in database: {e}");
        internal_failure()
    })?;

    let (group_id, group_name_cased): (String, String) = match group_row {
        Some(row) => (row.get(0), row.get(1)),
        None => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The group with name {group_name} cannot be found."))
                .build()
                .into());
        }
    };

    let policy_row = query(indoc! {"
            SELECT policy_name_cased, policy_document
            FROM iam.group_inline_policies
            WHERE group_id = $1 AND policy_name_lower = $2
        "})
    .bind(&group_id)
    .bind(policy_name.to_ascii_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch group inline policy from database: {e}");
        internal_failure()
    })?;

    let (policy_name_cased, policy_document): (String, String) = match policy_row {
        Some(row) => (row.get(0), row.get(1)),
        None => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The inline policy {policy_name} was not found on group {group_name}."))
                .build()
                .into());
        }
    };

    GetGroupPolicyResponse::builder()
        .group_name(group_name_cased)
        .policy_name(policy_name_cased)
        .policy_document(policy_document)
        .build()
        .map_err(|e| {
            log::error!("Failed to build GetGroupPolicyResponse: {e}");
            internal_failure().into()
        })
}
