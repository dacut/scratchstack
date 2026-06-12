//! GetRolePolicy database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, internal_failure, policy::validate_policy_name,
        role::validate_role_name,
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{GetRolePolicyInternalRequest, GetRolePolicyResponse},
        types::error::NoSuchEntityException,
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for GetRolePolicyInternalRequest {
    type Response = GetRolePolicyResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        get_role_policy(tx, &self.account_id, &self.role_name, &self.policy_name).await
    }
}

/// Retrieve the document of an inline policy attached to a role. Returns `NoSuchEntity` if the
/// role or the named inline policy does not exist.
pub async fn get_role_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
    policy_name: &str,
) -> Result<GetRolePolicyResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name)?;
    validate_policy_name(policy_name)?;

    let role_row = query(indoc! {"
            SELECT role_id, role_name_cased
            FROM iam.roles
            WHERE account_id = $1 AND role_name_lower = $2
        "})
    .bind(account_id)
    .bind(role_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to look up role in database: {e}");
        internal_failure()
    })?;

    let (role_id, role_name_cased): (String, String) = match role_row {
        Some(row) => (row.get(0), row.get(1)),
        None => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The role with name {role_name} cannot be found."))
                .build()
                .into());
        }
    };

    let policy_row = query(indoc! {"
            SELECT policy_name_cased, policy_document
            FROM iam.role_inline_policies
            WHERE role_id = $1 AND policy_name_lower = $2
        "})
    .bind(&role_id)
    .bind(policy_name.to_ascii_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch role inline policy from database: {e}");
        internal_failure()
    })?;

    let (policy_name_cased, policy_document): (String, String) = match policy_row {
        Some(row) => (row.get(0), row.get(1)),
        None => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The inline policy {policy_name} was not found on role {role_name}."))
                .build()
                .into());
        }
    };

    GetRolePolicyResponse::builder()
        .role_name(role_name_cased)
        .policy_name(policy_name_cased)
        .policy_document(policy_document)
        .build()
        .map_err(|e| {
            log::error!("Failed to build GetRolePolicyResponse: {e}");
            internal_failure().into()
        })
}
