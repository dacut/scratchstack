//! GetUserPolicy database operation
use {
    crate::{
        constants::iam::*,
        ops::{
            RequestExecutor,
            iam::{validate_account_id, validate_policy_name, validate_user_name},
        },
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{GetUserPolicyInternalRequest, GetUserPolicyResponse},
        types::error::{InternalFailure, NoSuchEntityException},
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for GetUserPolicyInternalRequest {
    type Response = GetUserPolicyResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        get_user_policy(tx, &self.account_id, &self.user_name, &self.policy_name).await
    }
}

/// Retrieve the document of an inline policy attached to a user. Returns `NoSuchEntity` if the
/// user or the named inline policy does not exist.
pub async fn get_user_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    policy_name: &str,
) -> Result<GetUserPolicyResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;
    validate_policy_name(policy_name)?;

    let user_row = query(indoc! {"
            SELECT user_id, user_name_cased
            FROM iam.users
            WHERE account_id = $1 AND user_name_lower = $2
        "})
    .bind(account_id)
    .bind(user_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to look up user in database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    let (user_id, user_name_cased): (String, String) = match user_row {
        Some(row) => (row.get(0), row.get(1)),
        None => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The user with name {user_name} cannot be found."))
                .build()
                .into());
        }
    };

    let policy_row = query(indoc! {"
            SELECT policy_name_cased, policy_document
            FROM iam.user_inline_policies
            WHERE user_id = $1 AND policy_name_lower = $2
        "})
    .bind(&user_id)
    .bind(policy_name.to_ascii_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch user inline policy from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    let (policy_name_cased, policy_document): (String, String) = match policy_row {
        Some(row) => (row.get(0), row.get(1)),
        None => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The inline policy {policy_name} was not found on user {user_name}."))
                .build()
                .into());
        }
    };

    GetUserPolicyResponse::builder()
        .user_name(user_name_cased)
        .policy_name(policy_name_cased)
        .policy_document(policy_document)
        .build()
        .map_err(|e| {
            log::error!("Failed to build GetUserPolicyResponse: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })
}
