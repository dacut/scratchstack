//! ListAccountAliases database level operations.
use {
    crate::{
        constants::iam::*,
        ops::{RequestExecutor, iam::validate_account_id},
    },
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListAccountAliasesInternalRequest, ListAccountAliasesResponse},
        types::error::{InternalFailure, NoSuchEntityException},
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for ListAccountAliasesInternalRequest {
    type Response = ListAccountAliasesResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_account_aliases(tx, self.account_id.clone()).await
    }
}

/// List all aliases for the account with the given account ID.
///
/// AWS accounts can only have one alias, so this will return either a single alias or an empty
/// list.
pub async fn list_account_aliases(
    tx: &mut PgTransaction<'_>,
    account_id: String,
) -> Result<ListAccountAliasesResponse, IamError> {
    validate_account_id(&account_id)?;

    let result = query("SELECT alias FROM iam.accounts WHERE account_id = $1")
        .bind(&account_id)
        .fetch_optional(tx.as_mut())
        .await
        .map_err(|e| {
            log::error!(
                "ListAccountAliases query failed for account {account_id} (query: SELECT alias FROM iam.accounts WHERE account_id = $1): {e}"
            );
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;

    match result {
        Some(row) => {
            let alias: Option<String> = row.try_get(0).map_err(|e| {
                log::error!("Failed to get account alias for account {account_id}: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?;
            Ok(ListAccountAliasesResponse {
                account_aliases: alias.into_iter().collect(),
                is_truncated: Some(false),
                marker: None,
            })
        }
        None => {
            let message = format!("Account with ID {account_id} does not exist.");
            Err(NoSuchEntityException::builder().message(message).build().into())
        }
    }
}
