//! ListAccountAliases database level operations.
use {
    crate::{RequestExecutor, account::validate_account_id, internal_failure},
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListAccountAliasesInternalRequest, ListAccountAliasesResponse},
        types::error::NoSuchEntityException,
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for ListAccountAliasesInternalRequest {
    type Response = ListAccountAliasesResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        list_account_aliases(tx, self.account_id.clone(), request_id).await
    }
}

/// List all aliases for the account with the given account ID.
///
/// AWS accounts can only have one alias, so this will return either a single alias or an empty
/// list.
pub async fn list_account_aliases(
    tx: &mut PgTransaction<'_>,
    account_id: String,
    request_id: RequestId,
) -> Result<ListAccountAliasesResponse, IamError> {
    validate_account_id(&account_id, request_id)?;

    let result = query("SELECT alias FROM iam.accounts WHERE account_id = $1")
        .bind(&account_id)
        .fetch_optional(tx.as_mut())
        .await
        .map_err(|e| {
            internal_failure!(request_id;
                "ListAccountAliases query failed for account {account_id} (query: SELECT alias FROM iam.accounts WHERE account_id = $1): {e}"
            )
        })?;

    match result {
        Some(row) => {
            let alias: Option<String> = row.try_get(0).map_err(
                |e| internal_failure!(request_id; "Failed to get account alias for account {account_id}: {e}"),
            )?;
            Ok(ListAccountAliasesResponse {
                account_aliases: alias.into_iter().collect(),
                is_truncated: Some(false),
                marker: None,
            })
        }
        None => {
            let message = format!("Account with ID {account_id} does not exist.");
            Err(NoSuchEntityException::builder().message(message).request_id(request_id).build().into())
        }
    }
}
