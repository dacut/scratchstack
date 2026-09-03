//! CreateAccountAlias database operation
use {
    crate::{
        RequestExecutor,
        account::{is_alias_unique_violation, validate_account_alias, validate_account_id},
        internal_failure,
    },
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::CreateAccountAliasInternalRequest,
        types::error::{EntityAlreadyExistsException, NoSuchEntityException},
    },
    sqlx::{postgres::PgTransaction, query},
};

impl RequestExecutor for CreateAccountAliasInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        create_account_alias(tx, self.account_id.clone(), self.account_alias.clone(), request_id).await
    }
}

/// Create an alias for the account with the given account ID.
///
/// If the account already has an alias, it is replaced with the new alias. Returns
/// `EntityAlreadyExistsException` when the requested alias is already in use by a different
/// account.
pub async fn create_account_alias(
    tx: &mut PgTransaction<'_>,
    account_id: String,
    account_alias: String,
    request_id: RequestId,
) -> Result<(), IamError> {
    validate_account_id(&account_id, request_id)?;
    validate_account_alias(&account_alias, request_id)?;

    let result = match query(indoc! {"
        UPDATE iam.accounts
        SET alias = $1
        WHERE account_id = $2
    "})
    .bind(&account_alias)
    .bind(&account_id)
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) if is_alias_unique_violation(&e) => {
            return Err(EntityAlreadyExistsException::builder()
                .message(format!("Account alias {account_alias} is already in use."))
                .request_id(request_id)
                .build()
                .into());
        }
        Err(e) => {
            return Err(
                internal_failure!(request_id; "Failed to create account alias for account {account_id}: {e}").into()
            );
        }
    };

    if result.rows_affected() == 0 {
        let message = format!("Account with ID {account_id} does not exist.");
        Err(NoSuchEntityException::builder().message(message).request_id(request_id).build().into())
    } else {
        Ok(())
    }
}
