//! CreateAccountAlias database level operations.
use {
    crate::{
        RequestExecutor,
        iam::{account::is_alias_unique_violation, internal_failure, validate_account_alias, validate_account_id},
    },
    indoc::indoc,
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

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        create_account_alias(tx, self.account_id.clone(), self.account_alias.clone()).await
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
) -> Result<(), IamError> {
    validate_account_id(&account_id)?;
    validate_account_alias(&account_alias)?;

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
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to create account alias for account {account_id}: {e}");
            return Err(internal_failure().into());
        }
    };

    if result.rows_affected() == 0 {
        let message = format!("Account with ID {account_id} does not exist.");
        Err(NoSuchEntityException::builder().message(message).build().into())
    } else {
        Ok(())
    }
}
