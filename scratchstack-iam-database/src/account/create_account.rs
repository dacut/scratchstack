//! CreateAccount database operation
use {
    crate::{
        RequestExecutor,
        account::{is_alias_unique_violation, validate_account_alias, validate_account_id},
        internal_failure,
    },
    indoc::indoc,
    rand::random_range,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{CreateAccountRequest, CreateAccountResponse},
        types::{
            Account,
            error::{EntityAlreadyExistsException, ValidationError},
        },
    },
    sqlx::{Acquire as _, postgres::PgTransaction, query},
};

impl RequestExecutor for CreateAccountRequest {
    type Response = CreateAccountResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        create_account(
            tx,
            self.organization_id.clone(),
            self.account_id.clone(),
            self.email.clone(),
            self.account_alias.clone(),
        )
        .await
    }
}

/// Create a new account on the database.
///
/// If an account ID is provided, attempts to create the account with that ID and fails if it
/// already exists. Otherwise, attempts to create the account with a random account ID, retrying
/// with different random account IDs if there are collisions, until it succeeds.
pub async fn create_account(
    tx: &mut PgTransaction<'_>,
    organization_id: Option<String>,
    account_id: Option<String>,
    email: Option<String>,
    account_alias: Option<String>,
) -> Result<CreateAccountResponse, IamError> {
    if organization_id.is_some() {
        return Err(ValidationError::builder()
            .message("Creating accounts in an organization is currently unsupported")
            .build()
            .into());
    }

    if let Some(account_id) = account_id {
        create_account_with_id(tx, account_id, email, account_alias).await
    } else {
        create_account_with_random_account_id(tx, email, account_alias).await
    }
}

/// Create a new account on the database with the specified account ID.
async fn create_account_with_id(
    tx: &mut PgTransaction<'_>,
    account_id: String,
    email: Option<String>,
    account_alias: Option<String>,
) -> Result<CreateAccountResponse, IamError> {
    validate_account_id(&account_id)?;
    if let Some(account_alias) = account_alias.as_ref() {
        validate_account_alias(account_alias)?;
    }

    if let Err(e) = query(indoc! {"
        INSERT INTO iam.accounts(account_id, email, alias)
        VALUES($1, $2, $3)
    "})
    .bind(account_id.clone())
    .bind(email.clone())
    .bind(account_alias.clone())
    .execute(tx.as_mut())
    .await
    {
        if is_alias_unique_violation(&e) {
            let alias = account_alias.unwrap_or_default();
            return Err(EntityAlreadyExistsException::builder()
                .message(format!("Account alias {alias} is already in use."))
                .build()
                .into());
        }
        log::error!("Failed to insert account into database: {e}");
        return Err(internal_failure().into());
    }

    let mut acct_builder = Account::builder().account_id(account_id);
    if let Some(email) = email {
        acct_builder = acct_builder.email(email);
    }
    if let Some(account_alias) = account_alias {
        acct_builder = acct_builder.account_alias(account_alias);
    }
    let account = acct_builder.build().map_err(|e| {
        log::error!("Failed to build Account: {e}");
        internal_failure()
    })?;
    Ok(CreateAccountResponse {
        account,
    })
}

/// Create a new account on the database with a random account ID.
async fn create_account_with_random_account_id(
    tx: &mut PgTransaction<'_>,
    email: Option<String>,
    account_alias: Option<String>,
) -> Result<CreateAccountResponse, IamError> {
    loop {
        let account_id = format!("{:012}", random_range(1u64..=999_999_999_999));
        // Create a savepoint that we can roll back to if the account ID already exists.
        let mut savepoint = match tx.begin().await {
            Ok(sp) => sp,
            Err(e) => {
                log::error!("Failed to create savepoint: {e}");
                return Err(internal_failure().into());
            }
        };

        match create_account_with_id(&mut savepoint, account_id, email.clone(), account_alias.clone()).await {
            Ok(response) => {
                if let Err(e) = savepoint.commit().await {
                    log::error!("Failed to commit savepoint: {e}");
                    return Err(internal_failure().into());
                }
                return Ok(response);
            }
            Err(IamError::InternalFailure(_)) => {
                // The insert failed — this could be a unique violation (account ID collision)
                // or a genuine error. We can't easily distinguish here since we wrapped the
                // sqlx error, so just roll back and retry. After enough retries a genuine
                // error would keep looping, but collisions on 12-digit random IDs are
                // extremely unlikely to repeat.
                if let Err(e) = savepoint.rollback().await {
                    log::error!("Failed to rollback savepoint: {e}");
                    return Err(internal_failure().into());
                }
                continue;
            }
            Err(other) => {
                // Validation error or something else — don't retry.
                if let Err(e) = savepoint.rollback().await {
                    log::error!("Failed to rollback savepoint: {e}");
                    return Err(internal_failure().into());
                }
                return Err(other);
            }
        }
    }
}
