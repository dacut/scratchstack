//! CreateAccount database level operation.

use {
    crate::{
        model::iam::{ACCOUNT_ALIAS_REGEX, ACCOUNT_ID_REGEX},
        ops::RequestExecutor,
    },
    anyhow::{Result as AnyResult, bail},
    indoc::indoc,
    rand::random_range,
    serde::{Deserialize, Serialize},
    sqlx::{
        Acquire as _,
        error::{Error as SqlxError, ErrorKind as SqlxErrorKind},
        postgres::PgTransaction,
        query,
    },
};

/// Parameters to create a new account on the Scratchstack IAM database.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct CreateAccountRequest {
    /// The organization id to create the account in. This is currently unsupported and must be
    /// `None`. In the future, this can be used to specify an organization to create the account in.
    #[cfg_attr(feature = "clap", arg(long))]
    pub organization_id: Option<String>,

    /// The account id to create. This is usually unspecified, which will return a random
    /// unused account id, but this can be used to specify a particular account id to create.
    /// The account id must be a 12-digit number.
    #[cfg_attr(feature = "clap", arg(long))]
    pub account_id: Option<String>,

    /// Email address associated with the account.
    #[cfg_attr(feature = "clap", arg(long))]
    pub email: Option<String>,

    /// Unique alias for the account. This must be a string of length 3 to 63 characters consisting
    /// of ASCII lowercase letters, digits, and dashes. The alias cannot start or finish with a
    /// dash and cannot contain consecutive dashes.
    #[cfg_attr(feature = "clap", arg(long))]
    pub alias: Option<String>,
}

/// Result of creating an account, which is returned as JSON in the API response.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct CreateAccountResponse {
    /// The organization id that the account was created in. This is currently always `None`, but
    /// in the future, this will be used to specify the organization that the account was created
    /// in.
    pub organization_id: Option<String>,

    /// The account id of the newly created account.
    pub account_id: String,

    /// Email address associated with the account.
    pub email: Option<String>,

    /// Unique alias for the account.
    pub alias: Option<String>,
}

impl RequestExecutor for CreateAccountRequest {
    type Response = CreateAccountResponse;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> AnyResult<Self::Response> {
        if self.organization_id.is_some() {
            bail!("Creating accounts in an organization is currently unsupported");
        }

        if let Some(account_id) = &self.account_id {
            create_account(tx, account_id.clone(), self.email.clone(), self.alias.clone()).await
        } else {
            create_account_with_random_account_id(tx, self.email.clone(), self.alias.clone()).await
        }
    }
}

/// Create a new account on the database.
async fn create_account(
    tx: &mut PgTransaction<'_>,
    account_id: String,
    email: Option<String>,
    alias: Option<String>,
) -> AnyResult<CreateAccountResponse> {
    if !ACCOUNT_ID_REGEX.is_match(&account_id) {
        bail!("Account ID must be a 12-digit number");
    }

    let alias = if let Some(alias) = alias {
        if !ACCOUNT_ALIAS_REGEX.is_match(&alias) || alias.len() < 3 || alias.len() > 63 {
            bail!(
                "Account alias must be 3-63 characters long and consist of lowercase letters, digits, and dashes. The alias cannot start or end with a dash and cannot contain consecutive dashes."
            );
        }
        Some(alias)
    } else {
        None
    };

    query(indoc! {"
        INSERT INTO iam.accounts(account_id, email, alias)
        VALUES($1, $2, $3)
    "})
    .bind(account_id.clone())
    .bind(email.clone())
    .bind(alias.clone())
    .execute(tx.as_mut())
    .await?;
    Ok(CreateAccountResponse {
        organization_id: None,
        account_id,
        email,
        alias,
    })
}

/// Create a new account on the database with a random account ID.
async fn create_account_with_random_account_id(
    tx: &mut PgTransaction<'_>,
    email: Option<String>,
    alias: Option<String>,
) -> AnyResult<CreateAccountResponse> {
    loop {
        let account_id = format!("{:012}", random_range(1u64..=999_999_999_999));
        // Create a savepoint that we can roll back to if the account ID already exists.
        let mut savepoint = tx.begin().await?;

        match create_account(&mut savepoint, account_id, email.clone(), alias.clone()).await {
            Ok(account_id) => {
                savepoint.commit().await?;
                return Ok(account_id);
            }
            Err(e) => match e.downcast::<SqlxError>() {
                Ok(sqlx_error) => {
                    if let SqlxError::Database(ref dbe) = sqlx_error
                        && dbe.kind() == SqlxErrorKind::UniqueViolation
                    {
                        // Account ID already exists, try again with a different random account ID.
                        savepoint.rollback().await?;
                        continue;
                    }

                    log::error!("Failed to create account with random account id: {sqlx_error}");
                    savepoint.rollback().await?;
                    return Err(sqlx_error.into());
                }
                Err(other) => {
                    log::error!("Failed to create account with random account id: {other}");
                    savepoint.rollback().await?;
                    return Err(other);
                }
            },
        }
    }
}
