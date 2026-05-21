//! UpdateUser database operation
use {
    crate::{
        constants::iam::*,
        ops::{
            RequestExecutor,
            iam::{validate_account_id, validate_path, validate_user_name},
        },
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::UpdateUserInternalRequest,
        types::error::{InternalFailure, NoSuchEntityException},
    },
    sqlx::{postgres::PgTransaction, query},
};

impl RequestExecutor for UpdateUserInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        update_user(tx, &self.account_id, &self.user_name, self.new_user_name.as_deref(), self.new_path.as_deref())
            .await
    }
}

/// Update a user on the database.
pub async fn update_user(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    new_user_name: Option<&str>,
    new_path: Option<&str>,
) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;
    let user_name_lower = user_name.to_lowercase();

    let (new_user_name_cased, new_user_name_lower) = if let Some(new_user_name) = new_user_name {
        validate_user_name(new_user_name)?;
        (Some(new_user_name), Some(new_user_name.to_lowercase()))
    } else {
        (None, None)
    };

    if let Some(new_path) = new_path {
        validate_path(new_path)?;
    }

    let result = match query(indoc! {"
        UPDATE iam.users
        SET user_name_lower = COALESCE($3, user_name_lower),
            user_name_cased = COALESCE($4, user_name_cased),
            path = COALESCE($5, path)
        WHERE account_id = $1 AND user_name_lower = $2
    "})
    .bind(account_id)
    .bind(&user_name_lower)
    .bind(new_user_name_lower)
    .bind(new_user_name_cased)
    .bind(new_path)
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to update user in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if result.rows_affected() == 0 {
        Err(NoSuchEntityException::builder()
            .message(format!("The user with name {user_name} cannot be found."))
            .build()
            .into())
    } else {
        Ok(())
    }
}
