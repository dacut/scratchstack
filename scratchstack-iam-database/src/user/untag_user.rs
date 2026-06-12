//! UntagUser database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, internal_failure, tag::validate_tag_key,
        user::validate_user_name,
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::UntagUserInternalRequest,
        types::error::{NoSuchEntityException, ValidationError},
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for UntagUserInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        untag_user(tx, &self.account_id, &self.user_name, &self.tag_keys).await
    }
}

/// Remove tags from a user in the database.
pub async fn untag_user(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    tag_keys: &[String],
) -> Result<(), IamError> {
    if tag_keys.is_empty() {
        return Err(ValidationError::builder().message("At least one tag key must be provided.").build().into());
    }

    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;

    for key in tag_keys {
        validate_tag_key(key)?;
    }

    // Verify the user exists and get the user_id.
    let user_id: String = match query(indoc! {"
            SELECT user_id
            FROM iam.users
            WHERE account_id = $1 AND user_name_lower = $2
        "})
    .bind(account_id)
    .bind(user_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The user with name {user_name} cannot be found."))
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up user in database: {e}");
            return Err(internal_failure().into());
        }
    };

    for key in tag_keys {
        let key_lower = key.to_ascii_lowercase();

        if let Err(e) = query(indoc! {"
                DELETE FROM iam.user_tags
                WHERE user_id = $1 AND key_lower = $2
            "})
        .bind(&user_id)
        .bind(key_lower)
        .execute(tx.as_mut())
        .await
        {
            log::error!("Failed to delete user tag from database: {e}");
            return Err(internal_failure().into());
        }
    }

    Ok(())
}
