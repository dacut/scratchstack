//! UntagUser database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, internal_failure, tag::validate_tag_key,
        user::validate_user_name,
    },
    indoc::indoc,
    scratchstack_core::RequestId,
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

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        untag_user(tx, &self.account_id, &self.user_name, &self.tag_keys, request_id).await
    }
}

/// Remove tags from a user in the database.
pub async fn untag_user(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    tag_keys: &[String],
    request_id: RequestId,
) -> Result<(), IamError> {
    if tag_keys.is_empty() {
        return Err(ValidationError::builder()
            .message("At least one tag key must be provided.")
            .request_id(request_id)
            .build()
            .into());
    }

    validate_account_id(account_id, request_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name, request_id)?;

    for key in tag_keys {
        validate_tag_key(key, request_id)?;
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
                .request_id(request_id)
                .build()
                .into());
        }
        Err(e) => {
            return Err(internal_failure!(request_id; "Failed to look up user in database: {e}").into());
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
            return Err(internal_failure!(request_id; "Failed to delete user tag from database: {e}").into());
        }
    }

    Ok(())
}
