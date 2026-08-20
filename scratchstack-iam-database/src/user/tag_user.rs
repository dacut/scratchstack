//! TagUser database operation
use {
    crate::{
        RequestExecutor,
        account::validate_account_id,
        constants::*,
        internal_failure,
        tag::{validate_tag_key, validate_tag_value},
        user::validate_user_name,
    },
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::TagUserInternalRequest,
        types::{
            Tag,
            error::{NoSuchEntityException, ValidationError},
        },
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for TagUserInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        tag_user(tx, &self.account_id, &self.user_name, &self.tags, request_id).await
    }
}

/// Add or update tags on a user in the database.
pub async fn tag_user(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    tags: &[Tag],
    request_id: RequestId,
) -> Result<(), IamError> {
    if tags.is_empty() {
        return Err(ValidationError::builder()
            .message("At least one tag must be provided.")
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

    for tag in tags {
        validate_tag_key(&tag.key, request_id)?;
        validate_tag_value(&tag.value, request_id)?;
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
            log::error!("Failed to look up user in database: {e}");
            return Err(internal_failure(request_id).into());
        }
    };

    for tag in tags {
        let key_cased = tag.key.as_str();
        let key_lower = key_cased.to_ascii_lowercase();
        let value = tag.value.as_str();

        if let Err(e) = query(indoc! {"
                INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value)
                VALUES($1, $2, $3, $4)
                ON CONFLICT (user_id, key_lower)
                DO UPDATE SET key_cased = EXCLUDED.key_cased, value = EXCLUDED.value
            "})
        .bind(&user_id)
        .bind(key_lower)
        .bind(key_cased)
        .bind(value)
        .execute(tx.as_mut())
        .await
        {
            log::error!("Failed to insert/update user tag in database: {e}");
            return Err(internal_failure(request_id).into());
        }
    }

    Ok(())
}
