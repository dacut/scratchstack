//! DeleteAccessKey database operation
use {
    crate::{
        constants::iam::*,
        ops::{
            RequestExecutor,
            iam::{user::validate_access_key_id, validate_account_id, validate_user_name},
        },
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::DeleteAccessKeyInternalRequest,
        types::error::{InternalFailure, NoSuchEntityException},
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for DeleteAccessKeyInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        delete_access_key(tx, &self.account_id, self.user_name.as_deref(), &self.access_key_id).await
    }
}

/// Delete an access key. `user_name` is optional; when provided, the access key must belong to
/// the named user (otherwise NoSuchEntity is returned).
pub async fn delete_access_key(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: Option<&str>,
    access_key_id: &str,
) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    if let Some(name) = user_name {
        validate_user_name(name)?;
    }
    validate_access_key_id(access_key_id)?;
    let access_key_id_stored = &access_key_id[4..];

    let row = query(indoc! {"
            SELECT u.user_name_lower, u.account_id
            FROM iam.user_credentials uc
            INNER JOIN iam.users u ON uc.user_id = u.user_id
            WHERE uc.access_key_id = $1
        "})
    .bind(access_key_id_stored)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to look up access key in database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    let (key_user_name_lower, key_account_id): (String, String) = match row {
        Some(row) => (row.get(0), row.get(1)),
        None => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The access key with id {access_key_id} cannot be found."))
                .build()
                .into());
        }
    };

    if key_account_id != account_id {
        return Err(NoSuchEntityException::builder()
            .message(format!("The access key with id {access_key_id} cannot be found."))
            .build()
            .into());
    }
    if let Some(name) = user_name
        && name.to_lowercase() != key_user_name_lower
    {
        return Err(NoSuchEntityException::builder()
            .message(format!("The access key with id {access_key_id} cannot be found."))
            .build()
            .into());
    }

    let result = query("DELETE FROM iam.user_credentials WHERE access_key_id = $1")
        .bind(access_key_id_stored)
        .execute(tx.as_mut())
        .await
        .map_err(|e| {
            log::error!("Failed to delete access key from database: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;

    if result.rows_affected() == 0 {
        return Err(NoSuchEntityException::builder()
            .message(format!("The access key with id {access_key_id} cannot be found."))
            .build()
            .into());
    }

    Ok(())
}
