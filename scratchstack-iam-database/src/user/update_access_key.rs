//! UpdateAccessKey database operation
use {
    crate::{
        RequestExecutor,
        account::validate_account_id,
        constants::*,
        internal_failure,
        user::{validate_access_key_id, validate_user_name},
    },
    indoc::indoc,
    log::error,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::UpdateAccessKeyInternalRequest,
        types::{
            StatusType,
            error::{NoSuchEntityException, ValidationError},
        },
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for UpdateAccessKeyInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        update_access_key(tx, &self.account_id, self.user_name.as_deref(), &self.access_key_id, self.status).await
    }
}

/// Change the `Active`/`Inactive` state of an access key. `user_name` is optional; when provided,
/// the access key must belong to the named user.
pub async fn update_access_key(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: Option<&str>,
    access_key_id: &str,
    status: StatusType,
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
    let enabled = match status {
        StatusType::Active => true,
        StatusType::Inactive => false,
        _ => {
            return Err(ValidationError::builder()
                .message("Status must be Active or Inactive for UpdateAccessKey.".to_string())
                .build()
                .into());
        }
    };
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
        error!("Failed to look up access key in database: {e}");
        internal_failure()
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

    let result = query("UPDATE iam.user_credentials SET enabled = $1 WHERE access_key_id = $2")
        .bind(enabled)
        .bind(access_key_id_stored)
        .execute(tx.as_mut())
        .await
        .map_err(|e| {
            error!("Failed to update access key in database: {e}");
            internal_failure()
        })?;

    if result.rows_affected() == 0 {
        return Err(NoSuchEntityException::builder()
            .message(format!("The access key with id {access_key_id} cannot be found."))
            .build()
            .into());
    }

    Ok(())
}
