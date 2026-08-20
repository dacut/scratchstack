//! UntagRole database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, internal_failure, role::validate_role_name,
        tag::validate_tag_key,
    },
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::UntagRoleInternalRequest,
        types::error::{NoSuchEntityException, ValidationError},
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for UntagRoleInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        untag_role(tx, &self.account_id, &self.role_name, &self.tag_keys, request_id).await
    }
}

/// Remove tags from a role in the database.
pub async fn untag_role(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
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
    validate_role_name(role_name, request_id)?;

    for key in tag_keys {
        validate_tag_key(key, request_id)?;
    }

    // Verify the role exists and get the role_id.
    let role_id: String = match query(indoc! {"
            SELECT role_id
            FROM iam.roles
            WHERE account_id = $1 AND role_name_lower = $2
        "})
    .bind(account_id)
    .bind(role_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The role with name {role_name} cannot be found."))
                .request_id(request_id)
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up role in database: {e}");
            return Err(internal_failure(request_id).into());
        }
    };

    for key in tag_keys {
        let key_lower = key.to_ascii_lowercase();

        if let Err(e) = query(indoc! {"
                DELETE FROM iam.role_tags
                WHERE role_id = $1 AND key_lower = $2
            "})
        .bind(&role_id)
        .bind(key_lower)
        .execute(tx.as_mut())
        .await
        {
            log::error!("Failed to delete role tag from database: {e}");
            return Err(internal_failure(request_id).into());
        }
    }

    Ok(())
}
