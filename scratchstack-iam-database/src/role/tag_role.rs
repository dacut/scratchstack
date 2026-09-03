//! TagRole database operation
use {
    crate::{
        RequestExecutor,
        account::validate_account_id,
        constants::*,
        internal_failure,
        role::validate_role_name,
        tag::{validate_tag_key, validate_tag_keys_unique, validate_tag_value},
    },
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::TagRoleInternalRequest,
        types::{
            Tag,
            error::{NoSuchEntityException, ValidationError},
        },
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for TagRoleInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        tag_role(tx, &self.account_id, &self.role_name, &self.tags, request_id).await
    }
}

/// Add or update tags on a role in the database.
pub async fn tag_role(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
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
    validate_role_name(role_name, request_id)?;

    for tag in tags {
        validate_tag_key(&tag.key, request_id)?;
        validate_tag_value(&tag.value, request_id)?;
    }

    // Two tags with the same key ask for two values for one tag. The upsert below would take the
    // last one and report success, which is not what the caller asked for, so the request is
    // rejected as tag_user rejects it.
    validate_tag_keys_unique(tags.iter().map(|tag| tag.key.as_str()), request_id)?;

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
            return Err(internal_failure!(request_id; "Failed to look up role in database: {e}").into());
        }
    };

    for tag in tags {
        let key_cased = tag.key.as_str();
        let key_lower = key_cased.to_ascii_lowercase();
        let value = tag.value.as_str();

        if let Err(e) = query(indoc! {"
                INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value)
                VALUES($1, $2, $3, $4)
                ON CONFLICT (role_id, key_lower)
                DO UPDATE SET
                    key_cased = EXCLUDED.key_cased,
                    value = EXCLUDED.value,
                    updated_at = CURRENT_TIMESTAMP
            "})
        .bind(&role_id)
        .bind(key_lower)
        .bind(key_cased)
        .bind(value)
        .execute(tx.as_mut())
        .await
        {
            return Err(internal_failure!(request_id; "Failed to insert/update role tag in database: {e}").into());
        }
    }

    Ok(())
}
