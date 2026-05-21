//! ListAccessKeys database operation
use {
    crate::{
        constants::iam::*,
        ops::{
            RequestExecutor,
            iam::{
                constrain_max_items, get_current_partition_or_fail, make_paginator, validate_account_id,
                validate_user_name,
            },
        },
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListAccessKeysInternalRequest, ListAccessKeysResponse},
        types::{
            AccessKeyMetadata, StatusType,
            error::{InternalFailure, NoSuchEntityException, ValidationError},
        },
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for ListAccessKeysInternalRequest {
    type Response = ListAccessKeysResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_access_keys(tx, &self.account_id, self.user_name.as_deref(), self.marker.as_deref(), self.max_items).await
    }
}

/// The marker innards for a ListAccessKeys operation.
#[derive(Deserialize, Serialize)]
struct ListAccessKeysMarker {
    next_access_key_id: String,
}

/// The rows returned by the ListAccessKeys query.
#[derive(FromRow)]
struct ListAccessKeysRow {
    access_key_id: String,
    enabled: bool,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// List the access keys for a user. The user name is required by this implementation because
/// there is no caller identity to fall back to.
pub async fn list_access_keys(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: Option<&str>,
    marker: Option<&str>,
    max_items: Option<i32>,
) -> Result<ListAccessKeysResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let user_name = match user_name {
        Some(name) => name,
        None => {
            return Err(ValidationError::builder()
                .message("UserName is required for ListAccessKeys in this implementation.".to_string())
                .build()
                .into());
        }
    };
    validate_user_name(user_name)?;
    let max_items = constrain_max_items(max_items)?;
    let partition = get_current_partition_or_fail(tx).await?;

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
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    let paginator = make_paginator(&partition, OP_LIST_ACCESS_KEYS)?;

    let mut sql = QueryBuilder::new(indoc! {"
        SELECT access_key_id, enabled, created_at
        FROM iam.user_credentials
        WHERE user_id = "});
    sql.push_bind(user_id);

    if let Some(marker) = marker {
        let m: ListAccessKeysMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token for ListAccessKeys: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;
        sql.push("\nAND access_key_id >= ");
        sql.push_bind(m.next_access_key_id);
    }

    sql.push("\nORDER BY access_key_id ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListAccessKeysRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch user access keys from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    let mut results: Vec<AccessKeyMetadata> = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if results.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListAccessKeysMarker {
                        next_access_key_id: row.access_key_id,
                    })
                    .await
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token for ListAccessKeys: {e}");
                        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                    })?,
            );
            break;
        }

        let metadata = AccessKeyMetadata::builder()
            .access_key_id(Some(format!("AKIA{}", row.access_key_id)))
            .create_date(Some(row.created_at))
            .status(Some(if row.enabled {
                StatusType::Active
            } else {
                StatusType::Inactive
            }))
            .user_name(Some(user_name.to_string()))
            .build()
            .map_err(|e| {
                log::error!("Failed to construct AccessKeyMetadata: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?;
        results.push(metadata);
    }

    let mut builder = ListAccessKeysResponse::builder();
    builder = builder.access_key_metadata(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(Some(true)).marker(Some(next_marker));
    }

    builder.build().map_err(|e| {
        log::error!("Failed to build ListAccessKeysResponse: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })
}
