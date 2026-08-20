//! ListSessionTokenEncryptionKeys database operation
use {
    crate::{
        RequestExecutor, constants::*, constrain_max_items, make_iam_paginator,
        partition::get_current_partition_or_fail,
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListSessionTokenEncryptionKeysRequest, ListSessionTokenEncryptionKeysResponse},
        types::{
            ListSessionTokenEncryptionKeysFilter, ListSessionTokenEncryptionKeysFilterName,
            SessionTokenEncryptionAlgorithm, SessionTokenEncryptionKey,
            error::{InternalFailure, ValidationError},
        },
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, postgres::PgTransaction},
    std::str::FromStr as _,
};

impl RequestExecutor for ListSessionTokenEncryptionKeysRequest {
    type Response = ListSessionTokenEncryptionKeysResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        list_session_token_encryption_keys(tx, &self.filters, self.marker.as_deref(), self.max_items, request_id).await
    }
}

/// The marker innards for a ListSessionTokenEncryptionKeys operation.
#[derive(Deserialize, Serialize)]
struct ListSessionTokenEncryptionKeysMarker {
    next_session_token_encryption_key_id: String,
}

/// The rows returned by the ListSessionTokenEncryptionKeys query.
#[derive(FromRow)]
struct ListSessionTokenEncryptionKeysRow {
    session_token_encryption_key_id: String,
    encryption_algorithm: String,
    encryption_key: String,
    issue_valid_from: DateTime<Utc>,
    issue_expires_at: DateTime<Utc>,
    accept_expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

/// List session token encryption keys on the database.
pub async fn list_session_token_encryption_keys(
    tx: &mut PgTransaction<'_>,
    filters: &[ListSessionTokenEncryptionKeysFilter],
    marker: Option<&str>,
    max_items: Option<i32>,
    request_id: RequestId,
) -> Result<ListSessionTokenEncryptionKeysResponse, IamError> {
    let max_items = constrain_max_items(max_items, request_id)?;
    let partition = get_current_partition_or_fail(tx, request_id).await?;
    let paginator = make_iam_paginator(&partition, OP_LIST_SESSION_TOKEN_ENCRYPTION_KEYS, request_id)?;

    let mut sql = QueryBuilder::new(indoc! {"
        SELECT
            session_token_encryption_key_id, encryption_algorithm, encryption_key, issue_valid_from,
            issue_expires_at, accept_expires_at, created_at
        FROM iam.session_token_encryption_keys
        WHERE TRUE
    "});

    let mut issue_valid_from_start_max: Option<DateTime<Utc>> = None;
    let mut issue_valid_from_end_min: Option<DateTime<Utc>> = None;
    let mut issue_expires_at_start_max: Option<DateTime<Utc>> = None;
    let mut issue_expires_at_end_min: Option<DateTime<Utc>> = None;
    let mut accept_expires_at_start_max: Option<DateTime<Utc>> = None;
    let mut accept_expires_at_end_min: Option<DateTime<Utc>> = None;

    for filter in filters.iter() {
        match filter.name {
            ListSessionTokenEncryptionKeysFilterName::IssueValidFromStartTime => {
                for value in &filter.values {
                    let Ok(time) = DateTime::parse_from_rfc3339(value) else {
                        let message = format!("Invalid datetime value in IssueValidFromStartTime filter: {value}");
                        return Err(ValidationError::builder().message(message).request_id(request_id).build().into());
                    };

                    issue_valid_from_start_max = Some(
                        issue_valid_from_start_max
                            .map_or(time.with_timezone(&Utc), |max| max.max(time.with_timezone(&Utc))),
                    );
                }
            }
            ListSessionTokenEncryptionKeysFilterName::IssueValidFromEndTime => {
                for value in &filter.values {
                    let Ok(time) = DateTime::parse_from_rfc3339(value) else {
                        let message = format!("Invalid datetime value in IssueValidFromEndTime filter: {value}");
                        return Err(ValidationError::builder().message(message).request_id(request_id).build().into());
                    };

                    issue_valid_from_end_min = Some(
                        issue_valid_from_end_min
                            .map_or(time.with_timezone(&Utc), |min| min.min(time.with_timezone(&Utc))),
                    );
                }
            }
            ListSessionTokenEncryptionKeysFilterName::IssueExpiresAtStartTime => {
                for value in &filter.values {
                    let Ok(time) = DateTime::parse_from_rfc3339(value) else {
                        let message = format!("Invalid datetime value in IssueExpiresAtStartTime filter: {value}");
                        return Err(ValidationError::builder().message(message).request_id(request_id).build().into());
                    };

                    issue_expires_at_start_max = Some(
                        issue_expires_at_start_max
                            .map_or(time.with_timezone(&Utc), |max| max.max(time.with_timezone(&Utc))),
                    );
                }
            }
            ListSessionTokenEncryptionKeysFilterName::IssueExpiresAtEndTime => {
                for value in &filter.values {
                    let Ok(time) = DateTime::parse_from_rfc3339(value) else {
                        let message = format!("Invalid datetime value in IssueExpiresAtEndTime filter: {value}");
                        return Err(ValidationError::builder().message(message).request_id(request_id).build().into());
                    };

                    issue_expires_at_end_min = Some(
                        issue_expires_at_end_min
                            .map_or(time.with_timezone(&Utc), |min| min.min(time.with_timezone(&Utc))),
                    );
                }
            }
            ListSessionTokenEncryptionKeysFilterName::AcceptExpiresAtStartTime => {
                for value in &filter.values {
                    let Ok(time) = DateTime::parse_from_rfc3339(value) else {
                        let message = format!("Invalid datetime value in AcceptExpiresAtStartTime filter: {value}");
                        return Err(ValidationError::builder().message(message).request_id(request_id).build().into());
                    };

                    accept_expires_at_start_max = Some(
                        accept_expires_at_start_max
                            .map_or(time.with_timezone(&Utc), |max| max.max(time.with_timezone(&Utc))),
                    );
                }
            }
            ListSessionTokenEncryptionKeysFilterName::AcceptExpiresAtEndTime => {
                for value in &filter.values {
                    let Ok(time) = DateTime::parse_from_rfc3339(value) else {
                        let message = format!("Invalid datetime value in AcceptExpiresAtEndTime filter: {value}");
                        return Err(ValidationError::builder().message(message).request_id(request_id).build().into());
                    };

                    accept_expires_at_end_min = Some(
                        accept_expires_at_end_min
                            .map_or(time.with_timezone(&Utc), |min| min.min(time.with_timezone(&Utc))),
                    );
                }
            }
            _ => {
                log::warn!("Received unsupported filter key: {:?}", filter.name);
                continue;
            }
        }
    }

    if let Some(valid_from_start_max) = issue_valid_from_start_max {
        sql.push(" AND issue_valid_from >= ");
        sql.push_bind(valid_from_start_max);
    }

    if let Some(valid_from_end_min) = issue_valid_from_end_min {
        sql.push(" AND issue_valid_from <= ");
        sql.push_bind(valid_from_end_min);
    }

    if let Some(expires_at_start_max) = issue_expires_at_start_max {
        sql.push(" AND issue_expires_at >= ");
        sql.push_bind(expires_at_start_max);
    }

    if let Some(expires_at_end_min) = issue_expires_at_end_min {
        sql.push(" AND issue_expires_at <= ");
        sql.push_bind(expires_at_end_min);
    }

    if let Some(accept_expires_at_start_max) = accept_expires_at_start_max {
        sql.push(" AND accept_expires_at >= ");
        sql.push_bind(accept_expires_at_start_max);
    }

    if let Some(accept_expires_at_end_min) = accept_expires_at_end_min {
        sql.push(" AND accept_expires_at <= ");
        sql.push_bind(accept_expires_at_end_min);
    }

    if let Some(marker) = marker {
        let info: ListSessionTokenEncryptionKeysMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token: {e}");
            InternalFailure::builder().message(MSG_INTERNAL_FAILURE.to_string()).request_id(request_id).build()
        })?;
        sql.push(" AND session_token_encryption_key_id >= ");
        sql.push_bind(info.next_session_token_encryption_key_id);
    }

    // Request one more than max_items so we can determine if there are more results.
    sql.push(" ORDER BY session_token_encryption_key_id ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListSessionTokenEncryptionKeysRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch session token encryption keys from database: {e}");
        InternalFailure::builder().message(MSG_INTERNAL_FAILURE.to_string()).request_id(request_id).build()
    })?;

    let mut result = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if result.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListSessionTokenEncryptionKeysMarker {
                        next_session_token_encryption_key_id: row.session_token_encryption_key_id.clone(),
                    })
                    .await
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token: {e}");
                        InternalFailure::builder()
                            .message(MSG_INTERNAL_FAILURE.to_string())
                            .request_id(request_id)
                            .build()
                    })?,
            );
            break;
        }

        let session_token_encryption_key_id =
            format!("{}{}", IamResourceType::SessionTokenEncryptionKey.as_str(), row.session_token_encryption_key_id);
        let encryption_algorithm =
            SessionTokenEncryptionAlgorithm::from_str(&row.encryption_algorithm).map_err(|e| {
                log::error!("Failed to parse encryption algorithm from database value: {e}");
                InternalFailure::builder().message(MSG_INTERNAL_FAILURE.to_string()).request_id(request_id).build()
            })?;

        result.push(SessionTokenEncryptionKey {
            session_token_encryption_key_id,
            encryption_algorithm,
            encryption_key: row.encryption_key,
            issue_valid_from: row.issue_valid_from,
            issue_expires_at: row.issue_expires_at,
            accept_expires_at: row.accept_expires_at,
            created_at: row.created_at,
        });
    }

    let is_truncated = next_marker.is_some();
    Ok(ListSessionTokenEncryptionKeysResponse {
        session_token_encryption_keys: result,
        is_truncated: Some(is_truncated),
        marker: next_marker,
    })
}
