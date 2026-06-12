//! ListUserTags database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, constrain_max_items, internal_failure,
        make_iam_paginator, partition::get_current_partition_or_fail, user::validate_user_name,
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListUserTagsInternalRequest, ListUserTagsResponse},
        types::{Tag, error::NoSuchEntityException},
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, postgres::PgTransaction, query},
};

impl RequestExecutor for ListUserTagsInternalRequest {
    type Response = ListUserTagsResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_user_tags(tx, &self.account_id, &self.user_name, self.marker.as_deref(), self.max_items).await
    }
}

/// The marker innards for a ListUserTags operation.
#[derive(Deserialize, Serialize)]
struct ListUserTagsMarker {
    next_key_lower: String,
}

/// The rows returned by the ListUserTags query.
#[derive(FromRow)]
struct ListUserTagsRow {
    key_cased: String,
    value: String,
}

/// List the tags for a user from the database.
pub async fn list_user_tags(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
) -> Result<ListUserTagsResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;
    let user_name_lower = user_name.to_lowercase();
    let max_items = constrain_max_items(max_items)?;
    let partition = get_current_partition_or_fail(tx).await?;

    let user_exists = query(indoc! {"
        SELECT 1
        FROM iam.users
        WHERE account_id = $1 AND user_name_lower = $2
        LIMIT 1
    "})
    .bind(account_id)
    .bind(&user_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to check if user exists in database: {e}");
        internal_failure()
    })?;
    if user_exists.is_none() {
        return Err(NoSuchEntityException::builder()
            .message(format!("The user with name {user_name} cannot be found."))
            .build()
            .into());
    }

    let paginator = make_iam_paginator(&partition, OP_LIST_USER_TAGS)?;

    let mut sql = QueryBuilder::new(
        r#"
        SELECT key_cased, value
        FROM iam.user_tags t
        INNER JOIN iam.users u
        ON t.user_id = u.user_id
        WHERE u.account_id =
        "#,
    );
    sql.push_bind(account_id);
    sql.push(" AND u.user_name_lower = ");
    sql.push_bind(user_name_lower);

    if let Some(marker) = marker {
        let m: ListUserTagsMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token for ListUserTags: {e}");
            internal_failure()
        })?;
        sql.push(" AND t.key_lower >= ");
        sql.push_bind(m.next_key_lower);
    }

    // Request one more than max_items so we can determine if there are more results.
    sql.push(" ORDER BY t.key_lower ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListUserTagsRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch user tags from database: {e}");
        internal_failure()
    })?;
    let mut results = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if results.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListUserTagsMarker {
                        next_key_lower: row.key_cased.to_lowercase(),
                    })
                    .await
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token for ListUserTags: {e}");
                        internal_failure()
                    })?,
            );
            break;
        }

        results.push(Tag::builder().key(row.key_cased).value(row.value).build().map_err(|e| {
            log::error!("Failed to construct tag object: {e}");
            internal_failure()
        })?);
    }

    let mut builder = ListUserTagsResponse::builder();
    builder = builder.tags(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(Some(true)).marker(Some(next_marker));
    }

    builder.build().map_err(|e| {
        log::error!("Failed to build ListUserTagsResponse: {e}");
        internal_failure().into()
    })
}
