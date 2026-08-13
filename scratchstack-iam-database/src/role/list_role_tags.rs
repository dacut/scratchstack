//! ListRoleTags database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, constrain_max_items, internal_failure,
        make_iam_paginator, partition::get_current_partition_or_fail, role::validate_role_name,
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListRoleTagsInternalRequest, ListRoleTagsResponse},
        types::{Tag, error::NoSuchEntityException},
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for ListRoleTagsInternalRequest {
    type Response = ListRoleTagsResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_role_tags(tx, &self.account_id, &self.role_name, self.marker.as_deref(), self.max_items).await
    }
}

/// The marker innards for a ListRoleTags operation.
#[derive(Deserialize, Serialize)]
struct ListRoleTagsMarker {
    next_key_lower: String,
}

/// The rows returned by the ListRoleTags query.
#[derive(FromRow)]
struct ListRoleTagsRow {
    key_lower: String,
    key_cased: String,
    value: String,
}

/// List the tags for a role from the database. Returns NoSuchEntity if the role does not exist.
pub async fn list_role_tags(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
) -> Result<ListRoleTagsResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name)?;
    let role_name_lower = role_name.to_lowercase();
    let max_items = constrain_max_items(max_items)?;
    let partition = get_current_partition_or_fail(tx).await?;

    let role_row = query(indoc! {"
        SELECT role_id
        FROM iam.roles
        WHERE account_id = $1 AND role_name_lower = $2
        LIMIT 1
    "})
    .bind(account_id)
    .bind(&role_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to check if role exists in database: {e}");
        internal_failure()
    })?;

    let role_id: String = match role_row {
        Some(row) => row.get(0),
        None => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The role with name {role_name} cannot be found."))
                .build()
                .into());
        }
    };

    let paginator = make_iam_paginator(&partition, OP_LIST_ROLE_TAGS)?;

    let mut sql = QueryBuilder::new(indoc! {"
        SELECT key_lower, key_cased, value
        FROM iam.role_tags
        WHERE role_id = "});
    sql.push_bind(role_id);

    if let Some(marker) = marker {
        let m: ListRoleTagsMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token for ListRoleTags: {e}");
            internal_failure()
        })?;
        sql.push("\nAND key_lower >= ");
        sql.push_bind(m.next_key_lower);
    }

    // Request one more than max_items so we can determine if there are more results.
    sql.push("\nORDER BY key_lower ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListRoleTagsRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch role tags from database: {e}");
        internal_failure()
    })?;
    let mut results = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if results.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListRoleTagsMarker {
                        next_key_lower: row.key_lower,
                    })
                    .await
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token for ListRoleTags: {e}");
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

    let mut builder = ListRoleTagsResponse::builder();
    builder = builder.set_tags(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(true).marker(next_marker);
    }

    builder.build().map_err(|e| {
        log::error!("Failed to build ListRoleTagsResponse: {e}");
        internal_failure().into()
    })
}
