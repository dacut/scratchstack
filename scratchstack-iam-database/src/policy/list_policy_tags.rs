//! ListPolicyTags database operation
use {
    crate::{
        RequestExecutor,
        constants::*,
        constrain_max_items, internal_failure, make_iam_paginator,
        partition::get_current_partition_or_fail,
        policy::{lookup_managed_policy_id, parse_policy_arn},
    },
    indoc::indoc,
    log::error,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListPolicyTagsRequest, ListPolicyTagsResponse},
        types::Tag,
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, postgres::PgTransaction},
};

impl RequestExecutor for ListPolicyTagsRequest {
    type Response = ListPolicyTagsResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_policy_tags(tx, &self.policy_arn, self.marker.as_deref(), self.max_items).await
    }
}

/// The marker innards for a ListPolicyTags operation.
#[derive(Deserialize, Serialize)]
struct ListPolicyTagsMarker {
    next_key_lower: String,
}

/// The rows returned by the ListPolicyTags query.
#[derive(FromRow)]
struct ListPolicyTagsRow {
    key_lower: String,
    key_cased: String,
    value: String,
}

/// List the tags attached to a managed policy by ARN. Returns NoSuchEntity if the policy does
/// not exist.
pub async fn list_policy_tags(
    tx: &mut PgTransaction<'_>,
    policy_arn: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
) -> Result<ListPolicyTagsResponse, IamError> {
    let max_items = constrain_max_items(max_items)?;
    let partition = get_current_partition_or_fail(tx).await?;

    let parts = parse_policy_arn(policy_arn)?;
    let managed_policy_id = lookup_managed_policy_id(tx, &parts).await?;

    let paginator = make_iam_paginator(&partition, OP_LIST_POLICY_TAGS)?;

    let mut sql = QueryBuilder::new(indoc! {"
        SELECT key_lower, key_cased, value
        FROM iam.managed_policy_tags
        WHERE managed_policy_id = "});
    sql.push_bind(managed_policy_id);

    if let Some(marker) = marker {
        let m: ListPolicyTagsMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            error!("Failed to decrypt pagination token for ListPolicyTags: {e}");
            internal_failure()
        })?;
        sql.push("\nAND key_lower >= ");
        sql.push_bind(m.next_key_lower);
    }

    // Request one more than max_items so we can determine if there are more results.
    sql.push("\nORDER BY key_lower ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListPolicyTagsRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        error!("Failed to fetch managed policy tags from database: {e}");
        internal_failure()
    })?;
    let mut results = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if results.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListPolicyTagsMarker {
                        next_key_lower: row.key_lower,
                    })
                    .await
                    .map_err(|e| {
                        error!("Failed to encrypt pagination token for ListPolicyTags: {e}");
                        internal_failure()
                    })?,
            );
            break;
        }

        results.push(Tag::builder().key(row.key_cased).value(row.value).build().map_err(|e| {
            error!("Failed to build Tag: {e}");
            internal_failure()
        })?);
    }

    Ok(ListPolicyTagsResponse::builder()
        .set_tags(results)
        .is_truncated(next_marker.is_some())
        .set_marker(next_marker)
        .build()
        .map_err(|e| {
            error!("Failed to build ListPolicyTagsResponse: {e}");
            internal_failure()
        })?)
}
