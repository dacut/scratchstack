//! ListGroups database operation
use {
    crate::{
        RequestExecutor,
        constants::iam::*,
        iam::{
            constrain_max_items, get_current_partition_or_fail, make_paginator, validate_account_id,
            validate_path_prefix,
        },
    },
    chrono::{DateTime, Utc},
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListGroupsInternalRequest, ListGroupsResponse},
        types::{Group, error::InternalFailure},
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, postgres::PgTransaction},
};

impl RequestExecutor for ListGroupsInternalRequest {
    type Response = ListGroupsResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_groups(tx, &self.account_id, self.marker.as_deref(), self.max_items, self.path_prefix.as_deref()).await
    }
}

/// The marker innards for a ListGroups operation.
#[derive(Deserialize, Serialize)]
struct ListGroupsMarker {
    next_group_name: String,
}

/// The rows returned by the ListGroups query.
#[derive(FromRow)]
struct ListGroupsRow {
    group_id: String,
    group_name_lower: String,
    group_name_cased: String,
    path: String,
    created_at: DateTime<Utc>,
}

/// List groups on the database.
pub async fn list_groups(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
    path_prefix: Option<&str>,
) -> Result<ListGroupsResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    if let Some(path_prefix) = path_prefix {
        validate_path_prefix(path_prefix)?;
    }
    let max_items = constrain_max_items(max_items)?;
    let partition = get_current_partition_or_fail(tx).await?;

    let paginator = make_paginator(&partition, OP_LIST_GROUPS)?;

    let mut sql = QueryBuilder::new(
        r#"
        SELECT group_id, group_name_lower, group_name_cased, path, created_at
        FROM iam.groups
        WHERE account_id =
    "#,
    );
    sql.push_bind(account_id);

    if let Some(path_prefix) = path_prefix {
        sql.push(" AND PATH LIKE ");
        sql.push_bind(format!("{}%", path_prefix.replace('%', "\\%").replace('_', "\\_")));
    }

    if let Some(marker) = marker {
        let info: ListGroupsMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token for ListGroups: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;
        sql.push(" AND group_name_lower >= ");
        sql.push_bind(info.next_group_name);
    }

    // Request one more than max_items so we can determine if there are more results.
    sql.push(" ORDER BY group_name_lower ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListGroupsRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch groups from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;
    let mut results = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if results.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListGroupsMarker {
                        next_group_name: row.group_name_lower,
                    })
                    .await
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token for ListGroups: {e}");
                        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                    })?,
            );
            break;
        }

        let arn = Arn::builder()
            .partition(partition.clone())
            .service("iam")
            .account_id(account_id)
            .resource(format!("group{}{}", row.path, row.group_name_cased))
            .build()
            .map_err(|e| {
                log::error!("Failed to construct ARN for group: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?;

        results.push(
            Group::builder()
                .arn(arn.to_string())
                .create_date(row.created_at)
                .path(row.path)
                .group_id(format!("{}{}", IamResourceType::Group.as_str(), row.group_id))
                .group_name(row.group_name_cased)
                .build()
                .map_err(|e| {
                    log::error!("Failed to construct group object: {e}");
                    IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                })?,
        );
    }

    let mut builder = ListGroupsResponse::builder();
    builder = builder.groups(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(Some(true)).marker(Some(next_marker));
    }

    builder.build().map_err(|e| {
        log::error!("Failed to build ListGroupsResponse: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })
}
