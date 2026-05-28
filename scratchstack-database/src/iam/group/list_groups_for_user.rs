//! ListGroupsForUser database operation
use {
    crate::{
        RequestExecutor,
        constants::iam::*,
        iam::{
            constrain_max_items, get_current_partition_or_fail, internal_failure, make_paginator, validate_account_id,
            validate_user_name,
        },
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListGroupsForUserInternalRequest, ListGroupsForUserResponse},
        types::{Group, error::NoSuchEntityException},
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, postgres::PgTransaction, query},
};

impl RequestExecutor for ListGroupsForUserInternalRequest {
    type Response = ListGroupsForUserResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_groups_for_user(tx, &self.account_id, &self.user_name, self.marker.as_deref(), self.max_items).await
    }
}

/// The marker innards for a ListGroupsForUser operation.
#[derive(Deserialize, Serialize)]
struct ListGroupsForUserMarker {
    next_group_name: String,
}

/// The rows returned by the ListGroupsForUser query.
#[derive(FromRow)]
struct ListGroupsForUserRow {
    group_id: String,
    group_name_lower: String,
    group_name_cased: String,
    path: String,
    created_at: DateTime<Utc>,
}

/// List groups that a user belongs to.
pub async fn list_groups_for_user(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
) -> Result<ListGroupsForUserResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_user_name(user_name)?;
    let user_name_lower = user_name.to_lowercase();
    let max_items = constrain_max_items(max_items)?;
    let partition = get_current_partition_or_fail(tx).await?;

    // Verify the user exists.
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

    let paginator = make_paginator(&partition, OP_LIST_GROUPS_FOR_USER)?;

    let mut sql = QueryBuilder::new(
        r#"
        SELECT g.group_id, g.group_name_lower, g.group_name_cased, g.path, g.created_at
        FROM iam.groups g
        INNER JOIN iam.group_memberships gm ON g.group_id = gm.group_id
        INNER JOIN iam.users u ON gm.user_id = u.user_id
        WHERE u.account_id =
        "#,
    );
    sql.push_bind(account_id);
    sql.push(" AND u.user_name_lower = ");
    sql.push_bind(user_name_lower);

    if let Some(marker) = marker {
        let info: ListGroupsForUserMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token for ListGroupsForUser: {e}");
            internal_failure()
        })?;
        sql.push(" AND g.group_name_lower >= ");
        sql.push_bind(info.next_group_name);
    }

    // Request one more than max_items so we can determine if there are more results.
    sql.push(" ORDER BY g.group_name_lower ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListGroupsForUserRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch groups for user from database: {e}");
        internal_failure()
    })?;
    let mut results = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if results.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListGroupsForUserMarker {
                        next_group_name: row.group_name_lower,
                    })
                    .await
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token for ListGroupsForUser: {e}");
                        internal_failure()
                    })?,
            );
            break;
        }

        let arn = Arn::builder()
            .partition(partition.clone())
            .service(SERVICE_KEY_IAM)
            .account_id(account_id)
            .resource(format!("group{}{}", row.path, row.group_name_cased))
            .build()
            .map_err(|e| {
                log::error!("Failed to construct ARN for group: {e}");
                internal_failure()
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
                    internal_failure()
                })?,
        );
    }

    let mut builder = ListGroupsForUserResponse::builder();
    builder = builder.groups(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(Some(true)).marker(Some(next_marker));
    }

    builder.build().map_err(|e| {
        log::error!("Failed to build ListGroupsForUserResponse: {e}");
        internal_failure().into()
    })
}
