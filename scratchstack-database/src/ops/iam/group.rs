//! Group database level operations.
use {
    crate::{
        constants::iam::*,
        model::iam::IamId,
        ops::{
            RequestExecutor,
            iam::{
                constrain_max_items, get_current_partition_or_fail, validate_account_id, validate_group_name,
                validate_path, validate_path_prefix,
            },
        },
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_pagination::{OperationPaginator, ScratchstackOperationMetadata, ScratchstackServiceMetadata},
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreateGroupInternalRequest, CreateGroupResponse, DeleteGroupInternalRequest, GetGroupInternalRequest,
            GetGroupResponse, ListGroupsInternalRequest, ListGroupsResponse, UpdateGroupInternalRequest,
        },
        types::{
            Group,
            error::{InternalFailure, NoSuchEntityException},
        },
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for CreateGroupInternalRequest {
    type Response = CreateGroupResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        create_group(tx, &self.account_id, &self.group_name, self.path.as_deref()).await
    }
}

/// Create a new group on the database.
pub async fn create_group(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    group_name: &str,
    path: Option<&str>,
) -> Result<CreateGroupResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let path = path.unwrap_or("/");
    validate_path(path)?;
    validate_group_name(group_name)?;

    // Generate a new group id for this group.
    let group_id = IamId::new(IamResourceType::Group, account_id.parse().unwrap()).to_string();
    let partition = get_current_partition_or_fail(tx).await?;

    let result = match query(indoc! {"
            INSERT INTO iam.groups(
                account_id, group_id, path, group_name_lower, group_name_cased)
            VALUES($1, $2, $3, $4, $5)
            RETURNING created_at
        "})
    .bind(account_id)
    .bind(group_id[4..].to_string())
    .bind(path)
    .bind(group_name.to_ascii_lowercase())
    .bind(group_name)
    .fetch_one(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to insert group into database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };
    let created_at: chrono::DateTime<chrono::Utc> = match result.try_get(0) {
        Ok(created_at) => created_at,
        Err(e) => {
            log::error!("Failed to get created_at from database row: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    let arn = match Arn::builder()
        .partition(partition)
        .service(SERVICE_KEY_IAM)
        .account_id(account_id)
        .resource(group_arn_resource(path, group_name))
        .build()
    {
        Ok(arn) => arn,
        Err(e) => {
            log::error!("Failed to construct ARN for new group: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    let group = Group::builder()
        .arn(arn.to_string())
        .create_date(created_at)
        .path(path.to_string())
        .group_id(group_id)
        .group_name(group_name.to_string())
        .build()
        .map_err(|e| {
            log::error!("Failed to construct group object for new group: {e}");
            InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
        })?;

    Ok(CreateGroupResponse::builder().group(group).build().unwrap())
}

impl RequestExecutor for DeleteGroupInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        delete_group(tx, &self.account_id, &self.group_name).await
    }
}

/// Delete a group from the database.
pub async fn delete_group(tx: &mut PgTransaction<'_>, account_id: &str, group_name: &str) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_group_name(group_name)?;

    let result = match query(indoc! {"
            DELETE FROM iam.groups
            WHERE account_id = $1 AND group_name_lower = $2
        "})
    .bind(account_id)
    .bind(group_name.to_lowercase())
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to delete group from database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if result.rows_affected() == 0 {
        Err(NoSuchEntityException::builder()
            .message(format!("The group with name {group_name} cannot be found."))
            .build()
            .into())
    } else {
        Ok(())
    }
}

impl RequestExecutor for GetGroupInternalRequest {
    type Response = GetGroupResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        get_group(tx, &self.account_id, &self.group_name).await
    }
}

/// Get a group from the database.
pub async fn get_group(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    group_name: &str,
) -> Result<GetGroupResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_group_name(group_name)?;
    let group_name_lower = group_name.to_lowercase();

    let partition = get_current_partition_or_fail(tx).await?;

    let row = query(indoc! {"
            SELECT group_id, group_name_cased, path, created_at
            FROM iam.groups
            WHERE account_id = $1 AND group_name_lower = $2
        "})
    .bind(account_id)
    .bind(&group_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch group from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    let row = row.ok_or_else(|| {
        IamError::from(
            NoSuchEntityException::builder()
                .message(format!("The group with name {group_name} cannot be found."))
                .build(),
        )
    })?;

    let group_id: String = row.get(0);
    let group_name_cased: String = row.get(1);
    let path: String = row.get(2);
    let created_at: DateTime<Utc> = row.get(3);

    let arn = Arn::builder()
        .partition(partition)
        .service(SERVICE_KEY_IAM)
        .account_id(account_id)
        .resource(group_arn_resource(&path, &group_name_cased))
        .build()
        .map_err(|e| {
            log::error!("Failed to construct ARN for group: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;

    let group = Group::builder()
        .arn(arn.to_string())
        .create_date(created_at)
        .path(path)
        .group_id(format!("{}{}", IamResourceType::Group.as_str(), group_id))
        .group_name(group_name_cased)
        .build()
        .map_err(|e| {
            log::error!("Failed to construct group object: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;

    Ok(GetGroupResponse::builder().group(group).build().unwrap())
}

fn group_arn_resource(path: &str, group_name: &str) -> String {
    let resource_path = path.trim_matches('/');
    if resource_path.is_empty() {
        format!("{ARN_RESOURCE_PREFIX_GROUP}{group_name}")
    } else {
        format!("{ARN_RESOURCE_PREFIX_GROUP}{resource_path}/{group_name}")
    }
}

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

    // Create the paginator for this operation.
    let service_metadata = ScratchstackServiceMetadata::new(partition.clone(), "", SERVICE_ID_IAM);
    let operation_metadata = ScratchstackOperationMetadata::new(IAM_API_VERSION, OP_LIST_GROUPS);
    let paginator =
        OperationPaginator::new_fixed_key(&service_metadata, &operation_metadata, PAGINATION_KEY_ID, *PAGINATION_KEY)
            .map_err(|e| {
            log::error!("Failed to create paginator for ListGroups: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;

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

impl RequestExecutor for UpdateGroupInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        update_group(tx, &self.account_id, &self.group_name, self.new_group_name.as_deref(), self.new_path.as_deref())
            .await
    }
}

/// Update a group on the database.
pub async fn update_group(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    group_name: &str,
    new_group_name: Option<&str>,
    new_path: Option<&str>,
) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_group_name(group_name)?;
    let group_name_lower = group_name.to_lowercase();

    let (new_group_name_cased, new_group_name_lower) = if let Some(new_group_name) = new_group_name {
        validate_group_name(new_group_name)?;
        (Some(new_group_name), Some(new_group_name.to_lowercase()))
    } else {
        (None, None)
    };

    if let Some(new_path) = new_path {
        validate_path(new_path)?;
    }

    let result = match query(indoc! {"
        UPDATE iam.groups
        SET group_name_lower = COALESCE($3, group_name_lower),
            group_name_cased = COALESCE($4, group_name_cased),
            path = COALESCE($5, path)
        WHERE account_id = $1 AND group_name_lower = $2
    "})
    .bind(account_id)
    .bind(&group_name_lower)
    .bind(new_group_name_lower)
    .bind(new_group_name_cased)
    .bind(new_path)
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to update group in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if result.rows_affected() == 0 {
        Err(NoSuchEntityException::builder()
            .message(format!("The group with name {group_name} cannot be found."))
            .build()
            .into())
    } else {
        Ok(())
    }
}
