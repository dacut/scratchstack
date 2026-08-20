//! GetGroup database operation
use {
    crate::{
        RequestExecutor,
        account::validate_account_id,
        constants::*,
        group::{group_arn_resource, validate_group_name},
        internal_failure,
        partition::get_current_partition_or_fail,
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{GetGroupInternalRequest, GetGroupResponse},
        types::{Group, error::NoSuchEntityException},
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for GetGroupInternalRequest {
    type Response = GetGroupResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        get_group(tx, &self.account_id, &self.group_name, request_id).await
    }
}

/// Get a group from the database.
pub async fn get_group(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    group_name: &str,
    request_id: RequestId,
) -> Result<GetGroupResponse, IamError> {
    validate_account_id(account_id, request_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_group_name(group_name, request_id)?;
    let group_name_lower = group_name.to_lowercase();

    let partition = get_current_partition_or_fail(tx, request_id).await?;

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
        internal_failure(request_id)
    })?;

    let row = row.ok_or_else(|| {
        NoSuchEntityException::builder()
            .message(format!("The group with name {group_name} cannot be found."))
            .request_id(request_id)
            .build()
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
            internal_failure(request_id)
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
            internal_failure(request_id)
        })?;

    Ok(GetGroupResponse::builder().group(group).build().unwrap())
}
