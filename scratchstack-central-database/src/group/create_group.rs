//! CreateGroup database operation
use {
    crate::{
        RequestExecutor,
        account::validate_account_id,
        constants::*,
        group::{group_arn_resource, is_group_name_unique_violation, validate_group_name},
        id::IamId,
        internal_failure,
        partition::get_current_partition_or_fail,
        path::validate_path,
    },
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{CreateGroupInternalRequest, CreateGroupResponse},
        types::{Group, error::EntityAlreadyExistsException},
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for CreateGroupInternalRequest {
    type Response = CreateGroupResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        create_group(tx, &self.account_id, &self.group_name, self.path.as_deref(), request_id).await
    }
}

/// Create a new group on the database.
pub async fn create_group(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    group_name: &str,
    path: Option<&str>,
    request_id: RequestId,
) -> Result<CreateGroupResponse, IamError> {
    validate_account_id(account_id, request_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let path = path.unwrap_or("/");
    validate_path(path, request_id)?;
    validate_group_name(group_name, request_id)?;

    // Generate a new group id for this group.
    let group_id = IamId::new(IamResourceType::Group, account_id.parse().unwrap()).to_string();
    let partition = get_current_partition_or_fail(tx, request_id).await?;

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
            if is_group_name_unique_violation(&e) {
                let message = format!("Group with name {group_name} already exists.");
                return Err(EntityAlreadyExistsException::builder()
                    .message(message)
                    .request_id(request_id)
                    .build()
                    .into());
            }
            return Err(internal_failure!(request_id; "Failed to insert group into database: {e}").into());
        }
    };
    let created_at: chrono::DateTime<chrono::Utc> = match result.try_get(0) {
        Ok(created_at) => created_at,
        Err(e) => {
            return Err(internal_failure!(request_id; "Failed to get created_at from database row: {e}").into());
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
            return Err(internal_failure!(request_id; "Failed to construct ARN for new group: {e}").into());
        }
    };

    let group = Group::builder()
        .arn(arn.to_string())
        .create_date(created_at)
        .path(path.to_string())
        .group_id(group_id)
        .group_name(group_name.to_string())
        .build()
        .map_err(|e| internal_failure!(request_id; "Failed to construct group object for new group: {e}"))?;

    Ok(CreateGroupResponse::builder().group(group).build().unwrap())
}
