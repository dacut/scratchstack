//! CreateGroup database operation
use {
    crate::{
        RequestExecutor,
        account::validate_account_id,
        constants::*,
        group::{group_arn_resource, validate_group_name},
        id::IamId,
        internal_failure,
        partition::get_current_partition_or_fail,
        path::validate_path,
    },
    indoc::indoc,
    log::error,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{CreateGroupInternalRequest, CreateGroupResponse},
        types::Group,
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
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
            error!("Failed to insert group into database: {e}");
            return Err(internal_failure().into());
        }
    };
    let created_at: chrono::DateTime<chrono::Utc> = match result.try_get(0) {
        Ok(created_at) => created_at,
        Err(e) => {
            error!("Failed to get created_at from database row: {e}");
            return Err(internal_failure().into());
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
            error!("Failed to construct ARN for new group: {e}");
            return Err(internal_failure().into());
        }
    };

    let group = Group::builder()
        .arn(arn.to_string())
        .create_date(created_at)
        .path(path.to_string())
        .group_id(group_id)
        .group_name(group_name.to_string())
        .build()?;

    Ok(CreateGroupResponse::builder().group(group).build()?)
}
