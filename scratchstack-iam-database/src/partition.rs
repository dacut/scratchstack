//! Partition database operations.
use {
    crate::{RequestExecutor, internal_failure},
    indoc::indoc,
    scratchstack_arn::utils::validate_partition,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            GetCurrentPartitionRequest, GetCurrentPartitionResponse, SetCurrentPartitionRequest,
            SetCurrentPartitionResponse,
        },
        types::error::ValidationError,
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for GetCurrentPartitionRequest {
    type Response = GetCurrentPartitionResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        get_current_partition(tx, request_id).await
    }
}

/// Retrieve the current partition of the service.
pub async fn get_current_partition(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
) -> Result<GetCurrentPartitionResponse, IamError> {
    let result = match query("SELECT partition FROM iam.partition").fetch_all(tx.as_mut()).await {
        Ok(result) => result,
        Err(e) => {
            return Err(internal_failure!(request_id; "Failed to query partition from database: {e}").into());
        }
    };
    let mut partition: Option<String> = None;

    for row in result {
        if partition.is_some() {
            return Err(internal_failure!(request_id; "Multiple partitions found in database").into());
        }

        partition = Some(match row.try_get(0) {
            Ok(partition) => partition,
            Err(e) => {
                return Err(internal_failure!(request_id; "Failed to get partition from database row: {}", e).into());
            }
        });
    }

    let Some(partition) = partition else {
        return Err(internal_failure!(request_id; "No partition found in database").into());
    };

    GetCurrentPartitionResponse::builder()
        .partition(partition)
        .build()
        .map_err(|e| internal_failure!(request_id; "Failed to build GetCurrentPartitionResponse: {e}").into())
}

/// Retrieve the current partition of the service, failing if it is not set.
pub async fn get_current_partition_or_fail(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
) -> Result<String, IamError> {
    let resp = get_current_partition(tx, request_id).await?;
    if let Some(partition) = resp.partition {
        Ok(partition.to_string())
    } else {
        Err(internal_failure!(request_id; "No partition found in database").into())
    }
}

impl RequestExecutor for SetCurrentPartitionRequest {
    type Response = SetCurrentPartitionResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        set_current_partition(tx, self, request_id).await
    }
}

/// Set the current partition of the service.
pub async fn set_current_partition(
    tx: &mut PgTransaction<'_>,
    req: &SetCurrentPartitionRequest,
    request_id: RequestId,
) -> Result<SetCurrentPartitionResponse, IamError> {
    if req.partition.is_empty() {
        return Err(ValidationError::builder()
            .message("Partition name cannot be empty")
            .request_id(request_id)
            .build()
            .into());
    }

    if let Err(e) = validate_partition(&req.partition) {
        return Err(ValidationError::builder()
            .message(format!("Invalid partition name {}: {e}", req.partition))
            .request_id(request_id)
            .build()
            .into());
    }

    // Remove any partitions with differing names.
    if let Err(e) =
        query("DELETE FROM iam.partition WHERE partition != $1").bind(req.partition.clone()).execute(tx.as_mut()).await
    {
        return Err(internal_failure!(request_id; "Failed to delete old partitions from database: {e}").into());
    }

    // Insert the new partition if it doesn't already exist.
    if let Err(e) = query(indoc! {"
            INSERT INTO iam.partition (partition)
            VALUES ($1)
            ON CONFLICT DO NOTHING
        "})
    .bind(req.partition.clone())
    .execute(tx.as_mut())
    .await
    {
        return Err(internal_failure!(request_id; "Failed to insert partition into database: {e}").into());
    }

    SetCurrentPartitionResponse::builder()
        .partition(req.partition.clone())
        .build()
        .map_err(|e| internal_failure!(request_id; "Failed to build SetCurrentPartitionResponse: {e}").into())
}
