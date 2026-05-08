//! Partition database level operations.
use {
    crate::{constants::iam::*, ops::RequestExecutor},
    anyhow::{Result as AnyResult, bail},
    indoc::indoc,
    scratchstack_shapes_iam::{
        operation::{
            GetCurrentPartitionRequest, GetCurrentPartitionResponse, SetCurrentPartitionRequest,
            SetCurrentPartitionResponse,
        },
        types::error::InternalFailure,
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for GetCurrentPartitionRequest {
    type Response = GetCurrentPartitionResponse;
    type Error = InternalFailure;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        get_current_partition(tx).await
    }
}

/// Retrieve the current partition of the service.
pub async fn get_current_partition(tx: &mut PgTransaction<'_>) -> Result<GetCurrentPartitionResponse, InternalFailure> {
    let result = match query("SELECT partition FROM iam.partition").fetch_all(tx.as_mut()).await {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to query partition from database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build());
        }
    };
    let mut partition: Option<String> = None;

    for row in result {
        if partition.is_some() {
            log::error!("Multiple partitions found in database");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build());
        }

        partition = Some(match row.try_get(0) {
            Ok(partition) => partition,
            Err(e) => {
                log::error!("Failed to get partition from database row: {}", e);
                return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build());
            }
        });
    }

    let Some(partition) = partition else {
        log::error!("No partition found in database");
        return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build());
    };

    GetCurrentPartitionResponse::builder().partition(partition).build().map_err(|e| {
        log::error!("Failed to build GetCurrentPartitionResponse: {e}");
        InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
    })
}

/// Retrieve the current partition of the service, failing if it is not set.
pub async fn get_current_partition_or_fail(tx: &mut PgTransaction<'_>) -> Result<String, InternalFailure> {
    let resp = get_current_partition(tx).await?;
    if let Some(partition) = resp.partition {
        Ok(partition.to_string())
    } else {
        log::error!("No partition found in database");
        Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    }
}

impl RequestExecutor for SetCurrentPartitionRequest {
    type Response = SetCurrentPartitionResponse;
    type Error = anyhow::Error;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> AnyResult<Self::Response> {
        set_current_partition(tx, self).await
    }
}

/// Set the current partition of the service.
pub async fn set_current_partition(
    tx: &mut PgTransaction<'_>,
    req: &SetCurrentPartitionRequest,
) -> AnyResult<SetCurrentPartitionResponse> {
    if req.partition.is_empty() {
        bail!("Partition name cannot be empty");
    }

    if !PARTITION_NAME_REGEX.is_match(&req.partition) {
        bail!("Invalid partition name {}", req.partition);
    }

    // Remove any partitions with differing names.
    query("DELETE FROM iam.partition WHERE partition != $1").bind(req.partition.clone()).execute(tx.as_mut()).await?;

    // Insert the new partition if it doesn't already exist.
    query(indoc! {"
            INSERT INTO iam.partition (partition)
            VALUES ($1)
            ON CONFLICT DO NOTHING
        "})
    .bind(req.partition.clone())
    .execute(tx.as_mut())
    .await?;

    Ok(SetCurrentPartitionResponse::builder().partition(req.partition.clone()).build()?)
}
