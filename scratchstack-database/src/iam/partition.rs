//! Partition database level operations.
use {
    crate::{RequestExecutor, constants::iam::*, iam::internal_failure},
    indoc::indoc,
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

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        get_current_partition(tx).await
    }
}

/// Retrieve the current partition of the service.
pub async fn get_current_partition(tx: &mut PgTransaction<'_>) -> Result<GetCurrentPartitionResponse, IamError> {
    let result = match query("SELECT partition FROM iam.partition").fetch_all(tx.as_mut()).await {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to query partition from database: {e}");
            return Err(internal_failure().into());
        }
    };
    let mut partition: Option<String> = None;

    for row in result {
        if partition.is_some() {
            log::error!("Multiple partitions found in database");
            return Err(internal_failure().into());
        }

        partition = Some(match row.try_get(0) {
            Ok(partition) => partition,
            Err(e) => {
                log::error!("Failed to get partition from database row: {}", e);
                return Err(internal_failure().into());
            }
        });
    }

    let Some(partition) = partition else {
        log::error!("No partition found in database");
        return Err(internal_failure().into());
    };

    GetCurrentPartitionResponse::builder().partition(partition).build().map_err(|e| {
        log::error!("Failed to build GetCurrentPartitionResponse: {e}");
        internal_failure().into()
    })
}

/// Retrieve the current partition of the service, failing if it is not set.
pub async fn get_current_partition_or_fail(tx: &mut PgTransaction<'_>) -> Result<String, IamError> {
    let resp = get_current_partition(tx).await?;
    if let Some(partition) = resp.partition {
        Ok(partition.to_string())
    } else {
        log::error!("No partition found in database");
        Err(internal_failure().into())
    }
}

impl RequestExecutor for SetCurrentPartitionRequest {
    type Response = SetCurrentPartitionResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        set_current_partition(tx, self).await
    }
}

/// Set the current partition of the service.
pub async fn set_current_partition(
    tx: &mut PgTransaction<'_>,
    req: &SetCurrentPartitionRequest,
) -> Result<SetCurrentPartitionResponse, IamError> {
    if req.partition.is_empty() {
        return Err(ValidationError::builder().message("Partition name cannot be empty").build().into());
    }

    if !PARTITION_NAME_REGEX.is_match(&req.partition) {
        return Err(ValidationError::builder()
            .message(format!("Invalid partition name {}", req.partition))
            .build()
            .into());
    }

    // Remove any partitions with differing names.
    if let Err(e) =
        query("DELETE FROM iam.partition WHERE partition != $1").bind(req.partition.clone()).execute(tx.as_mut()).await
    {
        log::error!("Failed to delete old partitions from database: {e}");
        return Err(internal_failure().into());
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
        log::error!("Failed to insert partition into database: {e}");
        return Err(internal_failure().into());
    }

    SetCurrentPartitionResponse::builder().partition(req.partition.clone()).build().map_err(|e| {
        log::error!("Failed to build SetCurrentPartitionResponse: {e}");
        internal_failure().into()
    })
}
