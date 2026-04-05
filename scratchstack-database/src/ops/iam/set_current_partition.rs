//! SetCurrentPartition database level operation.

use {
    crate::{model::iam::PARTITION_NAME_REGEX, ops::RequestExecutor},
    anyhow::{Result as AnyResult, bail},
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::{postgres::PgTransaction, query},
};

/// Sets the partition for the Scratchstack database.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct SetCurrentPartitionRequest {
    /// The name of the partition to set for the database. Must match the regex `^[a-z][-a-z0-9]+[a-z0-9]$`.
    #[cfg_attr(feature = "clap", arg(long))]
    pub partition_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct SetCurrentPartitionResponse {
    partition_id: String,
}

impl RequestExecutor for SetCurrentPartitionRequest {
    type Response = SetCurrentPartitionResponse;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> AnyResult<Self::Response> {
        set_current_partition(tx, self).await
    }
}

/// Set the current partition of the database.
pub async fn set_current_partition(
    tx: &mut PgTransaction<'_>,
    req: &SetCurrentPartitionRequest,
) -> AnyResult<SetCurrentPartitionResponse> {
    if req.partition_id.is_empty() {
        bail!("Partition name cannot be empty");
    }

    if !PARTITION_NAME_REGEX.is_match(&req.partition_id) {
        bail!("Invalid partition name {}", req.partition_id);
    }

    // Remove any partitions with differing names.
    query("DELETE FROM iam.partition WHERE partition_id != $1")
        .bind(req.partition_id.clone())
        .execute(tx.as_mut())
        .await?;

    // Insert the new partition if it doesn't already exist.
    query(indoc! {"
            INSERT INTO iam.partition (partition_id)
            VALUES ($1)
            ON CONFLICT DO NOTHING
        "})
    .bind(req.partition_id.clone())
    .execute(tx.as_mut())
    .await?;

    Ok(SetCurrentPartitionResponse {
        partition_id: req.partition_id.clone(),
    })
}
