//! GetCurrentPartition database level operation.

use {
    crate::ops::RequestExecutor,
    anyhow::{Result as AnyResult, anyhow},
    serde::{Deserialize, Serialize},
    sqlx::{Row as _, postgres::PgTransaction, query},
};

/// Parameters to get the current partition on the Scratchstack IAM database.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct GetCurrentPartitionRequest {}

/// Response for the GetCurrentPartition operation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct GetCurrentPartitionResponse {
    /// The current partition of the database.
    #[serde(skip_serializing_if = "Option::is_none")]
    partition_id: Option<String>,
}

impl GetCurrentPartitionResponse {
    /// Returns the current partition of the database, if it exists.
    #[inline(always)]
    pub fn partition_id(&self) -> Option<&str> {
        self.partition_id.as_deref()
    }
}

impl RequestExecutor for GetCurrentPartitionRequest {
    type Response = GetCurrentPartitionResponse;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> AnyResult<Self::Response> {
        get_current_partition(tx).await
    }
}

/// Retrieve the current partition of the database.
pub async fn get_current_partition(tx: &mut PgTransaction<'_>) -> AnyResult<GetCurrentPartitionResponse> {
    let result = query("SELECT partition_id FROM iam.partition").fetch_all(tx.as_mut()).await?;
    let mut partition_id = None;

    for row in result {
        if partition_id.is_some() {
            return Err(anyhow!("Multiple partitions found in database"));
        }
        partition_id = Some(row.try_get(0)?);
    }

    Ok(GetCurrentPartitionResponse {
        partition_id,
    })
}
