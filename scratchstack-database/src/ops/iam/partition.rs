//! Partition database level operations.

use {
    crate::{constants::iam::*, ops::RequestExecutor},
    anyhow::{Result as AnyResult, anyhow, bail},
    derive_builder::Builder,
    indoc::indoc,
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

/// Retrieve the current partition of the database, failing if it is not set.
pub async fn get_current_partition_or_fail(tx: &mut PgTransaction<'_>) -> AnyResult<String> {
    let resp = get_current_partition(tx).await?;
    if let Some(partition_id) = resp.partition_id() {
        Ok(partition_id.to_string())
    } else {
        Err(anyhow!("No partition found in database"))
    }
}

/// Sets the partition for the Scratchstack database.
#[derive(Builder, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct SetCurrentPartitionRequest {
    /// The name of the partition to set for the database. Must match the regex `^[a-z][-a-z0-9]+[a-z0-9]$`.
    #[cfg_attr(feature = "clap", arg(long))]
    #[builder(setter(into))]
    partition_id: String,
}

impl SetCurrentPartitionRequest {
    /// Creates a [`SetCurrentPartitionRequestBuilder`] for constructing a [`SetCurrentPartitionRequest`].
    #[inline(always)]
    pub fn builder() -> SetCurrentPartitionRequestBuilder {
        SetCurrentPartitionRequestBuilder::default()
    }

    /// Returns the partition ID to set for the database.
    pub fn partition_id(&self) -> &str {
        &self.partition_id
    }
}

/// Response returned by the `SetCurrentPartition` operation.
#[derive(Builder, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct SetCurrentPartitionResponse {
    /// The partition ID that was set for the service.
    #[builder(setter(into))]
    partition_id: String,
}

impl SetCurrentPartitionResponse {
    /// Creates a [`SetCurrentPartitionResponseBuilder`] for constructing a [`SetCurrentPartitionResponse`].
    #[inline(always)]
    pub fn builder() -> SetCurrentPartitionResponseBuilder {
        SetCurrentPartitionResponseBuilder::default()
    }

    /// Returns the partition ID that was set for the database.
    pub fn partition_id(&self) -> &str {
        &self.partition_id
    }
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

    Ok(SetCurrentPartitionResponse::builder().partition_id(req.partition_id.clone()).build()?)
}
