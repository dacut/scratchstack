//! Scratchstack bootsrap partition subcommands
use {
    crate::{Cli, Runnable},
    anyhow::{Result as AnyResult, bail},
    clap::Args,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::Row as _,
    std::sync::LazyLock,
};

static PARTITION_NAME_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-z][-a-z0-9]+[a-z0-9]$").unwrap());

/// Retrieves the current partition for the Scratchstack database.
#[derive(Args, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct GetPartitionRequest;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct GetPartitionResponse {
    partition: String,
}

impl Runnable for GetPartitionRequest {
    type Result = GetPartitionResponse;

    async fn run(&self, args: &Cli) -> AnyResult<GetPartitionResponse> {
        let conn = args.connect().await?;
        let mut tx = conn.begin().await?;
        let result = sqlx::query("SELECT partition_name FROM partitions").fetch_one(&mut *tx).await?;

        let partition: String = result.try_get(1)?;
        Ok(GetPartitionResponse {
            partition,
        })
    }
}

/// Sets the partition for the Scratchstack database.
#[derive(Args, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct SetPartitionRequest {
    pub partition_name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct SetPartitionResponse {
    partition: String,
}

impl Runnable for SetPartitionRequest {
    type Result = SetPartitionResponse;

    async fn run(&self, args: &Cli) -> AnyResult<SetPartitionResponse> {
        if self.partition_name.is_empty() {
            bail!("Partition name cannot be empty");
        }

        if !PARTITION_NAME_REGEX.is_match(&self.partition_name) {
            bail!("Invalid partition name {}", self.partition_name);
        }

        let conn = args.connect().await?;
        let mut tx = conn.begin().await?;

        // Remove any partitions with differing names.
        sqlx::query("DELETE FROM partitions WHERE partition_name != $1")
            .bind(self.partition_name.clone())
            .execute(&mut *tx)
            .await?;

        // Insert the new partition if it doesn't already exist.
        sqlx::query(indoc! {"
            INSERT INTO partitions (partition_name)
            VALUES ($1)
            ON CONFLICT DO NOTHING
        "})
        .bind(self.partition_name.clone())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(SetPartitionResponse {
            partition: self.partition_name.clone(),
        })
    }
}
