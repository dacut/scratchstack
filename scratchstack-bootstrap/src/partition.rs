//! Scratchstack bootsrap partition subcommands
use {
    crate::{Cli, Runnable},
    anyhow::Result as AnyResult,
    scratchstack_database::ops::{
        RequestExecutor as _,
        iam::{
            GetCurrentPartitionRequest, GetCurrentPartitionResponse, SetCurrentPartitionRequest,
            SetCurrentPartitionResponse,
        },
    },
};

impl Runnable for GetCurrentPartitionRequest {
    type Result = GetCurrentPartitionResponse;

    async fn run(&self, args: &Cli) -> AnyResult<GetCurrentPartitionResponse> {
        let conn = args.connect().await?;
        let mut tx = conn.begin().await?;
        let result = self.execute(&mut tx).await?;
        tx.commit().await?;
        Ok(result)
    }
}

impl Runnable for SetCurrentPartitionRequest {
    type Result = SetCurrentPartitionResponse;

    async fn run(&self, args: &Cli) -> AnyResult<SetCurrentPartitionResponse> {
        let conn = args.connect().await?;
        let mut tx = conn.begin().await?;
        let result = self.execute(&mut tx).await?;
        tx.commit().await?;
        Ok(result)
    }
}
