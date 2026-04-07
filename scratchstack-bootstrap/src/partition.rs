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

    async fn run<I>(&self, args: &Cli, vars: I) -> AnyResult<GetCurrentPartitionResponse>
    where
        I: IntoIterator<Item = (std::ffi::OsString, String)> + Clone + Send,
    {
        let conn = args.connect(vars).await?;
        let mut tx = conn.begin().await?;
        let result = self.execute(&mut tx).await?;
        tx.commit().await?;
        Ok(result)
    }
}

impl Runnable for SetCurrentPartitionRequest {
    type Result = SetCurrentPartitionResponse;

    async fn run<I>(&self, args: &Cli, vars: I) -> AnyResult<SetCurrentPartitionResponse>
    where
        I: IntoIterator<Item = (std::ffi::OsString, String)> + Clone + Send,
    {
        let conn = args.connect(vars).await?;
        let mut tx = conn.begin().await?;
        let result = self.execute(&mut tx).await?;
        tx.commit().await?;
        Ok(result)
    }
}
