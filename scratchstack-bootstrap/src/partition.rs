//! Scratchstack bootsrap partition subcommands
use {
    crate::{Cli, Runnable},
    anyhow::Result as AnyResult,
    clap::Parser,
    scratchstack_database::ops::RequestExecutor as _,
    scratchstack_shapes_iam::operation::{
        GetCurrentPartitionRequest, GetCurrentPartitionResponse, SetCurrentPartitionRequest,
        SetCurrentPartitionResponse,
    },
    std::ffi::OsString,
};

/// Returns the current partition of the service.
#[derive(Debug, Parser)]
pub(crate) struct GetCurrentPartitionCommand {}

/// Sets the current partition of the service.
#[derive(Debug, Parser)]
pub(crate) struct SetCurrentPartitionCommand {
    /// The partition to set for the service.
    #[clap(long)]
    pub partition: String,
}

impl Runnable for GetCurrentPartitionCommand {
    type Result = GetCurrentPartitionResponse;

    async fn run<I>(&self, args: &Cli, vars: I) -> AnyResult<GetCurrentPartitionResponse>
    where
        I: IntoIterator<Item = (std::ffi::OsString, String)> + Clone + Send,
    {
        let conn = args.connect(vars).await?;
        let mut tx = conn.begin().await?;
        let result = GetCurrentPartitionRequest {}.execute(&mut tx).await?;
        tx.commit().await?;
        Ok(result)
    }
}

impl Runnable for GetCurrentPartitionRequest {
    type Result = GetCurrentPartitionResponse;

    async fn run<I>(&self, args: &Cli, vars: I) -> AnyResult<GetCurrentPartitionResponse>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let conn = args.connect(vars).await?;
        let mut tx = conn.begin().await?;
        let result = self.execute(&mut tx).await?;
        tx.commit().await?;
        Ok(result)
    }
}

impl Runnable for SetCurrentPartitionCommand {
    type Result = SetCurrentPartitionResponse;

    async fn run<I>(&self, args: &Cli, vars: I) -> AnyResult<SetCurrentPartitionResponse>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = SetCurrentPartitionRequest::builder().partition(self.partition.clone()).build()?;
        request.run(args, vars).await
    }
}

impl Runnable for SetCurrentPartitionRequest {
    type Result = SetCurrentPartitionResponse;

    async fn run<I>(&self, args: &Cli, vars: I) -> AnyResult<SetCurrentPartitionResponse>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let conn = args.connect(vars).await?;
        let mut tx = conn.begin().await?;
        let result = self.execute(&mut tx).await?;
        tx.commit().await?;
        Ok(result)
    }
}
