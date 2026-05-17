//! Scratchstack bootsrap partition subcommands
use {
    crate::{Cli, Runnable, execute_in_transaction},
    clap::Parser,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            GetCurrentPartitionRequest, GetCurrentPartitionResponse, SetCurrentPartitionRequest,
            SetCurrentPartitionResponse,
        },
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

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<GetCurrentPartitionResponse, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        execute_in_transaction(cli, vars, &GetCurrentPartitionRequest {}).await
    }
}

impl Runnable for SetCurrentPartitionCommand {
    type Result = SetCurrentPartitionResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<SetCurrentPartitionResponse, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = SetCurrentPartitionRequest::builder().partition(self.partition.clone()).build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}
