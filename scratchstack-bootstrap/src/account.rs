//! Scratchstack bootsrap account subcommands
use {
    crate::{Cli, Runnable},
    anyhow::Error as AnyError,
    scratchstack_database::ops::{
        RequestExecutor,
        iam::{CreateAccountRequest, CreateAccountResponse, ListAccountsRequest, ListAccountsResponse},
    },
};

impl Runnable for CreateAccountRequest {
    type Result = CreateAccountResponse;

    async fn run(&self, args: &Cli) -> Result<Self::Result, AnyError> {
        let conn = args.connect().await?;
        let mut tx = conn.begin().await?;
        let response = self.execute(&mut tx).await?;
        tx.commit().await?;

        Ok(response)
    }
}

impl Runnable for ListAccountsRequest {
    type Result = ListAccountsResponse;

    async fn run(&self, args: &Cli) -> Result<Self::Result, AnyError> {
        let conn = args.connect().await?;
        let mut tx = conn.begin().await?;
        let response = self.execute(&mut tx).await?;
        tx.commit().await?;

        Ok(response)
    }
}
