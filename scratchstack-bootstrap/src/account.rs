//! Scratchstack bootsrap account subcommands
use {
    crate::{Cli, Runnable},
    anyhow::Error as AnyError,
    scratchstack_database::ops::{
        RequestExecutor,
        iam::{CreateAccountRequest, CreateAccountResponse, ListAccountsRequest, ListAccountsResponse},
    },
    std::ffi::OsString,
};

impl Runnable for CreateAccountRequest {
    type Result = CreateAccountResponse;

    async fn run<I>(&self, args: &Cli, vars: I) -> Result<Self::Result, AnyError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let conn = args.connect(vars).await?;
        let mut tx = conn.begin().await?;
        let response = self.execute(&mut tx).await?;
        tx.commit().await?;

        Ok(response)
    }
}

impl Runnable for ListAccountsRequest {
    type Result = ListAccountsResponse;

    async fn run<I>(&self, args: &Cli, vars: I) -> Result<Self::Result, AnyError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let conn = args.connect(vars).await?;
        let mut tx = conn.begin().await?;
        let response = self.execute(&mut tx).await?;
        tx.commit().await?;

        Ok(response)
    }
}
