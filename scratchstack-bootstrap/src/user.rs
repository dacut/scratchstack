//! Scratchstack bootsrap create-user subcommand
use {
    crate::{Cli, Runnable},
    scratchstack_database::ops::{
        RequestExecutor,
        iam::{CreateUserRequest, CreateUserResponse},
    },
};

impl Runnable for CreateUserRequest {
    type Result = CreateUserResponse;

    async fn run(&self, args: &Cli) -> anyhow::Result<CreateUserResponse> {
        let conn = args.connect().await?;
        let mut tx = conn.begin().await?;
        let response = self.execute(&mut tx).await?;
        tx.commit().await?;

        Ok(response)
    }
}
