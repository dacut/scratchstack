//! Scratchstack bootsrap create-user subcommand
use {
    crate::{Cli, Runnable},
    anyhow::Result as AnyResult,
    scratchstack_database::ops::RequestExecutor,
    scratchstack_shapes_iam::{
        CreateUserInternalRequest, CreateUserResponse, ListUsersInternalRequest, ListUsersResponse,
    },
    std::ffi::OsString,
};

impl Runnable for CreateUserInternalRequest {
    type Result = CreateUserResponse;

    async fn run<I>(&self, args: &Cli, vars: I) -> AnyResult<CreateUserResponse>
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

impl Runnable for ListUsersInternalRequest {
    type Result = ListUsersResponse;

    async fn run<I>(&self, args: &Cli, vars: I) -> AnyResult<ListUsersResponse>
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
