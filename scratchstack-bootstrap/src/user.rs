//! Scratchstack bootsrap create-user subcommand
use {
    crate::{Cli, Runnable},
    anyhow::Result as AnyResult,
    scratchstack_database::ops::RequestExecutor,
    scratchstack_shapes::iam::{CreateUserRequestInternal, CreateUserResponseInternal},
};

impl Runnable for CreateUserRequestInternal {
    type Result = CreateUserResponseInternal;

    async fn run<I>(&self, args: &Cli, vars: I) -> AnyResult<CreateUserResponseInternal>
    where
        I: IntoIterator<Item = (std::ffi::OsString, String)> + Clone + Send,
    {
        let conn = args.connect(vars).await?;
        let mut tx = conn.begin().await?;
        let response = self.execute(&mut tx).await?;
        tx.commit().await?;

        Ok(response)
    }
}
