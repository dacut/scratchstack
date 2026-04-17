//! Scratchstack bootstrap database migration utility.
use {
    crate::{Cli, Runnable},
    anyhow::Result as AnyResult,
    clap::Args,
    scratchstack_database::model::iam::MIGRATOR,
    serde::{Deserialize, Serialize},
    std::ffi::OsString,
};

#[derive(Args, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct MigrateCommand {
    /// If specified, downgrade the database to the specified version instead of upgrading it.
    #[arg(long)]
    pub(crate) downgrade_to: Option<i64>,
}

impl MigrateCommand {}

impl Runnable for MigrateCommand {
    type Result = ();

    async fn run<I>(&self, args: &Cli, vars: I) -> AnyResult<Self::Result>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let conn = args.connect(vars).await?;

        if let Some(downgrade_to) = self.downgrade_to {
            MIGRATOR.undo(&conn, downgrade_to).await?;
        } else {
            MIGRATOR.run(&conn).await?;
        }

        Ok(())
    }
}
