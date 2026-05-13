//! Scratchstack bootstrap database migration utility.
use {
    crate::{Cli, MSG_INTERNAL_FAILURE, Runnable},
    clap::Args,
    scratchstack_database::model::iam::MIGRATOR,
    scratchstack_shapes_iam::{error_meta::Error as IamError, types::error::InternalFailure},
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

    async fn run<I>(&self, args: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let conn = args.connect(vars).await?;

        if let Some(downgrade_to) = self.downgrade_to {
            MIGRATOR.undo(&conn, downgrade_to).await.map_err(|e| {
                log::error!("Failed to run database migration (downgrade): {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?;
        } else {
            MIGRATOR.run(&conn).await.map_err(|e| {
                log::error!("Failed to run database migration: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?;
        }

        Ok(())
    }
}
