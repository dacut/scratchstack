//! Scratchstack bootstrap database migration utility.
use {
    crate::{Cli, Runnable},
    anyhow::Result as AnyResult,
    clap::Args,
    scratchstack_database::{
        model::iam::MIGRATOR,
        utils::{create_database_if_not_exists, create_user_if_not_exists, grant_ddl_permissions},
    },
    serde::{Deserialize, Serialize},
    sqlx::query,
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
        // Get the name of the user who will actually perform the migraiton.
        let username = args.get_username()?;
        let password = args.get_password(vars.clone(), &username, "PGPASSWORD")?;

        // Connect to the database as the `postgres` user so we can initialize the database if it
        // doesn't already exist.
        log::info!("Connecting to database 'postgres' as user 'postgres'");
        let pool = args.connect_bootstrap(vars.clone(), "postgres").await?;
        let mut c = pool.acquire().await?;
        create_database_if_not_exists(&mut c, args.get_database()).await?;
        create_user_if_not_exists(&mut c, &username, &password).await?;
        grant_ddl_permissions(&mut c, args.get_database(), &username).await?;
        drop(c);

        log::info!("Connecting to database scratchstack_iam as user postgres");
        let bs_conn = args.connect_bootstrap(vars.clone(), "scratchstack_iam").await?;

        log::info!("Granting permissions to user {username} on scratchstack_iam database public schema");
        let sql = format!("GRANT CREATE ON SCHEMA public TO \"{}\"", username.replace('"', "\"\""));
        query(&sql).execute(&bs_conn).await?;
        log::info!("Granted permissions to user scratchstack on public schema in scratchstack_iam database");
        drop(bs_conn);

        log::info!("Connecting to database scratchstack_iam as {username}");
        let conn = args.connect(vars).await?;

        if let Some(downgrade_to) = self.downgrade_to {
            MIGRATOR.undo(&conn, downgrade_to).await?;
        } else {
            MIGRATOR.run(&conn).await?;
        }

        Ok(())
    }
}
