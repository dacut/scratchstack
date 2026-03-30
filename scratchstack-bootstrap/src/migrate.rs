//! Scratchstack bootstrap database migration utility.
use {
    crate::{Cli, Runnable},
    anyhow::Result as AnyResult,
    clap::Args,
    indoc::indoc,
    scratchstack_database::model::iam::MIGRATOR,
    serde::{Deserialize, Serialize},
    sqlx::{Row as _, query},
};

#[derive(Args, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct MigrateCommand {
    /// If specified, downgrade the database to the specified version instead of upgrading it.
    #[arg(long)]
    pub(crate) downgrade_to: Option<i64>,
}

impl Runnable for MigrateCommand {
    type Result = ();

    async fn run(&self, args: &Cli) -> AnyResult<Self::Result> {
        // Get the name of the user who will actually perform the migraiton.
        let username = args.get_username()?;

        log::info!("Connecting to database as postgres user");

        // Connect to the database as the `postgres` user so we can initialize the database if it
        // doesn't already exist.
        let bs_conn = args.connect_bootstrap().await?;

        // Has the scratchstack_iam database been created?
        let present = query("SELECT COUNT(1) FROM pg_catalog.pg_database WHERE datname = 'scratchstack_iam'")
            .fetch_one(&bs_conn)
            .await?
            .try_get::<i64, _>(0)?;

        if present == 0 {
            // No; create it.
            log::info!("Creating scratchstack_iam database");
            query("CREATE DATABASE scratchstack_iam").execute(&bs_conn).await?;
            log::info!("Created scratchstack_iam database");
        } else {
            // Yes; do nothing.
            log::info!("scratchstack_iam database already exists");
        }

        // Has the user been created on the database?
        let present = query("SELECT COUNT(1) FROM pg_catalog.pg_roles WHERE rolname = $1")
            .bind(&username)
            .fetch_one(&bs_conn)
            .await?
            .try_get::<i64, _>(0)?;

        if present == 0 {
            // No; create the user.
            log::info!("Creating database role for user {}", username);
            query(indoc!("CREATE ROLE $1 WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION"))
                .bind(&username)
                .execute(&bs_conn)
                .await?;
            log::info!("Created database role for user {}", username);
        } else {
            log::info!("Database role for user {} already exists", username);
        }

        // Does the user have permissions to create and delete tables on the database?
        let rows = query(indoc! {"
            SELECT
                (aclexplode(datacl)).grantee::regrole::text AS grantee,
                (aclexplode(datacl)).privilege_type,
                (aclexplode(datacl)).is_grantable
            FROM pg_catalog.pg_database
            WHERE datname = 'scratchstack_iam'
        "})
        .fetch_all(&bs_conn)
        .await?;
        let mut has_create = false;
        let mut has_temporary = false;
        let mut has_connect = false;

        for row in rows {
            let grantee: String = row.try_get(0)?;
            if grantee == username {
                let privilege_type: String = row.try_get(1)?;
                let is_grantable: bool = row.try_get(2)?;

                if privilege_type == "CREATE" && is_grantable {
                    has_create = true;
                } else if privilege_type == "TEMPORARY" && is_grantable {
                    has_temporary = true;
                } else if privilege_type == "CONNECT" && is_grantable {
                    has_connect = true;
                }
            }
        }

        if !has_create || !has_temporary || !has_connect {
            log::info!("Granting permissions to user {username} on scratchstack_iam database");

            // Can't use a bind parameter in DDL here. Just escape quotes in the username.
            let sql = format!(
                "GRANT CREATE, TEMPORARY, CONNECT ON DATABASE scratchstack_iam TO \"{}\" WITH GRANT OPTION",
                username.replace('"', "\"\"")
            );
            query(&sql).bind(&username).execute(&bs_conn).await?;
            log::info!("Granted permissions to user {username} on scratchstack_iam database");
        } else {
            log::info!("User {username} already has necessary permissions on scratchstack_iam database");
        }

        drop(bs_conn);

        log::info!("Connecting to database as {username}");
        let conn = args.connect().await?;

        if let Some(downgrade_to) = self.downgrade_to {
            MIGRATOR.undo(&conn, downgrade_to).await?;
        } else {
            MIGRATOR.run(&conn).await?;
        }

        Ok(())
    }
}
