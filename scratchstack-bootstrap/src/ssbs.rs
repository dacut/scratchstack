//! Scratchstack database bootstrap utility for creating initial users
#![warn(clippy::all)]
#![allow(clippy::manual_range_contains)]
#![deny(
    missing_docs,
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_html_tags,
    rustdoc::private_intra_doc_links,
    rustdoc::unescaped_backticks
)]
#![cfg_attr(doc, feature(doc_cfg))]

mod account;
mod migrate;
mod partition;
mod user;

#[cfg(test)]
mod tests;

use {
    anyhow::{Error as AnyError, Result as AnyResult},
    clap::{Parser, Subcommand},
    scratchstack_database::ops::iam::{
        CreateAccountRequest, GetCurrentPartitionRequest, ListAccountsRequest, SetCurrentPartitionRequest,
    },
    scratchstack_shapes_iam::{CreateUserInternalRequest, ListUsersInternalRequest},
    sqlx::{
        Error as SqlxError,
        postgres::{PgConnectOptions, PgPool, PgPoolOptions},
    },
    std::{
        ffi::OsString,
        io::{Write, stdout},
        time::Duration,
    },
};

/// Trait that subcommands must implement to be run by the CLI.
trait Runnable {
    type Result;

    /// Execute the subcommand.
    fn run<I>(&self, cli: &Cli, vars: I) -> impl Future<Output = Result<Self::Result, AnyError>> + Send
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send;
}

/// Scratchstack database bootstrap utility for creating initial users.
#[derive(Debug, Parser)]
#[command(name = "ssbs", version, about = "Scratchstack database bootstrap utility")]
struct Cli {
    /// The subcommand to run
    #[command(subcommand)]
    command: Commands,

    /// The database to connect to.
    #[arg(long, env = "PGDATABASE", default_value = "scratchstack_iam")]
    database: String,

    /// The database host to connect to. This can also be a directory on Unix systems, in which
    /// case a Unix socket will be used to connect to the database instead of TCP.
    #[arg(long, env = "PGHOST", default_value = "/tmp")]
    host: String,

    /// The database port to connect to.
    #[arg(long, env = "PGPORT", default_value = "7154")]
    port: u16,

    /// The database username to connect as.
    #[arg(long = "username", env = "PGUSER")]
    username: Option<String>,

    /// Never prompt for a password.
    #[arg(short = 'w', long = "no-password")]
    no_password: bool,

    /// Force password prompt. This overrides --no-password if both are specified. A password can
    /// also be provided via the PGPASSWORD environment variable, which will be used if neither
    /// --force-password-prompt nor --no-password are specified.
    #[arg(long = "force-password-prompt", default_value_t = false, conflicts_with = "no_password")]
    force_password_prompt: bool,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Create an IAM account.
    #[command(name = "create-account")]
    CreateAccount(CreateAccountRequest),

    /// Create an IAM user in an account.
    #[command(name = "create-user")]
    CreateUser(CreateUserInternalRequest),

    /// Get the current partition of the database.
    #[command(name = "get-current-partition")]
    GetCurrentPartition(GetCurrentPartitionRequest),

    /// List IAM accounts.
    #[command(name = "list-accounts")]
    ListAccounts(ListAccountsRequest),

    /// List IAM users in an account.
    #[command(name = "list-users")]
    ListUsers(ListUsersInternalRequest),

    /// Migrate the database to the latest version or a specified version.
    #[command(name = "migrate")]
    Migrate(migrate::MigrateCommand),

    /// Set the current partition for the database.
    ///
    /// This is required to be set before using any other features of the database. Partitions are
    /// separate instances of a cloud and are independent of any other partitions.
    #[command(name = "set-current-partition")]
    SetCurrentPartition(SetCurrentPartitionRequest),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> AnyResult<()> {
    env_logger::init();
    let vars = std::env::vars().map(|(k, v)| (k.into(), v)).collect::<Vec<(OsString, String)>>();
    run(std::env::args_os(), vars, &mut stdout()).await
}

/// Execute the CLI with the given arguments, environment variables, and stdout writer. This is
/// separated from the `main` function to allow for easier testing.
pub(crate) async fn run<I, T, I2, W>(args: I, vars: I2, out: &mut W) -> AnyResult<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
    I2: IntoIterator<Item = (OsString, String)> + Clone + Send,
    W: Write + Send,
{
    let cli = Cli::parse_from(args);
    let output = match &cli.command {
        Commands::CreateAccount(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response)?
        }
        Commands::CreateUser(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response)?
        }
        Commands::GetCurrentPartition(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response)?
        }
        Commands::ListAccounts(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response)?
        }
        Commands::ListUsers(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response)?
        }
        Commands::Migrate(sub) => {
            sub.run(&cli, vars).await?;
            "Migration completed successfully.".to_string()
        }
        Commands::SetCurrentPartition(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response)?
        }
    };

    writeln!(out, "{output}")?;
    Ok(())
}

impl Cli {
    /// Returns the username to connect to the database as, which is determined by the following
    /// precedence:
    /// 1. The `username` field in this configuration, if specified.
    /// 2. The `PGUSER` environment variable, if set.
    /// 3. The current system user, as returned by the `whoami` crate.
    pub(crate) fn get_username(&self) -> AnyResult<String> {
        if let Some(username) = &self.username {
            Ok(username.clone())
        } else {
            Ok(whoami::username()?)
        }
    }

    /// Returns the database name to connect to.
    pub(crate) fn get_database(&self) -> &str {
        &self.database
    }

    /// Get database connection options using the given password (or no password if `None`).
    pub(crate) fn get_connection_options(&self, password: Option<&str>) -> AnyResult<PgConnectOptions> {
        let mut opts = PgConnectOptions::new();
        opts = opts.application_name("scratchstack-bootstrap");

        opts = opts.username(&self.get_username()?);

        if let Some(pw) = password
            && !pw.is_empty()
        {
            opts = opts.password(pw);
        }

        if !self.host.is_empty() {
            opts = opts.host(&self.host);
        }

        opts = opts.port(self.port);
        opts = opts.database(self.get_database());
        Ok(opts)
    }

    pub(crate) async fn connect<I>(&self, vars: I) -> AnyResult<PgPool>
    where
        I: IntoIterator<Item = (OsString, String)> + Send,
    {
        let pool_opts = PgPoolOptions::new().max_connections(1).acquire_timeout(Duration::from_secs(5));

        if self.force_password_prompt {
            // -W: always prompt before connecting
            let username = self.get_username().map(Some).unwrap_or(None);
            let password = prompt_password(username)?;
            let opts = self.get_connection_options(Some(&password))?;
            return Ok(pool_opts.connect_with(opts).await?);
        }

        if self.no_password {
            // -w: never prompt; fail if the server requires a password
            let opts = self.get_connection_options(None)?;
            return Ok(pool_opts.connect_with(opts).await?);
        }

        // Default (psql-like): use PGPASSWORD if set, otherwise try without a password first.
        // Only prompt if the server sends an auth challenge and we had nothing to offer.
        let env_password: Option<String> = vars.into_iter().find(|(k, _)| k == "PGPASSWORD").map(|(_, v)| v);
        let opts = self.get_connection_options(env_password.as_deref())?;

        match pool_opts.clone().connect_with(opts).await {
            Ok(pool) => Ok(pool),
            Err(e) if env_password.is_none() && is_auth_error(&e) => {
                let username = self.get_username().map(Some).unwrap_or(None);
                let password = prompt_password(username)?;
                let opts = self.get_connection_options(Some(&password))?;
                Ok(pool_opts.connect_with(opts).await?)
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Prompt for a password for the given username.
pub(crate) fn prompt_password(username: Option<impl AsRef<str>>) -> AnyResult<String> {
    let prompt = if let Some(username) = &username {
        format!("Password for {}: ", username.as_ref())
    } else {
        "Password: ".to_string()
    };

    Ok(rpassword::prompt_password(&prompt)?)
}

/// PostgreSQL class 28 error codes (Invalid Authorization Specification)
const PG_CLASS_28_CODES: &[&str] = &["28P01", "28000"];

/// Returns true if the error is a Postgres authentication failure, meaning the server required
/// a password (or the one supplied was wrong).
fn is_auth_error(e: &SqlxError) -> bool {
    match e {
        SqlxError::Database(db_err) => {
            // 28P01 = invalid_password, 28000 = invalid_authorization_specification
            db_err.code().map(|c| PG_CLASS_28_CODES.contains(&&*c)).unwrap_or(false)
        }
        _ => false,
    }
}
