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
    crate::{
        account::{CreateAccountCommand, ListAccountsCommand},
        partition::{GetCurrentPartitionCommand, SetCurrentPartitionCommand},
        user::{CreateUserInternalCommand, DeleteUserInternalCommand, ListUsersInternalCommand, UpdateUserInternalCommand},
    },
    aws_smithy_types::error::metadata::ProvideErrorMetadata,
    clap::{Parser, Subcommand},
    scratchstack_shapes_iam::{error_meta::Error as IamError, types::error::InternalFailure},
    scratchstack_database::ops::RequestExecutor,
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
    fn run<I>(&self, cli: &Cli, vars: I) -> impl Future<Output = Result<Self::Result, IamError>> + Send
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
    CreateAccount(CreateAccountCommand),

    /// Create an IAM user in an account.
    #[command(name = "create-user")]
    CreateUser(CreateUserInternalCommand),

    /// Delete an IAM user from an account.
    #[command(name = "delete-user")]
    DeleteUser(DeleteUserInternalCommand),

    /// Get the current partition of the database.
    #[command(name = "get-current-partition")]
    GetCurrentPartition(GetCurrentPartitionCommand),

    /// List IAM accounts.
    #[command(name = "list-accounts")]
    ListAccounts(ListAccountsCommand),

    /// List IAM users in an account.
    #[command(name = "list-users")]
    ListUsers(ListUsersInternalCommand),

    /// Migrate the database to the latest version or a specified version.
    #[command(name = "migrate")]
    Migrate(migrate::MigrateCommand),

    /// Set the current partition for the database.
    ///
    /// This is required to be set before using any other features of the database. Partitions are
    /// separate instances of a cloud and are independent of any other partitions.
    #[command(name = "set-current-partition")]
    SetCurrentPartition(SetCurrentPartitionCommand),

    /// Update an IAM user in an account.
    #[command(name = "update-user")]
    UpdateUser(UpdateUserInternalCommand),
}

impl Commands {
    /// Return the AWS-style operation name for this command.
    fn operation_name(&self) -> &'static str {
        match self {
            Commands::CreateAccount(_) => "CreateAccount",
            Commands::CreateUser(_) => "CreateUser",
            Commands::DeleteUser(_) => "DeleteUser",
            Commands::GetCurrentPartition(_) => "GetCurrentPartition",
            Commands::ListAccounts(_) => "ListAccounts",
            Commands::ListUsers(_) => "ListUsers",
            Commands::Migrate(_) => "Migrate",
            Commands::SetCurrentPartition(_) => "SetCurrentPartition",
            Commands::UpdateUser(_) => "UpdateUser",
        }
    }
}

/// Format an IamError in the AWS CLI style.
pub(crate) fn format_iam_error(error: &IamError, operation: &str) -> String {
    let code = error.code().unwrap_or("Unknown");
    let message = error.message().unwrap_or_default();
    format!("An error occurred ({code}) when calling the {operation} operation: {message}")
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();
    let args: Vec<OsString> = std::env::args_os().collect();
    let vars = std::env::vars().map(|(k, v)| (k.into(), v)).collect::<Vec<(OsString, String)>>();

    // Pre-parse just to extract the operation name for error formatting.
    let cli = Cli::parse_from(&args);
    let operation = cli.command.operation_name();

    if let Err(e) = run(args, vars, &mut stdout()).await {
        eprintln!("{}", format_iam_error(&e, operation));
        std::process::exit(1);
    }
}

/// Execute the CLI with the given arguments, environment variables, and stdout writer. This is
/// separated from the `main` function to allow for easier testing.
pub(crate) async fn run<I, T, I2, W>(args: I, vars: I2, out: &mut W) -> Result<(), IamError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
    I2: IntoIterator<Item = (OsString, String)> + Clone + Send,
    W: Write + Send,
{
    let cli = Cli::parse_from(args);
    let result = match &cli.command {
        Commands::CreateAccount(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::CreateUser(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::DeleteUser(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::GetCurrentPartition(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListAccounts(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListUsers(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::Migrate(sub) => {
            sub.run(&cli, vars).await?;
            "Migration completed successfully.".to_string()
        }
        Commands::SetCurrentPartition(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::UpdateUser(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
    };

    writeln!(out, "{result}").map_err(|e| {
        log::error!("Failed to write output: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;
    Ok(())
}

/// Internal failure message constant.
const MSG_INTERNAL_FAILURE: &str = "An internal error has occurred.";

/// Connect to the database, run a [`RequestExecutor`] inside a transaction, and commit.
///
/// On error the transaction is explicitly rolled back before the pool is dropped, avoiding
/// PostgreSQL "unexpected EOF on client connection with an open transaction" warnings.
pub(crate) async fn execute_in_transaction<R>(
    cli: &Cli,
    vars: impl IntoIterator<Item = (OsString, String)> + Send,
    request: &R,
) -> Result<R::Response, IamError>
where
    R: RequestExecutor<Error = IamError> + Sync,
{
    let conn = cli.connect(vars).await?;
    let mut tx = conn.begin().await.map_err(|e| {
        log::error!("Failed to begin transaction: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    match request.execute(&mut tx).await {
        Ok(response) => {
            tx.commit().await.map_err(|e| {
                log::error!("Failed to commit transaction: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?;
            Ok(response)
        }
        Err(e) => {
            if let Err(rollback_err) = tx.rollback().await {
                log::error!("Failed to rollback transaction: {rollback_err}");
            }
            Err(e)
        }
    }
}

impl Cli {
    /// Returns the username to connect to the database as, which is determined by the following
    /// precedence:
    /// 1. The `username` field in this configuration, if specified.
    /// 2. The `PGUSER` environment variable, if set.
    /// 3. The current system user, as returned by the `whoami` crate.
    pub(crate) fn get_username(&self) -> Result<String, IamError> {
        if let Some(username) = &self.username {
            Ok(username.clone())
        } else {
            whoami::username().map_err(|e| {
                log::error!("Failed to determine current username: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })
        }
    }

    /// Returns the database name to connect to.
    pub(crate) fn get_database(&self) -> &str {
        &self.database
    }

    /// Get database connection options using the given password (or no password if `None`).
    pub(crate) fn get_connection_options(&self, password: Option<&str>) -> Result<PgConnectOptions, IamError> {
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

    pub(crate) async fn connect<I>(&self, vars: I) -> Result<PgPool, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Send,
    {
        let pool_opts = PgPoolOptions::new().max_connections(1).acquire_timeout(Duration::from_secs(5));

        if self.force_password_prompt {
            // -W: always prompt before connecting
            let username = self.get_username().map(Some).unwrap_or(None);
            let password = prompt_password(username)?;
            let opts = self.get_connection_options(Some(&password))?;
            return pool_opts.connect_with(opts).await.map_err(|e| {
                log::error!("Failed to connect to database: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            });
        }

        if self.no_password {
            // -w: never prompt; fail if the server requires a password
            let opts = self.get_connection_options(None)?;
            return pool_opts.connect_with(opts).await.map_err(|e| {
                log::error!("Failed to connect to database: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            });
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
                pool_opts.connect_with(opts).await.map_err(|e| {
                    log::error!("Failed to connect to database: {e}");
                    IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                })
            }
            Err(e) => {
                log::error!("Failed to connect to database: {e}");
                Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into())
            }
        }
    }
}

/// Prompt for a password for the given username.
pub(crate) fn prompt_password(username: Option<impl AsRef<str>>) -> Result<String, IamError> {
    let prompt = if let Some(username) = &username {
        format!("Password for {}: ", username.as_ref())
    } else {
        "Password: ".to_string()
    };

    rpassword::prompt_password(&prompt).map_err(|e| {
        log::error!("Failed to prompt for password: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })
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
