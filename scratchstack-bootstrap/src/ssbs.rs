//! Scratchstack database bootstrap utility for creating initial users
mod account;
mod migrate;
mod partition;
mod user;

use {
    anyhow::{Error as AnyError, Result as AnyResult},
    clap::{Parser, Subcommand},
    rpassword::prompt_password,
    scratchstack_database::ops::iam::{
        CreateAccountRequest, CreateUserRequest, GetCurrentPartitionRequest, ListAccountsRequest,
        SetCurrentPartitionRequest,
    },
    sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions},
    std::{env, time::Duration},
};

/// Trait that subcommands must implement to be run by the CLI.
trait Runnable {
    type Result;

    /// Execute the subcommand.
    fn run(&self, cli: &Cli) -> impl Future<Output = Result<Self::Result, AnyError>> + Send;
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
    #[arg(long = "force-password-prompt")]
    force_password_prompt: bool,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Create an IAM account.
    #[command(name = "create-account")]
    CreateAccount(CreateAccountRequest),

    /// Create an IAM user in an account.
    #[command(name = "create-user")]
    CreateUser(CreateUserRequest),

    /// Get the current partition of the database.
    #[command(name = "get-current-partition")]
    GetCurrentPartition(GetCurrentPartitionRequest),

    /// List IAM accounts.
    #[command(name = "list-accounts")]
    ListAccounts(ListAccountsRequest),

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
    let cli = Cli::parse();
    let output = match &cli.command {
        Commands::CreateAccount(sub) => {
            let response = sub.run(&cli).await?;
            serde_json::to_string_pretty(&response)?
        }
        Commands::CreateUser(sub) => {
            let response = sub.run(&cli).await?;
            serde_json::to_string_pretty(&response)?
        }
        Commands::GetCurrentPartition(sub) => {
            let response = sub.run(&cli).await?;
            serde_json::to_string_pretty(&response)?
        }
        Commands::ListAccounts(sub) => {
            let response = sub.run(&cli).await?;
            serde_json::to_string_pretty(&response)?
        }
        Commands::Migrate(sub) => {
            sub.run(&cli).await?;
            "Migration completed successfully.".to_string()
        }
        Commands::SetCurrentPartition(sub) => {
            let response = sub.run(&cli).await?;
            serde_json::to_string_pretty(&response)?
        }
    };
    println!("{output}");
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
        } else if let Ok(username) = env::var("PGUSER") {
            Ok(username)
        } else {
            Ok(whoami::username()?)
        }
    }

    /// Get database connection options based on the CLI arguments and environment variables.
    pub(crate) fn connection_options(&self) -> AnyResult<PgConnectOptions> {
        let mut opts = PgConnectOptions::new();

        opts = opts.application_name("scratchstack-bootstrap");

        if let Some(username) = &self.username {
            opts = opts.username(username);
        };

        if self.force_password_prompt {
            opts = opts.password(&prompt_password("Database password: ")?);
        } else if !self.no_password {
            match env::var("PGPASSWORD") {
                Ok(p) => opts = opts.password(&p),
                Err(env::VarError::NotPresent) => (),
                Err(e) => return Err(anyhow::anyhow!("Failed to read PGPASSWORD environment variable: {e}")),
            }
        }

        if !self.host.is_empty() {
            opts = opts.host(&self.host);
        }

        opts = opts.port(self.port);
        opts = opts.database(&self.database);
        Ok(opts)
    }

    /// Get bootstrap database connection options, which are the same as the regular connection
    /// options but with the database set to "postgres".
    pub(crate) fn get_bootstrap_connection_options(&self) -> AnyResult<PgConnectOptions> {
        let mut opts = self.connection_options()?;
        opts = opts.database("postgres");
        Ok(opts)
    }

    pub(crate) async fn connect(&self) -> AnyResult<PgPool> {
        let pg_opts = self.connection_options()?;
        let pool_opts = PgPoolOptions::new().max_connections(1).acquire_timeout(Duration::from_secs(5));
        Ok(pool_opts.connect_with(pg_opts).await?)
    }

    pub(crate) async fn connect_bootstrap(&self) -> AnyResult<PgPool> {
        let pg_opts = self.get_bootstrap_connection_options()?;
        let pool_opts = PgPoolOptions::new().max_connections(1).acquire_timeout(Duration::from_secs(5));
        Ok(pool_opts.connect_with(pg_opts).await?)
    }
}
