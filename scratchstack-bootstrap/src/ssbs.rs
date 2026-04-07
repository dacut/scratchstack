//! Scratchstack database bootstrap utility for creating initial users
mod account;
mod migrate;
mod partition;
#[cfg(test)]
mod tests;
mod user;

use {
    anyhow::{Error as AnyError, Result as AnyResult},
    clap::{Parser, Subcommand},
    rpassword::prompt_password,
    scratchstack_database::ops::iam::{
        CreateAccountRequest, GetCurrentPartitionRequest, ListAccountsRequest, SetCurrentPartitionRequest,
    },
    scratchstack_shapes::iam::CreateUserRequestInternal,
    sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions},
    std::{
        collections::{HashMap, hash_map::Entry},
        ffi::OsString,
        io::{Write, stdout},
        sync::{Arc, Mutex},
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
    #[arg(long = "force-password-prompt")]
    force_password_prompt: bool,

    /// A mapping from the environment variable name to use as the password to the password itself.
    /// This is used to resolve the password for the database user if it has not already been resolved.
    #[arg(skip)]
    passwords: Arc<Mutex<HashMap<String, String>>>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Create an IAM account.
    #[command(name = "create-account")]
    CreateAccount(CreateAccountRequest),

    /// Create an IAM user in an account.
    #[command(name = "create-user")]
    CreateUser(CreateUserRequestInternal),

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

    /// Returns the database password.
    pub(crate) fn get_password<I>(&self, vars: I, username: &str, env_password: &str) -> AnyResult<String>
    where
        I: IntoIterator<Item = (OsString, String)> + Send,
    {
        let mut passwords = self.passwords.lock().expect("Passwords lock poisoned");

        match passwords.entry(env_password.to_string()) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                let password = if self.force_password_prompt {
                    let prompt = format!("Password for database user {username}: ");
                    prompt_password(&prompt)?
                } else if self.no_password {
                    "".to_string()
                } else if let Some(env_password) = vars.into_iter().find_map(|(k, v)| {
                    if k == env_password {
                        Some(v)
                    } else {
                        None
                    }
                }) {
                    env_password
                } else {
                    "".to_string()
                };

                entry.insert(password.clone());
                Ok(password)
            }
        }
    }

    /// Returns the database name to connect to.
    pub(crate) fn get_database(&self) -> &str {
        &self.database
    }

    /// Get database connection options based on the CLI arguments and environment variables.
    pub(crate) fn get_connection_options<I>(&self, vars: I) -> AnyResult<PgConnectOptions>
    where
        I: IntoIterator<Item = (OsString, String)> + Send,
    {
        self.get_connection_options_ex(vars, &self.get_username()?, "PGPASSWORD")
    }

    /// Get bootstrap database connection options, which are the same as the regular connection
    /// options but with the database set to "postgres".
    pub(crate) fn get_bootstrap_connection_options<I>(&self, var: I, database: &str) -> AnyResult<PgConnectOptions>
    where
        I: IntoIterator<Item = (OsString, String)> + Send,
    {
        let options = self.get_connection_options_ex(var, "postgres", "BOOTSTRAP_PGPASSWORD")?;
        Ok(options.username("postgres").database(database))
    }

    /// Get database connection options based on the CLI arguments and environment variables.
    /// The environment variable to use as the password is also specified here.
    ///
    fn get_connection_options_ex<I>(&self, vars: I, username: &str, env_var: &str) -> AnyResult<PgConnectOptions>
    where
        I: IntoIterator<Item = (OsString, String)> + Send,
    {
        let mut opts = PgConnectOptions::new();
        opts = opts.application_name("scratchstack-bootstrap");

        if let Some(username) = &self.username {
            opts = opts.username(username);
        };

        let password = self.get_password(vars, username, env_var)?;
        if !password.is_empty() {
            opts = opts.password(&password);
        }

        if !self.host.is_empty() {
            opts = opts.host(&self.host);
        }

        opts = opts.port(self.port);
        opts = opts.database(&self.database);
        Ok(opts)
    }

    pub(crate) async fn connect<I>(&self, vars: I) -> AnyResult<PgPool>
    where
        I: IntoIterator<Item = (OsString, String)> + Send,
    {
        let pg_opts = self.get_connection_options(vars)?;
        let pool_opts = PgPoolOptions::new().max_connections(1).acquire_timeout(Duration::from_secs(5));
        Ok(pool_opts.connect_with(pg_opts).await?)
    }

    pub(crate) async fn connect_bootstrap<I>(&self, vars: I, database: &str) -> AnyResult<PgPool>
    where
        I: IntoIterator<Item = (OsString, String)> + Send,
    {
        let pg_opts = self.get_bootstrap_connection_options(vars, database)?;
        let pool_opts = PgPoolOptions::new().max_connections(1).acquire_timeout(Duration::from_secs(5));
        Ok(pool_opts.connect_with(pg_opts).await?)
    }
}
