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
mod group;
mod migrate;
mod partition;
mod policy;
mod role;
mod user;

#[cfg(test)]
mod tests;

use {
    crate::{
        account::{CreateAccountCommand, ListAccountsCommand},
        group::{
            AddUserToGroupInternalCommand, AttachGroupPolicyInternalCommand, CreateGroupInternalCommand,
            DeleteGroupInternalCommand, DetachGroupPolicyInternalCommand, GetGroupInternalCommand,
            ListAttachedGroupPoliciesInternalCommand, ListGroupsForUserInternalCommand, ListGroupsInternalCommand,
            RemoveUserFromGroupInternalCommand, UpdateGroupInternalCommand,
        },
        partition::{GetCurrentPartitionCommand, SetCurrentPartitionCommand},
        policy::{
            CreatePolicyInternalCommand, CreatePolicyVersionCommand, DeletePolicyCommand, DeletePolicyVersionCommand,
            GetPolicyCommand, GetPolicyVersionCommand, ListEntitiesForPolicyCommand, ListPoliciesInternalCommand,
            ListPolicyVersionsCommand, SetDefaultPolicyVersionCommand, TagPolicyCommand, UntagPolicyCommand,
        },
        role::{
            AttachRolePolicyInternalCommand, CreateRoleInternalCommand, DetachRolePolicyInternalCommand,
            ListAttachedRolePoliciesInternalCommand,
        },
        user::{
            AttachUserPolicyInternalCommand, CreateUserInternalCommand, DeleteUserInternalCommand,
            DetachUserPolicyInternalCommand, GetUserInternalCommand, ListAttachedUserPoliciesInternalCommand,
            ListUserTagsInternalCommand, ListUsersInternalCommand, TagUserInternalCommand, UntagUserInternalCommand,
            UpdateUserInternalCommand,
        },
    },
    aws_smithy_types::error::metadata::ProvideErrorMetadata,
    clap::{Parser, Subcommand},
    scratchstack_database::ops::RequestExecutor,
    scratchstack_shapes_iam::{error_meta::Error as IamError, types::error::InternalFailure},
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
    /// Add a user to a group in an account.
    #[command(name = "add-user-to-group")]
    AddUserToGroup(AddUserToGroupInternalCommand),

    /// Attach a managed policy to a group in an account.
    #[command(name = "attach-group-policy")]
    AttachGroupPolicy(AttachGroupPolicyInternalCommand),

    /// Attach a managed policy to a role in an account.
    #[command(name = "attach-role-policy")]
    AttachRolePolicy(AttachRolePolicyInternalCommand),

    /// Attach a managed policy to a user in an account.
    #[command(name = "attach-user-policy")]
    AttachUserPolicy(AttachUserPolicyInternalCommand),

    /// Create an IAM account.
    #[command(name = "create-account")]
    CreateAccount(CreateAccountCommand),

    /// Create an IAM group in an account.
    #[command(name = "create-group")]
    CreateGroup(CreateGroupInternalCommand),

    /// Create an IAM managed policy in an account.
    #[command(name = "create-policy")]
    CreatePolicy(CreatePolicyInternalCommand),

    /// Create a new version of an IAM managed policy.
    #[command(name = "create-policy-version")]
    CreatePolicyVersion(CreatePolicyVersionCommand),

    /// Create an IAM role in an account.
    #[command(name = "create-role")]
    CreateRole(CreateRoleInternalCommand),

    /// Create an IAM user in an account.
    #[command(name = "create-user")]
    CreateUser(CreateUserInternalCommand),

    /// Delete an IAM group from an account.
    #[command(name = "delete-group")]
    DeleteGroup(DeleteGroupInternalCommand),

    /// Delete an IAM managed policy. The policy must have no attachments, no permissions-boundary
    /// usages, and no non-default versions remaining.
    #[command(name = "delete-policy")]
    DeletePolicy(DeletePolicyCommand),

    /// Delete a non-default version of an IAM managed policy.
    #[command(name = "delete-policy-version")]
    DeletePolicyVersion(DeletePolicyVersionCommand),

    /// Delete an IAM user from an account.
    #[command(name = "delete-user")]
    DeleteUser(DeleteUserInternalCommand),

    /// Detach a managed policy from a group in an account.
    #[command(name = "detach-group-policy")]
    DetachGroupPolicy(DetachGroupPolicyInternalCommand),

    /// Detach a managed policy from a role in an account.
    #[command(name = "detach-role-policy")]
    DetachRolePolicy(DetachRolePolicyInternalCommand),

    /// Detach a managed policy from a user in an account.
    #[command(name = "detach-user-policy")]
    DetachUserPolicy(DetachUserPolicyInternalCommand),

    /// Get the current partition of the database.
    #[command(name = "get-current-partition")]
    GetCurrentPartition(GetCurrentPartitionCommand),

    /// Get information about an IAM group in an account.
    #[command(name = "get-group")]
    GetGroup(GetGroupInternalCommand),

    /// Get information about an IAM managed policy.
    #[command(name = "get-policy")]
    GetPolicy(GetPolicyCommand),

    /// Get a specific version of an IAM managed policy.
    #[command(name = "get-policy-version")]
    GetPolicyVersion(GetPolicyVersionCommand),

    /// Get information about an IAM user in an account.
    #[command(name = "get-user")]
    GetUser(GetUserInternalCommand),

    /// List IAM accounts.
    #[command(name = "list-accounts")]
    ListAccounts(ListAccountsCommand),

    /// List managed policies attached to an IAM group in an account.
    #[command(name = "list-attached-group-policies")]
    ListAttachedGroupPolicies(ListAttachedGroupPoliciesInternalCommand),

    /// List managed policies attached to an IAM role in an account.
    #[command(name = "list-attached-role-policies")]
    ListAttachedRolePolicies(ListAttachedRolePoliciesInternalCommand),

    /// List managed policies attached to an IAM user in an account.
    #[command(name = "list-attached-user-policies")]
    ListAttachedUserPolicies(ListAttachedUserPoliciesInternalCommand),

    /// List IAM entities (users, groups, roles) that a managed policy is attached to or that
    /// use the policy as a permissions boundary.
    #[command(name = "list-entities-for-policy")]
    ListEntitiesForPolicy(ListEntitiesForPolicyCommand),

    /// List IAM groups in an account.
    #[command(name = "list-groups")]
    ListGroups(ListGroupsInternalCommand),

    /// List IAM groups that a user belongs to.
    #[command(name = "list-groups-for-user")]
    ListGroupsForUser(ListGroupsForUserInternalCommand),

    /// List IAM managed policies in an account (optionally including AWS-managed policies).
    #[command(name = "list-policies")]
    ListPolicies(ListPoliciesInternalCommand),

    /// List the versions of an IAM managed policy.
    #[command(name = "list-policy-versions")]
    ListPolicyVersions(ListPolicyVersionsCommand),

    /// List IAM users in an account.
    #[command(name = "list-users")]
    ListUsers(ListUsersInternalCommand),

    /// List tags for an IAM user in an account.
    #[command(name = "list-user-tags")]
    ListUserTags(ListUserTagsInternalCommand),

    /// Migrate the database to the latest version or a specified version.
    #[command(name = "migrate")]
    Migrate(migrate::MigrateCommand),

    /// Remove a user from a group in an account.
    #[command(name = "remove-user-from-group")]
    RemoveUserFromGroup(RemoveUserFromGroupInternalCommand),

    /// Set the current partition for the database.
    ///
    /// This is required to be set before using any other features of the database. Partitions are
    /// separate instances of a cloud and are independent of any other partitions.
    #[command(name = "set-current-partition")]
    SetCurrentPartition(SetCurrentPartitionCommand),

    /// Set the default version of an IAM managed policy.
    #[command(name = "set-default-policy-version")]
    SetDefaultPolicyVersion(SetDefaultPolicyVersionCommand),

    /// Add or update tags on an IAM managed policy.
    #[command(name = "tag-policy")]
    TagPolicy(TagPolicyCommand),

    /// Add or update tags on an IAM user in an account.
    #[command(name = "tag-user")]
    TagUser(TagUserInternalCommand),

    /// Remove tags from an IAM managed policy.
    #[command(name = "untag-policy")]
    UntagPolicy(UntagPolicyCommand),

    /// Update an IAM group in an account.
    #[command(name = "update-group")]
    UpdateGroup(UpdateGroupInternalCommand),

    /// Update an IAM user in an account.
    #[command(name = "update-user")]
    UpdateUser(UpdateUserInternalCommand),

    /// Remove tags from an IAM user in an account.
    #[command(name = "untag-user")]
    UntagUser(UntagUserInternalCommand),
}

impl Commands {
    /// Return the AWS-style operation name for this command.
    fn operation_name(&self) -> &'static str {
        match self {
            Commands::AddUserToGroup(_) => "AddUserToGroup",
            Commands::AttachGroupPolicy(_) => "AttachGroupPolicy",
            Commands::AttachRolePolicy(_) => "AttachRolePolicy",
            Commands::AttachUserPolicy(_) => "AttachUserPolicy",
            Commands::CreateAccount(_) => "CreateAccount",
            Commands::CreateGroup(_) => "CreateGroup",
            Commands::CreatePolicy(_) => "CreatePolicy",
            Commands::CreatePolicyVersion(_) => "CreatePolicyVersion",
            Commands::CreateRole(_) => "CreateRole",
            Commands::CreateUser(_) => "CreateUser",
            Commands::DeleteGroup(_) => "DeleteGroup",
            Commands::DeletePolicy(_) => "DeletePolicy",
            Commands::DeletePolicyVersion(_) => "DeletePolicyVersion",
            Commands::DeleteUser(_) => "DeleteUser",
            Commands::DetachGroupPolicy(_) => "DetachGroupPolicy",
            Commands::DetachRolePolicy(_) => "DetachRolePolicy",
            Commands::DetachUserPolicy(_) => "DetachUserPolicy",
            Commands::GetCurrentPartition(_) => "GetCurrentPartition",
            Commands::GetGroup(_) => "GetGroup",
            Commands::GetPolicy(_) => "GetPolicy",
            Commands::GetPolicyVersion(_) => "GetPolicyVersion",
            Commands::GetUser(_) => "GetUser",
            Commands::ListAccounts(_) => "ListAccounts",
            Commands::ListAttachedGroupPolicies(_) => "ListAttachedGroupPolicies",
            Commands::ListAttachedRolePolicies(_) => "ListAttachedRolePolicies",
            Commands::ListAttachedUserPolicies(_) => "ListAttachedUserPolicies",
            Commands::ListEntitiesForPolicy(_) => "ListEntitiesForPolicy",
            Commands::ListGroups(_) => "ListGroups",
            Commands::ListGroupsForUser(_) => "ListGroupsForUser",
            Commands::ListPolicies(_) => "ListPolicies",
            Commands::ListPolicyVersions(_) => "ListPolicyVersions",
            Commands::ListUsers(_) => "ListUsers",
            Commands::ListUserTags(_) => "ListUserTags",
            Commands::Migrate(_) => "Migrate",
            Commands::RemoveUserFromGroup(_) => "RemoveUserFromGroup",
            Commands::SetCurrentPartition(_) => "SetCurrentPartition",
            Commands::SetDefaultPolicyVersion(_) => "SetDefaultPolicyVersion",
            Commands::TagPolicy(_) => "TagPolicy",
            Commands::TagUser(_) => "TagUser",
            Commands::UntagPolicy(_) => "UntagPolicy",
            Commands::UntagUser(_) => "UntagUser",
            Commands::UpdateGroup(_) => "UpdateGroup",
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
        Commands::AddUserToGroup(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::AttachGroupPolicy(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::AttachRolePolicy(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::AttachUserPolicy(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::CreateAccount(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::CreateGroup(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::CreatePolicy(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::CreatePolicyVersion(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::CreateRole(sub) => {
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
        Commands::DeleteGroup(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::DeletePolicy(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::DeletePolicyVersion(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::DeleteUser(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::DetachGroupPolicy(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::DetachRolePolicy(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::DetachUserPolicy(sub) => {
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
        Commands::GetGroup(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::GetPolicy(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::GetPolicyVersion(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::GetUser(sub) => {
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
        Commands::ListAttachedGroupPolicies(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListAttachedRolePolicies(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListAttachedUserPolicies(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListEntitiesForPolicy(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListGroups(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListGroupsForUser(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListPolicies(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListPolicyVersions(sub) => {
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
        Commands::ListUserTags(sub) => {
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
        Commands::RemoveUserFromGroup(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::SetCurrentPartition(sub) => {
            let response = sub.run(&cli, vars).await?;
            serde_json::to_string_pretty(&response).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::SetDefaultPolicyVersion(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::TagPolicy(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::TagUser(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::UntagPolicy(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::UpdateGroup(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::UpdateUser(sub) => {
            sub.run(&cli, vars).await?;
            "".to_string()
        }
        Commands::UntagUser(sub) => {
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
