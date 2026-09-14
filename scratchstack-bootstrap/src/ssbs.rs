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
mod session_token_encryption_key;
pub(crate) mod tag;
mod user;

#[cfg(test)]
mod tests;

use {
    crate::{account::*, group::*, partition::*, policy::*, role::*, session_token_encryption_key::*, user::*},
    clap::{Parser, Subcommand},
    scratchstack_central_database::RequestExecutor,
    scratchstack_core::{RequestId, error::ProvideErrorMetadata},
    scratchstack_shapes_iam::{error_meta::Error as IamError, types::error::InternalFailure},
    serde::Serialize as _,
    serde_json::ser::{PrettyFormatter, Serializer as JsonSerializer},
    sqlx::{
        Error as SqlxError,
        postgres::{PgConnectOptions, PgPool, PgPoolOptions},
    },
    std::{
        ffi::OsString,
        io::{Write, stdout},
        pin::Pin,
        time::Duration,
    },
};

/// Construct the future returned by `make` and immediately box it.
///
/// In unoptimized builds, every future a function creates is materialized in that function's
/// stack frame, and those slots are not reused across match arms or sequential awaits. With the
/// dozens of subcommand futures dispatched in [`run`] (and the hundreds of invocations in the
/// test suite), those frames overflow the 8 MiB thread stack. Constructing each future in this
/// helper's transient frame and returning it boxed keeps the callers' frames small.
pub(crate) fn boxed_future<F, Fut>(make: F) -> Pin<Box<Fut>>
where
    F: FnOnce() -> Fut,
    Fut: Future,
{
    Box::pin(make())
}

/// Trait that subcommands must implement to be run by the CLI.
trait Runnable {
    type Result;
    type Error;

    /// Execute the subcommand.
    fn run<I>(&self, cli: &Cli, vars: I) -> impl Future<Output = Result<Self::Result, Self::Error>> + Send
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send;
}

/// Scratchstack database bootstrap utility for creating initial users.
#[derive(Debug, Parser)]
#[command(name = "ssbs", version, about = "Scratchstack database bootstrap utility")]
struct Cli {
    /// The service containing the subcommand to run
    #[command(subcommand)]
    command: ServiceCommands,

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

/// The service whose subcommand should be run.
#[derive(Debug, Subcommand)]
enum ServiceCommands {
    /// Database commands.
    #[command(name = "db", subcommand)]
    Db(DbCommands),

    /// Identity and Access Management (IAM) and Security Token Service (STS) commands.
    #[command(name = "iam", subcommand)]
    Iam(IamCommands),
}

#[derive(Debug, Subcommand)]
enum DbCommands {
    /// Migrate the database to the latest version or a specified version.
    #[command(name = "migrate")]
    Migrate(migrate::MigrateCommand),
}

#[derive(Debug, Subcommand)]
enum IamCommands {
    /// Add a user to a group in an account.
    #[command(name = "add-user-to-group")]
    AddUserToGroup(AddUserToGroupInternalCommand),

    /// Assume a role, returning a set of temporary security credentials.
    #[command(name = "assume-role")]
    AssumeRole(AssumeRoleCommand),

    /// Attach a managed policy to a group in an account.
    #[command(name = "attach-group-policy")]
    AttachGroupPolicy(AttachGroupPolicyInternalCommand),

    /// Attach a managed policy to a role in an account.
    #[command(name = "attach-role-policy")]
    AttachRolePolicy(AttachRolePolicyInternalCommand),

    /// Attach a managed policy to a user in an account.
    #[command(name = "attach-user-policy")]
    AttachUserPolicy(AttachUserPolicyInternalCommand),

    /// Create a new access key for an IAM user. The response includes the access key id and
    /// the (one-time-shown) secret access key.
    #[command(name = "create-access-key")]
    CreateAccessKey(CreateAccessKeyInternalCommand),

    /// Create an IAM account.
    #[command(name = "create-account")]
    CreateAccount(CreateAccountCommand),

    /// Set the alias for an IAM account. Replaces any existing alias.
    #[command(name = "create-account-alias")]
    CreateAccountAlias(CreateAccountAliasInternalCommand),

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

    /// Create a session token encryption key.
    #[command(name = "create-session-token-encryption-key")]
    CreateSessionTokenEncryptionKey(CreateSessionTokenEncryptionKeyCommand),

    /// Create an IAM user in an account.
    #[command(name = "create-user")]
    CreateUser(CreateUserInternalCommand),

    /// Delete an access key from an IAM user.
    #[command(name = "delete-access-key")]
    DeleteAccessKey(DeleteAccessKeyInternalCommand),

    /// Delete an IAM group from an account.
    #[command(name = "delete-group")]
    DeleteGroup(DeleteGroupInternalCommand),

    /// Delete an inline policy from an IAM group in an account.
    #[command(name = "delete-group-policy")]
    DeleteGroupPolicy(DeleteGroupPolicyInternalCommand),

    /// Delete an IAM managed policy. The policy must have no attachments, no permissions-boundary
    /// usages, and no non-default versions remaining.
    #[command(name = "delete-policy")]
    DeletePolicy(DeletePolicyCommand),

    /// Delete a non-default version of an IAM managed policy.
    #[command(name = "delete-policy-version")]
    DeletePolicyVersion(DeletePolicyVersionCommand),

    /// Delete an IAM role from an account. The role must have no attached managed policies and no
    /// inline policies remaining.
    #[command(name = "delete-role")]
    DeleteRole(DeleteRoleInternalCommand),

    /// Remove the permissions boundary from an IAM role. Succeeds whether or not the role has a
    /// permissions boundary set.
    #[command(name = "delete-role-permissions-boundary")]
    DeleteRolePermissionsBoundary(DeleteRolePermissionsBoundaryInternalCommand),

    /// Delete an inline policy from an IAM role in an account.
    #[command(name = "delete-role-policy")]
    DeleteRolePolicy(DeleteRolePolicyInternalCommand),

    /// Delete an IAM user from an account.
    #[command(name = "delete-user")]
    DeleteUser(DeleteUserInternalCommand),

    /// Remove the permissions boundary from an IAM user. Succeeds whether or not the user has a
    /// permissions boundary set.
    #[command(name = "delete-user-permissions-boundary")]
    DeleteUserPermissionsBoundary(DeleteUserPermissionsBoundaryInternalCommand),

    /// Delete an inline policy from an IAM user in an account.
    #[command(name = "delete-user-policy")]
    DeleteUserPolicy(DeleteUserPolicyInternalCommand),

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

    /// Retrieve an inline policy document attached to an IAM group.
    #[command(name = "get-group-policy")]
    GetGroupPolicy(GetGroupPolicyInternalCommand),

    /// Get information about an IAM managed policy.
    #[command(name = "get-policy")]
    GetPolicy(GetPolicyCommand),

    /// Get a specific version of an IAM managed policy.
    #[command(name = "get-policy-version")]
    GetPolicyVersion(GetPolicyVersionCommand),

    /// Get information about an IAM role in an account.
    #[command(name = "get-role")]
    GetRole(GetRoleInternalCommand),

    /// Retrieve an inline policy document attached to an IAM role.
    #[command(name = "get-role-policy")]
    GetRolePolicy(GetRolePolicyInternalCommand),

    /// Get information about a session token encryption key.
    #[command(name = "get-session-token-encryption-key")]
    GetSessionTokenEncryptionKey(GetSessionTokenEncryptionKeyCommand),

    /// Get information about an IAM user in an account.
    #[command(name = "get-user")]
    GetUser(GetUserInternalCommand),

    /// Retrieve an inline policy document attached to an IAM user.
    #[command(name = "get-user-policy")]
    GetUserPolicy(GetUserPolicyInternalCommand),

    /// List the access keys attached to an IAM user.
    #[command(name = "list-access-keys")]
    ListAccessKeys(ListAccessKeysInternalCommand),

    /// List the aliases attached to an IAM account (always one or zero).
    #[command(name = "list-account-aliases")]
    ListAccountAliases(ListAccountAliasesInternalCommand),

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

    /// List the names of inline policies attached to an IAM group.
    #[command(name = "list-group-policies")]
    ListGroupPolicies(ListGroupPoliciesInternalCommand),

    /// List IAM groups in an account.
    #[command(name = "list-groups")]
    ListGroups(ListGroupsInternalCommand),

    /// List IAM groups that a user belongs to.
    #[command(name = "list-groups-for-user")]
    ListGroupsForUser(ListGroupsForUserInternalCommand),

    /// List IAM managed policies in an account (optionally including AWS-managed policies).
    #[command(name = "list-policies")]
    ListPolicies(ListPoliciesInternalCommand),

    /// List the tags attached to an IAM managed policy.
    #[command(name = "list-policy-tags")]
    ListPolicyTags(ListPolicyTagsCommand),

    /// List the versions of an IAM managed policy.
    #[command(name = "list-policy-versions")]
    ListPolicyVersions(ListPolicyVersionsCommand),

    /// List the names of inline policies attached to an IAM role.
    #[command(name = "list-role-policies")]
    ListRolePolicies(ListRolePoliciesInternalCommand),

    /// List IAM roles in an account.
    #[command(name = "list-roles")]
    ListRoles(ListRolesInternalCommand),

    /// List tags for an IAM role in an account.
    #[command(name = "list-role-tags")]
    ListRoleTags(ListRoleTagsInternalCommand),

    /// List session token encryption keys available.
    #[command(name = "list-session-token-encryption-keys")]
    ListSessionTokenEncryptionKeys(ListSessionTokenEncryptionKeysCommand),

    /// List the names of inline policies attached to an IAM user.
    #[command(name = "list-user-policies")]
    ListUserPolicies(ListUserPoliciesInternalCommand),

    /// List IAM users in an account.
    #[command(name = "list-users")]
    ListUsers(ListUsersInternalCommand),

    /// List tags for an IAM user in an account.
    #[command(name = "list-user-tags")]
    ListUserTags(ListUserTagsInternalCommand),

    /// Add or replace an inline policy on an IAM group in an account.
    #[command(name = "put-group-policy")]
    PutGroupPolicy(PutGroupPolicyInternalCommand),

    /// Set or replace the permissions boundary on an IAM role in an account.
    #[command(name = "put-role-permissions-boundary")]
    PutRolePermissionsBoundary(PutRolePermissionsBoundaryInternalCommand),

    /// Add or replace an inline policy on an IAM role in an account.
    #[command(name = "put-role-policy")]
    PutRolePolicy(PutRolePolicyInternalCommand),

    /// Set or replace the permissions boundary on an IAM user in an account.
    #[command(name = "put-user-permissions-boundary")]
    PutUserPermissionsBoundary(PutUserPermissionsBoundaryInternalCommand),

    /// Add or replace an inline policy on an IAM user in an account.
    #[command(name = "put-user-policy")]
    PutUserPolicy(PutUserPolicyInternalCommand),

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

    /// Add or update tags on an IAM role in an account.
    #[command(name = "tag-role")]
    TagRole(TagRoleInternalCommand),

    /// Add or update tags on an IAM user in an account.
    #[command(name = "tag-user")]
    TagUser(TagUserInternalCommand),

    /// Remove tags from an IAM managed policy.
    #[command(name = "untag-policy")]
    UntagPolicy(UntagPolicyCommand),

    /// Remove tags from an IAM role in an account.
    #[command(name = "untag-role")]
    UntagRole(UntagRoleInternalCommand),

    /// Change the status (Active or Inactive) of an access key.
    #[command(name = "update-access-key")]
    UpdateAccessKey(UpdateAccessKeyInternalCommand),

    /// Update an IAM group in an account.
    #[command(name = "update-group")]
    UpdateGroup(UpdateGroupInternalCommand),

    /// Update an IAM role's description, max session duration, and/or service flag in an account.
    #[command(name = "update-role")]
    UpdateRole(UpdateRoleInternalCommand),

    /// Replace the description on an IAM role in an account.
    #[command(name = "update-role-description")]
    UpdateRoleDescription(UpdateRoleDescriptionInternalCommand),

    /// Update the expiration windows of a session token encryption key.
    #[command(name = "update-session-token-encryption-key")]
    UpdateSessionTokenEncryptionKey(UpdateSessionTokenEncryptionKeyCommand),

    /// Update an IAM user in an account.
    #[command(name = "update-user")]
    UpdateUser(UpdateUserInternalCommand),

    /// Remove tags from an IAM user in an account.
    #[command(name = "untag-user")]
    UntagUser(UntagUserInternalCommand),
}

impl ServiceCommands {
    /// Return the AWS-style operation name for the service subcommand this wraps.
    fn operation_name(&self) -> &'static str {
        match self {
            ServiceCommands::Db(command) => command.operation_name(),
            ServiceCommands::Iam(command) => command.operation_name(),
        }
    }
}

impl DbCommands {
    /// Return the AWS-style operation name for this command.
    fn operation_name(&self) -> &'static str {
        match self {
            DbCommands::Migrate(_) => "Migrate",
        }
    }
}

impl IamCommands {
    /// Return the AWS-style operation name for this command.
    fn operation_name(&self) -> &'static str {
        match self {
            IamCommands::AddUserToGroup(_) => "AddUserToGroup",
            IamCommands::AssumeRole(_) => "AssumeRole",
            IamCommands::AttachGroupPolicy(_) => "AttachGroupPolicy",
            IamCommands::AttachRolePolicy(_) => "AttachRolePolicy",
            IamCommands::AttachUserPolicy(_) => "AttachUserPolicy",
            IamCommands::CreateAccessKey(_) => "CreateAccessKey",
            IamCommands::CreateAccount(_) => "CreateAccount",
            IamCommands::CreateAccountAlias(_) => "CreateAccountAlias",
            IamCommands::CreateGroup(_) => "CreateGroup",
            IamCommands::CreatePolicy(_) => "CreatePolicy",
            IamCommands::CreatePolicyVersion(_) => "CreatePolicyVersion",
            IamCommands::CreateRole(_) => "CreateRole",
            IamCommands::CreateSessionTokenEncryptionKey(_) => "CreateSessionTokenEncryptionKey",
            IamCommands::CreateUser(_) => "CreateUser",
            IamCommands::DeleteAccessKey(_) => "DeleteAccessKey",
            IamCommands::DeleteGroup(_) => "DeleteGroup",
            IamCommands::DeleteGroupPolicy(_) => "DeleteGroupPolicy",
            IamCommands::DeletePolicy(_) => "DeletePolicy",
            IamCommands::DeletePolicyVersion(_) => "DeletePolicyVersion",
            IamCommands::DeleteRole(_) => "DeleteRole",
            IamCommands::DeleteRolePermissionsBoundary(_) => "DeleteRolePermissionsBoundary",
            IamCommands::DeleteRolePolicy(_) => "DeleteRolePolicy",
            IamCommands::DeleteUser(_) => "DeleteUser",
            IamCommands::DeleteUserPermissionsBoundary(_) => "DeleteUserPermissionsBoundary",
            IamCommands::DeleteUserPolicy(_) => "DeleteUserPolicy",
            IamCommands::DetachGroupPolicy(_) => "DetachGroupPolicy",
            IamCommands::DetachRolePolicy(_) => "DetachRolePolicy",
            IamCommands::DetachUserPolicy(_) => "DetachUserPolicy",
            IamCommands::GetCurrentPartition(_) => "GetCurrentPartition",
            IamCommands::GetGroup(_) => "GetGroup",
            IamCommands::GetGroupPolicy(_) => "GetGroupPolicy",
            IamCommands::GetPolicy(_) => "GetPolicy",
            IamCommands::GetPolicyVersion(_) => "GetPolicyVersion",
            IamCommands::GetRole(_) => "GetRole",
            IamCommands::GetRolePolicy(_) => "GetRolePolicy",
            IamCommands::GetSessionTokenEncryptionKey(_) => "GetSessionTokenEncryptionKey",
            IamCommands::GetUser(_) => "GetUser",
            IamCommands::GetUserPolicy(_) => "GetUserPolicy",
            IamCommands::ListAccessKeys(_) => "ListAccessKeys",
            IamCommands::ListAccountAliases(_) => "ListAccountAliases",
            IamCommands::ListAccounts(_) => "ListAccounts",
            IamCommands::ListAttachedGroupPolicies(_) => "ListAttachedGroupPolicies",
            IamCommands::ListAttachedRolePolicies(_) => "ListAttachedRolePolicies",
            IamCommands::ListAttachedUserPolicies(_) => "ListAttachedUserPolicies",
            IamCommands::ListEntitiesForPolicy(_) => "ListEntitiesForPolicy",
            IamCommands::ListGroupPolicies(_) => "ListGroupPolicies",
            IamCommands::ListGroups(_) => "ListGroups",
            IamCommands::ListGroupsForUser(_) => "ListGroupsForUser",
            IamCommands::ListPolicies(_) => "ListPolicies",
            IamCommands::ListPolicyTags(_) => "ListPolicyTags",
            IamCommands::ListPolicyVersions(_) => "ListPolicyVersions",
            IamCommands::ListRolePolicies(_) => "ListRolePolicies",
            IamCommands::ListRoles(_) => "ListRoles",
            IamCommands::ListRoleTags(_) => "ListRoleTags",
            IamCommands::ListSessionTokenEncryptionKeys(_) => "ListSessionTokenEncryptionKeys",
            IamCommands::ListUserPolicies(_) => "ListUserPolicies",
            IamCommands::ListUsers(_) => "ListUsers",
            IamCommands::ListUserTags(_) => "ListUserTags",
            IamCommands::PutGroupPolicy(_) => "PutGroupPolicy",
            IamCommands::PutRolePermissionsBoundary(_) => "PutRolePermissionsBoundary",
            IamCommands::PutRolePolicy(_) => "PutRolePolicy",
            IamCommands::PutUserPermissionsBoundary(_) => "PutUserPermissionsBoundary",
            IamCommands::PutUserPolicy(_) => "PutUserPolicy",
            IamCommands::RemoveUserFromGroup(_) => "RemoveUserFromGroup",
            IamCommands::SetCurrentPartition(_) => "SetCurrentPartition",
            IamCommands::SetDefaultPolicyVersion(_) => "SetDefaultPolicyVersion",
            IamCommands::TagPolicy(_) => "TagPolicy",
            IamCommands::TagRole(_) => "TagRole",
            IamCommands::TagUser(_) => "TagUser",
            IamCommands::UntagPolicy(_) => "UntagPolicy",
            IamCommands::UntagRole(_) => "UntagRole",
            IamCommands::UntagUser(_) => "UntagUser",
            IamCommands::UpdateAccessKey(_) => "UpdateAccessKey",
            IamCommands::UpdateGroup(_) => "UpdateGroup",
            IamCommands::UpdateRole(_) => "UpdateRole",
            IamCommands::UpdateRoleDescription(_) => "UpdateRoleDescription",
            IamCommands::UpdateSessionTokenEncryptionKey(_) => "UpdateSessionTokenEncryptionKey",
            IamCommands::UpdateUser(_) => "UpdateUser",
        }
    }
}

/// Format a service error in the AWS CLI style.
pub(crate) fn format_service_error<E: ProvideErrorMetadata>(error: &E, operation: &str) -> String {
    let code = error.code();
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
        eprintln!("{}", format_service_error(&e, operation));
        std::process::exit(1);
    }
}

/// The JSON serializer that command responses are written into.
type ResponseSerializer<'a> = JsonSerializer<&'a mut Vec<u8>, PrettyFormatter<'static>>;

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
    let formatter = PrettyFormatter::with_indent(b"    ");

    if let ServiceCommands::Db(command) = &cli.command {
        boxed_future(|| run_db(&cli, command, vars, out)).await?;
    } else {
        let mut buffer = Vec::new();
        let mut writer = JsonSerializer::with_formatter(&mut buffer, formatter);

        match &cli.command {
            ServiceCommands::Db(_) => unreachable!(),
            ServiceCommands::Iam(command) => boxed_future(|| run_iam(&cli, command, vars, &mut writer)).await?,
        }

        let buffer = writer.into_inner();
        if !buffer.is_empty() {
            writeln!(out, "{}", String::from_utf8_lossy(buffer)).map_err(|e| {
                log::error!("Failed to write output: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?;
        }
    }

    Ok(())
}

/// Execute a database subcommand, serializing any response into `writer`.
async fn run_db<I, W>(cli: &Cli, command: &DbCommands, vars: I, out: &mut W) -> Result<(), IamError>
where
    I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    W: Write + Send,
{
    match command {
        DbCommands::Migrate(sub) => {
            boxed_future(|| sub.run(cli, vars)).await?;
            writeln!(out, "Migration completed successfully.").map_err(|e| {
                log::error!("Failed to write output: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
    };

    Ok(())
}

/// Execute an IAM subcommand, serializing any response into `writer`.
async fn run_iam<I>(
    cli: &Cli,
    command: &IamCommands,
    vars: I,
    writer: &mut ResponseSerializer<'_>,
) -> Result<(), IamError>
where
    I: IntoIterator<Item = (OsString, String)> + Clone + Send,
{
    match command {
        IamCommands::AddUserToGroup(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::AssumeRole(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::AttachGroupPolicy(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::AttachRolePolicy(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::AttachUserPolicy(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::CreateAccessKey(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::CreateAccount(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::CreateAccountAlias(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::CreateGroup(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::CreatePolicy(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::CreatePolicyVersion(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::CreateRole(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::CreateSessionTokenEncryptionKey(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::CreateUser(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::DeleteAccessKey(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::DeleteGroup(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::DeleteGroupPolicy(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::DeletePolicy(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::DeletePolicyVersion(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::DeleteRole(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::DeleteRolePermissionsBoundary(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::DeleteRolePolicy(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::DeleteUserPermissionsBoundary(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::DeleteUser(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::DeleteUserPolicy(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::DetachGroupPolicy(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::DetachRolePolicy(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::DetachUserPolicy(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::GetCurrentPartition(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::GetGroup(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::GetGroupPolicy(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::GetPolicy(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::GetPolicyVersion(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::GetRole(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::GetRolePolicy(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::GetSessionTokenEncryptionKey(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::GetUser(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::GetUserPolicy(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListAccessKeys(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListAccountAliases(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListAccounts(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListAttachedGroupPolicies(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListAttachedRolePolicies(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListAttachedUserPolicies(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListEntitiesForPolicy(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListGroupPolicies(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListGroups(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListGroupsForUser(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListPolicies(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListPolicyTags(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListPolicyVersions(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListRolePolicies(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListRoles(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListRoleTags(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListSessionTokenEncryptionKeys(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListUserPolicies(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListUsers(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::ListUserTags(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::PutGroupPolicy(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::PutRolePermissionsBoundary(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::PutRolePolicy(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::PutUserPermissionsBoundary(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::PutUserPolicy(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::RemoveUserFromGroup(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::SetCurrentPartition(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::SetDefaultPolicyVersion(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::TagPolicy(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::TagRole(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::TagUser(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::UntagPolicy(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::UntagRole(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::UpdateAccessKey(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::UpdateGroup(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::UpdateRole(sub) => {
            let _ = boxed_future(|| sub.run(cli, vars)).await?;
        }
        IamCommands::UpdateRoleDescription(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::UpdateSessionTokenEncryptionKey(sub) => {
            let response = boxed_future(|| sub.run(cli, vars)).await?;
            response.serialize(&mut *writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        IamCommands::UpdateUser(sub) => boxed_future(|| sub.run(cli, vars)).await?,
        IamCommands::UntagUser(sub) => boxed_future(|| sub.run(cli, vars)).await?,
    }

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
) -> Result<R::Response, R::Error>
where
    R: RequestExecutor + Sync,
    R::Error: From<IamError>,
{
    let request_id = RequestId::new();
    let conn = cli.connect(vars).await?;
    let mut tx = conn.begin().await.map_err(|e| {
        log::error!("Failed to begin transaction: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).request_id(request_id).build())
    })?;

    match request.execute(&mut tx, request_id).await {
        Ok(response) => {
            tx.commit().await.map_err(|e| {
                log::error!("Failed to commit transaction: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).request_id(request_id).build())
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
