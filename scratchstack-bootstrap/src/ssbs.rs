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
    scratchstack_core::{RequestId, error::ProvideErrorMetadata},
    scratchstack_iam_database::RequestExecutor,
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

    /// Migrate the database to the latest version or a specified version.
    #[command(name = "migrate")]
    Migrate(migrate::MigrateCommand),

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

    /// Update an IAM role's description and/or max session duration in an account.
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

impl Commands {
    /// Return the AWS-style operation name for this command.
    fn operation_name(&self) -> &'static str {
        match self {
            Commands::AddUserToGroup(_) => "AddUserToGroup",
            Commands::AssumeRole(_) => "AssumeRole",
            Commands::AttachGroupPolicy(_) => "AttachGroupPolicy",
            Commands::AttachRolePolicy(_) => "AttachRolePolicy",
            Commands::AttachUserPolicy(_) => "AttachUserPolicy",
            Commands::CreateAccessKey(_) => "CreateAccessKey",
            Commands::CreateAccount(_) => "CreateAccount",
            Commands::CreateAccountAlias(_) => "CreateAccountAlias",
            Commands::CreateGroup(_) => "CreateGroup",
            Commands::CreatePolicy(_) => "CreatePolicy",
            Commands::CreatePolicyVersion(_) => "CreatePolicyVersion",
            Commands::CreateRole(_) => "CreateRole",
            Commands::CreateSessionTokenEncryptionKey(_) => "CreateSessionTokenEncryptionKey",
            Commands::CreateUser(_) => "CreateUser",
            Commands::DeleteAccessKey(_) => "DeleteAccessKey",
            Commands::DeleteGroup(_) => "DeleteGroup",
            Commands::DeleteGroupPolicy(_) => "DeleteGroupPolicy",
            Commands::DeletePolicy(_) => "DeletePolicy",
            Commands::DeletePolicyVersion(_) => "DeletePolicyVersion",
            Commands::DeleteRole(_) => "DeleteRole",
            Commands::DeleteRolePermissionsBoundary(_) => "DeleteRolePermissionsBoundary",
            Commands::DeleteRolePolicy(_) => "DeleteRolePolicy",
            Commands::DeleteUser(_) => "DeleteUser",
            Commands::DeleteUserPermissionsBoundary(_) => "DeleteUserPermissionsBoundary",
            Commands::DeleteUserPolicy(_) => "DeleteUserPolicy",
            Commands::DetachGroupPolicy(_) => "DetachGroupPolicy",
            Commands::DetachRolePolicy(_) => "DetachRolePolicy",
            Commands::DetachUserPolicy(_) => "DetachUserPolicy",
            Commands::GetCurrentPartition(_) => "GetCurrentPartition",
            Commands::GetGroup(_) => "GetGroup",
            Commands::GetGroupPolicy(_) => "GetGroupPolicy",
            Commands::GetPolicy(_) => "GetPolicy",
            Commands::GetPolicyVersion(_) => "GetPolicyVersion",
            Commands::GetRole(_) => "GetRole",
            Commands::GetRolePolicy(_) => "GetRolePolicy",
            Commands::GetSessionTokenEncryptionKey(_) => "GetSessionTokenEncryptionKey",
            Commands::GetUser(_) => "GetUser",
            Commands::GetUserPolicy(_) => "GetUserPolicy",
            Commands::ListAccessKeys(_) => "ListAccessKeys",
            Commands::ListAccountAliases(_) => "ListAccountAliases",
            Commands::ListAccounts(_) => "ListAccounts",
            Commands::ListAttachedGroupPolicies(_) => "ListAttachedGroupPolicies",
            Commands::ListAttachedRolePolicies(_) => "ListAttachedRolePolicies",
            Commands::ListAttachedUserPolicies(_) => "ListAttachedUserPolicies",
            Commands::ListEntitiesForPolicy(_) => "ListEntitiesForPolicy",
            Commands::ListGroupPolicies(_) => "ListGroupPolicies",
            Commands::ListGroups(_) => "ListGroups",
            Commands::ListGroupsForUser(_) => "ListGroupsForUser",
            Commands::ListPolicies(_) => "ListPolicies",
            Commands::ListPolicyTags(_) => "ListPolicyTags",
            Commands::ListPolicyVersions(_) => "ListPolicyVersions",
            Commands::ListRolePolicies(_) => "ListRolePolicies",
            Commands::ListRoles(_) => "ListRoles",
            Commands::ListRoleTags(_) => "ListRoleTags",
            Commands::ListSessionTokenEncryptionKeys(_) => "ListSessionTokenEncryptionKeys",
            Commands::ListUserPolicies(_) => "ListUserPolicies",
            Commands::ListUsers(_) => "ListUsers",
            Commands::ListUserTags(_) => "ListUserTags",
            Commands::Migrate(_) => "Migrate",
            Commands::PutGroupPolicy(_) => "PutGroupPolicy",
            Commands::PutRolePermissionsBoundary(_) => "PutRolePermissionsBoundary",
            Commands::PutRolePolicy(_) => "PutRolePolicy",
            Commands::PutUserPermissionsBoundary(_) => "PutUserPermissionsBoundary",
            Commands::PutUserPolicy(_) => "PutUserPolicy",
            Commands::RemoveUserFromGroup(_) => "RemoveUserFromGroup",
            Commands::SetCurrentPartition(_) => "SetCurrentPartition",
            Commands::SetDefaultPolicyVersion(_) => "SetDefaultPolicyVersion",
            Commands::TagPolicy(_) => "TagPolicy",
            Commands::TagRole(_) => "TagRole",
            Commands::TagUser(_) => "TagUser",
            Commands::UntagPolicy(_) => "UntagPolicy",
            Commands::UntagRole(_) => "UntagRole",
            Commands::UntagUser(_) => "UntagUser",
            Commands::UpdateAccessKey(_) => "UpdateAccessKey",
            Commands::UpdateGroup(_) => "UpdateGroup",
            Commands::UpdateRole(_) => "UpdateRole",
            Commands::UpdateRoleDescription(_) => "UpdateRoleDescription",
            Commands::UpdateSessionTokenEncryptionKey(_) => "UpdateSessionTokenEncryptionKey",
            Commands::UpdateUser(_) => "UpdateUser",
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
    let mut buffer = Vec::new();
    let mut writer = JsonSerializer::with_formatter(&mut buffer, formatter);

    match &cli.command {
        Commands::AddUserToGroup(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::AssumeRole(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::AttachGroupPolicy(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::AttachRolePolicy(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::AttachUserPolicy(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::CreateAccessKey(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::CreateAccount(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::CreateAccountAlias(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::CreateGroup(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::CreatePolicy(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::CreatePolicyVersion(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::CreateRole(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::CreateSessionTokenEncryptionKey(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::CreateUser(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::DeleteAccessKey(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::DeleteGroup(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::DeleteGroupPolicy(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::DeletePolicy(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::DeletePolicyVersion(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::DeleteRole(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::DeleteRolePermissionsBoundary(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::DeleteRolePolicy(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::DeleteUserPermissionsBoundary(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::DeleteUser(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::DeleteUserPolicy(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::DetachGroupPolicy(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::DetachRolePolicy(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::DetachUserPolicy(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::GetCurrentPartition(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::GetGroup(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::GetGroupPolicy(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::GetPolicy(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::GetPolicyVersion(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::GetRole(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::GetRolePolicy(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::GetSessionTokenEncryptionKey(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::GetUser(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::GetUserPolicy(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListAccessKeys(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListAccountAliases(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListAccounts(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListAttachedGroupPolicies(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListAttachedRolePolicies(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListAttachedUserPolicies(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListEntitiesForPolicy(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListGroupPolicies(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListGroups(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListGroupsForUser(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListPolicies(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListPolicyTags(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListPolicyVersions(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListRolePolicies(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListRoles(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListRoleTags(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListSessionTokenEncryptionKeys(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListUserPolicies(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListUsers(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::ListUserTags(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::Migrate(sub) => {
            boxed_future(|| sub.run(&cli, vars)).await?;
            writeln!(out, "Migration completed successfully.").map_err(|e| {
                log::error!("Failed to write output: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::PutGroupPolicy(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::PutRolePermissionsBoundary(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::PutRolePolicy(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::PutUserPermissionsBoundary(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::PutUserPolicy(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::RemoveUserFromGroup(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::SetCurrentPartition(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::SetDefaultPolicyVersion(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::TagPolicy(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::TagRole(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::TagUser(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::UntagPolicy(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::UntagRole(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::UpdateAccessKey(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::UpdateGroup(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::UpdateRole(sub) => {
            let _ = boxed_future(|| sub.run(&cli, vars)).await?;
        }
        Commands::UpdateRoleDescription(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::UpdateSessionTokenEncryptionKey(sub) => {
            let response = boxed_future(|| sub.run(&cli, vars)).await?;
            response.serialize(&mut writer).map_err(|e| {
                log::error!("Failed to serialize response: {e}");
                IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
            })?
        }
        Commands::UpdateUser(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
        Commands::UntagUser(sub) => boxed_future(|| sub.run(&cli, vars)).await?,
    };

    let buffer = writer.into_inner();
    if !buffer.is_empty() {
        writeln!(out, "{}", String::from_utf8_lossy(buffer)).map_err(|e| {
            log::error!("Failed to write output: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;
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
