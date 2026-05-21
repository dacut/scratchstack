//! Scratchstack bootstrap role subcommands
use {
    crate::{Cli, Runnable, execute_in_transaction, user::tags_from_shorthand},
    clap::Parser,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            AttachRolePolicyInternalRequest, CreateRoleInternalRequest, CreateRoleResponse, DeleteRoleInternalRequest,
            DeleteRolePermissionsBoundaryInternalRequest, DetachRolePolicyInternalRequest, GetRoleInternalRequest,
            GetRoleResponse, ListAttachedRolePoliciesInternalRequest, ListAttachedRolePoliciesResponse,
            ListRolesInternalRequest, ListRolesResponse,
        },
    },
    std::ffi::OsString,
};

/// Create a new role in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct CreateRoleInternalCommand {
    /// The unique identifier for the account to create the role in.
    #[clap(long)]
    pub account_id: String,

    /// The trust relationship policy document granting an entity permission to assume the role.
    #[clap(long)]
    pub assume_role_policy_document: String,

    /// A description of the role.
    #[clap(long)]
    pub description: Option<String>,

    /// The maximum session duration (in seconds) that you want to set for the role. Must be
    /// between 3600 (1 hour) and 43200 (12 hours).
    #[clap(long)]
    pub max_session_duration: Option<i32>,

    /// The path for the role.
    #[clap(long, default_value = "/")]
    pub path: String,

    /// The ARN of the managed policy used to set the permissions boundary for the role.
    #[clap(long)]
    pub permissions_boundary: Option<String>,

    /// The name of the role to create.
    #[clap(long)]
    pub role_name: String,

    /// A list of tags to associate with the role. Each tag must use AWS CLI-style shorthand,
    /// for example: `Key=Environment,Value=Production`.
    /// Multiple tags may be passed as multiple `--tags` arguments and/or as a bracketed list,
    /// for example:
    /// `--tags Key=Environment,Value=Production --tags Key=Team,Value=Platform`
    /// or
    /// `--tags "[{Key=Environment,Value=Production},{Key=Team,Value=Platform}]"`.
    #[clap(long, num_args = 1..)]
    pub tags: Vec<String>,
}

/// Attach a managed policy to a role in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct AttachRolePolicyInternalCommand {
    /// The unique identifier for the account the role belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The ARN of the managed policy to attach to the role.
    #[clap(long)]
    pub policy_arn: String,

    /// The name of the role to attach the policy to.
    #[clap(long)]
    pub role_name: String,
}

/// Delete a role from the given account in the Scratchstack IAM service. The role must have no
/// attached managed policies and no inline policies; detach them with `detach-role-policy` (and
/// delete any inline policies) before invoking this command.
#[derive(Debug, Parser)]
pub(crate) struct DeleteRoleInternalCommand {
    /// The unique identifier for the account to delete the role from.
    #[clap(long)]
    pub account_id: String,

    /// The name of the role to delete.
    #[clap(long)]
    pub role_name: String,
}

/// Remove the permissions boundary from a role in the Scratchstack IAM service. Succeeds even
/// when the role has no permissions boundary set; only a missing role yields NoSuchEntity.
#[derive(Debug, Parser)]
pub(crate) struct DeleteRolePermissionsBoundaryInternalCommand {
    /// The unique identifier for the account the role belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the role to remove the permissions boundary from.
    #[clap(long)]
    pub role_name: String,
}

/// Detach a managed policy from a role in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct DetachRolePolicyInternalCommand {
    /// The unique identifier for the account the role belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The ARN of the managed policy to detach from the role.
    #[clap(long)]
    pub policy_arn: String,

    /// The name of the role to detach the policy from.
    #[clap(long)]
    pub role_name: String,
}

/// Get information about a role in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct GetRoleInternalCommand {
    /// The unique identifier for the account the role belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the role to retrieve.
    #[clap(long)]
    pub role_name: String,
}

/// List managed policies attached to a role in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct ListAttachedRolePoliciesInternalCommand {
    /// The unique identifier for the account the role belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the role to list attached policies for.
    #[clap(long)]
    pub role_name: String,

    /// The path prefix for filtering the list of attached policies. Only policies with a path
    /// that starts with this prefix will be included in the response.
    #[clap(long)]
    pub path_prefix: Option<String>,

    /// The maximum number of attached policies to include in the response.
    #[clap(long)]
    pub max_items: Option<i32>,

    /// A marker for paginating the list of attached policies. If the response from a previous
    /// ListAttachedRolePolicies request was truncated, the response will include a marker that
    /// you can use in a subsequent ListAttachedRolePolicies request to retrieve the next set of
    /// attached policies.
    #[clap(long)]
    pub marker: Option<String>,
}

impl Runnable for AttachRolePolicyInternalCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = AttachRolePolicyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .policy_arn(self.policy_arn.clone())
            .role_name(self.role_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for CreateRoleInternalCommand {
    type Result = CreateRoleResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let tags = tags_from_shorthand(&self.tags)?;
        let request = CreateRoleInternalRequest::builder()
            .account_id(self.account_id.clone())
            .assume_role_policy_document(self.assume_role_policy_document.clone())
            .description(self.description.clone())
            .max_session_duration(self.max_session_duration)
            .path(Some(self.path.clone()))
            .permissions_boundary(self.permissions_boundary.clone())
            .role_name(self.role_name.clone())
            .tags(tags)
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DeleteRoleInternalCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = DeleteRoleInternalRequest::builder()
            .account_id(self.account_id.clone())
            .role_name(self.role_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DeleteRolePermissionsBoundaryInternalCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = DeleteRolePermissionsBoundaryInternalRequest::builder()
            .account_id(self.account_id.clone())
            .role_name(self.role_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DetachRolePolicyInternalCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = DetachRolePolicyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .policy_arn(self.policy_arn.clone())
            .role_name(self.role_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for GetRoleInternalCommand {
    type Result = GetRoleResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = GetRoleInternalRequest::builder()
            .account_id(self.account_id.clone())
            .role_name(self.role_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListAttachedRolePoliciesInternalCommand {
    type Result = ListAttachedRolePoliciesResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListAttachedRolePoliciesInternalRequest::builder()
            .account_id(self.account_id.clone())
            .role_name(self.role_name.clone())
            .path_prefix(self.path_prefix.clone())
            .max_items(self.max_items)
            .marker(self.marker.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

/// List roles in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct ListRolesInternalCommand {
    /// The unique identifier for the account to list roles from.
    #[clap(long)]
    pub account_id: String,

    /// The path prefix for filtering the list of roles. Only roles with a path that starts with
    /// this prefix will be included in the response.
    #[clap(long)]
    pub path_prefix: Option<String>,

    /// The maximum number of roles to include in the response.
    #[clap(long)]
    pub max_items: Option<i32>,

    /// A marker for paginating the list of roles. If the response from a previous ListRoles
    /// request was truncated, the response will include a marker that you can use in a subsequent
    /// ListRoles request to retrieve the next page of roles.
    #[clap(long)]
    pub marker: Option<String>,
}

impl Runnable for ListRolesInternalCommand {
    type Result = ListRolesResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListRolesInternalRequest::builder()
            .account_id(self.account_id.clone())
            .path_prefix(self.path_prefix.clone())
            .max_items(self.max_items)
            .marker(self.marker.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}
