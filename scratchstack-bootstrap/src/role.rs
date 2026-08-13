//! Scratchstack bootstrap role subcommands
use {
    crate::{Cli, Runnable, execute_in_transaction, tag::tags_from_shorthand},
    clap::Parser,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            AttachRolePolicyInternalRequest, CreateRoleInternalRequest, CreateRoleResponse, DeleteRoleInternalRequest,
            DeleteRolePermissionsBoundaryInternalRequest, DeleteRolePolicyInternalRequest,
            DetachRolePolicyInternalRequest, GetRoleInternalRequest, GetRolePolicyInternalRequest,
            GetRolePolicyResponse, GetRoleResponse, ListAttachedRolePoliciesInternalRequest,
            ListAttachedRolePoliciesResponse, ListRolePoliciesInternalRequest, ListRolePoliciesResponse,
            ListRoleTagsInternalRequest, ListRoleTagsResponse, ListRolesInternalRequest, ListRolesResponse,
            PutRolePermissionsBoundaryInternalRequest, PutRolePolicyInternalRequest, TagRoleInternalRequest,
            UntagRoleInternalRequest, UpdateRoleDescriptionInternalRequest, UpdateRoleDescriptionResponse,
            UpdateRoleInternalRequest, UpdateRoleResponse,
        },
    },
    scratchstack_shapes_sts::{
        error_meta::Error as StsError,
        operation::{AssumeRoleRequest, AssumeRoleResponse},
        types::{PolicyDescriptorType, Tag as StsTag},
    },
    std::ffi::OsString,
};

/// Assume a role in the Scratchstack IAM service, returning a set of temporary security
/// credentials. The account is inferred from the role ARN.
#[derive(Debug, Parser)]
pub(crate) struct AssumeRoleCommand {
    /// The duration, in seconds, of the role session. Must be between 900 (15 minutes) and
    /// 43200 (12 hours). The session duration is capped at the role's maximum session duration.
    #[clap(long)]
    pub duration_seconds: Option<i32>,

    /// An IAM policy in JSON format to use as an inline session policy.
    #[clap(long)]
    pub policy: Option<String>,

    /// The ARNs of managed policies to use as managed session policies. The policies must exist
    /// in the same account as the role.
    #[clap(long, num_args = 1..)]
    pub policy_arns: Vec<String>,

    /// The ARN of the role to assume.
    #[clap(long)]
    pub role_arn: String,

    /// An identifier for the assumed role session.
    #[clap(long)]
    pub role_session_name: String,

    /// The source identity specified by the principal assuming the role.
    #[clap(long)]
    pub source_identity: Option<String>,

    /// A list of session tags to pass. Each tag must use AWS CLI-style shorthand,
    /// for example: `Key=Environment,Value=Production`.
    /// Multiple tags may be passed as multiple `--tags` arguments and/or as a bracketed list,
    /// for example:
    /// `--tags Key=Environment,Value=Production --tags Key=Team,Value=Platform`
    /// or
    /// `--tags "[{Key=Environment,Value=Production},{Key=Team,Value=Platform}]"`.
    #[clap(long, num_args = 1..)]
    pub tags: Vec<String>,

    /// A list of keys for session tags to set as transitive in subsequent sessions in a role
    /// chain.
    #[clap(long, num_args = 1..)]
    pub transitive_tag_keys: Vec<String>,
}

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

/// Delete an inline policy from a role in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct DeleteRolePolicyInternalCommand {
    /// The unique identifier for the account the role belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the role to remove the inline policy from.
    #[clap(long)]
    pub role_name: String,

    /// The name of the inline policy to delete.
    #[clap(long)]
    pub policy_name: String,
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

/// Retrieve the document of an inline policy attached to a role in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct GetRolePolicyInternalCommand {
    /// The unique identifier for the account the role belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the role the policy is associated with.
    #[clap(long)]
    pub role_name: String,

    /// The name of the inline policy to retrieve.
    #[clap(long)]
    pub policy_name: String,
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

/// List the names of inline policies attached to a role in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct ListRolePoliciesInternalCommand {
    /// The unique identifier for the account the role belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the role to list inline policies for.
    #[clap(long)]
    pub role_name: String,

    /// The maximum number of inline policies to include in the response.
    #[clap(long)]
    pub max_items: Option<i32>,

    /// A marker for paginating the list of inline policies. If the response from a previous
    /// ListRolePolicies request was truncated, the response will include a marker that you can
    /// use in a subsequent ListRolePolicies request to retrieve the next set of inline policies.
    #[clap(long)]
    pub marker: Option<String>,
}

impl Runnable for AssumeRoleCommand {
    type Result = AssumeRoleResponse;
    type Error = StsError;

    /// Execute the subcommand. This is an inherent counterpart to [`Runnable::run`]; it cannot
    /// implement the trait because `AssumeRole` is an STS operation and returns [`StsError`]
    /// rather than [`IamError`].
    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let tags: Vec<StsTag> = tags_from_shorthand(&self.tags)?
            .into_iter()
            .map(|tag| StsTag {
                key: tag.key,
                value: tag.value,
            })
            .collect();
        let policy_arns = self
            .policy_arns
            .iter()
            .map(|arn| PolicyDescriptorType::builder().arn(arn.clone()).build())
            .collect::<Result<Vec<_>, _>>()?;
        let request = AssumeRoleRequest::builder()
            .set_duration_seconds(self.duration_seconds)
            .set_policy(self.policy.clone())
            .set_policy_arns(policy_arns)
            .role_arn(self.role_arn.clone())
            .role_session_name(self.role_session_name.clone())
            .set_source_identity(self.source_identity.clone())
            .set_tags(tags)
            .set_transitive_tag_keys(self.transitive_tag_keys.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for AttachRolePolicyInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
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
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let tags = tags_from_shorthand(&self.tags)?;
        let request = CreateRoleInternalRequest::builder()
            .account_id(self.account_id.clone())
            .assume_role_policy_document(self.assume_role_policy_document.clone())
            .set_description(self.description.clone())
            .set_max_session_duration(self.max_session_duration)
            .path(self.path.clone())
            .set_permissions_boundary(self.permissions_boundary.clone())
            .role_name(self.role_name.clone())
            .set_tags(tags)
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DeleteRoleInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
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
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
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

impl Runnable for DeleteRolePolicyInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = DeleteRolePolicyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .role_name(self.role_name.clone())
            .policy_name(self.policy_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DetachRolePolicyInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
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
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
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

impl Runnable for GetRolePolicyInternalCommand {
    type Result = GetRolePolicyResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = GetRolePolicyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .role_name(self.role_name.clone())
            .policy_name(self.policy_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListAttachedRolePoliciesInternalCommand {
    type Result = ListAttachedRolePoliciesResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListAttachedRolePoliciesInternalRequest::builder()
            .account_id(self.account_id.clone())
            .role_name(self.role_name.clone())
            .set_path_prefix(self.path_prefix.clone())
            .set_max_items(self.max_items)
            .set_marker(self.marker.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListRolePoliciesInternalCommand {
    type Result = ListRolePoliciesResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListRolePoliciesInternalRequest::builder()
            .account_id(self.account_id.clone())
            .role_name(self.role_name.clone())
            .set_max_items(self.max_items)
            .set_marker(self.marker.clone())
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
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListRolesInternalRequest::builder()
            .account_id(self.account_id.clone())
            .set_path_prefix(self.path_prefix.clone())
            .set_max_items(self.max_items)
            .set_marker(self.marker.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

/// List the tags attached to a role in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct ListRoleTagsInternalCommand {
    /// The unique identifier for the account the role belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the role to list tags for.
    #[clap(long)]
    pub role_name: String,

    /// The maximum number of tags to include in the response.
    #[clap(long)]
    pub max_items: Option<i32>,

    /// A marker for paginating the list of tags. If the response from a previous ListRoleTags
    /// request was truncated, the response will include a marker that you can use in a subsequent
    /// ListRoleTags request to retrieve the next page of tags.
    #[clap(long)]
    pub marker: Option<String>,
}

impl Runnable for ListRoleTagsInternalCommand {
    type Result = ListRoleTagsResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListRoleTagsInternalRequest::builder()
            .account_id(self.account_id.clone())
            .role_name(self.role_name.clone())
            .set_max_items(self.max_items)
            .set_marker(self.marker.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

/// Add or update tags on a role in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct TagRoleInternalCommand {
    /// The unique identifier for the account the role belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the role to tag.
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

/// Remove tags from a role in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct UntagRoleInternalCommand {
    /// The unique identifier for the account the role belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the role to untag.
    #[clap(long)]
    pub role_name: String,

    /// A list of tag keys to remove from the role.
    #[clap(long, num_args = 1..)]
    pub tag_keys: Vec<String>,
}

impl Runnable for TagRoleInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let tags = tags_from_shorthand(&self.tags)?;
        let request = TagRoleInternalRequest::builder()
            .account_id(self.account_id.clone())
            .role_name(self.role_name.clone())
            .set_tags(tags)
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for UntagRoleInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = UntagRoleInternalRequest::builder()
            .account_id(self.account_id.clone())
            .role_name(self.role_name.clone())
            .set_tag_keys(self.tag_keys.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

/// Update the description and/or max session duration of a role in a given account in the
/// Scratchstack IAM service. Fields that are not specified are left unchanged.
#[derive(Debug, Parser)]
pub(crate) struct UpdateRoleInternalCommand {
    /// The unique identifier for the account the role belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The new description for the role.
    #[clap(long)]
    pub description: Option<String>,

    /// The new maximum session duration (in seconds) for the role. Must be between 3600 (1 hour)
    /// and 43200 (12 hours).
    #[clap(long)]
    pub max_session_duration: Option<i32>,

    /// The name of the role to update.
    #[clap(long)]
    pub role_name: String,
}

/// Replace the description on a role in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct UpdateRoleDescriptionInternalCommand {
    /// The unique identifier for the account the role belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The new description for the role. May be empty.
    #[clap(long)]
    pub description: String,

    /// The name of the role to update.
    #[clap(long)]
    pub role_name: String,
}

impl Runnable for UpdateRoleInternalCommand {
    type Result = UpdateRoleResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = UpdateRoleInternalRequest::builder()
            .account_id(self.account_id.clone())
            .set_description(self.description.clone())
            .set_max_session_duration(self.max_session_duration)
            .role_name(self.role_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for UpdateRoleDescriptionInternalCommand {
    type Result = UpdateRoleDescriptionResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = UpdateRoleDescriptionInternalRequest::builder()
            .account_id(self.account_id.clone())
            .description(self.description.clone())
            .role_name(self.role_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

/// Set or replace the permissions boundary on a role in a given account in the Scratchstack IAM
/// service.
#[derive(Debug, Parser)]
pub(crate) struct PutRolePermissionsBoundaryInternalCommand {
    /// The unique identifier for the account the role belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The ARN of the managed policy used to set the permissions boundary for the role.
    #[clap(long)]
    pub permissions_boundary: String,

    /// The name of the role to set the permissions boundary on.
    #[clap(long)]
    pub role_name: String,
}

impl Runnable for PutRolePermissionsBoundaryInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = PutRolePermissionsBoundaryInternalRequest::builder()
            .account_id(self.account_id.clone())
            .permissions_boundary(self.permissions_boundary.clone())
            .role_name(self.role_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

/// Add or replace an inline policy on a role in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct PutRolePolicyInternalCommand {
    /// The unique identifier for the account the role belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the role on which to set the inline policy.
    #[clap(long)]
    pub role_name: String,

    /// The name of the inline policy to add or replace.
    #[clap(long)]
    pub policy_name: String,

    /// The JSON policy document. Must parse as a valid Aspen policy.
    #[clap(long)]
    pub policy_document: String,
}

impl Runnable for PutRolePolicyInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = PutRolePolicyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .role_name(self.role_name.clone())
            .policy_name(self.policy_name.clone())
            .policy_document(self.policy_document.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}
