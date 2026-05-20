//! Scratchstack bootstrap policy subcommands
use {
    crate::{Cli, Runnable, execute_in_transaction, user::tags_from_shorthand},
    clap::Parser,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreatePolicyInternalRequest, CreatePolicyResponse, CreatePolicyVersionRequest, CreatePolicyVersionResponse,
            DeletePolicyRequest, DeletePolicyVersionRequest, GetPolicyRequest, GetPolicyResponse,
            GetPolicyVersionRequest, GetPolicyVersionResponse, ListEntitiesForPolicyRequest,
            ListEntitiesForPolicyResponse, ListPoliciesInternalRequest, ListPoliciesResponse,
            ListPolicyVersionsRequest, ListPolicyVersionsResponse, SetDefaultPolicyVersionRequest, TagPolicyRequest,
            UntagPolicyRequest,
        },
        types::{EntityType, PolicyScopeType, PolicyUsageType},
    },
    std::ffi::OsString,
};

/// Create a new managed policy in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct CreatePolicyInternalCommand {
    /// The unique identifier for the account to create the policy in.
    #[clap(long)]
    pub account_id: String,

    /// The friendly name of the policy.
    #[clap(long)]
    pub policy_name: String,

    /// The JSON policy document. Must be a valid Aspen policy.
    #[clap(long)]
    pub policy_document: String,

    /// A friendly description of the policy.
    #[clap(long)]
    pub description: Option<String>,

    /// The path for the policy.
    #[clap(long, default_value = "/")]
    pub path: String,

    /// A list of tags to associate with the policy. Each tag must use AWS CLI-style shorthand,
    /// for example: `Key=Environment,Value=Production`.
    /// Multiple tags may be passed as multiple `--tags` arguments and/or as a bracketed list.
    #[clap(long, num_args = 1..)]
    pub tags: Vec<String>,
}

/// Create a new version of a managed policy in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct CreatePolicyVersionCommand {
    /// The ARN of the managed policy to create a new version for.
    #[clap(long)]
    pub policy_arn: String,

    /// The JSON policy document. Must be a valid Aspen policy.
    #[clap(long)]
    pub policy_document: String,

    /// Set this version as the policy's default version.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub set_as_default: bool,
}

/// Delete a managed policy in the Scratchstack IAM service. The policy must have no attachments
/// to users, groups, or roles, must not be used as a permissions boundary, and must have only the
/// default version remaining (all other versions must be deleted first via
/// `delete-policy-version`).
#[derive(Debug, Parser)]
pub(crate) struct DeletePolicyCommand {
    /// The ARN of the managed policy to delete.
    #[clap(long)]
    pub policy_arn: String,
}

/// Delete a version of a managed policy in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct DeletePolicyVersionCommand {
    /// The ARN of the managed policy to delete a version from.
    #[clap(long)]
    pub policy_arn: String,

    /// The version id to delete, e.g. `v1`. The default version cannot be deleted.
    #[clap(long)]
    pub version_id: String,
}

/// Get details for a managed policy in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct GetPolicyCommand {
    /// The ARN of the managed policy to get.
    #[clap(long)]
    pub policy_arn: String,
}

/// Get a specific version of a managed policy in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct GetPolicyVersionCommand {
    /// The ARN of the managed policy to fetch a version for.
    #[clap(long)]
    pub policy_arn: String,

    /// The version id to fetch, e.g. `v1`.
    #[clap(long)]
    pub version_id: String,
}

/// List the IAM entities (users, groups, roles) that a managed policy is attached to or that
/// use the policy as a permissions boundary.
#[derive(Debug, Parser)]
pub(crate) struct ListEntitiesForPolicyCommand {
    /// The ARN of the managed policy whose entities to list.
    #[clap(long)]
    pub policy_arn: String,

    /// Optional entity type filter: `User`, `Role`, or `Group`. If unspecified, all three are
    /// returned.
    #[clap(long)]
    pub entity_filter: Option<EntityType>,

    /// Optional usage filter: `PermissionsPolicy` (default — list attached entities) or
    /// `PermissionsBoundary` (list entities using the policy as a permissions boundary).
    #[clap(long)]
    pub policy_usage_filter: Option<PolicyUsageType>,

    /// Path prefix for filtering the returned entities by their path.
    #[clap(long)]
    pub path_prefix: Option<String>,

    /// Maximum number of entities to return across the combined groups/roles/users sections.
    #[clap(long)]
    pub max_items: Option<i32>,

    /// Marker for paginating list results.
    #[clap(long)]
    pub marker: Option<String>,
}

/// List managed policies in an account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct ListPoliciesInternalCommand {
    /// The unique identifier for the account to list policies in.
    #[clap(long)]
    pub account_id: String,

    /// The scope to filter by: AWS, Local, or All (default: All).
    #[clap(long)]
    pub scope: Option<PolicyScopeType>,

    /// When set, list only attached policies.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub only_attached: bool,

    /// Optional path prefix to filter by.
    #[clap(long)]
    pub path_prefix: Option<String>,

    /// Optional usage filter: PermissionsPolicy or PermissionsBoundary.
    #[clap(long)]
    pub policy_usage_filter: Option<PolicyUsageType>,

    /// Maximum number of policies to return.
    #[clap(long)]
    pub max_items: Option<i32>,

    /// Marker for paginating list results.
    #[clap(long)]
    pub marker: Option<String>,
}

/// List versions of a managed policy in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct ListPolicyVersionsCommand {
    /// The ARN of the managed policy whose versions to list.
    #[clap(long)]
    pub policy_arn: String,

    /// Maximum number of versions to return.
    #[clap(long)]
    pub max_items: Option<i32>,

    /// Marker for paginating list results.
    #[clap(long)]
    pub marker: Option<String>,
}

/// Set the default version for a managed policy in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct SetDefaultPolicyVersionCommand {
    /// The ARN of the managed policy whose default version to set.
    #[clap(long)]
    pub policy_arn: String,

    /// The version id to make default, e.g. `v2`.
    #[clap(long)]
    pub version_id: String,
}

/// Add or update tags on a managed policy in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct TagPolicyCommand {
    /// The ARN of the managed policy to tag.
    #[clap(long)]
    pub policy_arn: String,

    /// A list of tags to associate with the policy. Each tag must use AWS CLI-style shorthand,
    /// for example: `Key=Environment,Value=Production`.
    #[clap(long, num_args = 1..)]
    pub tags: Vec<String>,
}

/// Remove tags from a managed policy in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct UntagPolicyCommand {
    /// The ARN of the managed policy to untag.
    #[clap(long)]
    pub policy_arn: String,

    /// A list of tag keys to remove from the policy.
    #[clap(long, num_args = 1..)]
    pub tag_keys: Vec<String>,
}

impl Runnable for CreatePolicyInternalCommand {
    type Result = CreatePolicyResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let tags = tags_from_shorthand(&self.tags)?;
        let request = CreatePolicyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .policy_name(self.policy_name.clone())
            .policy_document(self.policy_document.clone())
            .description(self.description.clone())
            .path(Some(self.path.clone()))
            .tags(tags)
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for CreatePolicyVersionCommand {
    type Result = CreatePolicyVersionResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let mut request_builder = CreatePolicyVersionRequest::builder()
            .policy_arn(self.policy_arn.clone())
            .policy_document(self.policy_document.clone());
        if self.set_as_default {
            request_builder = request_builder.set_as_default(Some(true));
        }
        let request = request_builder.build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DeletePolicyCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = DeletePolicyRequest::builder().policy_arn(self.policy_arn.clone()).build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DeletePolicyVersionCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = DeletePolicyVersionRequest::builder()
            .policy_arn(self.policy_arn.clone())
            .version_id(self.version_id.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for GetPolicyCommand {
    type Result = GetPolicyResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = GetPolicyRequest::builder().policy_arn(self.policy_arn.clone()).build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for GetPolicyVersionCommand {
    type Result = GetPolicyVersionResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = GetPolicyVersionRequest::builder()
            .policy_arn(self.policy_arn.clone())
            .version_id(self.version_id.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListEntitiesForPolicyCommand {
    type Result = ListEntitiesForPolicyResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let mut builder = ListEntitiesForPolicyRequest::builder().policy_arn(self.policy_arn.clone());
        if let Some(filter) = self.entity_filter {
            builder = builder.entity_filter(Some(filter));
        }
        if let Some(filter) = self.policy_usage_filter {
            builder = builder.policy_usage_filter(Some(filter));
        }
        if let Some(path_prefix) = &self.path_prefix {
            builder = builder.path_prefix(Some(path_prefix.clone()));
        }
        if let Some(max_items) = self.max_items {
            builder = builder.max_items(Some(max_items));
        }
        if let Some(marker) = &self.marker {
            builder = builder.marker(Some(marker.clone()));
        }
        let request = builder.build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListPoliciesInternalCommand {
    type Result = ListPoliciesResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let mut builder = ListPoliciesInternalRequest::builder().account_id(self.account_id.clone());
        if let Some(scope) = self.scope {
            builder = builder.scope(Some(scope));
        }
        if self.only_attached {
            builder = builder.only_attached(Some(true));
        }
        if let Some(path_prefix) = &self.path_prefix {
            builder = builder.path_prefix(Some(path_prefix.clone()));
        }
        if let Some(filter) = self.policy_usage_filter {
            builder = builder.policy_usage_filter(Some(filter));
        }
        if let Some(max_items) = self.max_items {
            builder = builder.max_items(Some(max_items));
        }
        if let Some(marker) = &self.marker {
            builder = builder.marker(Some(marker.clone()));
        }
        let request = builder.build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListPolicyVersionsCommand {
    type Result = ListPolicyVersionsResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let mut builder = ListPolicyVersionsRequest::builder().policy_arn(self.policy_arn.clone());
        if let Some(max_items) = self.max_items {
            builder = builder.max_items(Some(max_items));
        }
        if let Some(marker) = &self.marker {
            builder = builder.marker(Some(marker.clone()));
        }
        let request = builder.build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for SetDefaultPolicyVersionCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = SetDefaultPolicyVersionRequest::builder()
            .policy_arn(self.policy_arn.clone())
            .version_id(self.version_id.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for TagPolicyCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let tags = tags_from_shorthand(&self.tags)?;
        let request = TagPolicyRequest::builder().policy_arn(self.policy_arn.clone()).tags(tags).build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for UntagPolicyCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = UntagPolicyRequest::builder()
            .policy_arn(self.policy_arn.clone())
            .tag_keys(self.tag_keys.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}
