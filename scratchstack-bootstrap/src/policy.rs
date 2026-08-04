//! Scratchstack bootstrap policy subcommands
use {
    crate::{Cli, Runnable, execute_in_transaction, internal_failure, tag::tags_from_shorthand},
    clap::Parser,
    log::error,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreatePolicyInternalRequest, CreatePolicyResponse, CreatePolicyVersionRequest, CreatePolicyVersionResponse,
            DeletePolicyRequest, DeletePolicyVersionRequest, GetPolicyRequest, GetPolicyResponse,
            GetPolicyVersionRequest, GetPolicyVersionResponse, ListEntitiesForPolicyRequest,
            ListEntitiesForPolicyResponse, ListPoliciesInternalRequest, ListPoliciesResponse, ListPolicyTagsRequest,
            ListPolicyTagsResponse, ListPolicyVersionsRequest, ListPolicyVersionsResponse,
            SetDefaultPolicyVersionRequest, TagPolicyRequest, UntagPolicyRequest,
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

/// List the tags attached to a managed policy in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct ListPolicyTagsCommand {
    /// The ARN of the managed policy whose tags to list.
    #[clap(long)]
    pub policy_arn: String,

    /// Maximum number of tags to return.
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
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let tags = tags_from_shorthand(&self.tags)?;
        let request = CreatePolicyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .policy_name(self.policy_name.clone())
            .policy_document(self.policy_document.clone())
            .set_description(self.description.clone())
            .path(self.path.clone())
            .set_tags(tags)
            .build()
            .map_err(|e| {
                error!("Failed to build CreatePolicyInternalRequest: {e}");
                internal_failure()
            })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for CreatePolicyVersionCommand {
    type Result = CreatePolicyVersionResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = CreatePolicyVersionRequest::builder()
            .policy_arn(self.policy_arn.clone())
            .policy_document(self.policy_document.clone())
            .set_as_default(self.set_as_default)
            .build()
            .map_err(|e| {
                error!("Failed to build CreatePolicyVersionRequest: {e}");
                internal_failure()
            })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DeletePolicyCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = DeletePolicyRequest::builder().policy_arn(self.policy_arn.clone()).build().map_err(|e| {
            error!("Failed to build DeletePolicyRequest: {e}");
            internal_failure()
        })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DeletePolicyVersionCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = DeletePolicyVersionRequest::builder()
            .policy_arn(self.policy_arn.clone())
            .version_id(self.version_id.clone())
            .build()
            .map_err(|e| {
                error!("Failed to build DeletePolicyVersionRequest: {e}");
                internal_failure()
            })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for GetPolicyCommand {
    type Result = GetPolicyResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = GetPolicyRequest::builder().policy_arn(self.policy_arn.clone()).build().map_err(|e| {
            error!("Failed to build GetPolicyRequest: {e}");
            internal_failure()
        })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for GetPolicyVersionCommand {
    type Result = GetPolicyVersionResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = GetPolicyVersionRequest::builder()
            .policy_arn(self.policy_arn.clone())
            .version_id(self.version_id.clone())
            .build()
            .map_err(|e| {
                error!("Failed to build GetPolicyVersionRequest: {e}");
                internal_failure()
            })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListEntitiesForPolicyCommand {
    type Result = ListEntitiesForPolicyResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListEntitiesForPolicyRequest::builder()
            .policy_arn(self.policy_arn.clone())
            .set_entity_filter(self.entity_filter.clone())
            .set_policy_usage_filter(self.policy_usage_filter.clone())
            .set_path_prefix(self.path_prefix.clone())
            .set_max_items(self.max_items)
            .set_marker(self.marker.clone())
            .build()
            .map_err(|e| {
                error!("Failed to build ListEntitiesForPolicyRequest: {e}");
                internal_failure()
            })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListPoliciesInternalCommand {
    type Result = ListPoliciesResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListPoliciesInternalRequest::builder()
            .account_id(self.account_id.clone())
            .set_scope(self.scope)
            .only_attached(self.only_attached)
            .set_path_prefix(self.path_prefix.clone())
            .set_policy_usage_filter(self.policy_usage_filter)
            .set_max_items(self.max_items)
            .set_marker(self.marker.clone())
            .build()
            .map_err(|e| {
                error!("Failed to build ListPoliciesInternalRequest: {e}");
                internal_failure()
            })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListPolicyTagsCommand {
    type Result = ListPolicyTagsResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListPolicyTagsRequest::builder()
            .policy_arn(self.policy_arn.clone())
            .set_max_items(self.max_items)
            .set_marker(self.marker.clone())
            .build()
            .map_err(|e| {
                error!("Failed to build ListPolicyTagsRequest: {e}");
                internal_failure()
            })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListPolicyVersionsCommand {
    type Result = ListPolicyVersionsResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListPolicyVersionsRequest::builder()
            .policy_arn(self.policy_arn.clone())
            .set_max_items(self.max_items)
            .set_marker(self.marker.clone())
            .build()
            .map_err(|e| {
                error!("Failed to build ListPolicyVersionsRequest: {e}");
                internal_failure()
            })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for SetDefaultPolicyVersionCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = SetDefaultPolicyVersionRequest::builder()
            .policy_arn(self.policy_arn.clone())
            .version_id(self.version_id.clone())
            .build()
            .map_err(|e| {
                error!("Failed to build SetDefaultPolicyVersionRequest: {e}");
                internal_failure()
            })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for TagPolicyCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let tags = tags_from_shorthand(&self.tags)?;
        let request =
            TagPolicyRequest::builder().policy_arn(self.policy_arn.clone()).set_tags(tags).build().map_err(|e| {
                error!("Failed to build TagPolicyRequest: {e}");
                internal_failure()
            })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for UntagPolicyCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = UntagPolicyRequest::builder()
            .policy_arn(self.policy_arn.clone())
            .set_tag_keys(self.tag_keys.clone())
            .build()
            .map_err(|e| {
                error!("Failed to build UntagPolicyRequest: {e}");
                internal_failure()
            })?;
        execute_in_transaction(cli, vars, &request).await
    }
}
