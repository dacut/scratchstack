//! Scratchstack bootstrap role subcommands
use {
    crate::{Cli, Runnable, execute_in_transaction},
    clap::Parser,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            AttachRolePolicyInternalRequest, DetachRolePolicyInternalRequest, ListAttachedRolePoliciesInternalRequest,
            ListAttachedRolePoliciesResponse,
        },
    },
    std::ffi::OsString,
};

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
