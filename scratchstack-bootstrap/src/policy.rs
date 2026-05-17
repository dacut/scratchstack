//! Scratchstack bootstrap policy subcommands
use {
    crate::{Cli, Runnable, execute_in_transaction, user::tags_from_shorthand},
    clap::Parser,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreatePolicyInternalRequest, CreatePolicyResponse, CreatePolicyVersionRequest, CreatePolicyVersionResponse,
        },
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
