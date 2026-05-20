//! Scratchstack bootstrap role subcommands
use {
    crate::{Cli, Runnable, execute_in_transaction},
    clap::Parser,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{AttachRolePolicyInternalRequest, DetachRolePolicyInternalRequest},
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
