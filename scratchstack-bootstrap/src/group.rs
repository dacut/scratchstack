//! Scratchstack bootstrap group subcommands
use {
    crate::{Cli, Runnable, execute_in_transaction},
    clap::Parser,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            AddUserToGroupInternalRequest, AttachGroupPolicyInternalRequest, CreateGroupInternalRequest,
            CreateGroupResponse, DeleteGroupInternalRequest, DetachGroupPolicyInternalRequest, GetGroupInternalRequest,
            GetGroupResponse, ListGroupsForUserInternalRequest, ListGroupsForUserResponse, ListGroupsInternalRequest,
            ListGroupsResponse, RemoveUserFromGroupInternalRequest, UpdateGroupInternalRequest,
        },
    },
    std::ffi::OsString,
};

/// Attach a managed policy to a group in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct AttachGroupPolicyInternalCommand {
    /// The unique identifier for the account the group belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the group to attach the policy to.
    #[clap(long)]
    pub group_name: String,

    /// The ARN of the managed policy to attach to the group.
    #[clap(long)]
    pub policy_arn: String,
}

/// Create a new group in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct CreateGroupInternalCommand {
    /// The unique identifier for the account to create the group in.
    #[clap(long)]
    pub account_id: String,

    /// The name of the group to create.
    #[clap(long)]
    pub group_name: String,

    /// The path for the group.
    #[clap(long, default_value = "/")]
    pub path: String,
}

/// Delete a group from the given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct DeleteGroupInternalCommand {
    /// The unique identifier for the account to delete the group from.
    #[clap(long)]
    pub account_id: String,

    /// The name of the group to delete.
    #[clap(long)]
    pub group_name: String,
}

/// Detach a managed policy from a group in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct DetachGroupPolicyInternalCommand {
    /// The unique identifier for the account the group belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the group to detach the policy from.
    #[clap(long)]
    pub group_name: String,

    /// The ARN of the managed policy to detach from the group.
    #[clap(long)]
    pub policy_arn: String,
}

/// Get information about an IAM group in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct GetGroupInternalCommand {
    /// The unique identifier for the account the group belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the group to get information about.
    #[clap(long)]
    pub group_name: String,
}

/// List groups in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct ListGroupsInternalCommand {
    /// The unique identifier for the account to list groups in.
    #[clap(long)]
    pub account_id: String,

    /// The path prefix for filtering the list of groups. Only groups with a path that starts with
    /// this prefix will be included in the response.
    #[clap(long)]
    pub path_prefix: Option<String>,

    /// The maximum number of groups to include in the response.
    #[clap(long)]
    pub max_items: Option<i32>,

    /// A marker for paginating the list of groups. If the response from a previous ListGroups
    /// request was truncated, the response will include a marker that you can use in a subsequent
    /// ListGroups request to retrieve the next set of groups.
    #[clap(long)]
    pub marker: Option<String>,
}

/// Update a group in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct UpdateGroupInternalCommand {
    /// The unique identifier for the account to update the group in.
    #[clap(long)]
    pub account_id: String,

    /// The name of the group to update.
    #[clap(long)]
    pub group_name: String,

    /// The new name of the group.
    #[clap(long)]
    pub new_group_name: Option<String>,

    /// The new path for the group.
    #[clap(long)]
    pub new_path: Option<String>,
}

impl Runnable for CreateGroupInternalCommand {
    type Result = CreateGroupResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = CreateGroupInternalRequest::builder()
            .account_id(self.account_id.clone())
            .group_name(self.group_name.clone())
            .path(Some(self.path.clone()))
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DeleteGroupInternalCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = DeleteGroupInternalRequest::builder()
            .account_id(self.account_id.clone())
            .group_name(self.group_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for GetGroupInternalCommand {
    type Result = GetGroupResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = GetGroupInternalRequest::builder()
            .account_id(self.account_id.clone())
            .group_name(self.group_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListGroupsInternalCommand {
    type Result = ListGroupsResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListGroupsInternalRequest {
            account_id: self.account_id.clone(),
            path_prefix: self.path_prefix.clone(),
            max_items: self.max_items,
            marker: self.marker.clone(),
        };
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for UpdateGroupInternalCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = UpdateGroupInternalRequest {
            account_id: self.account_id.clone(),
            group_name: self.group_name.clone(),
            new_group_name: self.new_group_name.clone(),
            new_path: self.new_path.clone(),
        };
        execute_in_transaction(cli, vars, &request).await
    }
}

/// Add a user to a group in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct AddUserToGroupInternalCommand {
    /// The unique identifier for the account.
    #[clap(long)]
    pub account_id: String,

    /// The name of the group to add the user to.
    #[clap(long)]
    pub group_name: String,

    /// The name of the user to add to the group.
    #[clap(long)]
    pub user_name: String,
}

/// List groups that a user belongs to in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct ListGroupsForUserInternalCommand {
    /// The unique identifier for the account.
    #[clap(long)]
    pub account_id: String,

    /// The name of the user to list groups for.
    #[clap(long)]
    pub user_name: String,

    /// The maximum number of groups to include in the response.
    #[clap(long)]
    pub max_items: Option<i32>,

    /// A marker for paginating the list of groups.
    #[clap(long)]
    pub marker: Option<String>,
}

/// Remove a user from a group in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct RemoveUserFromGroupInternalCommand {
    /// The unique identifier for the account.
    #[clap(long)]
    pub account_id: String,

    /// The name of the group to remove the user from.
    #[clap(long)]
    pub group_name: String,

    /// The name of the user to remove from the group.
    #[clap(long)]
    pub user_name: String,
}

impl Runnable for AddUserToGroupInternalCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = AddUserToGroupInternalRequest::builder()
            .account_id(self.account_id.clone())
            .group_name(self.group_name.clone())
            .user_name(self.user_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListGroupsForUserInternalCommand {
    type Result = ListGroupsForUserResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListGroupsForUserInternalRequest {
            account_id: self.account_id.clone(),
            user_name: self.user_name.clone(),
            max_items: self.max_items,
            marker: self.marker.clone(),
        };
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for RemoveUserFromGroupInternalCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = RemoveUserFromGroupInternalRequest::builder()
            .account_id(self.account_id.clone())
            .group_name(self.group_name.clone())
            .user_name(self.user_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for AttachGroupPolicyInternalCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = AttachGroupPolicyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .group_name(self.group_name.clone())
            .policy_arn(self.policy_arn.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DetachGroupPolicyInternalCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = DetachGroupPolicyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .group_name(self.group_name.clone())
            .policy_arn(self.policy_arn.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}
