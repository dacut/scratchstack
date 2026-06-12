//! Scratchstack bootsrap create-user subcommand
use {
    crate::{Cli, Runnable, execute_in_transaction, tag::tags_from_shorthand},
    clap::Parser,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            AttachUserPolicyInternalRequest, CreateAccessKeyInternalRequest, CreateAccessKeyResponse,
            CreateUserInternalRequest, CreateUserResponse, DeleteAccessKeyInternalRequest, DeleteUserInternalRequest,
            DeleteUserPermissionsBoundaryInternalRequest, DeleteUserPolicyInternalRequest,
            DetachUserPolicyInternalRequest, GetUserInternalRequest, GetUserPolicyInternalRequest,
            GetUserPolicyResponse, GetUserResponse, ListAccessKeysInternalRequest, ListAccessKeysResponse,
            ListAttachedUserPoliciesInternalRequest, ListAttachedUserPoliciesResponse, ListUserPoliciesInternalRequest,
            ListUserPoliciesResponse, ListUserTagsInternalRequest, ListUserTagsResponse, ListUsersInternalRequest,
            ListUsersResponse, PutUserPermissionsBoundaryInternalRequest, PutUserPolicyInternalRequest,
            TagUserInternalRequest, UntagUserInternalRequest, UpdateAccessKeyInternalRequest,
            UpdateUserInternalRequest,
        },
        types::StatusType,
    },
    std::ffi::OsString,
};

/// Attach a managed policy to a user in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct AttachUserPolicyInternalCommand {
    /// The unique identifier for the account the user belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The ARN of the managed policy to attach to the user.
    #[clap(long)]
    pub policy_arn: String,

    /// The name of the user to attach the policy to.
    #[clap(long)]
    pub user_name: String,
}

/// Create a new access key (access key id + secret key pair) for an IAM user in the Scratchstack
/// IAM service.
#[derive(Debug, Parser)]
pub(crate) struct CreateAccessKeyInternalCommand {
    /// The unique identifier for the account the user belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the user to create the access key for.
    #[clap(long)]
    pub user_name: String,
}

/// Create a new user in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct CreateUserInternalCommand {
    /// The unique identifier for the account to create the user in.
    #[clap(long)]
    pub account_id: String,

    /// The path for the user name.
    #[clap(long, default_value = "/")]
    pub path: String,

    /// The name of the user to create.
    #[clap(long)]
    pub user_name: String,

    /// The ARN of the managed policy used to set the permissions boundary for the user.
    #[clap(long)]
    pub permissions_boundary: Option<String>,

    /// A list of tags to associate with the user. Each tag is a `Key=<name>,Value=<value>`
    /// structure; multiple tags may be passed in a single `--tags` argument.
    ///
    /// Example: `--tags Key=Environment,Value=Production Key=Team,Value=Platform`
    #[clap(long, num_args = 1..)]
    pub tags: Vec<String>,
}

/// Delete an access key from an IAM user in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct DeleteAccessKeyInternalCommand {
    /// The unique identifier for the account the user belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The access key id to delete (the full 20-character `AKIA...` form).
    #[clap(long)]
    pub access_key_id: String,

    /// The name of the user that owns the access key. Optional; if specified, the access key
    /// must belong to this user.
    #[clap(long)]
    pub user_name: Option<String>,
}

/// Delete a user from the given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct DeleteUserInternalCommand {
    /// The unique identifier for the account to delete the user from.
    #[clap(long)]
    pub account_id: String,

    /// The name of the user to delete.
    #[clap(long)]
    pub user_name: String,
}

/// Delete the permissions boundary from a user in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct DeleteUserPermissionsBoundaryInternalCommand {
    /// The unique identifier for the account the user belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the user to delete the permissions boundary from.
    #[clap(long)]
    pub user_name: String,
}

/// Delete an inline policy from a user in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct DeleteUserPolicyInternalCommand {
    /// The unique identifier for the account the user belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the user to remove the inline policy from.
    #[clap(long)]
    pub user_name: String,

    /// The name of the inline policy to delete.
    #[clap(long)]
    pub policy_name: String,
}

/// Detach a managed policy from a user in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct DetachUserPolicyInternalCommand {
    /// The unique identifier for the account the user belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The ARN of the managed policy to detach from the user.
    #[clap(long)]
    pub policy_arn: String,

    /// The name of the user to detach the policy from.
    #[clap(long)]
    pub user_name: String,
}

/// Get information about an IAM user in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct GetUserInternalCommand {
    /// The unique identifier for the account the user belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the user to get information about.
    #[clap(long)]
    pub user_name: String,
}

/// Retrieve the document of an inline policy attached to a user in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct GetUserPolicyInternalCommand {
    /// The unique identifier for the account the user belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the user the policy is associated with.
    #[clap(long)]
    pub user_name: String,

    /// The name of the inline policy to retrieve.
    #[clap(long)]
    pub policy_name: String,
}

/// List the access keys attached to an IAM user in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct ListAccessKeysInternalCommand {
    /// The unique identifier for the account the user belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the user to list access keys for.
    #[clap(long)]
    pub user_name: String,

    /// The maximum number of access keys to include in the response.
    #[clap(long)]
    pub max_items: Option<i32>,

    /// A marker for paginating the list of access keys.
    #[clap(long)]
    pub marker: Option<String>,
}

/// List managed policies attached to a user in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct ListAttachedUserPoliciesInternalCommand {
    /// The unique identifier for the account the user belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the user to list attached policies for.
    #[clap(long)]
    pub user_name: String,

    /// The path prefix for filtering the list of attached policies. Only policies with a path
    /// that starts with this prefix will be included in the response.
    #[clap(long)]
    pub path_prefix: Option<String>,

    /// The maximum number of attached policies to include in the response.
    #[clap(long)]
    pub max_items: Option<i32>,

    /// A marker for paginating the list of attached policies. If the response from a previous
    /// ListAttachedUserPolicies request was truncated, the response will include a marker that
    /// you can use in a subsequent ListAttachedUserPolicies request to retrieve the next set of
    /// attached policies.
    #[clap(long)]
    pub marker: Option<String>,
}

/// List the names of inline policies attached to a user in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct ListUserPoliciesInternalCommand {
    /// The unique identifier for the account the user belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the user to list inline policies for.
    #[clap(long)]
    pub user_name: String,

    /// The maximum number of inline policies to include in the response.
    #[clap(long)]
    pub max_items: Option<i32>,

    /// A marker for paginating the list of inline policies. If the response from a previous
    /// ListUserPolicies request was truncated, the response will include a marker that you can
    /// use in a subsequent ListUserPolicies request to retrieve the next set of inline policies.
    #[clap(long)]
    pub marker: Option<String>,
}

/// List users in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct ListUsersInternalCommand {
    /// The unique identifier for the account to list users in.
    #[clap(long)]
    pub account_id: String,

    /// The path prefix for filtering the list of users. Only users with a path that starts with
    /// this prefix will be included in the response.
    #[clap(long)]
    pub path_prefix: Option<String>,

    /// The maximum number of users to include in the response.
    #[clap(long)]
    pub max_items: Option<i32>,

    /// A marker for paginating the list of users. If the response from a previous ListUsers
    /// request was truncated, the response will include a marker that you can use in a subsequent
    /// ListUsers request to retrieve the next set of users.
    #[clap(long)]
    pub marker: Option<String>,
}

/// List tags for a user in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct ListUserTagsInternalCommand {
    /// The unique identifier for the account to list user tags in.
    #[clap(long)]
    pub account_id: String,

    /// The name of the user to list tags for.
    #[clap(long)]
    pub user_name: String,

    /// The maximum number of tags to include in the response.
    #[clap(long)]
    pub max_items: Option<i32>,

    /// A marker for paginating the list of tags. If the response from a previous ListUserTags
    /// request was truncated, the response will include a marker that you can use in a subsequent
    /// ListUserTags request to retrieve the next set of tags.
    #[clap(long)]
    pub marker: Option<String>,
}

/// Add or update tags on a user in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct TagUserInternalCommand {
    /// The unique identifier for the account the user belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the user to tag.
    #[clap(long)]
    pub user_name: String,

    /// A list of tags to associate with the user. Each tag must use AWS CLI-style shorthand,
    /// for example: `Key=Environment,Value=Production`.
    /// Multiple tags may be passed as multiple `--tags` arguments and/or as a bracketed list,
    /// for example:
    /// `--tags Key=Environment,Value=Production --tags Key=Team,Value=Platform`
    /// or
    /// `--tags "[{Key=Environment,Value=Production},{Key=Team,Value=Platform}]"`.
    #[clap(long, num_args = 1..)]
    pub tags: Vec<String>,
}

/// Remove tags from a user in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct UntagUserInternalCommand {
    /// The unique identifier for the account the user belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the user to untag.
    #[clap(long)]
    pub user_name: String,

    /// A list of tag keys to remove from the user.
    #[clap(long, num_args = 1..)]
    pub tag_keys: Vec<String>,
}

/// Change the status (Active or Inactive) of an access key in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct UpdateAccessKeyInternalCommand {
    /// The unique identifier for the account the user belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The access key id to update (the full 20-character `AKIA...` form).
    #[clap(long)]
    pub access_key_id: String,

    /// The new status for the access key.
    #[clap(long, value_enum)]
    pub status: StatusType,

    /// The name of the user that owns the access key. Optional; if specified, the access key
    /// must belong to this user.
    #[clap(long)]
    pub user_name: Option<String>,
}

/// Update a user in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct UpdateUserInternalCommand {
    /// The unique identifier for the account to update the user in.
    #[clap(long)]
    pub account_id: String,

    /// The name of the user to update.
    #[clap(long)]
    pub user_name: String,

    /// The new path for the user name.
    #[clap(long)]
    pub new_path: Option<String>,

    /// The new name of the user.
    #[clap(long)]
    pub new_user_name: Option<String>,
}

impl Runnable for AttachUserPolicyInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = AttachUserPolicyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .policy_arn(self.policy_arn.clone())
            .user_name(self.user_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for CreateAccessKeyInternalCommand {
    type Result = CreateAccessKeyResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = CreateAccessKeyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .user_name(Some(self.user_name.clone()))
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for CreateUserInternalCommand {
    type Result = CreateUserResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let mut builder = CreateUserInternalRequest::builder()
            .account_id(self.account_id.clone())
            .path(self.path.clone())
            .user_name(self.user_name.clone())
            .permissions_boundary(self.permissions_boundary.clone());
        let tags = tags_from_shorthand(&self.tags)?;
        builder = builder.tags(tags);

        let request = builder.build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DeleteAccessKeyInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = DeleteAccessKeyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .access_key_id(self.access_key_id.clone())
            .user_name(self.user_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DeleteUserInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = DeleteUserInternalRequest {
            account_id: self.account_id.clone(),
            user_name: self.user_name.clone(),
        };
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DeleteUserPermissionsBoundaryInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = DeleteUserPermissionsBoundaryInternalRequest {
            account_id: self.account_id.clone(),
            user_name: self.user_name.clone(),
        };
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DeleteUserPolicyInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = DeleteUserPolicyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .user_name(self.user_name.clone())
            .policy_name(self.policy_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DetachUserPolicyInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = DetachUserPolicyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .policy_arn(self.policy_arn.clone())
            .user_name(self.user_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for GetUserInternalCommand {
    type Result = GetUserResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = GetUserInternalRequest::builder()
            .user_name(Some(self.user_name.clone()))
            .account_id(self.account_id.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for GetUserPolicyInternalCommand {
    type Result = GetUserPolicyResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = GetUserPolicyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .user_name(self.user_name.clone())
            .policy_name(self.policy_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListAccessKeysInternalCommand {
    type Result = ListAccessKeysResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListAccessKeysInternalRequest::builder()
            .account_id(self.account_id.clone())
            .user_name(Some(self.user_name.clone()))
            .max_items(self.max_items)
            .marker(self.marker.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListAttachedUserPoliciesInternalCommand {
    type Result = ListAttachedUserPoliciesResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListAttachedUserPoliciesInternalRequest::builder()
            .account_id(self.account_id.clone())
            .user_name(self.user_name.clone())
            .path_prefix(self.path_prefix.clone())
            .max_items(self.max_items)
            .marker(self.marker.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListUserPoliciesInternalCommand {
    type Result = ListUserPoliciesResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListUserPoliciesInternalRequest::builder()
            .account_id(self.account_id.clone())
            .user_name(self.user_name.clone())
            .max_items(self.max_items)
            .marker(self.marker.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListUsersInternalCommand {
    type Result = ListUsersResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListUsersInternalRequest {
            account_id: self.account_id.clone(),
            path_prefix: self.path_prefix.clone(),
            max_items: self.max_items,
            marker: self.marker.clone(),
        };
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for ListUserTagsInternalCommand {
    type Result = ListUserTagsResponse;
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListUserTagsInternalRequest {
            account_id: self.account_id.clone(),
            user_name: self.user_name.clone(),
            max_items: self.max_items,
            marker: self.marker.clone(),
        };
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for TagUserInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let tags = tags_from_shorthand(&self.tags)?;
        let request = TagUserInternalRequest::builder()
            .account_id(self.account_id.clone())
            .user_name(self.user_name.clone())
            .tags(tags)
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for UntagUserInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = UntagUserInternalRequest::builder()
            .account_id(self.account_id.clone())
            .user_name(self.user_name.clone())
            .tag_keys(self.tag_keys.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for UpdateAccessKeyInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = UpdateAccessKeyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .access_key_id(self.access_key_id.clone())
            .status(self.status)
            .user_name(self.user_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for UpdateUserInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = UpdateUserInternalRequest {
            account_id: self.account_id.clone(),
            user_name: self.user_name.clone(),
            new_path: self.new_path.clone(),
            new_user_name: self.new_user_name.clone(),
        };
        execute_in_transaction(cli, vars, &request).await
    }
}

/// Set or replace the permissions boundary on a user in a given account in the Scratchstack IAM
/// service.
#[derive(Debug, Parser)]
pub(crate) struct PutUserPermissionsBoundaryInternalCommand {
    /// The unique identifier for the account the user belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The ARN of the managed policy used to set the permissions boundary for the user.
    #[clap(long)]
    pub permissions_boundary: String,

    /// The name of the user to set the permissions boundary on.
    #[clap(long)]
    pub user_name: String,
}

impl Runnable for PutUserPermissionsBoundaryInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = PutUserPermissionsBoundaryInternalRequest::builder()
            .account_id(self.account_id.clone())
            .permissions_boundary(self.permissions_boundary.clone())
            .user_name(self.user_name.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}

/// Add or replace an inline policy on a user in a given account in the Scratchstack IAM service.
#[derive(Debug, Parser)]
pub(crate) struct PutUserPolicyInternalCommand {
    /// The unique identifier for the account the user belongs to.
    #[clap(long)]
    pub account_id: String,

    /// The name of the user on which to set the inline policy.
    #[clap(long)]
    pub user_name: String,

    /// The name of the inline policy to add or replace.
    #[clap(long)]
    pub policy_name: String,

    /// The JSON policy document. Must parse as a valid Aspen policy.
    #[clap(long)]
    pub policy_document: String,
}

impl Runnable for PutUserPolicyInternalCommand {
    type Result = ();
    type Error = IamError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = PutUserPolicyInternalRequest::builder()
            .account_id(self.account_id.clone())
            .user_name(self.user_name.clone())
            .policy_name(self.policy_name.clone())
            .policy_document(self.policy_document.clone())
            .build()?;
        execute_in_transaction(cli, vars, &request).await
    }
}
