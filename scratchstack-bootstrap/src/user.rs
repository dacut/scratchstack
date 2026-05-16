//! Scratchstack bootsrap create-user subcommand
use {
    crate::{Cli, MSG_INTERNAL_FAILURE, Runnable, execute_in_transaction},
    clap::Parser,
    scratchstack_cli_utils::{ShorthandValue, parse_shorthand},
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreateUserInternalRequest, CreateUserResponse, DeleteUserInternalRequest, ListUserTagsInternalRequest,
            ListUserTagsResponse, ListUsersInternalRequest, ListUsersResponse, UpdateUserInternalRequest,
        },
        types::{
            Tag,
            error::{InternalFailure, ValidationError},
        },
    },
    std::{collections::HashMap, ffi::OsString},
};

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

    /// A list of tags to associate with the user. Each tag is a key-value pair separated by an
    /// equals sign (`=`), and multiple tags are separated by commas (`,`). For example:
    /// `Key1=Value1,Key2=Value2`.
    #[clap(long, num_args = 1..)]
    pub tags: Vec<String>,
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

impl Runnable for CreateUserInternalCommand {
    type Result = CreateUserResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
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

        let request = builder.build().map_err(|e| {
            log::error!("Failed to build CreateUserInternalRequest: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;
        execute_in_transaction(cli, vars, &request).await
    }
}

impl Runnable for DeleteUserInternalCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
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

impl Runnable for ListUsersInternalCommand {
    type Result = ListUsersResponse;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
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

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
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

impl Runnable for UpdateUserInternalCommand {
    type Result = ();

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, IamError>
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

/// Convert a list of shorthand values to a `Vec<Tag>`.
fn tags_from_shorthand(values: &[impl AsRef<str>]) -> Result<Vec<Tag>, IamError> {
    let mut tags = Vec::with_capacity(values.len());
    let mut tag_keys_lower = Vec::with_capacity(values.len());

    for value in values {
        let value = value.as_ref();
        let parsed = parse_shorthand(value).map_err(|e| {
            IamError::from(ValidationError::builder().message(format!("Invalid tag format: {value:?}: {e}")).build())
        })?;
        match parsed {
            ShorthandValue::List(values) => {
                for value in values {
                    let ShorthandValue::Map(map) = value else {
                        return Err(ValidationError::builder()
                            .message(format!(
                                "Invalid tag format: {value:?}. Tags must be in the format 'Key=k,Value=v' or a JSON object with 'Key' and 'Value' fields"
                            ))
                            .build()
                            .into());
                    };
                    let tag = tag_from_shorthand(&map)?;
                    let tag_key_lower = tag.key.to_lowercase();
                    if tag_keys_lower.contains(&tag_key_lower) {
                        return Err(ValidationError::builder()
                            .message(format!("Duplicate tag key {}. Note that tag keys are case-insensitive.", tag.key))
                            .build()
                            .into());
                    }
                    tag_keys_lower.push(tag_key_lower);
                    tags.push(tag);
                }
            }
            ShorthandValue::Map(map) => {
                let tag = tag_from_shorthand(&map)?;
                let tag_key_lower = tag.key.to_lowercase();
                if tag_keys_lower.contains(&tag_key_lower) {
                    return Err(ValidationError::builder()
                        .message(format!("Duplicate tag key {}. Note that tag keys are case-insensitive.", tag.key))
                        .build()
                        .into());
                }
                tag_keys_lower.push(tag_key_lower);
                tags.push(tag);
            }
            _ => {
                return Err(ValidationError::builder()
                    .message(format!(
                        "Invalid tag format: {value:?}. Tags must be in the format 'Key=k,Value=v' or a JSON object with 'Key' and 'Value' fields"
                    ))
                    .build()
                    .into());
            }
        }
    }
    Ok(tags)
}

/// Convert a map of keys to shorthand values to a [`Tag`].
fn tag_from_shorthand(map: &HashMap<String, ShorthandValue>) -> Result<Tag, IamError> {
    let mut tag_key = None;
    let mut tag_value = None;

    for (key, value) in map {
        match key.as_str() {
            "Key" => {
                tag_key = Some(value.as_str().ok_or_else(|| {
                    IamError::from(
                        ValidationError::builder()
                            .message(format!("Invalid tag format: {map:?}. 'Key' must be a string"))
                            .build(),
                    )
                })?);
            }
            "Value" => {
                tag_value = Some(value.as_str().ok_or_else(|| {
                    IamError::from(
                        ValidationError::builder()
                            .message(format!("Invalid tag format: {map:?}. 'Value' must be a string"))
                            .build(),
                    )
                })?);
            }
            _ => {
                return Err(ValidationError::builder()
                    .message(format!("Invalid tag format: {map:?}. Tags must only contain 'Key' and 'Value' fields"))
                    .build()
                    .into());
            }
        }
    }

    let Some(tag_key) = tag_key else {
        return Err(ValidationError::builder()
            .message(format!("Invalid tag format: {map:?}. Missing 'Key' field"))
            .build()
            .into());
    };

    let Some(tag_value) = tag_value else {
        return Err(ValidationError::builder()
            .message(format!("Invalid tag format: {map:?}. Missing 'Value' field"))
            .build()
            .into());
    };

    Ok(Tag {
        key: tag_key.to_string(),
        value: tag_value.to_string(),
    })
}
