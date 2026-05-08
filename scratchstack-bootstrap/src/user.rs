//! Scratchstack bootsrap create-user subcommand
use {
    crate::{Cli, Runnable},
    anyhow::{Result as AnyResult, anyhow, bail},
    clap::Parser,
    scratchstack_cli_utils::{ShorthandValue, parse_shorthand},
    scratchstack_database::ops::RequestExecutor,
    scratchstack_shapes_iam::{
        operation::{
            CreateUserInternalRequest, CreateUserResponse, ListUsersInternalRequest, ListUsersResponse,
            UpdateUserInternalRequest,
        },
        types::Tag,
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

    async fn run<I>(&self, args: &Cli, vars: I) -> AnyResult<Self::Result>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let mut builder = CreateUserInternalRequest::builder()
            .account_id(self.account_id.clone())
            .path(self.path.clone())
            .user_name(self.user_name.clone())
            .permissions_boundary(self.permissions_boundary.clone());
        let mut tags = Vec::with_capacity(self.tags.len());

        for tag in &self.tags {
            match parse_shorthand(tag)? {
                ShorthandValue::List(values) => {
                    for value in values {
                        let ShorthandValue::Map(map) = value else {
                            bail!(
                                "Invalid tag format: {tag}. Tags must be in the format 'Key=k,Value=v' or a JSON object with 'Key' and 'Value' fields"
                            );
                        };
                        tags = tags_from_shorthand(&map)?;
                    }
                }
                ShorthandValue::Map(value) => {
                    tags.extend(tags_from_shorthand(&value)?);
                }
                _ => bail!(
                    "Invalid tag format: {tag}. Tags must be in the format 'Key=k,Value=v' or a JSON object with 'Key' and 'Value' fields"
                ),
            }
        }

        builder = builder.tags(tags);

        let request = builder.build()?;
        request.run(args, vars).await
    }
}

impl Runnable for CreateUserInternalRequest {
    type Result = CreateUserResponse;

    async fn run<I>(&self, args: &Cli, vars: I) -> AnyResult<Self::Result>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let conn = args.connect(vars).await?;
        let mut tx = conn.begin().await?;
        let response = self.execute(&mut tx).await?;
        tx.commit().await?;

        Ok(response)
    }
}

impl Runnable for ListUsersInternalCommand {
    type Result = ListUsersResponse;

    async fn run<I>(&self, args: &Cli, vars: I) -> AnyResult<Self::Result>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = ListUsersInternalRequest {
            account_id: self.account_id.clone(),
            path_prefix: self.path_prefix.clone(),
            max_items: self.max_items,
            marker: self.marker.clone(),
        };
        request.run(args, vars).await
    }
}

impl Runnable for ListUsersInternalRequest {
    type Result = ListUsersResponse;

    async fn run<I>(&self, args: &Cli, vars: I) -> AnyResult<Self::Result>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let conn = args.connect(vars).await?;
        let mut tx = conn.begin().await?;
        let response = self.execute(&mut tx).await?;
        tx.commit().await?;

        Ok(response)
    }
}

impl Runnable for UpdateUserInternalCommand {
    type Result = ();

    async fn run<I>(&self, args: &Cli, vars: I) -> AnyResult<Self::Result>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let request = UpdateUserInternalRequest {
            account_id: self.account_id.clone(),
            user_name: self.user_name.clone(),
            new_path: self.new_path.clone(),
            new_user_name: self.new_user_name.clone(),
        };
        request.run(args, vars).await
    }
}

impl Runnable for UpdateUserInternalRequest {
    type Result = ();

    async fn run<I>(&self, args: &Cli, vars: I) -> AnyResult<Self::Result>
    where
        I: IntoIterator<Item = (OsString, String)> + Clone + Send,
    {
        let conn = args.connect(vars).await?;
        let mut tx = conn.begin().await?;
        self.execute(&mut tx).await?;
        tx.commit().await?;

        Ok(())
    }
}

fn tags_from_shorthand(map: &HashMap<String, ShorthandValue>) -> AnyResult<Vec<Tag>> {
    let mut result = Vec::new();
    for (key, value) in map {
        let key = match key.as_str() {
            "Key" => value.as_str().ok_or_else(|| anyhow!("Invalid tag format: {map:?}. 'Key' must be a string"))?,
            "Value" => {
                value.as_str().ok_or_else(|| anyhow!("Invalid tag format: {map:?}. 'Value' must be a string"))?
            }
            _ => bail!("Invalid tag format: {map:?}. Tags must only contain 'Key' and 'Value' fields"),
        };
        let value = value.as_str().ok_or_else(|| anyhow!("Invalid tag format: {map:?}. 'Value' must be a string"))?;
        result.push(Tag {
            key: key.to_string(),
            value: value.to_string(),
        });
    }
    Ok(result)
}
