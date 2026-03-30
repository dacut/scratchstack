//! Identity and Access Management (IAM) API shapes.
//!
use serde::{Deserialize, Serialize};

/// Information about an attached permissions boundary.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct AttachedPermissionsBoundary {
    /// The ARN of the policy used to set the permissions boundary.
    pub permissions_boundary_arn: String,

    /// The type of IAM resource defining the permissions boundary. This is always `Policy` currently.
    pub permissions_boundary_type: String,
}

/// Parameters to create a new user on the Scratchstack IAM database.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct CreateUserRequest {
    /// The user name to create. This is required and must be unique within the account
    /// (case-insensitive).
    #[cfg_attr(feature = "clap", arg(long))]
    pub user_name: String,

    /// The path to create the user at. This is optional and defaults to a slash (`/`).
    ///
    /// Paths must start and end with a slash, and can contain any ASCII characters from 33 to 126.
    /// Paths must not contain consecutive slashes, and must be at most 512 characters long.
    #[cfg_attr(feature = "clap", arg(long, default_value = "/"))]
    pub path: String,

    /// The permissions boundary to set for the user. This is optional and can be used to set a
    /// managed policy as the permissions boundary for the user. The permissions boundary must be a
    /// valid IAM policy ARN.
    #[cfg_attr(feature = "clap", arg(long))]
    pub permissions_boundary: Option<String>,

    /// The tags to attach to the user. This is optional and can be used to attach any number of
    /// key-value pairs as tags to the user.
    #[cfg_attr(feature = "clap", arg(long))]
    pub tags: Vec<Tag>,
}

/// Result of creating a user, which is returned as JSON in the API response.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct CreateUserResponse {
    /// The user that was created.
    pub user: User,
}

/// User-provided metadata associated with an IAM resource.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct Tag {
    /// The key used to identify or look up the tag.
    pub key: String,

    /// The value associated with this tag.
    pub value: String,
}

/// Parse a single `Tag` from either AWS shorthand or a JSON object.
///
/// This allows `Vec<Tag>` to be specified on a CLI using Clap as either shorthand in the form
/// `--tags Key=Foo,Value=Bar` or as a JSON object in the form
/// `--tags '[{"Key":"Foo","Value":"Bar"},{"Key":"Hello","Value":"World"}]'`.
#[cfg(feature = "clap")]
impl std::str::FromStr for Tag {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.starts_with('{') {
            // JSON object: {"Key":"...","Value":"..."}
            serde_json::from_str(s).map_err(|e| format!("Invalid JSON tag object: {e}"))
        } else {
            // Shorthand: Key=name,Value=value
            parse_tag_shorthand(s)
        }
    }
}

/// Parse the shared shorthand logic used by both [`Tag`]'s and [`TagInput`]'s `FromStr`.
#[cfg(feature = "clap")]
fn parse_tag_shorthand(s: &str) -> Result<Tag, String> {
    let value = crate::shorthand::parse(s).map_err(|e| format!("Invalid shorthand tag syntax: {e}"))?;
    let map = value.as_map().ok_or("Expected shorthand key=value pairs")?;
    let get = |field: &str| -> Result<String, String> {
        map.iter()
            .find(|(k, _)| k == field)
            .and_then(|(_, v)| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("Missing '{field}' in tag shorthand (expected Key=...,Value=...)"))
    };
    Ok(Tag {
        key: get("Key")?,
        value: get("Value")?,
    })
}

/// Parse a single `Tag` from either AWS shorthand or a JSON object.
///
/// This allows `Vec<Tag>` to be specified on a CLI using Clap as either shorthand in the form
/// `--tags Key=Foo,Value=Bar` or as a JSON object in the form
/// `--tags '[{"Key":"Foo","Value":"Bar"},{"Key":"Hello","Value":"World"}]'`.
#[cfg(feature = "clap")]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum TagInput {
    Single(Tag),
    Array(Vec<Tag>),
}

#[cfg(feature = "clap")]
impl TagInput {
    /// Consume this input and return the contained tags as a flat `Vec<Tag>`.
    pub fn into_tags(self) -> Vec<Tag> {
        match self {
            TagInput::Single(tag) => vec![tag],
            TagInput::Array(tags) => tags,
        }
    }
}

#[cfg(feature = "clap")]
impl std::str::FromStr for TagInput {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.starts_with('[') {
            // JSON array: [{"Key":"...","Value":"..."}, ...]
            serde_json::from_str(s).map(TagInput::Array).map_err(|e| format!("Invalid JSON tag array: {e}"))
        } else {
            // Shorthand: Key=name,Value=value
            Tag::from_str(s).map(TagInput::Single).map_err(|e| format!("Invalid shorthand tag syntax: {e}"))
        }
    }
}

/// Information about an IAM user entity
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct User {
    /// The Amazon Resource Name (ARN) of the user.
    pub arn: String,

    /// The creation timestamp when the user was created, in ISO 8601 date-time format.
    pub create_date: String,

    /// The path to the user.
    pub path: String,

    /// The unique identifier for the user.
    pub user_id: String,

    /// The name of the user.
    pub user_name: String,

    /// The timestamp when the user's password was last used, in ISO 8601 date-time format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_last_used: Option<String>,

    /// The permissions boundary that is set for the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions_boundary: Option<AttachedPermissionsBoundary>,

    /// The tags that are attached to the user.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<Tag>,
}
