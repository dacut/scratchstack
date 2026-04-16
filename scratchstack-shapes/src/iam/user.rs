use {
    super::{
        AttachedPermissionsBoundary, Tag, validate_account_id, validate_marker, validate_max_items, validate_path,
        validate_path_prefix, validate_policy_arn,
    },
    crate::Arn,
    anyhow::{Result as AnyResult, bail},
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    regex::Regex,
    serde::{Deserialize, Serialize},
    std::sync::LazyLock,
};

#[cfg(feature = "clap")]
use super::{
    clap_parse_account_id, clap_parse_marker, clap_parse_max_items, clap_parse_path, clap_parse_path_prefix,
    clap_parse_policy_arn, clap_parse_tags,
};

/// Validate that the given user name is valid according to AWS IAM rules.
pub fn validate_user_name(user_name: impl AsRef<str>) -> AnyResult<()> {
    // Regular expression for user names. Don't check the length here; it results in an overly large
    // regex.
    static USER_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\w+=,.@-]*$").unwrap());

    let user_name = user_name.as_ref();

    if !USER_NAME_REGEX.is_match(user_name) {
        bail!("User name contains invalid characters");
    }

    if user_name.chars().count() < 1 || user_name.chars().count() > 64 {
        bail!("User name must be between 1 and 64 characters long");
    }

    Ok(())
}

/// Parse and validate a `user_name` field for Clap.
#[cfg(feature = "clap")]
pub fn clap_parse_user_name(user_name: &str) -> Result<String, String> {
    validate_user_name(user_name).map_err(|e| format!("Invalid user name: {e}"))?;
    Ok(user_name.to_owned())
}

/// Parameters to create a new user.
///
/// ## References
/// * [AWS CreateUser API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html)
/// * [Archived](https://web.archive.org/web/20251201154605/https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html)
#[derive(Builder, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
#[builder(build_fn(validate = "CreateUserRequestBuilder::validate"), setter(into))]
pub struct CreateUserRequest {
    /// The user name to create. This is required and must be unique within the account
    /// (case-insensitive).
    #[cfg_attr(feature = "clap", arg(long, value_parser = clap_parse_user_name))]
    user_name: String,

    /// The path to create the user at. This is optional and defaults to a slash (`/`).
    ///
    /// Paths must start and end with a slash, and can contain any ASCII characters from 33 to 126.
    /// Paths must not contain consecutive slashes, and must be at most 512 characters long.
    #[builder(default = "/".to_string())]
    #[cfg_attr(feature = "clap", arg(long, default_value = "/", value_parser = clap_parse_path))]
    path: String,

    /// The permissions boundary to set for the user. This is optional and can be used to set a
    /// managed policy as the permissions boundary for the user. The permissions boundary must be a
    /// valid IAM policy ARN.
    #[builder(default)]
    #[cfg_attr(feature = "clap", arg(long, value_parser = clap_parse_policy_arn))]
    permissions_boundary: Option<Arn>,

    /// Tags to attach to the user. This is optional and can be used to attach any number of
    /// key-value pairs as tags to the user.
    #[builder(default)]
    #[cfg_attr(feature = "clap", arg(long, num_args = 1.., value_parser = clap_parse_tags))]
    tags: Vec<Tag>,
}

impl CreateUserRequest {
    /// Create a new [`CreateUserRequestBuilder`] for programmatically constructing a `CreateUserRequest`.
    #[inline(always)]
    pub fn builder() -> CreateUserRequestBuilder {
        CreateUserRequestBuilder::default()
    }

    /// Return the user_name field of this request.
    #[inline(always)]
    pub fn user_name(&self) -> &str {
        &self.user_name
    }

    /// Return the path field of this request.
    #[inline(always)]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Return the permissions_boundary field of this request.
    #[inline(always)]
    pub fn permissions_boundary(&self) -> Option<&Arn> {
        self.permissions_boundary.as_ref()
    }

    /// Return the tags field of this request.
    #[inline(always)]
    pub fn tags(&self) -> &[Tag] {
        &self.tags
    }
}

impl CreateUserRequestBuilder {
    fn validate(&self) -> Result<(), String> {
        let Some(user_name) = &self.user_name else {
            Err("UserName is required".to_string())?
        };

        let path = self.path.as_deref().unwrap_or("/");

        validate_user_name(user_name).map_err(|e| format!("Invalid user name: {e}"))?;
        validate_path(path).map_err(|e| format!("Invalid path: {e}"))?;
        if let Some(permissions_boundary_opt) = self.permissions_boundary.as_ref()
            && let Some(permissions_boundary) = permissions_boundary_opt.as_ref()
        {
            validate_policy_arn(permissions_boundary).map_err(|e| format!("Invalid permissions boundary: {e}"))?;
        }

        Ok(())
    }
}

/// Parameters to create a new user in a specific AWS account.
///
/// This is used internally in the Scratchstack database operations, and includes the `account_id`
/// field to specify which account to create the user in.
#[derive(Builder, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
#[builder(build_fn(validate = "CreateUserInternalRequestBuilder::validate"), setter(into))]
pub struct CreateUserInternalRequest {
    /// The user name to create. This is required and must be unique within the account
    /// (case-insensitive).
    #[cfg_attr(feature = "clap", arg(long, value_parser = clap_parse_user_name))]
    user_name: String,

    /// The path to create the user at. This is optional and defaults to a slash (`/`).
    ///
    /// Paths must start and end with a slash, and can contain any ASCII characters from 33 to 126.
    /// Paths must not contain consecutive slashes, and must be at most 512 characters long.
    #[builder(default = "/".to_string())]
    #[cfg_attr(feature = "clap", arg(long, default_value = "/", value_parser = clap_parse_path))]
    path: String,

    /// The permissions boundary to set for the user. This is optional and can be used to set a
    /// managed policy as the permissions boundary for the user. The permissions boundary must be a
    /// valid IAM policy ARN.
    #[builder(default)]
    #[cfg_attr(feature = "clap", arg(long, value_parser = clap_parse_policy_arn))]
    permissions_boundary: Option<Arn>,

    /// Tags to attach to the user. This is optional and can be used to attach any number of
    /// key-value pairs as tags to the user.
    #[builder(default)]
    #[cfg_attr(feature = "clap", arg(long, num_args = 1.., value_parser = clap_parse_tags))]
    tags: Vec<Tag>,

    /// The account id to create the user in. The account must already exist.
    #[cfg_attr(feature = "clap", arg(long, value_parser = clap_parse_account_id))]
    account_id: String,
}

impl CreateUserInternalRequest {
    /// Create a new [`CreateUserInternalRequestBuilder`] for programmatically constructing a `CreateUserInternalRequest`.
    #[inline(always)]
    pub fn builder() -> CreateUserInternalRequestBuilder {
        CreateUserInternalRequestBuilder::default()
    }

    /// Return the user_name field of this request.
    #[inline(always)]
    pub fn user_name(&self) -> &str {
        &self.user_name
    }

    /// Return the path field of this request.
    #[inline(always)]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Return the permissions_boundary field of this request.
    #[inline(always)]
    pub fn permissions_boundary(&self) -> Option<&Arn> {
        self.permissions_boundary.as_ref()
    }

    /// Return the tags field of this request.
    #[inline(always)]
    pub fn tags(&self) -> &[Tag] {
        &self.tags
    }

    /// Return the account_id field of this request.
    #[inline(always)]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
}

impl CreateUserInternalRequestBuilder {
    fn validate(&self) -> Result<(), String> {
        let Some(user_name) = &self.user_name else {
            Err("UserName is required".to_string())?
        };

        let path = self.path.as_deref().unwrap_or("/");

        let Some(account_id) = &self.account_id else {
            Err("AccountId is required".to_string())?
        };

        validate_user_name(user_name).map_err(|e| format!("Invalid user name: {e}"))?;
        validate_path(path).map_err(|e| format!("Invalid path: {e}"))?;
        if let Some(permissions_boundary_opt) = self.permissions_boundary.as_ref()
            && let Some(permissions_boundary) = permissions_boundary_opt.as_ref()
        {
            validate_policy_arn(permissions_boundary).map_err(|e| format!("Invalid permissions boundary: {e}"))?;
        }
        validate_account_id(account_id).map_err(|e| format!("Invalid account id: {e}"))?;

        Ok(())
    }
}

/// Result of creating a user, which is returned as JSON in the API response.
///
/// ## References
/// * [AWS CreateUser API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html)
/// * [Archived](https://web.archive.org/web/20251201154605/https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html)
#[derive(Builder, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct CreateUserResponse {
    /// The user that was created.
    user: User,
}

impl CreateUserResponse {
    /// Create a new [`CreateUserResponseBuilder`] for programmatically constructing a `CreateUserResponse`.
    #[inline(always)]
    pub fn builder() -> CreateUserResponseBuilder {
        CreateUserResponseBuilder::default()
    }

    /// Returns the user that was created.
    #[inline(always)]
    pub fn user(&self) -> &User {
        &self.user
    }
}

/// Parameters to list users in the AWS account.
///
/// ## References
/// * [AWS ListUsers API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html)
/// * [Archived](https://web.archive.org/web/20251208003306/https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html)
#[derive(Builder, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
#[builder(build_fn(validate = "ListUsersRequestBuilder::validate"), setter(into))]
pub struct ListUsersRequest {
    /// Marker for paginating results.
    #[cfg_attr(feature = "clap", arg(long, value_parser = clap_parse_marker))]
    marker: Option<String>,

    /// Maximum number of items to return. Valid range is 1-1000.
    #[cfg_attr(feature = "clap", arg(long, value_parser = clap_parse_max_items))]
    max_items: Option<usize>,

    /// Path prefix for filtering the results.
    #[cfg_attr(feature = "clap", arg(long, value_parser = clap_parse_path_prefix))]
    path_prefix: Option<String>,
}

impl ListUsersRequest {
    /// Create a new [`ListUsersRequestBuilder`] for programmatically constructing a `ListUsersRequest`.
    #[inline(always)]
    pub fn builder() -> ListUsersRequestBuilder {
        ListUsersRequestBuilder::default()
    }

    /// Return the marker field of this request.
    #[inline(always)]
    pub fn marker(&self) -> Option<&str> {
        self.marker.as_deref()
    }

    /// Return the max_items field of this request.
    #[inline(always)]
    pub fn max_items(&self) -> Option<usize> {
        self.max_items
    }

    /// Return the path_prefix field of this request.
    #[inline(always)]
    pub fn path_prefix(&self) -> Option<&str> {
        self.path_prefix.as_deref()
    }
}

impl ListUsersRequestBuilder {
    fn validate(&self) -> Result<(), String> {
        if let Some(marker_opt) = self.marker.as_ref()
            && let Some(marker) = marker_opt.as_ref()
        {
            validate_marker(marker).map_err(|e| format!("Invalid marker: {e}"))?;
        }

        if let Some(max_items_opt) = self.max_items
            && let Some(max_items) = max_items_opt
        {
            validate_max_items(max_items).map_err(|e| format!("Invalid max_items: {e}"))?;
        }

        if let Some(path_prefix_opt) = &self.path_prefix.as_ref()
            && let Some(path_prefix) = path_prefix_opt.as_ref()
        {
            validate_path_prefix(path_prefix).map_err(|e| format!("Invalid path_prefix: {e}"))?;
        }

        Ok(())
    }
}

/// Parameters to list users in a specific AWS account.
///
/// This is used internally in the Scratchstack database operations, and includes the `account_id`
/// field to specify which account to list the users in.
#[derive(Builder, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
#[builder(build_fn(validate = "ListUsersInternalRequestBuilder::validate"), setter(into))]
pub struct ListUsersInternalRequest {
    /// Marker for paginating results.
    #[cfg_attr(feature = "clap", arg(long, value_parser = clap_parse_marker))]
    marker: Option<String>,

    /// Maximum number of items to return. Valid range is 1-1000.
    #[cfg_attr(feature = "clap", arg(long, value_parser = clap_parse_max_items))]
    max_items: Option<usize>,

    /// Path prefix for filtering the results.
    #[cfg_attr(feature = "clap", arg(long, value_parser = clap_parse_path_prefix))]
    path_prefix: Option<String>,

    /// The account id to create the user in. The account must already exist.
    #[cfg_attr(feature = "clap", arg(long, value_parser = clap_parse_account_id))]
    account_id: String,
}

impl ListUsersInternalRequest {
    /// Create a new [`ListUsersInternalRequestBuilder`] for programmatically constructing a `ListUsersInternalRequest`.
    #[inline(always)]
    pub fn builder() -> ListUsersInternalRequestBuilder {
        ListUsersInternalRequestBuilder::default()
    }

    /// Return the marker field of this request.
    #[inline(always)]
    pub fn marker(&self) -> Option<&str> {
        self.marker.as_deref()
    }

    /// Return the max_items field of this request.
    #[inline(always)]
    pub fn max_items(&self) -> Option<usize> {
        self.max_items
    }

    /// Return the path_prefix field of this request.
    #[inline(always)]
    pub fn path_prefix(&self) -> Option<&str> {
        self.path_prefix.as_deref()
    }

    /// Return the account_id field of this request.
    #[inline(always)]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
}

impl ListUsersInternalRequestBuilder {
    fn validate(&self) -> Result<(), String> {
        if let Some(marker_opt) = self.marker.as_ref()
            && let Some(marker) = marker_opt.as_ref()
        {
            validate_marker(marker).map_err(|e| format!("Invalid marker: {e}"))?;
        }

        if let Some(max_items_opt) = self.max_items
            && let Some(max_items) = max_items_opt
        {
            validate_max_items(max_items).map_err(|e| format!("Invalid max_items: {e}"))?;
        }

        if let Some(path_prefix_opt) = &self.path_prefix.as_ref()
            && let Some(path_prefix) = path_prefix_opt.as_ref()
        {
            validate_path_prefix(path_prefix).map_err(|e| format!("Invalid path_prefix: {e}"))?;
        }

        if let Some(account_id) = self.account_id.as_ref() {
            validate_account_id(account_id).map_err(|e| format!("Invalid account id: {e}"))?;
        }

        Ok(())
    }
}

/// Result of listing users, which is returned as JSON in the API response.
///
/// ## References
/// * [AWS ListUsers API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html)
/// * [Archived](https://web.archive.org/web/20251208003306/https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html)
#[derive(Builder, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[builder(setter(into))]
pub struct ListUsersResponse {
    /// A flag that indicates whether there are more items to return.
    #[builder(default)]
    is_truncated: bool,

    /// When `IsTruncated` is `true`, this element is present and contains the value to use for the `Marker`
    /// parameter in a subsequent pagination request.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    marker: Option<String>,

    /// A list of users.
    users: Vec<User>,
}

impl ListUsersResponse {
    /// Create a new [`ListUsersResponseBuilder`] for programmatically constructing a `ListUsersResponse`.
    #[inline(always)]
    pub fn builder() -> ListUsersResponseBuilder {
        ListUsersResponseBuilder::default()
    }

    /// Returns whether there are more items to return.
    #[inline(always)]
    pub fn is_truncated(&self) -> bool {
        self.is_truncated
    }

    /// Returns the marker to use for pagination, if present.
    #[inline(always)]
    pub fn marker(&self) -> Option<&str> {
        self.marker.as_deref()
    }

    /// Returns the list of users.
    #[inline(always)]
    pub fn users(&self) -> &[User] {
        &self.users
    }
}

/// Information about an IAM user entity.
///
/// ## References
/// * [AWS User data type](https://docs.aws.amazon.com/IAM/latest/APIReference/API_User.html)
/// * [Archived](https://web.archive.org/web/20251124073340/https://docs.aws.amazon.com/IAM/latest/APIReference/API_User.html)
#[derive(Builder, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[builder(build_fn(validate = "UserBuilder::validate"), setter(into))]
pub struct User {
    /// The Amazon Resource Name (ARN) of the user.
    arn: Arn,

    /// The creation timestamp when the user was created.
    create_date: DateTime<Utc>,

    /// The path to the user.
    path: String,

    /// The unique identifier for the user.
    user_id: String,

    /// The name of the user.
    user_name: String,

    /// The timestamp when the user's password was last used.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    password_last_used: Option<DateTime<Utc>>,

    /// The permissions boundary that is set for the user.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    permissions_boundary: Option<AttachedPermissionsBoundary>,

    /// The tags that are attached to the user.
    #[builder(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<Tag>,
}

impl User {
    /// Create a new [`UserBuilder`] for programmatically constructing a `User`.
    #[inline(always)]
    pub fn builder() -> UserBuilder {
        UserBuilder::default()
    }

    /// Returns the ARN of this user.
    #[inline(always)]
    pub fn arn(&self) -> &Arn {
        &self.arn
    }

    /// Returns the creation timestamp of this user.
    #[inline(always)]
    pub fn create_date(&self) -> &DateTime<Utc> {
        &self.create_date
    }

    /// Returns the path of this user.
    #[inline(always)]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the unique identifier for this user.
    #[inline(always)]
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Returns the name of this user.
    #[inline(always)]
    pub fn user_name(&self) -> &str {
        &self.user_name
    }

    /// Returns the timestamp when the user's password was last used, if available.
    #[inline(always)]
    pub fn password_last_used(&self) -> Option<&DateTime<Utc>> {
        self.password_last_used.as_ref()
    }

    /// Returns the permissions boundary set for this user, if any.
    #[inline(always)]
    pub fn permissions_boundary(&self) -> Option<&AttachedPermissionsBoundary> {
        self.permissions_boundary.as_ref()
    }

    /// Returns the tags attached to this user.
    #[inline(always)]
    pub fn tags(&self) -> &[Tag] {
        &self.tags
    }
}

impl UserBuilder {
    fn validate(&self) -> Result<(), String> {
        let Some(path) = &self.path else {
            Err("Path is required".to_string())?
        };

        let Some(user_name) = &self.user_name else {
            Err("UserName is required".to_string())?
        };

        validate_path(path).map_err(|e| format!("Invalid path: {e}"))?;
        validate_user_name(user_name).map_err(|e| format!("Invalid user name: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    mod builder {
        use {
            crate::{
                Arn,
                iam::{CreateUserInternalRequest, CreateUserRequest, CreateUserResponse, User},
            },
            chrono::{DateTime, Utc},
            std::str::FromStr as _,
        };

        const TEST_ARN: &str = "arn:aws:iam::123456789012:user/alice";
        const TEST_USER_ID: &str = "AIDA000000000000ALICE";
        /// Unix timestamp 2025-01-01T00:00:00Z, used as a fixed create_date in tests.
        const TEST_CREATE_DATE_SECS: i64 = 1735689600;

        fn test_arn() -> Arn {
            Arn::from_str(TEST_ARN).unwrap()
        }

        fn test_create_date() -> DateTime<Utc> {
            DateTime::from_timestamp(TEST_CREATE_DATE_SECS, 0).unwrap()
        }

        /// Construct a valid [`User`] with fixed field values for use in tests.
        fn valid_user() -> User {
            User::builder()
                .arn(test_arn())
                .create_date(test_create_date())
                .path("/".to_string())
                .user_id(TEST_USER_ID.to_string())
                .user_name("alice".to_string())
                .build()
                .unwrap()
        }

        // ── UserBuilder ──────────────────────────────────────────────────────

        #[test_log::test]
        fn user_builder_valid() {
            let user = valid_user();
            assert_eq!(user.arn(), &test_arn());
            assert_eq!(user.create_date(), &test_create_date());
            assert_eq!(user.user_id(), TEST_USER_ID);
            assert_eq!(user.user_name(), "alice");
            assert_eq!(user.path(), "/");
            assert!(user.password_last_used().is_none());
            assert!(user.permissions_boundary().is_none());
            assert!(user.tags().is_empty());
        }

        #[test_log::test]
        fn user_builder_missing_arn() {
            assert!(
                User::builder()
                    .create_date(test_create_date())
                    .path("/".to_string())
                    .user_id(TEST_USER_ID.to_string())
                    .user_name("alice".to_string())
                    .build()
                    .is_err()
            );
        }

        #[test_log::test]
        fn user_builder_missing_create_date() {
            assert!(
                User::builder()
                    .arn(test_arn())
                    .path("/".to_string())
                    .user_id(TEST_USER_ID.to_string())
                    .user_name("alice".to_string())
                    .build()
                    .is_err()
            );
        }

        #[test_log::test]
        fn user_builder_missing_path() {
            assert!(
                User::builder()
                    .arn(test_arn())
                    .create_date(test_create_date())
                    .user_id(TEST_USER_ID.to_string())
                    .user_name("alice".to_string())
                    .build()
                    .is_err()
            );
        }

        #[test_log::test]
        fn user_builder_missing_user_id() {
            assert!(
                User::builder()
                    .arn(test_arn())
                    .create_date(test_create_date())
                    .path("/".to_string())
                    .user_name("alice".to_string())
                    .build()
                    .is_err()
            );
        }

        #[test_log::test]
        fn user_builder_missing_user_name() {
            assert!(
                User::builder()
                    .arn(test_arn())
                    .create_date(test_create_date())
                    .path("/".to_string())
                    .user_id(TEST_USER_ID.to_string())
                    .build()
                    .is_err()
            );
        }

        #[test_log::test]
        fn user_builder_invalid_path() {
            assert!(
                User::builder()
                    .arn(test_arn())
                    .create_date(test_create_date())
                    .path("no-slashes".to_string())
                    .user_id(TEST_USER_ID.to_string())
                    .user_name("alice".to_string())
                    .build()
                    .is_err()
            );
        }

        #[test_log::test]
        fn user_builder_invalid_user_name() {
            assert!(
                User::builder()
                    .arn(test_arn())
                    .create_date(test_create_date())
                    .path("/".to_string())
                    .user_id(TEST_USER_ID.to_string())
                    .user_name("bad name!".to_string())
                    .build()
                    .is_err()
            );
        }

        // ── CreateUserRequestBuilder ─────────────────────────────────────────

        #[test_log::test]
        fn create_user_request_builder_valid() {
            let req =
                CreateUserRequest::builder().user_name("alice".to_string()).path("/".to_string()).build().unwrap();
            assert_eq!(req.user_name(), "alice");
            assert_eq!(req.path(), "/");
            assert!(req.permissions_boundary().is_none());
            assert!(req.tags().is_empty());
        }

        #[test_log::test]
        fn create_user_request_builder_missing_user_name() {
            assert!(CreateUserRequest::builder().path("/".to_string()).build().is_err());
        }

        #[test_log::test]
        fn create_user_request_builder_default_path() {
            let req = CreateUserRequest::builder().user_name("alice".to_string()).build().unwrap();
            assert_eq!(req.path(), "/");
        }

        #[test_log::test]
        fn create_user_request_builder_invalid_user_name() {
            assert!(
                CreateUserRequest::builder().user_name("bad name!".to_string()).path("/".to_string()).build().is_err()
            );
        }

        #[test_log::test]
        fn create_user_request_builder_user_name_too_long() {
            assert!(CreateUserRequest::builder().user_name("a".repeat(65)).path("/".to_string()).build().is_err());
        }

        #[test_log::test]
        fn create_user_request_builder_invalid_path() {
            assert!(
                CreateUserRequest::builder()
                    .user_name("alice".to_string())
                    .path("no-slashes".to_string())
                    .build()
                    .is_err()
            );
        }

        #[test_log::test]
        fn create_user_request_builder_invalid_permissions_boundary() {
            assert!(
                CreateUserRequest::builder()
                    .user_name("alice".to_string())
                    .path("/".to_string())
                    .permissions_boundary(Arn::from_str("arn:aws:iam::123456789012:user/Alice").unwrap())
                    .build()
                    .is_err()
            );
        }

        // ── CreateUserRequestInternalBuilder ────────────────────────────────

        #[test_log::test]
        fn create_user_request_internal_builder_valid() {
            let req = CreateUserInternalRequest::builder()
                .user_name("bob".to_string())
                .account_id("123456789012".to_string())
                .build()
                .unwrap();
            assert_eq!(req.user_name(), "bob");
            assert_eq!(req.path(), "/");
            assert_eq!(req.account_id(), "123456789012");
            assert!(req.permissions_boundary().is_none());
            assert!(req.tags().is_empty());
        }

        #[test_log::test]
        fn create_user_request_internal_builder_missing_user_name() {
            assert!(CreateUserInternalRequest::builder().account_id("123456789012".to_string()).build().is_err());
        }

        #[test_log::test]
        fn create_user_request_internal_builder_missing_account_id() {
            assert!(CreateUserInternalRequest::builder().user_name("bob".to_string()).build().is_err());
        }

        #[test_log::test]
        fn create_user_request_internal_builder_invalid_user_name() {
            assert!(
                CreateUserInternalRequest::builder()
                    .user_name("bad name!".to_string())
                    .account_id("123456789012".to_string())
                    .build()
                    .is_err()
            );
        }

        #[test_log::test]
        fn create_user_request_internal_builder_invalid_path() {
            assert!(
                CreateUserInternalRequest::builder()
                    .user_name("bob".to_string())
                    .path("no-slashes".to_string())
                    .account_id("123456789012".to_string())
                    .build()
                    .is_err()
            );
        }

        #[test_log::test]
        fn create_user_request_internal_builder_invalid_account_id() {
            assert!(
                CreateUserInternalRequest::builder()
                    .user_name("bob".to_string())
                    .account_id("not-an-account".to_string())
                    .build()
                    .is_err()
            );
        }

        #[test_log::test]
        fn create_user_request_internal_builder_invalid_permissions_boundary() {
            assert!(
                CreateUserInternalRequest::builder()
                    .user_name("bob".to_string())
                    .account_id("123456789012".to_string())
                    .permissions_boundary(Arn::from_str("arn:aws:iam::123456789012:user/Alice").unwrap())
                    .build()
                    .is_err()
            );
        }

        // ── CreateUserResponseBuilder ────────────────────────────────────────

        #[test_log::test]
        fn create_user_response_builder_valid() {
            let resp = CreateUserResponse::builder().user(valid_user()).build().unwrap();
            assert_eq!(resp.user().user_name(), "alice");
        }

        #[test_log::test]
        fn create_user_response_builder_missing_user() {
            assert!(CreateUserResponse::builder().build().is_err());
        }
    }

    #[cfg(feature = "clap")]
    mod clap_parsing {
        use {
            crate::iam::{CreateUserInternalRequest, CreateUserRequest},
            clap::Parser,
            pretty_assertions::assert_eq,
        };

        /// Thin wrapper so `CreateUserRequest` can be used as a top-level clap command in tests.
        #[derive(Parser)]
        struct CreateUserCmd {
            #[command(flatten)]
            req: CreateUserRequest,
        }

        /// Thin wrapper so `CreateUserRequestInternal` can be used as a top-level clap command in tests.
        #[derive(Parser)]
        struct CreateUserInternalCmd {
            #[command(flatten)]
            req: CreateUserInternalRequest,
        }

        // ── CreateUserRequest: missing validation (these tests currently fail) ─

        /// `CreateUserRequest` has no `value_parser` on `--user-name`, so clap accepts names
        /// containing invalid characters. This test documents the missing validation.
        #[test_log::test]
        fn create_user_request_invalid_user_name_chars_rejected() {
            assert!(CreateUserCmd::try_parse_from(["cmd", "--user-name", "bad name!",]).is_err());
        }

        /// `CreateUserRequest` has no `value_parser` on `--user-name`, so clap accepts names
        /// that are too long. This test documents the missing validation.
        #[test_log::test]
        fn create_user_request_invalid_user_name_too_long_rejected() {
            assert!(CreateUserCmd::try_parse_from(["cmd", "--user-name", &"a".repeat(65),]).is_err());
        }

        /// `CreateUserRequest` has no `value_parser` on `--path`, so clap accepts paths that
        /// don't start and end with a slash. This test documents the missing validation.
        #[test_log::test]
        fn create_user_request_invalid_path_no_leading_slash_rejected() {
            assert!(CreateUserCmd::try_parse_from(["cmd", "--user-name", "alice", "--path", "noslashes",]).is_err());
        }

        /// `CreateUserRequest` has no `value_parser` on `--path`, so clap accepts paths that
        /// are missing a trailing slash. This test documents the missing validation.
        #[test_log::test]
        fn create_user_request_invalid_path_no_trailing_slash_rejected() {
            assert!(CreateUserCmd::try_parse_from(["cmd", "--user-name", "alice", "--path", "/no-trailing",]).is_err());
        }

        /// `CreateUserRequest` has no `value_parser` on `--permissions-boundary`, so clap
        /// accepts ARNs that are syntactically valid but not policy ARNs. This test documents
        /// the missing validation.
        #[test_log::test]
        fn create_user_request_permissions_boundary_not_policy_rejected() {
            assert!(
                CreateUserCmd::try_parse_from([
                    "cmd",
                    "--user-name",
                    "alice",
                    "--permissions-boundary",
                    "arn:aws:iam::123456789012:user/Alice",
                ])
                .is_err()
            );
        }

        // ── CreateUserRequest ────────────────────────────────────────────────

        #[test_log::test]
        fn create_user_request_minimal() {
            let cmd = CreateUserCmd::try_parse_from(["cmd", "--user-name", "alice"]).unwrap();
            assert_eq!(cmd.req.user_name(), "alice");
            assert_eq!(cmd.req.path(), "/");
            assert!(cmd.req.permissions_boundary().is_none());
            assert!(cmd.req.tags().is_empty());
        }

        #[test_log::test]
        fn create_user_request_with_path() {
            let cmd = CreateUserCmd::try_parse_from(["cmd", "--user-name", "alice", "--path", "/eng/"]).unwrap();
            assert_eq!(cmd.req.path(), "/eng/");
        }

        #[test_log::test]
        fn create_user_request_with_permissions_boundary() {
            let cmd = CreateUserCmd::try_parse_from([
                "cmd",
                "--user-name",
                "alice",
                "--permissions-boundary",
                "arn:aws:iam::123456789012:policy/MyPolicy",
            ])
            .unwrap();
            assert!(cmd.req.permissions_boundary().is_some());
        }

        /// `CreateUserRequest` has no value_parser on permissions_boundary, so clap rejects
        /// syntactically invalid ARNs via `Arn::from_str`.
        #[test_log::test]
        fn create_user_request_invalid_permissions_boundary_syntax() {
            assert!(
                CreateUserCmd::try_parse_from(["cmd", "--user-name", "alice", "--permissions-boundary", "not-an-arn",])
                    .is_err()
            );
        }

        #[test_log::test]
        fn create_user_request_with_single_tag() {
            let cmd =
                CreateUserCmd::try_parse_from(["cmd", "--user-name", "alice", "--tags", "Key=env,Value=prod"]).unwrap();
            assert_eq!(cmd.req.tags().len(), 1);
            assert_eq!(cmd.req.tags()[0].key(), "env");
            assert_eq!(cmd.req.tags()[0].value(), "prod");
        }

        #[test_log::test]
        fn create_user_request_with_multiple_tags() {
            let cmd = CreateUserCmd::try_parse_from([
                "cmd",
                "--user-name",
                "alice",
                "--tags",
                "Key=env,Value=prod",
                "Key=team,Value=eng",
            ])
            .unwrap();
            assert_eq!(cmd.req.tags().len(), 2);
        }

        #[test_log::test]
        fn create_user_request_invalid_tag_emoji_key() {
            assert!(
                CreateUserCmd::try_parse_from(["cmd", "--user-name", "alice", "--tags", "Key=😀,Value=bar",]).is_err()
            );
        }

        #[test_log::test]
        fn create_user_request_invalid_tag_emoji_value() {
            assert!(
                CreateUserCmd::try_parse_from(["cmd", "--user-name", "alice", "--tags", "Key=env,Value=😀",]).is_err()
            );
        }

        // ── CreateUserRequestInternal ────────────────────────────────────────

        #[test_log::test]
        fn create_user_request_internal_minimal() {
            let cmd =
                CreateUserInternalCmd::try_parse_from(["cmd", "--user-name", "bob", "--account-id", "123456789012"])
                    .unwrap();
            assert_eq!(cmd.req.user_name(), "bob");
            assert_eq!(cmd.req.path(), "/");
            assert_eq!(cmd.req.account_id(), "123456789012");
            assert!(cmd.req.permissions_boundary().is_none());
            assert!(cmd.req.tags().is_empty());
        }

        #[test_log::test]
        fn create_user_request_internal_with_path() {
            let cmd = CreateUserInternalCmd::try_parse_from([
                "cmd",
                "--user-name",
                "bob",
                "--account-id",
                "123456789012",
                "--path",
                "/ops/",
            ])
            .unwrap();
            assert_eq!(cmd.req.path(), "/ops/");
        }

        #[test_log::test]
        fn create_user_request_internal_invalid_user_name_chars() {
            assert!(
                CreateUserInternalCmd::try_parse_from([
                    "cmd",
                    "--user-name",
                    "bad name!",
                    "--account-id",
                    "123456789012",
                ])
                .is_err()
            );
        }

        #[test_log::test]
        fn create_user_request_internal_invalid_user_name_too_long() {
            assert!(
                CreateUserInternalCmd::try_parse_from([
                    "cmd",
                    "--user-name",
                    &"a".repeat(65),
                    "--account-id",
                    "123456789012",
                ])
                .is_err()
            );
        }

        #[test_log::test]
        fn create_user_request_internal_invalid_path_no_leading_slash() {
            assert!(
                CreateUserInternalCmd::try_parse_from([
                    "cmd",
                    "--user-name",
                    "bob",
                    "--account-id",
                    "123456789012",
                    "--path",
                    "noslashes",
                ])
                .is_err()
            );
        }

        #[test_log::test]
        fn create_user_request_internal_invalid_path_no_trailing_slash() {
            assert!(
                CreateUserInternalCmd::try_parse_from([
                    "cmd",
                    "--user-name",
                    "bob",
                    "--account-id",
                    "123456789012",
                    "--path",
                    "/no-trailing",
                ])
                .is_err()
            );
        }

        #[test_log::test]
        fn create_user_request_internal_invalid_account_id_non_numeric() {
            assert!(
                CreateUserInternalCmd::try_parse_from(["cmd", "--user-name", "bob", "--account-id", "not-an-account",])
                    .is_err()
            );
        }

        #[test_log::test]
        fn create_user_request_internal_invalid_account_id_too_short() {
            assert!(
                CreateUserInternalCmd::try_parse_from(["cmd", "--user-name", "bob", "--account-id", "12345",]).is_err()
            );
        }

        #[test_log::test]
        fn create_user_request_internal_invalid_permissions_boundary_syntax() {
            assert!(
                CreateUserInternalCmd::try_parse_from([
                    "cmd",
                    "--user-name",
                    "bob",
                    "--account-id",
                    "123456789012",
                    "--permissions-boundary",
                    "not-an-arn",
                ])
                .is_err()
            );
        }

        /// `CreateUserRequestInternal` rejects ARNs that are syntactically valid but not policy ARNs.
        #[test_log::test]
        fn create_user_request_internal_invalid_permissions_boundary_not_policy() {
            assert!(
                CreateUserInternalCmd::try_parse_from([
                    "cmd",
                    "--user-name",
                    "bob",
                    "--account-id",
                    "123456789012",
                    "--permissions-boundary",
                    "arn:aws:iam::123456789012:user/Alice",
                ])
                .is_err()
            );
        }

        #[test_log::test]
        fn create_user_request_internal_with_permissions_boundary() {
            let cmd = CreateUserInternalCmd::try_parse_from([
                "cmd",
                "--user-name",
                "bob",
                "--account-id",
                "123456789012",
                "--permissions-boundary",
                "arn:aws:iam::123456789012:policy/MyPolicy",
            ])
            .unwrap();
            assert!(cmd.req.permissions_boundary().is_some());
        }

        #[test_log::test]
        fn create_user_request_internal_invalid_tag_emoji_key() {
            assert!(
                CreateUserInternalCmd::try_parse_from([
                    "cmd",
                    "--user-name",
                    "bob",
                    "--account-id",
                    "123456789012",
                    "--tags",
                    "Key=😀,Value=bar",
                ])
                .is_err()
            );
        }

        #[test_log::test]
        fn create_user_request_internal_invalid_tag_emoji_value() {
            assert!(
                CreateUserInternalCmd::try_parse_from([
                    "cmd",
                    "--user-name",
                    "bob",
                    "--account-id",
                    "123456789012",
                    "--tags",
                    "Key=env,Value=😀",
                ])
                .is_err()
            );
        }

        #[test_log::test]
        fn create_user_request_internal_with_tags() {
            let cmd = CreateUserInternalCmd::try_parse_from([
                "cmd",
                "--user-name",
                "bob",
                "--account-id",
                "123456789012",
                "--tags",
                "Key=env,Value=prod",
            ])
            .unwrap();
            assert_eq!(cmd.req.tags().len(), 1);
            assert_eq!(cmd.req.tags()[0].key(), "env");
            assert_eq!(cmd.req.tags()[0].value(), "prod");
        }
    }
}
