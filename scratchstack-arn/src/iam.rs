//! IAM-related ARN types and validators, available with the `iam` feature (enabled by default).
use {
    crate::{Arn, ArnError},
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

/// The service component for IAM ARNs.
pub(crate) const SERVICE_KEY_IAM: &str = "iam";

/// An IAM resource ARN, split into its resource type, path, and name.
///
/// The resource component of an IAM ARN has the form `type/path/name`. The path runs from the first slash through the
/// last, so it always both begins and ends with one and is never empty: a resource with no path segments has a path
/// of `/`, matching how AWS reports one. The name is never empty either.
///
/// For example, `arn:aws:iam::123456789012:role/engineering/admins/Deployer` has resource type `role`, path
/// `/engineering/admins/`, and name `Deployer`, while `arn:aws:iam::123456789012:role/Deployer` has path `/`.
///
/// Build one from an existing [`Arn`] with [`TryFrom`], or parse one directly with [`FromStr`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IamResourceArn {
    /// The base ARN for this resource.
    arn: Arn,

    /// The start of the path component of the resource, including the leading slash.
    resource_path_start: usize,

    /// The start of the resource name component of the resource.
    resource_name_start: usize,
}

impl Display for IamResourceArn {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.arn, f)
    }
}

impl FromStr for IamResourceArn {
    type Err = ArnError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let arn = Arn::from_str(s)?;
        Self::try_from(arn)
    }
}

impl TryFrom<Arn> for IamResourceArn {
    type Error = ArnError;

    fn try_from(arn: Arn) -> Result<Self, Self::Error> {
        if arn.service() != SERVICE_KEY_IAM {
            return Err(ArnError::InvalidService(arn.service().to_string()));
        }

        let resource = arn.resource();
        let path_start = resource.find('/').ok_or_else(|| ArnError::InvalidResource(resource.to_string()))?;
        let name_start = resource.rfind('/').ok_or_else(|| ArnError::InvalidResource(resource.to_string()))? + 1;
        if name_start >= resource.len() {
            return Err(ArnError::InvalidResource(resource.to_string()));
        }

        validate_iam_path(&resource[path_start..name_start])?;
        validate_iam_resource_name(&resource[name_start..])?;

        Ok(IamResourceArn {
            arn,
            resource_path_start: path_start,
            resource_name_start: name_start,
        })
    }
}

impl IamResourceArn {
    /// Parse a string into an [`IamResourceArn`], requiring the resource type to be `expected_resource_type`.
    ///
    /// * `arn_str` - The ARN to parse, e.g. `arn:aws:iam::123456789012:role/engineering/Deployer`.
    /// * `expected_resource_type` - The resource type the ARN must carry, e.g. `role` or `policy`.
    ///
    /// # Errors
    ///
    /// * If `arn_str` is not a well-formed ARN, the corresponding [`ArnError`] from [`Arn::from_str`] is returned.
    /// * If the service is not `iam`, [`ArnError::InvalidService`] is returned.
    /// * If the resource does not have the form `type/path/name`, or the resource type does not match
    ///   `expected_resource_type`, [`ArnError::InvalidResource`] is returned.
    /// * If the path or name are malformed, [`ArnError::InvalidIamResourcePath`] or
    ///   [`ArnError::InvalidIamResourceName`] is returned.
    pub fn expect_resource_type(arn_str: impl AsRef<str>, expected_resource_type: &str) -> Result<Self, ArnError> {
        let arn = Arn::from_str(arn_str.as_ref())?;
        let iam_arn = Self::try_from(arn)?;
        if iam_arn.resource_type() != expected_resource_type {
            return Err(ArnError::InvalidResource(iam_arn.arn.resource().to_string()));
        }
        Ok(iam_arn)
    }

    /// Returns the partition the resource is in.
    #[inline(always)]
    pub fn partition(&self) -> &str {
        self.arn.partition()
    }

    /// Returns the service the resource belongs to.
    #[inline(always)]
    pub fn service(&self) -> &str {
        self.arn.service()
    }

    /// Returns the region the resource is in.
    #[inline(always)]
    pub fn region(&self) -> &str {
        self.arn.region()
    }

    /// Returns the account ID the resource belongs to.
    #[inline(always)]
    pub fn account_id(&self) -> &str {
        self.arn.account_id()
    }

    /// Returns the resource name.
    #[inline(always)]
    pub fn resource(&self) -> &str {
        self.arn.resource()
    }

    /// Returns the resource type.
    #[inline(always)]
    pub fn resource_type(&self) -> &str {
        &self.arn.resource()[..self.resource_path_start]
    }

    /// Returns the path component of this ARN, including the leading and trailing slashes.
    ///
    /// This is never empty; a resource with no path segments, such as `role/Deployer`, has a path of `/`.
    #[inline(always)]
    pub fn resource_path(&self) -> &str {
        &self.arn.resource()[self.resource_path_start..self.resource_name_start]
    }

    /// Returns the resource name component of this ARN.
    #[inline(always)]
    pub fn resource_name(&self) -> &str {
        &self.arn.resource()[self.resource_name_start..]
    }

    /// Returns a lowercase version of the resource name, for case-insensitive comparisons.
    #[inline(always)]
    pub fn resource_name_lower(&self) -> String {
        self.resource_name().to_ascii_lowercase()
    }
}

/// Validate that a resource path is valid according to AWS IAM rules.
///
/// Paths must be between 1 and 512 characters long, end with a slash (`/`), and contain only printable ASCII
/// characters other than space (character codes 33 through 126).
///
/// AWS additionally requires paths to *begin* with a slash; that is not checked here, because callers such as
/// [`IamResourceArn`] slice the path out of an ARN starting at the first slash and so always satisfy it.
///
/// # Errors
///
/// Returns [`ArnError::InvalidResource`] if `path` does not meet the requirements above.
///
/// ## References
/// * [AWS CreateGroup](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateGroup.html)
/// * [AWS CreatePolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicy.html)
/// * [AWS CreateRole](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html)
/// * [AWS CreateUser](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html)
#[inline(always)]
pub fn validate_iam_path(path: impl AsRef<str>) -> Result<(), ArnError> {
    validate_iam_path_inner(path.as_ref())
}

fn validate_iam_path_inner(path: &str) -> Result<(), ArnError> {
    if path.is_empty() || path.len() > 512 {
        return Err(ArnError::InvalidResource(path.to_string()));
    }

    let mut last_was_slash = false;

    for c in path.chars() {
        if c < '\x21' || c > '\x7e' {
            return Err(ArnError::InvalidResource(path.to_string()));
        }

        last_was_slash = c == '/';
    }

    if !last_was_slash {
        return Err(ArnError::InvalidResource(path.to_string()));
    }

    Ok(())
}

/// Validate that a path prefix — a path used to filter IAM resources, such as the `PathPrefix` parameter of the AWS
/// `ListRoles` API — is valid.
///
/// The rules are those of [`validate_iam_path`], except that the prefix need not end with a slash: it must be between
/// 1 and 512 characters long and contain only printable ASCII characters other than space (character codes 33 through
/// 126).
///
/// # Errors
///
/// Returns [`ArnError::InvalidIamResourcePath`] if `path_prefix` does not meet the requirements above. Note that this
/// differs from [`validate_iam_path`], which reports [`ArnError::InvalidResource`].
#[inline(always)]
pub fn validate_iam_path_prefix(path_prefix: impl AsRef<str>) -> Result<(), ArnError> {
    validate_iam_path_prefix_inner(path_prefix.as_ref())
}

fn validate_iam_path_prefix_inner(path_prefix: &str) -> Result<(), ArnError> {
    if path_prefix.is_empty() || path_prefix.len() > 512 {
        return Err(ArnError::InvalidIamResourcePath(path_prefix.to_string()));
    }

    for c in path_prefix.chars() {
        if c < '\x21' || c > '\x7e' {
            return Err(ArnError::InvalidIamResourcePath(path_prefix.to_string()));
        }
    }

    Ok(())
}

/// Validate that a resource name is valid according to AWS IAM rules.
///
/// Resource names must be non-empty and consist only of ASCII alphanumeric characters and the symbols `+=,.@-_`.
///
/// The maximum length of a resource name varies by resource type (for example, 64 characters for a user and 128 for a
/// role), so this function does not check length at all; callers must apply their own limit.
///
/// # Errors
///
/// Returns [`ArnError::InvalidIamResourceName`] if `resource_name` does not meet the requirements above.
pub fn validate_iam_resource_name(resource_name: impl AsRef<str>) -> Result<(), ArnError> {
    validate_iam_resource_name_inner(resource_name.as_ref())
}

fn validate_iam_resource_name_inner(resource_name: &str) -> Result<(), ArnError> {
    if resource_name.is_empty() {
        return Err(ArnError::InvalidIamResourceName(resource_name.to_string()));
    }

    for c in resource_name.chars() {
        if !(c.is_ascii_alphanumeric() || matches!(c, '+' | '=' | ',' | '.' | '@' | '-' | '_')) {
            return Err(ArnError::InvalidIamResourceName(resource_name.to_string()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_resource_arns() {
        let arn = Arn::from_str("arn:aws:iam::123456789012:role/path/to/role").unwrap();
        let iam_arn = IamResourceArn::try_from(arn).unwrap();
        assert_eq!(iam_arn.resource_type(), "role");
        assert_eq!(iam_arn.resource_path(), "/path/to/");
        assert_eq!(iam_arn.resource_name(), "role");

        let arn = Arn::from_str("arn:aws:iam::123456789012:policy/path/to/policy").unwrap();
        let iam_arn = IamResourceArn::try_from(arn).unwrap();
        assert_eq!(iam_arn.resource_type(), "policy");
        assert_eq!(iam_arn.resource_path(), "/path/to/");
        assert_eq!(iam_arn.resource_name(), "policy");
    }

    #[test]
    fn test_resource_arn_without_path_segments() {
        // The path spans the first slash through the last, so a resource with no path segments
        // reports "/" rather than an empty string.
        let iam_arn = IamResourceArn::from_str("arn:aws:iam::123456789012:role/Deployer").unwrap();
        assert_eq!(iam_arn.resource_type(), "role");
        assert_eq!(iam_arn.resource_path(), "/");
        assert_eq!(iam_arn.resource_name(), "Deployer");
        assert_eq!(iam_arn.resource_name_lower(), "deployer");
        assert_eq!(iam_arn.resource(), "role/Deployer");
        assert_eq!(iam_arn.to_string(), "arn:aws:iam::123456789012:role/Deployer");
    }

    #[test]
    fn test_invalid_resource_arns() {
        let arn = Arn::from_str("arn:aws:s3:::my_corporate_bucket").unwrap();
        assert!(IamResourceArn::try_from(arn).is_err());

        let arn = Arn::from_str("arn:aws:iam::123456789012:role").unwrap();
        assert!(IamResourceArn::try_from(arn).is_err());

        let arn = Arn::from_str("arn:aws:iam::123456789012:role/").unwrap();
        assert!(IamResourceArn::try_from(arn).is_err());

        let arn = Arn::from_str("arn:aws:iam::123456789012:role/path/to/").unwrap();
        assert!(IamResourceArn::try_from(arn).is_err());
    }
}
