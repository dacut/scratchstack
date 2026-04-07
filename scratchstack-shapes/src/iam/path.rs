use {
    anyhow::{Result as AnyResult, bail},
    regex::Regex,
    std::sync::LazyLock,
};

/// Regular expression for paths.
static PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(/|/[\x21-\x7e]+/)$").unwrap());

/// Validate that the path is valid according to AWS IAM rules.
///
/// Paths must be between 1 and 512 characters long, start and end with a slash, and can contain any printable
/// ASCII character except for space (i.e. character codes 33 through 126).
///
/// ## References
/// * [AWS CreateGroup](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateGroup.html)
/// * [AWS CreatePolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicy.html)
/// * [AWS CreateRole](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html)
/// * [AWS CreateUser](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html)
pub fn validate_path(path: impl AsRef<str>) -> AnyResult<()> {
    let path = path.as_ref();
    if !PATH_REGEX.is_match(path) {
        bail!(
            "Path must start and end with a slash, can contain any printable ASCII characters (codes 33–126), and must be at most 512 characters long."
        );
    }
    Ok(())
}
