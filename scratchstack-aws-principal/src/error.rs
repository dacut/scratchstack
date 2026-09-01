use {
    scratchstack_arn::ArnError,
    std::{
        error::Error,
        fmt::{Debug, Display, Formatter, Result as FmtResult},
    },
};

/// Errors that can be raised during the parsing of principals.
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrincipalError {
    /// An error from [`scratchstack_arn`] with no more specific counterpart here.
    ///
    /// [`ArnError`] is `#[non_exhaustive]`, so variants added there in future are carried through unchanged rather
    /// than being forced into an approximate translation.
    Arn(ArnError),

    /// Entity does not have a valid ARN.
    CannotConvertToArn,

    /// Invalid AWS account id. The argument contains the specified account id.
    InvalidAccountId(String),

    /// Invalid ARN. The argument contains the specified ARN.
    InvalidArn(String),

    /// Invalid Canonical User Id. The argument contains the spcified canonical user id.
    InvalidCanonicalUserId(String),

    /// Invalid partition. The argument contains the specified partition.
    InvalidPartition(String),

    /// Invalid federated user name. The argument contains the specified user name.
    InvalidFederatedUserName(String),

    /// Invalid group name. The argument contains the specified group name.
    InvalidGroupName(String),

    /// Invalid group id. The argument contains the specified group id.
    InvalidGroupId(String),

    /// Invalid instance profile name. The argument contains the specified instance profile name.
    InvalidInstanceProfileName(String),

    /// Invalid instance profile id. The argument contains the specified instance profile id.
    InvalidInstanceProfileId(String),

    /// Invalid IAM path. The argument contains the specified path.
    InvalidPath(String),

    /// Invalid region. The argument contains the specified region.
    InvalidRegion(String),

    /// Invalid resource. The argument contains the specified resource.
    InvalidResource(String),

    /// Invalid resource name. The argument contains the specified resource name.
    InvalidResourceName(String),

    /// Invalid resource path. The argument contains the specified resource path.
    InvalidResourcePath(String),

    /// Invalid role name. The argument contains the specified role name.
    InvalidRoleName(String),

    /// Invalid role id. The argument contains the specified role id.
    InvalidRoleId(String),

    /// Invalid scheme. The argument contains the specified scheme.
    InvalidScheme(String),

    /// Invalid service. The argument contains the specified service name.
    InvalidService(String),

    /// Invalid session name. The argument contains the specified session name.
    InvalidSessionName(String),

    /// Invalid user name. The argument contains the specified user name.
    InvalidUserName(String),

    /// Invalid user id. The argument contains the specified user id.
    InvalidUserId(String),

    /// A required field was not set on a builder. The argument contains the name of the field.
    MissingField(&'static str),
}

impl Error for PrincipalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Arn(err) => Some(err),
            _ => None,
        }
    }
}

impl Display for PrincipalError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Arn(err) => Display::fmt(err, f),
            Self::CannotConvertToArn => f.write_str("Cannot convert entity to ARN"),
            Self::InvalidArn(arn) => write!(f, "Invalid ARN: {arn:#?}"),
            Self::InvalidAccountId(account_id) => write!(f, "Invalid account id: {account_id:#?}"),
            Self::InvalidCanonicalUserId(canonical_user_id) => {
                write!(f, "Invalid canonical user id: {canonical_user_id:#?}")
            }
            Self::InvalidFederatedUserName(user_name) => {
                write!(f, "Invalid federated user name: {user_name:#?}")
            }
            Self::InvalidGroupName(group_name) => {
                write!(f, "Invalid group name: {group_name:#?}")
            }
            Self::InvalidGroupId(group_id) => write!(f, "Invalid group id: {group_id:#?}"),
            Self::InvalidInstanceProfileName(instance_profile_name) => {
                write!(f, "Invalid instance profile name: {instance_profile_name:#?}")
            }
            Self::InvalidInstanceProfileId(instance_profile_id) => {
                write!(f, "Invalid instance profile id: {instance_profile_id:#?}")
            }
            Self::InvalidPartition(partition) => write!(f, "Invalid partition: {partition:#?}"),
            Self::InvalidPath(path) => write!(f, "Invalid path: {path:#?}"),
            Self::InvalidRegion(region) => write!(f, "Invalid region: {region:#?}"),
            Self::InvalidResource(resource) => write!(f, "Invalid resource: {resource:#?}"),
            Self::InvalidResourceName(resource_name) => {
                write!(f, "Invalid resource name: {resource_name:#?}")
            }
            Self::InvalidResourcePath(resource_path) => {
                write!(f, "Invalid resource path: {resource_path:#?}")
            }
            Self::InvalidRoleName(role_name) => write!(f, "Invalid role name: {role_name:#?}"),
            Self::InvalidRoleId(role_id) => write!(f, "Invalid role id: {role_id:#?}"),
            Self::InvalidScheme(scheme) => write!(f, "Invalid scheme: {scheme:#?}"),
            Self::InvalidService(service_name) => {
                write!(f, "Invalid service name: {service_name:#?}")
            }
            Self::InvalidSessionName(session_name) => {
                write!(f, "Invalid session name: {session_name:#?}")
            }
            Self::InvalidUserName(user_name) => write!(f, "Invalid user name: {user_name:#?}"),
            Self::InvalidUserId(user_id) => write!(f, "Invalid user id: {user_id:#?}"),
            Self::MissingField(field) => write!(f, "Missing required field: {field}"),
        }
    }
}

impl From<ArnError> for PrincipalError {
    /// Translate an [`ArnError`] into the closest [`PrincipalError`].
    ///
    /// Variants with no direct counterpart are wrapped in [`PrincipalError::Arn`]. [`ArnError`] is
    /// `#[non_exhaustive]`, so this conversion must stay total no matter what is added to it.
    fn from(err: ArnError) -> Self {
        match err {
            ArnError::InvalidScheme(scheme) => Self::InvalidScheme(scheme),
            ArnError::InvalidPartition(partition) => Self::InvalidPartition(partition),
            ArnError::InvalidService(service_name) => Self::InvalidService(service_name),
            ArnError::InvalidRegion(region) => Self::InvalidRegion(region),
            ArnError::InvalidAccountId(account_id) => Self::InvalidAccountId(account_id),
            ArnError::InvalidResource(resource) => Self::InvalidResource(resource),
            ArnError::InvalidArn(arn) => Self::InvalidArn(arn),
            ArnError::InvalidIamResourcePath(path) => Self::InvalidResourcePath(path),
            ArnError::InvalidIamResourceName(name) => Self::InvalidResourceName(name),
            ArnError::MissingPartition => Self::MissingField("partition"),
            ArnError::MissingService => Self::MissingField("service"),
            err => Self::Arn(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::PrincipalError, scratchstack_arn::ArnError};

    #[test]
    fn exercise_unused_in_crate() {
        // These errors are not created in code used here, but are used in other crates.
        let err = PrincipalError::InvalidGroupName("test+1".to_string());
        assert_eq!(err.to_string(), r#"Invalid group name: "test+1""#);

        let err = PrincipalError::InvalidInstanceProfileName("test+1".to_string());
        assert_eq!(err.to_string(), r#"Invalid instance profile name: "test+1""#);

        let err = PrincipalError::MissingField("account_id");
        assert_eq!(err.to_string(), "Missing required field: account_id");
    }

    fn check_arn_err_into(arn_err: ArnError) {
        let arn_err_string = arn_err.to_string();
        let principal_err = PrincipalError::from(arn_err);
        assert_eq!(principal_err.to_string(), arn_err_string);

        // Ensure we can debug print the principal error.
        let _ = format!("{principal_err:?}");
    }

    #[test]
    fn test_from_arn_error_missing_fields() {
        // ArnBuilder's Missing* variants map onto PrincipalError's own MissingField.
        assert_eq!(PrincipalError::from(ArnError::MissingPartition), PrincipalError::MissingField("partition"));
        assert_eq!(PrincipalError::from(ArnError::MissingService), PrincipalError::MissingField("service"));
    }

    #[test]
    fn test_arn_variant_displays_and_sources() {
        use std::error::Error as _;

        // ArnError is not Clone, so build two equal values.
        let expected = ArnError::InvalidPartition("Aws".to_string()).to_string();
        let principal_err = PrincipalError::Arn(ArnError::InvalidPartition("Aws".to_string()));
        assert_eq!(principal_err.to_string(), expected);
        assert!(principal_err.source().is_some());
        assert!(PrincipalError::CannotConvertToArn.source().is_none());
    }

    #[test]
    fn test_from_arn_error() {
        check_arn_err_into(ArnError::InvalidAccountId("abcd".to_string()));
        check_arn_err_into(ArnError::InvalidArn("arn:foo:bar".to_string()));
        check_arn_err_into(ArnError::InvalidPartition("-foo".to_string()));
        check_arn_err_into(ArnError::InvalidRegion("foo-".to_string()));
        check_arn_err_into(ArnError::InvalidResource("".to_string()));
        check_arn_err_into(ArnError::InvalidScheme("https".to_string()));
        check_arn_err_into(ArnError::InvalidService("foo".to_string()));
    }
}
// end tests -- do not delete; needed for coverage.
