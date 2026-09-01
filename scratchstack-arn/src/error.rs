use std::{
    error::Error,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};

/// Errors that can be raised while parsing, validating, or building an [`Arn`][crate::Arn].
///
/// The `Missing*` variants are produced only by [`ArnBuilder::build`][crate::ArnBuilder::build], for required
/// components that were never set; everything else can come from [`Arn::new`][crate::Arn::new] or from parsing a
/// string via [`Arn`][crate::Arn]'s [`FromStr`][std::str::FromStr] implementation.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArnError {
    /// Invalid AWS account id. The argument contains the specified account id.
    InvalidAccountId(String),

    /// Invalid or malformed ARN. The argument contains the specified ARN.
    InvalidArn(String),

    /// Invalid partition. The argument contains the specified partition.
    InvalidPartition(String),

    /// Invalid region. The argument contains the specified region.
    InvalidRegion(String),

    /// Invalid resource. The argument contains the specified resource.
    InvalidResource(String),

    /// Invalid scheme. The scheme must be `arn`. The argument contains the specified scheme.
    InvalidScheme(String),

    /// Invalid service. The argument contains the specified service.
    InvalidService(String),

    /// The partition was never set on an [`ArnBuilder`][crate::ArnBuilder].
    MissingPartition,

    /// The service was never set on an [`ArnBuilder`][crate::ArnBuilder].
    MissingService,

    /// Invalid IAM resource name. The argument contains the specified name.
    #[cfg(feature = "iam")]
    InvalidIamResourceName(String),

    /// Invalid IAM resource path. The argument contains the specified path.
    #[cfg(feature = "iam")]
    InvalidIamResourcePath(String),
}

impl Error for ArnError {}

impl Display for ArnError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::InvalidAccountId(account_id) => write!(f, "Invalid account id: {account_id:#?}"),
            Self::InvalidArn(arn) => write!(f, "Invalid ARN: {arn:#?}"),
            Self::InvalidPartition(partition) => write!(f, "Invalid partition: {partition:#?}"),
            Self::InvalidRegion(region) => write!(f, "Invalid region: {region:#?}"),
            Self::InvalidResource(resource) => write!(f, "Invalid resource: {resource:#?}"),
            Self::InvalidScheme(scheme) => write!(f, "Invalid scheme: {scheme:#?}"),
            Self::InvalidService(service) => write!(f, "Invalid service name: {service:#?}"),
            Self::MissingPartition => write!(f, "Missing partition"),
            Self::MissingService => write!(f, "Missing service"),
            #[cfg(feature = "iam")]
            Self::InvalidIamResourceName(name) => write!(f, "Invalid IAM resource name: {name:#?}"),
            #[cfg(feature = "iam")]
            Self::InvalidIamResourcePath(path) => write!(f, "Invalid IAM resource path: {path:#?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, pretty_assertions::assert_eq};

    // ── ArnError display ─────────────────────────────────────────────────────

    #[test]
    fn arn_error_display_invalid_account_id() {
        assert_eq!(ArnError::InvalidAccountId("1234".to_string()).to_string(), r#"Invalid account id: "1234""#);
    }

    #[test]
    fn arn_error_display_invalid_arn() {
        assert_eq!(
            ArnError::InvalidArn("arn:aws:iam::1234:role/r".to_string()).to_string(),
            r#"Invalid ARN: "arn:aws:iam::1234:role/r""#
        );
    }

    #[test]
    fn arn_error_display_invalid_partition() {
        assert_eq!(ArnError::InvalidPartition("Aws".to_string()).to_string(), r#"Invalid partition: "Aws""#);
    }

    #[test]
    fn arn_error_display_invalid_region() {
        assert_eq!(ArnError::InvalidRegion("us-east-1-".to_string()).to_string(), r#"Invalid region: "us-east-1-""#);
    }

    #[test]
    fn arn_error_display_invalid_resource() {
        assert_eq!(ArnError::InvalidResource("".to_string()).to_string(), r#"Invalid resource: """#);
    }

    #[test]
    fn arn_error_display_invalid_scheme() {
        assert_eq!(ArnError::InvalidScheme("http".to_string()).to_string(), r#"Invalid scheme: "http""#);
    }

    #[test]
    fn arn_error_display_invalid_service() {
        assert_eq!(ArnError::InvalidService("Ec2".to_string()).to_string(), r#"Invalid service name: "Ec2""#);
    }

    #[test]
    fn arn_error_display_missing_partition() {
        assert_eq!(ArnError::MissingPartition.to_string(), "Missing partition");
    }

    #[test]
    fn arn_error_display_missing_service() {
        assert_eq!(ArnError::MissingService.to_string(), "Missing service");
    }

    #[cfg(feature = "iam")]
    #[test]
    fn arn_error_display_iam_variants() {
        assert_eq!(
            ArnError::InvalidIamResourceName("bad name".to_string()).to_string(),
            r#"Invalid IAM resource name: "bad name""#
        );
        assert_eq!(
            ArnError::InvalidIamResourcePath("bad path".to_string()).to_string(),
            r#"Invalid IAM resource path: "bad path""#
        );
    }

    // ── ArnError derived traits ──────────────────────────────────────────────

    #[test]
    fn arn_error_derived() {
        let errors = [
            ArnError::InvalidAccountId("1234".to_string()),
            ArnError::InvalidArn("arn:aws:iam::1234:role/role-name".to_string()),
            ArnError::InvalidPartition("aws".to_string()),
            ArnError::InvalidRegion("us-east-1".to_string()),
            ArnError::InvalidResource("role/role-name".to_string()),
            ArnError::InvalidScheme("arn".to_string()),
            ArnError::InvalidService("iam".to_string()),
            ArnError::MissingPartition,
            ArnError::MissingService,
        ];

        for i in 0..errors.len() {
            for j in 0..errors.len() {
                if i == j {
                    assert_eq!(errors[i], errors[j]);
                } else {
                    assert_ne!(errors[i], errors[j]);
                }
            }
        }
        let _ = format!("{:?}", errors[0]);
    }
}
// end tests -- do not delete; needed for coverage.
