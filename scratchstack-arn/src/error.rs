use std::{
    error::Error,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};

/// Errors that can be raise during the parsing of ARNs.
#[derive(Debug, PartialEq, Eq)]
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
        }
    }
}

/// Errors that can be raise during the parsing of ARNs.
#[derive(Debug, PartialEq, Eq)]
pub enum ArnBuilderError {
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

    /// Missing partition.
    MissingPartition,

    /// Missing service.
    MissingService,
}

impl Error for ArnBuilderError {}

impl Display for ArnBuilderError {
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
        }
    }
}

impl From<ArnError> for ArnBuilderError {
    fn from(err: ArnError) -> Self {
        match err {
            ArnError::InvalidAccountId(account_id) => Self::InvalidAccountId(account_id),
            ArnError::InvalidArn(arn) => Self::InvalidArn(arn),
            ArnError::InvalidPartition(partition) => Self::InvalidPartition(partition),
            ArnError::InvalidRegion(region) => Self::InvalidRegion(region),
            ArnError::InvalidResource(resource) => Self::InvalidResource(resource),
            ArnError::InvalidScheme(scheme) => Self::InvalidScheme(scheme),
            ArnError::InvalidService(service) => Self::InvalidService(service),
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

    // ── ArnBuilderError display ──────────────────────────────────────────────

    #[test]
    fn arn_builder_error_display_invalid_account_id() {
        assert_eq!(ArnBuilderError::InvalidAccountId("1234".to_string()).to_string(), r#"Invalid account id: "1234""#);
    }

    #[test]
    fn arn_builder_error_display_invalid_arn() {
        assert_eq!(
            ArnBuilderError::InvalidArn("arn:aws:iam::1234:role/r".to_string()).to_string(),
            r#"Invalid ARN: "arn:aws:iam::1234:role/r""#
        );
    }

    #[test]
    fn arn_builder_error_display_invalid_partition() {
        assert_eq!(ArnBuilderError::InvalidPartition("Aws".to_string()).to_string(), r#"Invalid partition: "Aws""#);
    }

    #[test]
    fn arn_builder_error_display_invalid_region() {
        assert_eq!(
            ArnBuilderError::InvalidRegion("us-east-1-".to_string()).to_string(),
            r#"Invalid region: "us-east-1-""#
        );
    }

    #[test]
    fn arn_builder_error_display_invalid_resource() {
        assert_eq!(ArnBuilderError::InvalidResource("".to_string()).to_string(), r#"Invalid resource: """#);
    }

    #[test]
    fn arn_builder_error_display_invalid_scheme() {
        assert_eq!(ArnBuilderError::InvalidScheme("http".to_string()).to_string(), r#"Invalid scheme: "http""#);
    }

    #[test]
    fn arn_builder_error_display_invalid_service() {
        assert_eq!(ArnBuilderError::InvalidService("Ec2".to_string()).to_string(), r#"Invalid service name: "Ec2""#);
    }

    #[test]
    fn arn_builder_error_display_missing_partition() {
        assert_eq!(ArnBuilderError::MissingPartition.to_string(), "Missing partition");
    }

    #[test]
    fn arn_builder_error_display_missing_service() {
        assert_eq!(ArnBuilderError::MissingService.to_string(), "Missing service");
    }

    // ── ArnBuilderError derived traits ───────────────────────────────────────

    #[test]
    fn arn_builder_error_derived() {
        let errors: &[ArnBuilderError] = &[
            ArnBuilderError::InvalidAccountId("1234".to_string()),
            ArnBuilderError::InvalidArn("arn:aws:iam::1234:role/role-name".to_string()),
            ArnBuilderError::InvalidPartition("aws".to_string()),
            ArnBuilderError::InvalidRegion("us-east-1".to_string()),
            ArnBuilderError::InvalidResource("role/role-name".to_string()),
            ArnBuilderError::InvalidScheme("arn".to_string()),
            ArnBuilderError::InvalidService("iam".to_string()),
            ArnBuilderError::MissingPartition,
            ArnBuilderError::MissingService,
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

    // ── From<ArnError> for ArnBuilderError ───────────────────────────────────

    #[test]
    fn from_arn_error_invalid_account_id() {
        let orig = "1234".to_string();
        let converted = ArnBuilderError::from(ArnError::InvalidAccountId(orig.clone()));
        assert_eq!(converted, ArnBuilderError::InvalidAccountId(orig.clone()));
        assert_eq!(converted.to_string(), ArnError::InvalidAccountId(orig).to_string());
    }

    #[test]
    fn from_arn_error_invalid_arn() {
        let orig = "arn:aws:iam::1234:role/r".to_string();
        let converted = ArnBuilderError::from(ArnError::InvalidArn(orig.clone()));
        assert_eq!(converted, ArnBuilderError::InvalidArn(orig.clone()));
        assert_eq!(converted.to_string(), ArnError::InvalidArn(orig).to_string());
    }

    #[test]
    fn from_arn_error_invalid_partition() {
        let orig = "Aws".to_string();
        let converted = ArnBuilderError::from(ArnError::InvalidPartition(orig.clone()));
        assert_eq!(converted, ArnBuilderError::InvalidPartition(orig.clone()));
        assert_eq!(converted.to_string(), ArnError::InvalidPartition(orig).to_string());
    }

    #[test]
    fn from_arn_error_invalid_region() {
        let orig = "us-east-1-".to_string();
        let converted = ArnBuilderError::from(ArnError::InvalidRegion(orig.clone()));
        assert_eq!(converted, ArnBuilderError::InvalidRegion(orig.clone()));
        assert_eq!(converted.to_string(), ArnError::InvalidRegion(orig).to_string());
    }

    #[test]
    fn from_arn_error_invalid_resource() {
        let orig = "bad/resource".to_string();
        let converted = ArnBuilderError::from(ArnError::InvalidResource(orig.clone()));
        assert_eq!(converted, ArnBuilderError::InvalidResource(orig.clone()));
        assert_eq!(converted.to_string(), ArnError::InvalidResource(orig).to_string());
    }

    #[test]
    fn from_arn_error_invalid_scheme() {
        let orig = "http".to_string();
        let converted = ArnBuilderError::from(ArnError::InvalidScheme(orig.clone()));
        assert_eq!(converted, ArnBuilderError::InvalidScheme(orig.clone()));
        assert_eq!(converted.to_string(), ArnError::InvalidScheme(orig).to_string());
    }

    #[test]
    fn from_arn_error_invalid_service() {
        let orig = "Ec2".to_string();
        let converted = ArnBuilderError::from(ArnError::InvalidService(orig.clone()));
        assert_eq!(converted, ArnBuilderError::InvalidService(orig.clone()));
        assert_eq!(converted.to_string(), ArnError::InvalidService(orig).to_string());
    }
}
// end tests -- do not delete; needed for coverage.
