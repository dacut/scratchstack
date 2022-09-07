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

    /// Invalid scheme. The scheme must be `arn`.
    InvalidScheme(String),

    /// Invalid service. The argument contains the specified service.
    InvalidService(String),
}

impl Error for ArnError {}

impl Display for ArnError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::InvalidAccountId(account_id) => write!(f, "Invalid account id: {:#?}", account_id),
            Self::InvalidArn(arn) => write!(f, "Invalid ARN: {:#?}", arn),
            Self::InvalidPartition(partition) => write!(f, "Invalid partition: {:#?}", partition),
            Self::InvalidRegion(region) => write!(f, "Invalid region: {:#?}", region),
            Self::InvalidResource(resource) => write!(f, "Invalid resource: {:#?}", resource),
            Self::InvalidScheme(scheme) => write!(f, "Invalid scheme: {:#?}", scheme),
            Self::InvalidService(service) => write!(f, "Invalid service name: {:#?}", service),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ArnError;

    #[test]
    fn check_derived() {
        // Ensure we can debug print the error.
        let err = ArnError::InvalidAccountId("1234".to_string());
        let _ = format!("{:?}", err);
    }

    #[test]
    fn check_resource() {
        // We do not construct InvalidResource currently.
        let err = ArnError::InvalidResource("".to_string());
        assert_eq!(err.to_string().as_str(), "Invalid resource: \"\"");
    }
}
