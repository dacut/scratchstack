use strum_macros::{Display, EnumString};

/// Protocol used by a service
#[derive(Clone, Copy, Debug, Display, EnumString, Eq, Hash, PartialEq)]
pub enum Protocol {
    /// AWS JSON 1.0 protocol
    #[strum(serialize = "aws.protocols#awsJson1_0")]
    AwsJson1_0,

    /// AWS JSON 1.1 protocol
    #[strum(serialize = "aws.protocols#awsJson1_1")]
    AwsJson1_1,

    /// AWS Query protocol
    #[strum(serialize = "aws.protocols#awsQuery")]
    AwsQuery,

    /// AWS EC2 query protocol
    #[strum(serialize = "aws.protocols#ec2Query")]
    Ec2Query,

    /// AWS REST JSON 1 protocol
    #[strum(serialize = "aws.protocols#restJson1")]
    RestJson1,

    /// AWS REST XML protocol
    #[strum(serialize = "aws.protocols#restXml")]
    RestXml,
}

impl Protocol {
    /// The `Content-Type` value responses under this protocol carry.
    ///
    /// Only the JSON protocols need this when generating code: their responders pass it to
    /// `scratchstack_core::response::json_response`, while the XML ones get theirs from
    /// `scratchstack_core::response::xml_response`, which serves one protocol and sets its own.
    #[must_use]
    pub fn content_type(&self) -> &'static str {
        match self {
            Self::AwsJson1_0 => "application/x-amz-json-1.0",
            Self::AwsJson1_1 => "application/x-amz-json-1.1",
            Self::AwsQuery | Self::Ec2Query | Self::RestXml => "text/xml; charset=utf-8",
            Self::RestJson1 => "application/json",
        }
    }
}
