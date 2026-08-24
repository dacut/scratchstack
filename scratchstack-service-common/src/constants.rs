//! Constants shared by the Scratchstack service implementations.
//!
//! Constants that vary per service -- the SigV4 credential-scope service name, the service's XML
//! namespace, and any service-specific error messages -- belong in that service's own
//! `constants` module rather than here.
//!
//! Please keep this file organized alphabetically.

/// Content-Type string for HTML forms
pub const CT_APPLICATION_X_WWW_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

/// HTTP header for `Content-Type`
pub const HDR_CONTENT_TYPE: &str = "content-type";

/// HTTP header for `X-Amzn-RequestId`
pub const HDR_X_AMZN_REQUEST_ID: &str = "x-amzn-requestid";

/// MIME type for XML responses
pub const MIME_TYPE_XML: &str = "text/xml";

/// Error message used when an operation fails for reasons the caller cannot act on.
pub const MSG_INTERNAL_FAILURE: &str = "Internal failure";

/// Action used when no action is specified in the request
pub const NO_ACTION_SPECIFIED: &str = "NO_ACTION_SPECIFIED";

/// Version used when no version is specified in the request
pub const NO_VERSION_SPECIFIED: &str = "NO_VERSION_SPECIFIED";

/// Query parameter for Action
pub const QP_ACTION: &str = "Action";

/// Query parameter for Version
pub const QP_VERSION: &str = "Version";

/// Session key for the time the request is evaluated.
pub const SESSION_KEY_AWS_CURRENT_TIME: &str = "aws:CurrentTime";

/// Session key for the time the request is evaluated, in seconds since the Unix epoch.
pub const SESSION_KEY_AWS_EPOCH_TIME: &str = "aws:EpochTime";

/// Session key for the account id of the calling principal.
pub const SESSION_KEY_AWS_PRINCIPAL_ACCOUNT: &str = "aws:PrincipalAccount";

/// Session key for the ARN of the calling principal.
pub const SESSION_KEY_AWS_PRINCIPAL_ARN: &str = "aws:PrincipalArn";

/// Session key for the `Referer` header the request carried, if any.
///
/// "Referer" is a misspelling of "referrer" introduced by the original HTTP specification and
/// preserved by every version since; AWS spells the condition key to match the header.
pub const SESSION_KEY_AWS_REFERER: &str = "aws:referer";

/// Session key indicating whether the request arrived over TLS.
pub const SESSION_KEY_AWS_SECURE_TRANSPORT: &str = "aws:SecureTransport";

/// Session key for the IP address the request was received from.
pub const SESSION_KEY_AWS_SOURCE_IP: &str = "aws:SourceIp";

/// Session key for the unique id of the calling principal.
pub const SESSION_KEY_AWS_USERID: &str = "aws:userid";

/// Session key for the `User-Agent` header the request carried, if any.
pub const SESSION_KEY_AWS_USER_AGENT: &str = "aws:UserAgent";

/// Session key prefix for the tags attached to the resource a request operates on; the tag key
/// follows the prefix.
pub const SESSION_KEY_PREFIX_AWS_RESOURCE_TAG: &str = "aws:ResourceTag/";

/// XML namespace for AWSFault errors.
pub const XML_NS_AWSFAULT: &str = "http://webservices.amazon.com/AWSFault/2005-15-09";
