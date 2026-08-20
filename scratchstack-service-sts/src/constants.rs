//! Constants used by the STS service.
//!
//! Please keep this file organized alphabetically.

/// Content-Type string for HTML forms
#[allow(dead_code)]
pub(crate) const CT_APPLICATION_X_WWW_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

/// HTTP header for `Content-Type`
#[allow(dead_code)]
pub(crate) const HDR_CONTENT_TYPE: &str = "content-type";

/// HTTP header for `X-Amzn-RequestId`
#[allow(dead_code)]
pub(crate) const HDR_X_AMZN_REQUEST_ID: &str = "x-amzn-requestid";

/// MIME type for XML responses
#[allow(dead_code)]
pub(crate) const MIME_TYPE_XML: &str = "text/xml";

/// Error message used when an operation fails for reasons the caller cannot act on.
pub(crate) const MSG_INTERNAL_FAILURE: &str = "Internal failure";

/// Error message used when the caller's credentials do not identify a usable principal.
pub(crate) const MSG_SECURITY_TOKEN_INVALID: &str = "The security token included in the request is invalid.";

/// Action used when no action is specified in the request
pub(crate) const NO_ACTION_SPECIFIED: &str = "NO_ACTION_SPECIFIED";

/// Version used when no version is specified in the request
pub(crate) const NO_VERSION_SPECIFIED: &str = "NO_VERSION_SPECIFIED";

/// Query parameter for Action
pub(crate) const QP_ACTION: &str = "Action";

/// Query parameter for Version
pub(crate) const QP_VERSION: &str = "Version";

/// The service name used in SigV4 credential scopes.
pub(crate) const SERVICE_STS: &str = "sts";

/// Session key holding the caller's user id.
pub(crate) const SESSION_KEY_AWS_USERID: &str = "aws:userid";

/// XML namespace for AWSFault errors.
#[allow(dead_code)]
pub(crate) const XML_NS_AWSFAULT: &str = "http://webservices.amazon.com/AWSFault/2005-15-09";

/// XML namespace for STS responses and errors
pub(crate) const XML_NS_STS: &str = "https://sts.amazonaws.com/doc/2011-06-15/";
