//! Constants used by the IAM service.
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

/// Error message used when an operation fails for reasons the caller cannot act on.
pub(crate) const MSG_INTERNAL_FAILURE: &str = "Internal failure";

/// Query parameter for Action
pub(crate) const QP_ACTION: &str = "Action";

/// Query parameter for Version
pub(crate) const QP_VERSION: &str = "Version";

/// MIME type for XML responses
#[allow(dead_code)]
pub(crate) const MIME_TYPE_XML: &str = "text/xml";

/// Action used when no action is specified in the request
pub(crate) const NO_ACTION_SPECIFIED: &str = "NO_ACTION_SPECIFIED";

/// Version used when no version is specified in the request
pub(crate) const NO_VERSION_SPECIFIED: &str = "NO_VERSION_SPECIFIED";

/// The service name used in SigV4 credential scopes.
pub(crate) const SERVICE_IAM: &str = "iam";

/// XML namespace for AWSFault errors.
#[allow(dead_code)]
pub(crate) const XML_NS_AWSFAULT: &str = "http://webservices.amazon.com/AWSFault/2005-15-09";

/// XML namespace for IAM responses and errors
pub(crate) const XML_NS_IAM: &str = "https://iam.amazonaws.com/doc/2010-05-08/";
