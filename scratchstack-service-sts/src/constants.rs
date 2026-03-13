/// Content-Type string for HTML forms
#[allow(dead_code)]
pub(crate) const CT_APPLICATION_X_WWW_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

/// Error code for InvalidAction errors
pub(crate) const ERR_CODE_INVALID_ACTION: &str = "InvalidAction";

/// Error type for Sender errors
pub(crate) const ERR_TYPE_SENDER: &str = "Sender";

/// HTTP header for `Content-Type`
pub(crate) const HDR_CONTENT_TYPE: &str = "content-type";

/// HTTP header for `X-Amzn-RequestId`
pub(crate) const HDR_X_AMZN_REQUEST_ID: &str = "x-amzn-requestid";

/// Query parameter for Action
pub(crate) const QP_ACTION: &str = "Action";

/// Query parameter for Version
pub(crate) const QP_VERSION: &str = "Version";

/// MIME type for XML responses
pub(crate) const MIME_TYPE_XML: &str = "text/xml";

/// Action used when no action is specified in the request
pub(crate) const NO_ACTION_SPECIFIED: &str = "NO_ACTION_SPECIFIED";

/// Version used when no version is specified in the request
pub(crate) const NO_VERSION_SPECIFIED: &str = "NO_VERSION_SPECIFIED";

/// Version 2011-06-15 of the STS API
pub(crate) const STS_VERSION_20110615: &str = "2011-06-15";

/// XML namespace for STS responses and errors
pub(crate) const XML_NS_STS: &str = "https://sts.amazonaws.com/doc/2011-06-15/";

/// XML namespace for AWSFault errors.
pub(crate) const XML_NS_AWSFAULT: &str = "http://webservices.amazon.com/AWSFault/2005-15-09";
