//! Constants used by the IAM service.
//!
//! Constants shared with the other Scratchstack services live in
//! [`scratchstack_service_common::constants`] and are re-exported here, so this module remains
//! the single import for everything a call site needs.
//!
//! Please keep this file organized alphabetically.

pub(crate) use scratchstack_service_common::constants::*;

/// The ARN resource type for IAM users.
pub(crate) const ARN_RESOURCE_TYPE_USER: &str = "user";

/// Error message used when an operation that defaults its target to the calling user is invoked
/// by credentials that do not identify an IAM user.
pub(crate) const MSG_USER_NAME_REQUIRED: &str = "Must specify userName when calling with non-User credentials";

/// The service name used in SigV4 credential scopes.
pub(crate) const SERVICE_IAM: &str = "iam";

/// Session key prefix for the tags attached to the IAM entity a request operates on; the tag key
/// follows the prefix.
///
/// IAM defines this alongside the service-agnostic [`SESSION_KEY_PREFIX_AWS_RESOURCE_TAG`], and
/// both carry the same values.
pub(crate) const SESSION_KEY_PREFIX_IAM_RESOURCE_TAG: &str = "iam:ResourceTag/";

/// XML namespace for IAM responses and errors
pub(crate) const XML_NS_IAM: &str = "https://iam.amazonaws.com/doc/2010-05-08/";
