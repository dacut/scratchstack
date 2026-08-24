//! Constants used by the STS service.
//!
//! Constants shared with the other Scratchstack services live in
//! [`scratchstack_service_common::constants`] and are re-exported here, so this module remains
//! the single import for everything a call site needs.
//!
//! Please keep this file organized alphabetically.

pub(crate) use scratchstack_service_common::constants::*;

/// The ARN resource type for IAM roles.
pub(crate) const ARN_RESOURCE_TYPE_ROLE: &str = "role";

/// Error message used when the account root user attempts to assume a role.
pub(crate) const MSG_ROOT_CANNOT_ASSUME_ROLE: &str = "Roles may not be assumed by root accounts.";

/// Error message used when the caller's credentials do not identify a usable principal.
pub(crate) const MSG_SECURITY_TOKEN_INVALID: &str = "The security token included in the request is invalid.";

/// The service name used in SigV4 credential scopes.
pub(crate) const SERVICE_STS: &str = "sts";

/// Session key holding the external id supplied in an AssumeRole request.
pub(crate) const SESSION_KEY_STS_EXTERNAL_ID: &str = "sts:ExternalId";

/// XML namespace for STS responses and errors
pub(crate) const XML_NS_STS: &str = "https://sts.amazonaws.com/doc/2011-06-15/";
