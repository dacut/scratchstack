//! Constants used by the IAM service.
//!
//! Constants shared with the other Scratchstack services live in
//! [`scratchstack_service_common::constants`] and are re-exported here, so this module remains
//! the single import for everything a call site needs.
//!
//! Please keep this file organized alphabetically.

pub(crate) use scratchstack_service_common::constants::*;

/// The service name used in SigV4 credential scopes.
pub(crate) const SERVICE_IAM: &str = "iam";

/// XML namespace for IAM responses and errors
pub(crate) const XML_NS_IAM: &str = "https://iam.amazonaws.com/doc/2010-05-08/";
