//! Constants used by the IAM service.
//!
//! Constants shared with the other Scratchstack services live in
//! [`scratchstack_service_common::constants`] and are re-exported here, so this module remains
//! the single import for everything a call site needs.
//!
//! Please keep this file organized alphabetically.

pub(crate) use scratchstack_service_common::constants::*;

/// The ARN resource type for IAM managed policies.
pub(crate) const ARN_RESOURCE_TYPE_POLICY: &str = "policy";

/// The ARN resource type for IAM users.
pub(crate) const ARN_RESOURCE_TYPE_USER: &str = "user";

/// The account id an AWS-managed policy is named by in an ARN.
///
/// AWS-managed policies belong to no customer account, and IAM spells that as the account alias
/// `aws` rather than as an account number. The database stores them under
/// [`AWS_ACCOUNT_ID_NUMERIC`], so an ARN may arrive spelled either way and both name the same
/// policy.
pub(crate) const AWS_ACCOUNT_ID: &str = "aws";

/// The numeric account id AWS-managed policies are stored under.
pub(crate) const AWS_ACCOUNT_ID_NUMERIC: &str = "000000000000";

/// Error message reported when a request names something that is not an IAM policy ARN at all.
///
/// This and the two messages below repeat what
/// [`scratchstack_iam_database::policy`] reports for the same input, so that a policy ARN is
/// rejected in the same words whether the service or the database is the one that looks at it.
pub(crate) const MSG_INVALID_POLICY_ARN: &str = "Invalid policy ARN";

/// Error message reported when a policy ARN names a region. IAM is a global service, so a policy
/// ARN has no region to name.
pub(crate) const MSG_POLICY_ARN_REGION: &str = "Policy ARN must not have a region";

/// Error message reported when a policy ARN names a resource that is not a policy.
pub(crate) const MSG_POLICY_ARN_RESOURCE: &str = "Policy ARN must have a resource that starts with \"policy/\"";

/// Error message used when an operation that defaults its target to the calling user is invoked
/// by credentials that do not identify an IAM user.
pub(crate) const MSG_USER_NAME_REQUIRED: &str = "Must specify userName when calling with non-User credentials";

/// The service name used in SigV4 credential scopes.
pub(crate) const SERVICE_IAM: &str = "iam";

/// Session key for the permissions boundary a request asks to attach to the entity it creates or
/// modifies, named by the ARN of the managed policy serving as the boundary.
///
/// A request that asks for no boundary supplies no value, so a policy requiring a particular
/// boundary does not match rather than matching an empty string.
pub(crate) const SESSION_KEY_IAM_PERMISSIONS_BOUNDARY: &str = "iam:PermissionsBoundary";

/// Session key for the managed policy a request asks to attach to or detach from an IAM entity,
/// named by its ARN.
///
/// This is what confines a grant of `iam:AttachUserPolicy` (or its detaching counterpart) to
/// particular policies, so that a caller able to attach policies cannot attach an arbitrarily
/// privileged one.
pub(crate) const SESSION_KEY_IAM_POLICY_ARN: &str = "iam:PolicyARN";

/// Session key prefix for the tags attached to the IAM entity a request operates on; the tag key
/// follows the prefix.
///
/// IAM defines this alongside the service-agnostic [`SESSION_KEY_PREFIX_AWS_RESOURCE_TAG`], and
/// both carry the same values.
pub(crate) const SESSION_KEY_PREFIX_IAM_RESOURCE_TAG: &str = "iam:ResourceTag/";

/// XML namespace for IAM responses and errors
pub(crate) const XML_NS_IAM: &str = "https://iam.amazonaws.com/doc/2010-05-08/";
