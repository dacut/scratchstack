//! Authorization support for the IAM service.
//!
//! The check itself is service-agnostic and lives in [`scratchstack_service_common::authz`]; what
//! remains here is IAM's own view of it -- the condition keys IAM defines beyond the ones every
//! service shares, and the generated error shapes IAM reports an authorization failure with.
use {
    crate::{
        constants::*,
        service::{RequestMetadata, internal_failure},
    },
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{Principal, SessionData, SessionValue},
    scratchstack_aws_signature::SessionPolicies,
    scratchstack_core::{
        RequestId,
        axum::{body::Body, response::Response},
        response::Responder as _,
    },
    scratchstack_service_common::authz::{AuthorizationError, request_session_data},
    scratchstack_shapes_iam::{
        action::Action,
        types::{Tag, error::AccessDeniedException},
    },
    sqlx::postgres::PgTransaction,
};

pub(crate) use scratchstack_service_common::authz::{
    request_tag_context, request_tag_keys_context, resource_account_context,
};

/// Authorize `action` for the calling principal, gathering the principal's identity-based
/// policies inside `tx`. An IAM user caller is governed by the user's policies (including
/// group-inherited policies and any permissions boundary); an assumed-role caller is governed by
/// the role's policies and any permissions boundary, intersected with the session policies
/// supplied to `sts:AssumeRole` (carried in `session_policies`).
///
/// `resources` holds the resource ARNs the request operates on; pass an empty slice for
/// operations without resource-level permissions (policies must then grant the action with
/// `Resource: "*"`).
///
/// `request_metadata` describes the request itself -- the connection it arrived on and the
/// headers it announced itself with -- and supplies the `aws:SecureTransport`, `aws:SourceIp`,
/// `aws:referer`, and `aws:UserAgent` condition keys. It is borrowed rather than consumed, since
/// one request may need several actions authorized against the same connection facts.
///
/// `request_context` holds the condition keys derived from the request itself and from the
/// resources it names -- the tags on those resources, for example. They are layered onto the
/// session data the authentication layer produced, so a caller cannot supply them.
///
/// `aws:ResourceAccount` is derived from `resources` here; an operation without resource-level
/// permissions supplies it through `request_context` instead, with
/// [`resource_account_context`].
///
/// Returns `Ok(())` when the request is allowed. Otherwise returns the ready-to-send error
/// response: an `AccessDeniedException` for policy denials, or an `InternalFailure` when
/// authorization could not be performed (which always fails closed).
// What is left after the connection facts are bundled into `request_metadata` are distinct
// facets of the request being authorized -- the caller, the policies governing it, and what it
// acts on -- with no further grouping to make; bundling those would only move the argument list
// into a builder call at each call site.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn check_authorization(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    principal: &Principal,
    session_data: &SessionData,
    session_policies: &SessionPolicies,
    request_metadata: &RequestMetadata,
    action: Action,
    resources: &[Arn],
    request_context: &SessionData,
) -> Result<(), Box<Response<Body>>> {
    let session_data = request_session_data(session_data, request_metadata, resources, request_context);

    scratchstack_service_common::authz::check_authorization(
        tx,
        request_id,
        principal,
        &session_data,
        session_policies,
        SERVICE_IAM,
        action.as_str(),
        resources,
    )
    .await
    .map_err(|error| Box::new(error_response(request_id, error)))
}

/// Build the condition keys describing the tags attached to the resource a request operates on,
/// for the `request_context` argument of [`check_authorization`].
///
/// Resource tags are exposed both through the service-agnostic `aws:ResourceTag/${TagKey}`
/// condition key and, for IAM entities, through IAM's own `iam:ResourceTag/${TagKey}` key. Tag
/// keys are compared case-insensitively, which [`SessionData`] provides by lower-casing keys as
/// they are inserted.
pub(crate) fn resource_tag_context(tags: &[Tag]) -> SessionData {
    let mut context = scratchstack_service_common::authz::resource_tag_context(
        tags.iter().map(|tag| (tag.key.as_str(), tag.value.as_str())),
    );

    for tag in tags {
        context.insert(
            &format!("{SESSION_KEY_PREFIX_IAM_RESOURCE_TAG}{}", tag.key),
            SessionValue::String(tag.value.clone()),
        );
    }

    context
}

/// Build the condition keys describing the permissions boundary a request asks to attach to the
/// entity it creates or modifies, for the `request_context` argument of [`check_authorization`].
///
/// The boundary is named by the ARN of the managed policy serving as it, which IAM exposes
/// through the `iam:PermissionsBoundary` condition key. This is what lets a policy require that
/// entities be created only with a particular boundary, so that a caller cannot create an entity
/// more privileged than itself.
///
/// A request asking for no boundary supplies no key, so such a condition does not match rather
/// than matching an empty string.
pub(crate) fn permissions_boundary_context(permissions_boundary: Option<&str>) -> SessionData {
    let mut context = SessionData::with_capacity(1);

    if let Some(permissions_boundary) = permissions_boundary {
        context.insert(SESSION_KEY_IAM_PERMISSIONS_BOUNDARY, SessionValue::String(permissions_boundary.to_string()));
    }

    context
}

/// Build the condition keys describing the managed policy a request asks to attach to or detach
/// from an IAM entity, for the `request_context` argument of [`check_authorization`].
///
/// The policy is named by its ARN, which IAM exposes through the `iam:PolicyARN` condition key.
/// This is what lets a policy say which managed policies a caller may hand out or take away,
/// separately from which entities it may hand them to; without it, a grant of
/// `iam:AttachUserPolicy` on a user reaches every policy in the account.
///
/// The ARN is reported as the request spelled it, since that is what the request acts on. A
/// request naming something that is not an ARN at all matches none of the ARNs a policy lists, so
/// such a condition denies rather than being skipped.
///
/// An AWS-owned policy can be named either through the `aws` account alias, as IAM spells it, or
/// through the numeric account this implementation stores it under, and the two spellings are
/// different strings to compare against. A condition meant to cover AWS-owned policies should
/// cover both.
pub(crate) fn policy_arn_context(policy_arn: &str) -> SessionData {
    let mut context = SessionData::with_capacity(1);
    context.insert(SESSION_KEY_IAM_POLICY_ARN, SessionValue::String(policy_arn.to_string()));
    context
}

/// Render an authorization failure as the error response IAM reports it with.
fn error_response(request_id: RequestId, error: AuthorizationError) -> Response<Body> {
    match error {
        AuthorizationError::AccessDenied(message) => {
            AccessDeniedException::builder().message(message).request_id(request_id).build().respond()
        }
        // The policies are read from the IAM database, so an IAM caller is the one caller that
        // can make sense of the error as it stands.
        AuthorizationError::Database(e) => e.respond(),
        AuthorizationError::InternalFailure => internal_failure(request_id),
    }
}
