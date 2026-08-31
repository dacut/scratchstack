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

/// An existing IAM entity -- a user or a role -- described as the resource an operation acts on.
///
/// An operation acting on an existing entity cannot name it without looking it up: the resource
/// ARN carries the entity's path, and the policy may be conditioned on the entity's tags or on
/// the permissions boundary set on it, none of which a request naming the entity supplies. The
/// lookup runs inside the operation's transaction, so what is authorized is what the operation
/// goes on to act on.
pub(crate) struct EntityResource {
    /// The ARN naming the entity, which is the resource the action is authorized against.
    pub(crate) arn: Arn,

    /// The ARN of the managed policy serving as the entity's permissions boundary, if it has one.
    pub(crate) permissions_boundary: Option<String>,

    /// The tags attached to the entity.
    pub(crate) tags: Vec<Tag>,
}

impl EntityResource {
    /// Build the condition keys describing this entity, for the `request_context` argument of
    /// [`check_authorization`].
    ///
    /// This reports the entity's tags and nothing else. An operation IAM lists
    /// `iam:PermissionsBoundary` among the condition keys for uses
    /// [`Self::context_with_boundary`] instead.
    pub(crate) fn context(&self) -> SessionData {
        resource_tag_context(&self.tags)
    }

    /// Build the condition keys describing this entity, including the permissions boundary set on
    /// it, for the `request_context` argument of [`check_authorization`].
    ///
    /// IAM lists `iam:PermissionsBoundary` among the condition keys for the operations that
    /// change what an entity may do -- attaching and detaching managed policies, writing and
    /// deleting inline policies, deleting the entity, and reading a role -- and there the key
    /// names the boundary already set on the entity, not one the request supplies. This is what
    /// lets a policy delegate entity management while requiring that the entities managed stay
    /// under a particular boundary, so a delegated administrator cannot raise an entity above
    /// itself.
    ///
    /// It is deliberately not supplied for every operation: an entity with no boundary supplies
    /// no key, and a key supplied where IAM does not define one would make a `StringNotEquals`
    /// deny guard fire where IAM leaves it dormant. [`Self::context`] covers those operations.
    pub(crate) fn context_with_boundary(&self) -> SessionData {
        let mut context = self.context();
        context.extend(&permissions_boundary_context(self.permissions_boundary.as_deref()));
        context
    }
}

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

/// Build the condition keys describing the tags a request asks to attach to the resource it
/// creates -- a user, a role, or a managed policy -- for the `request_context` argument of
/// [`check_authorization`].
///
/// These are request-supplied tags naming a resource that does not exist yet, so
/// `aws:RequestTag/${TagKey}` and `aws:TagKeys` describe them as they would for any tagging
/// request. IAM additionally reports them through both resource-tag spellings --
/// `aws:ResourceTag/${TagKey}` and `iam:ResourceTag/${TagKey}` -- even though there is as yet no
/// resource carrying them. A policy that guards tagging through either resource-tag key therefore
/// governs creation as well, and omitting them leaves such a guard dormant on exactly the request
/// that establishes the tags.
///
/// # Why this does not follow the documentation
///
/// The IAM documentation lists the `iam:` condition keys for CreateUser and CreateRole but not
/// for CreatePolicy, which would mean a managed policy is created with only the service-agnostic
/// keys in context. The service does not behave that way: CreatePolicy supplies
/// `iam:ResourceTag/${TagKey}` exactly as the entity operations do.
///
/// That was established against live IAM with a controlled experiment, since a single
/// allow/deny observation on a freshly attached policy proves nothing -- IAM passes through
/// propagation states that deny everything, and briefly one where a statement matches before its
/// condition applies. Under a settled grant, and with a nonexistent condition key as a negative
/// control to show an absent key denies both ways:
///
/// | grant conditioned on          | tag matches | tag differs  |
/// |-------------------------------|-------------|--------------|
/// | `aws:ResourceTag/{}` (control)| allow       | AccessDenied |
/// | `iam:NoSuchKeyAtAll/{}`       | AccessDenied| AccessDenied |
/// | `iam:ResourceTag/{}`          | allow       | AccessDenied |
///
/// A `StringEquals` on an absent key can never match, so tracking the value the way the control
/// does is only possible if the key is present. All three creates therefore share this function;
/// the tests in this module pin that, and tests/test_authz_policy.py in the scratchstack-e2e repo
/// re-checks it against live IAM.
///
/// An operation tagging a resource that already exists supplies the resource-tag keys from the
/// resource instead, through [`resource_tag_context`] or [`EntityResource::context`].
///
/// The resource-tag keys are inserted here rather than merged in from [`resource_tag_context`]:
/// [`SessionData`] can only be extended from a borrowed one, so merging would build a second map
/// only to clone every entry out of it and drop it again.
pub(crate) fn created_resource_tag_context(tags: &[Tag]) -> SessionData {
    let mut context = request_tag_context(tags.iter().map(|tag| (tag.key.as_str(), tag.value.as_str())));
    context.reserve(tags.len() * 2);

    for tag in tags {
        context.insert(
            &format!("{SESSION_KEY_PREFIX_AWS_RESOURCE_TAG}{}", tag.key),
            SessionValue::String(tag.value.clone()),
        );
        context.insert(
            &format!("{SESSION_KEY_PREFIX_IAM_RESOURCE_TAG}{}", tag.key),
            SessionValue::String(tag.value.clone()),
        );
    }

    context
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

#[cfg(test)]
mod tests {
    use {
        super::{created_resource_tag_context, resource_tag_context},
        crate::constants::*,
        pretty_assertions::assert_eq,
        scratchstack_aws_principal::SessionValue,
        scratchstack_shapes_iam::types::Tag,
    };

    /// Build the tags a request would name.
    fn tags(pairs: &[(&str, &str)]) -> Vec<Tag> {
        pairs.iter().map(|(key, value)| Tag::builder().key(*key).value(*value).build().unwrap()).collect()
    }

    /// Creating an entity with tags reports them through the resource-tag condition keys as well
    /// as the request-tag ones, even though the entity does not exist yet.
    ///
    /// This is the whole reason [`created_resource_tag_context`] exists rather than the plain
    /// `request_tag_context` every other tagging operation uses: a policy guarding tags through
    /// `aws:ResourceTag/${TagKey}` or `iam:ResourceTag/${TagKey}` would otherwise lie dormant on
    /// the one request that establishes those tags.
    #[test]
    fn creating_an_entity_reports_its_tags_as_resource_tags() {
        let context =
            created_resource_tag_context(&tags(&[("Department", "Engineering"), ("Project", "Scratchstack")]));

        assert_eq!(
            context.get(&format!("{SESSION_KEY_PREFIX_AWS_RESOURCE_TAG}Department")),
            Some(&SessionValue::String("Engineering".to_string()))
        );
        assert_eq!(
            context.get(&format!("{SESSION_KEY_PREFIX_IAM_RESOURCE_TAG}Department")),
            Some(&SessionValue::String("Engineering".to_string()))
        );
        assert_eq!(
            context.get(&format!("{SESSION_KEY_PREFIX_AWS_RESOURCE_TAG}Project")),
            Some(&SessionValue::String("Scratchstack".to_string()))
        );
        assert_eq!(
            context.get(&format!("{SESSION_KEY_PREFIX_IAM_RESOURCE_TAG}Project")),
            Some(&SessionValue::String("Scratchstack".to_string()))
        );
    }

    /// The resource-tag keys are reported alongside the request-tag ones, not instead of them: a
    /// policy conditioned on `aws:RequestTag/${TagKey}` or on `aws:TagKeys` governs entity
    /// creation as it governs any other tagging request.
    #[test]
    fn creating_an_entity_also_reports_its_tags_as_request_tags() {
        let context =
            created_resource_tag_context(&tags(&[("Department", "Engineering"), ("Project", "Scratchstack")]));

        assert_eq!(
            context.get(&format!("{SESSION_KEY_PREFIX_AWS_REQUEST_TAG}Department")),
            Some(&SessionValue::String("Engineering".to_string()))
        );
        assert_eq!(
            context.get(&format!("{SESSION_KEY_PREFIX_AWS_REQUEST_TAG}Project")),
            Some(&SessionValue::String("Scratchstack".to_string()))
        );

        // The keys are reported as the request spelled them: the `ForAllValues:`/`ForAnyValue:`
        // set operators compare them the way the operator they qualify does.
        assert_eq!(
            context.get(SESSION_KEY_AWS_TAG_KEYS),
            Some(&SessionValue::List(vec![
                SessionValue::String("Department".to_string()),
                SessionValue::String("Project".to_string()),
            ]))
        );
    }

    /// Tag keys are compared case-insensitively, which `SessionData` provides by lower-casing
    /// keys as they are inserted -- so a policy naming a tag key in any casing reaches the value.
    #[test]
    fn created_entity_tag_keys_are_case_insensitive() {
        let context = created_resource_tag_context(&tags(&[("Department", "Engineering")]));

        assert_eq!(context.get("aws:requesttag/department"), Some(&SessionValue::String("Engineering".to_string())));
        assert_eq!(context.get("aws:resourcetag/DEPARTMENT"), Some(&SessionValue::String("Engineering".to_string())));
        assert_eq!(context.get("IAM:ResourceTag/Department"), Some(&SessionValue::String("Engineering".to_string())));
    }

    /// A request naming no tags supplies none of these keys, so a policy conditioned on a tag the
    /// request does not carry does not match rather than matching an empty string -- and an empty
    /// `aws:TagKeys` is not reported, which says no more than an absent one.
    #[test]
    fn creating_an_entity_without_tags_supplies_no_tag_keys() {
        let context = created_resource_tag_context(&[]);

        assert_eq!(context.get(&format!("{SESSION_KEY_PREFIX_AWS_REQUEST_TAG}Department")), None);
        assert_eq!(context.get(&format!("{SESSION_KEY_PREFIX_AWS_RESOURCE_TAG}Department")), None);
        assert_eq!(context.get(&format!("{SESSION_KEY_PREFIX_IAM_RESOURCE_TAG}Department")), None);
        assert_eq!(context.get(SESSION_KEY_AWS_TAG_KEYS), None);
    }

    /// Creating a managed policy reports its tags through the service-agnostic keys, the
    /// Creating a managed policy supplies no `iam:` condition key at all -- confirmed against the
    /// service. IAM defines `iam:ResourceTag/${TagKey}` for its entities, not for managed
    /// policies, so a policy guarding CreatePolicy through it never matches; supplying it would
    /// make a `StringEquals` guard match, and a `StringNotEquals` deny guard fire, where IAM
    /// The `iam:ResourceTag/${TagKey}` spelling is what separates creating an entity from
    /// Creating a managed policy reports the same keys creating a user or a role does, the
    /// `iam:ResourceTag/${TagKey}` spelling included.
    ///
    /// The IAM documentation lists the `iam:` keys for CreateUser and CreateRole but not for
    /// CreatePolicy. The service does not agree with its own documentation here, and this
    /// follows the service: a grant conditioned on `iam:ResourceTag/${TagKey}` allows CreatePolicy
    /// when the requested tag matches and denies it when it does not, which an absent key could
    /// not produce. See `created_resource_tag_context` for the experiment.
    #[test]
    fn creating_a_policy_reports_the_iam_resource_tag_spelling_too() {
        let context = created_resource_tag_context(&tags(&[("Department", "Engineering")]));

        assert_eq!(
            context.get(&format!("{SESSION_KEY_PREFIX_AWS_REQUEST_TAG}Department")),
            Some(&SessionValue::String("Engineering".to_string()))
        );
        assert_eq!(
            context.get(&format!("{SESSION_KEY_PREFIX_AWS_RESOURCE_TAG}Department")),
            Some(&SessionValue::String("Engineering".to_string()))
        );
        assert_eq!(
            context.get(&format!("{SESSION_KEY_PREFIX_IAM_RESOURCE_TAG}Department")),
            Some(&SessionValue::String("Engineering".to_string()))
        );
        assert_eq!(
            context.get(SESSION_KEY_AWS_TAG_KEYS),
            Some(&SessionValue::List(vec![SessionValue::String("Department".to_string())]))
        );
    }

    /// The tags already on an entity are reported through the resource-tag keys alone: an
    /// operation acting on an existing entity is not asking for those tags, so nothing about it
    /// is a request tag.
    #[test]
    fn existing_entity_tags_are_not_request_tags() {
        let context = resource_tag_context(&tags(&[("Department", "Engineering")]));

        assert_eq!(
            context.get(&format!("{SESSION_KEY_PREFIX_AWS_RESOURCE_TAG}Department")),
            Some(&SessionValue::String("Engineering".to_string()))
        );
        assert_eq!(
            context.get(&format!("{SESSION_KEY_PREFIX_IAM_RESOURCE_TAG}Department")),
            Some(&SessionValue::String("Engineering".to_string()))
        );
        assert_eq!(context.get(&format!("{SESSION_KEY_PREFIX_AWS_REQUEST_TAG}Department")), None);
        assert_eq!(context.get(SESSION_KEY_AWS_TAG_KEYS), None);
    }
}
