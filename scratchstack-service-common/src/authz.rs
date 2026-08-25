//! Authorization support shared by the Scratchstack service implementations.
//!
//! Every operation of every service is authorized the same way: the condition keys the request
//! itself supplies are layered onto the session data the authentication layer produced, the
//! policies governing the caller are gathered from the IAM database, and the two are handed to
//! the policy evaluator. None of that varies with the service being called, so it lives here.
//!
//! What does vary is how a service reports the outcome: each has its own generated error shapes.
//! The check therefore reports what went wrong as an [`AuthorizationError`] and leaves the
//! rendering to the service, which knows how to build its own responses.
//!
//! A service that authorizes a request against something other than the caller's identity-based
//! policies -- a resource-based policy such as a role's trust policy, say -- builds its own
//! [`PolicySet`] and evaluates it with [`evaluate`], reporting a denial with the sentence
//! [`access_denied_message`] builds.

use {
    crate::{RequestMetadata, constants::*},
    chrono::Utc,
    scratchstack_arn::Arn,
    scratchstack_aspen::{AuthorizationResult, Context, Decision, PolicySet, PolicySource, authorize},
    scratchstack_aws_principal::{IamResourceType, Principal, SessionData, SessionValue},
    scratchstack_aws_signature::SessionPolicies,
    scratchstack_core::RequestId,
    scratchstack_iam_database::authz::{get_policies_by_ids, get_policies_for_role, get_policies_for_user},
    scratchstack_shapes_iam::error_meta::Error as IamError,
    sqlx::postgres::PgTransaction,
};

/// Why a request was not authorized.
///
/// Authorization always fails closed: every variant refuses the request. They are distinguished
/// only so that a service can report each one with the error shape its callers expect.
#[derive(Debug)]
pub enum AuthorizationError {
    /// The policies governing the caller do not allow the request.
    ///
    /// The message is the complete sentence AWS reports with an access denial, ready to be
    /// carried by the service's own access-denied error shape.
    AccessDenied(String),

    /// The policies governing the caller could not be read.
    ///
    /// Identity-based policies are read from the IAM database whichever service is being called,
    /// so the failure is described by IAM's error shapes. A service whose callers would not
    /// understand an IAM error reports an internal failure instead.
    Database(IamError),

    /// Authorization could not be performed at all: the session data does not describe a caller
    /// whose policies can be gathered, or a stored policy could not be evaluated.
    ///
    /// The caller can act on none of these, so a service reports its internal-failure error.
    InternalFailure,
}

/// Authorize `action` on `resources` for the calling principal, gathering the principal's
/// identity-based policies inside `tx`.
///
/// An IAM user caller is governed by the user's policies (including group-inherited policies and
/// any permissions boundary); an assumed-role caller is governed by the role's policies and any
/// permissions boundary, intersected with the session policies supplied to `sts:AssumeRole`
/// (carried in `session_policies`). The account root user is governed by neither, and is allowed
/// whatever it asks for.
///
/// `service` and `action` name the operation being invoked, as a policy's `Action` element spells
/// them: `iam` and `GetUser`, for instance.
///
/// `resources` holds the resource ARNs the request operates on; pass an empty slice for
/// operations without resource-level permissions (policies must then grant the action with
/// `Resource: "*"`).
///
/// `session_data` describes the caller and the request, as [`request_session_data`] assembles it.
/// Passing session data that has not been through it evaluates the request without the condition
/// keys the request itself supplies, which fails open for a policy conditioned on them.
///
/// Returns `Ok(())` when the request is allowed, and otherwise the reason it was not.
// What is left after the connection facts are folded into `session_data` are distinct facets of
// the request being authorized -- the caller, the policies governing it, and what it acts on --
// with no further grouping to make; bundling those would only move the argument list into a
// builder call at each call site.
#[allow(clippy::too_many_arguments)]
pub async fn check_authorization(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    principal: &Principal,
    session_data: &SessionData,
    session_policies: &SessionPolicies,
    service: &str,
    action: &str,
    resources: &[Arn],
) -> Result<(), AuthorizationError> {
    // The account root user is not constrained by identity-based policies or permissions
    // boundaries (and has no user row to gather policies for). Nothing in the system mints root
    // sessions carrying session policies, so a restricted root session is an invariant
    // violation; fail closed rather than silently ignore the restriction.
    if principal.as_root_user().is_some() {
        if !session_policies.is_empty() {
            log::error!("{request_id}: Root user session unexpectedly carries session policies");
            return Err(AuthorizationError::InternalFailure);
        }
        log::debug!("{request_id}: Implicitly allowing root user to invoke {service}:{action}");
        return Ok(());
    }

    let Some(policy_set) = identity_policy_set(tx, request_id, session_data, session_policies).await? else {
        // A managed session policy no longer resolves (e.g. it was deleted after the session was
        // created). The session gate cannot be reconstructed, so nothing can be allowed; this is
        // a legitimate runtime state, so deny rather than fail with an internal error.
        log::info!("{request_id}: {service}:{action} denied (unresolvable managed session policy)");
        let mut message = access_denied_message(session_data, principal, service, action, resources);
        message.push_str(&format!(" because no session policy allows the {service}:{action} action"));
        return Err(AuthorizationError::AccessDenied(message));
    };

    let result = evaluate(request_id, principal, session_data.clone(), service, action, resources, &policy_set)?;

    if result.is_allowed() {
        log::debug!("{request_id}: {service}:{action} allowed by {:?}", result.sources());
        return Ok(());
    }

    log::info!("{request_id}: {service}:{action} denied ({}) by {:?}", result.decision(), result.sources());

    let mut message = access_denied_message(session_data, principal, service, action, resources);
    if let Some(detail) = denial_detail(&result, service, action) {
        message.push_str(&detail);
    }

    Err(AuthorizationError::AccessDenied(message))
}

/// Evaluate `policy_set` for a request, reporting what the policies decided.
///
/// This is the evaluator every authorization gate runs, whether the policies came from the
/// caller's identity, from the resource being acted on, or from both gathered into one set.
/// [`check_authorization`] runs it over the caller's identity-based policies; a service with a
/// resource-based policy to consult runs it over that.
///
/// `session_data` describes the caller and the request, as [`request_session_data`] assembles it.
///
/// A policy that cannot be evaluated fails closed: it must not grant access, and the failure is
/// an operational problem rather than the caller's.
pub fn evaluate<'p>(
    request_id: RequestId,
    principal: &Principal,
    session_data: SessionData,
    service: &str,
    action: &str,
    resources: &[Arn],
    policy_set: &'p PolicySet,
) -> Result<AuthorizationResult<'p>, AuthorizationError> {
    let context = match Context::builder()
        .api(action)
        .actor(principal.clone())
        .resources(resources.to_vec())
        .service(service)
        .session_data(session_data)
        .build()
    {
        Ok(context) => context,
        Err(e) => {
            log::error!("{request_id}: Failed to build evaluation context for {service}:{action}: {e}");
            return Err(AuthorizationError::InternalFailure);
        }
    };

    match authorize(&context, policy_set) {
        Ok(result) => Ok(result),
        Err(e) => {
            log::error!("{request_id}: Failed to evaluate policies for {service}:{action}: {e}");
            Err(AuthorizationError::InternalFailure)
        }
    }
}

/// Build the base "not authorized" sentence for an access-denied message, deriving the
/// principal's display ARN from the `aws:PrincipalArn` session value when present.
///
/// A gate that can say more about why the request was refused appends its own clause; the
/// sentence is complete without one.
pub fn access_denied_message(
    session_data: &SessionData,
    principal: &Principal,
    service: &str,
    action: &str,
    resources: &[Arn],
) -> String {
    let principal_arn = match session_data.get(SESSION_KEY_AWS_PRINCIPAL_ARN) {
        Some(SessionValue::String(arn)) => arn.clone(),
        _ => match Arn::try_from(principal) {
            Ok(arn) => arn.to_string(),
            Err(_) => principal.to_string(),
        },
    };
    let resource = match resources.first() {
        Some(arn) => arn.to_string(),
        None => "*".to_string(),
    };

    format!("User: {principal_arn} is not authorized to perform: {service}:{action} on resource: {resource}")
}

/// Layer the condition keys the request itself supplies onto the session data the authentication
/// layer produced for the caller.
///
/// `request_metadata` describes the request itself -- the connection it arrived on and the
/// headers it announced itself with -- and supplies the `aws:SecureTransport`, `aws:SourceIp`,
/// `aws:referer`, and `aws:UserAgent` condition keys.
///
/// `request_context` holds the keys derived from the operation's own arguments and from the
/// resources it names -- the tags on those resources, for example. Building them separately keeps
/// the operation's knowledge of its resources out of the authorization check;
/// [`resource_account_context`] and [`resource_tag_context`] build the ones every service shares.
///
/// `aws:ResourceAccount` is derived from `resources`, so that every operation with resource-level
/// permissions supplies it without having to remember to. An operation without a resource ARN to
/// derive it from names the account through `request_context` instead.
///
/// Every key here is layered on top of the caller's session data rather than read from the
/// request, so a caller cannot supply any of them.
pub fn request_session_data(
    session_data: &SessionData,
    request_metadata: &RequestMetadata,
    resources: &[Arn],
    request_context: &SessionData,
) -> SessionData {
    let mut session_data = session_data.clone();
    session_data.extend(request_context);

    // The condition keys naming the time must reflect the time of evaluation, not the time of
    // signature verification.
    let now = Utc::now();
    session_data.insert(SESSION_KEY_AWS_CURRENT_TIME, SessionValue::Timestamp(now));
    session_data.insert(SESSION_KEY_AWS_EPOCH_TIME, SessionValue::Integer(now.timestamp()));
    session_data.insert(SESSION_KEY_AWS_SECURE_TRANSPORT, SessionValue::Bool(request_metadata.secure_transport));
    session_data.insert(SESSION_KEY_AWS_SOURCE_IP, SessionValue::IpAddr(request_metadata.source_ip));

    // A header the caller did not send leaves its key out of the session data entirely, so a
    // condition on it does not match rather than matching an empty string.
    if let Some(referer) = &request_metadata.referer {
        session_data.insert(SESSION_KEY_AWS_REFERER, SessionValue::String(referer.clone()));
    }
    if let Some(user_agent) = &request_metadata.user_agent {
        session_data.insert(SESSION_KEY_AWS_USER_AGENT, SessionValue::String(user_agent.clone()));
    }

    // The account owning the resources the request names, taken from their ARNs. This does not
    // overwrite what `request_context` had unless a resource actually says otherwise. Resources
    // within one request belong to the same account; if they somehow disagree, no single account
    // describes the request, so the key is left as the request context had it rather than
    // guessed at.
    if let Some((first, rest)) = resources.split_first()
        && rest.iter().all(|arn| arn.account_id() == first.account_id())
    {
        session_data.insert(SESSION_KEY_AWS_RESOURCE_ACCOUNT, SessionValue::String(first.account_id().to_string()));
    }

    session_data
}

/// Build the condition keys describing the account an operation acts on when it names no
/// resource ARN, for the `request_context` argument of [`request_session_data`].
///
/// An operation with resource-level permissions has its `aws:ResourceAccount` derived from the
/// resource ARNs it names; one without has no ARN to derive it from and knows the account only
/// from the request itself.
pub fn resource_account_context(account_id: &str) -> SessionData {
    let mut context = SessionData::with_capacity(1);
    context.insert(SESSION_KEY_AWS_RESOURCE_ACCOUNT, SessionValue::String(account_id.to_string()));
    context
}

/// Build the service-agnostic condition keys describing the tags attached to the resource a
/// request operates on, for the `request_context` argument of [`request_session_data`].
///
/// `tags` names each tag as a key/value pair. A service that also exposes resource tags through a
/// condition key of its own -- IAM's `iam:ResourceTag/${TagKey}`, for instance -- adds those to
/// the returned context. Tag keys are compared case-insensitively, which [`SessionData`] provides
/// by lower-casing keys as they are inserted.
pub fn resource_tag_context<'a>(tags: impl IntoIterator<Item = (&'a str, &'a str)>) -> SessionData {
    let tags = tags.into_iter();
    let mut context = SessionData::with_capacity(tags.size_hint().0);

    for (key, value) in tags {
        context.insert(&format!("{SESSION_KEY_PREFIX_AWS_RESOURCE_TAG}{key}"), SessionValue::String(value.to_string()));
    }

    context
}

/// The clause explaining a denial, appended to the sentence [`access_denied_message`] builds.
///
/// A denial whose sources are all session policies means no session policy allowed the action;
/// all permissions boundaries means no boundary allowed it; anything else involves an explicit
/// deny statement. (An explicit deny inside a session or boundary policy is reported with the
/// corresponding wording as well.) A request that was simply never allowed says nothing further:
/// the sentence already reports it.
fn denial_detail(result: &AuthorizationResult<'_>, service: &str, action: &str) -> Option<String> {
    if result.decision() != Decision::Deny {
        return None;
    }

    let sources = result.sources();
    if !sources.is_empty() && sources.iter().all(|source| matches!(source, PolicySource::Session)) {
        Some(format!(" because no session policy allows the {service}:{action} action"))
    } else if !sources.is_empty() && sources.iter().all(|source| source.is_boundary()) {
        Some(format!(" because no permissions boundary allows the {service}:{action} action"))
    } else {
        Some(" with an explicit deny in an identity-based policy".to_string())
    }
}

/// Gather the policies governing the calling principal, as the session data identifies it.
///
/// Session policies form an additional gate on top of the principal's identity-based policies:
/// every session policy supplied to `sts:AssumeRole` must also allow the action. The inline
/// document travels in the session token; managed session policies are recorded by id and
/// resolve to their current default version here.
///
/// Returns `Ok(None)` when a managed session policy no longer resolves, which leaves the session
/// gate unreconstructable rather than unauthorized.
async fn identity_policy_set(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    session_data: &SessionData,
    session_policies: &SessionPolicies,
) -> Result<Option<PolicySet>, AuthorizationError> {
    let Some(SessionValue::String(account_id)) = session_data.get(SESSION_KEY_AWS_PRINCIPAL_ACCOUNT) else {
        log::error!("{request_id}: Missing or non-string {SESSION_KEY_AWS_PRINCIPAL_ACCOUNT} in session data");
        return Err(AuthorizationError::InternalFailure);
    };

    let Some(SessionValue::String(prefixed_user_id)) = session_data.get(SESSION_KEY_AWS_USERID) else {
        log::error!("{request_id}: Missing or non-string {SESSION_KEY_AWS_USERID} in session data");
        return Err(AuthorizationError::InternalFailure);
    };

    // The session user id identifies the calling principal: an IAM user carries the internal
    // user id with the IAM user prefix ("AIDA") prepended, while an assumed-role session carries
    // the internal role id with the IAM role prefix ("AROA") prepended and the role session name
    // appended after a colon. Strip the decorations to recover the database key and gather the
    // matching principal's policies.
    let result = if let Some(user_id) = prefixed_user_id.strip_prefix(IamResourceType::User.as_str()) {
        get_policies_for_user(tx, account_id, user_id, request_id).await
    } else if let Some(role_id) = prefixed_user_id.strip_prefix(IamResourceType::Role.as_str()) {
        let role_id = role_id.split_once(':').map_or(role_id, |(role_id, _session_name)| role_id);
        get_policies_for_role(tx, account_id, role_id, request_id).await
    } else {
        log::error!(
            "{request_id}: Session {SESSION_KEY_AWS_USERID} {prefixed_user_id} is not an IAM user or assumed-role id"
        );
        return Err(AuthorizationError::InternalFailure);
    };

    let mut policy_set = result.map_err(AuthorizationError::Database)?;

    if let Some(policy) = session_policies.inline_policy() {
        policy_set.add_policy(PolicySource::new_session(), policy.clone());
    }

    if !session_policies.managed_policy_ids().is_empty() {
        match get_policies_by_ids(tx, session_policies.managed_policy_ids(), request_id).await {
            Ok(Some(policies)) => {
                for policy in policies {
                    policy_set.add_policy(PolicySource::new_session(), policy);
                }
            }
            Ok(None) => return Ok(None),
            Err(e) => return Err(AuthorizationError::Database(e)),
        }
    }

    Ok(Some(policy_set))
}

#[cfg(test)]
mod tests {
    use {
        super::{access_denied_message, request_session_data, resource_account_context, resource_tag_context},
        crate::{RequestMetadata, constants::*},
        pretty_assertions::assert_eq,
        scratchstack_arn::Arn,
        scratchstack_aws_principal::{Principal, SessionData, SessionValue, User},
        std::{
            net::{IpAddr, Ipv4Addr},
            str::FromStr as _,
        },
    };

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    const OTHER_ACCOUNT_ID: &str = "222222222222";
    const TEST_ACCOUNT_ID: &str = "123456789012";

    /// The principal and session data the SigV4 layer would produce for an IAM user.
    fn user_identity() -> (Principal, SessionData) {
        let principal = Principal::from(
            User::builder()
                .partition("aws")
                .account_id(TEST_ACCOUNT_ID)
                .path("/")
                .user_name("Alice")
                .build()
                .expect("failed to build user"),
        );
        let mut session_data = SessionData::new();
        session_data.insert(SESSION_KEY_AWS_PRINCIPAL_ACCOUNT, SessionValue::String(TEST_ACCOUNT_ID.to_string()));
        session_data.insert(
            SESSION_KEY_AWS_PRINCIPAL_ARN,
            SessionValue::String(format!("arn:aws:iam::{TEST_ACCOUNT_ID}:user/Alice")),
        );

        (principal, session_data)
    }

    /// The metadata for a request from [`CLIENT`] that announced nothing about itself.
    fn bare_metadata() -> RequestMetadata {
        RequestMetadata::builder().secure_transport(true).source_ip(CLIENT).build()
    }

    /// The ARN of a user in `account_id`.
    fn user_arn(account_id: &str) -> Arn {
        Arn::from_str(&format!("arn:aws:iam::{account_id}:user/Bob")).expect("failed to build ARN")
    }

    /// The connection a request arrived on backs condition keys of its own, whatever the caller
    /// signed.
    #[test]
    fn the_connection_supplies_its_own_condition_keys() {
        let (_, session_data) = user_identity();

        let session_data = request_session_data(&session_data, &bare_metadata(), &[], &SessionData::new());

        assert_eq!(session_data.get(SESSION_KEY_AWS_SECURE_TRANSPORT), Some(&SessionValue::Bool(true)));
        assert_eq!(session_data.get(SESSION_KEY_AWS_SOURCE_IP), Some(&SessionValue::IpAddr(CLIENT)));
        assert!(session_data.get(SESSION_KEY_AWS_CURRENT_TIME).is_some());
        assert!(session_data.get(SESSION_KEY_AWS_EPOCH_TIME).is_some());

        // A header the caller did not send leaves its key absent rather than empty, so a
        // condition on it does not match.
        assert_eq!(session_data.get(SESSION_KEY_AWS_REFERER), None);
        assert_eq!(session_data.get(SESSION_KEY_AWS_USER_AGENT), None);
    }

    /// The headers a caller chose to send are reported as it sent them.
    #[test]
    fn the_headers_supply_their_condition_keys() {
        let (_, session_data) = user_identity();
        let metadata = RequestMetadata::builder()
            .referer("https://example.com/console".to_string())
            .secure_transport(false)
            .source_ip(CLIENT)
            .user_agent("aws-cli/2.15.0".to_string())
            .build();

        let session_data = request_session_data(&session_data, &metadata, &[], &SessionData::new());

        assert_eq!(
            session_data.get(SESSION_KEY_AWS_REFERER),
            Some(&SessionValue::String("https://example.com/console".to_string()))
        );
        assert_eq!(
            session_data.get(SESSION_KEY_AWS_USER_AGENT),
            Some(&SessionValue::String("aws-cli/2.15.0".to_string()))
        );
        assert_eq!(session_data.get(SESSION_KEY_AWS_SECURE_TRANSPORT), Some(&SessionValue::Bool(false)));
    }

    /// An operation naming resources has `aws:ResourceAccount` derived from them, so it need not
    /// supply the key itself.
    #[test]
    fn the_resources_supply_the_resource_account() {
        let (_, session_data) = user_identity();
        let resources = [user_arn(OTHER_ACCOUNT_ID), user_arn(OTHER_ACCOUNT_ID)];

        let session_data = request_session_data(&session_data, &bare_metadata(), &resources, &SessionData::new());

        assert_eq!(
            session_data.get(SESSION_KEY_AWS_RESOURCE_ACCOUNT),
            Some(&SessionValue::String(OTHER_ACCOUNT_ID.to_string()))
        );
    }

    /// An operation naming no resource has no ARN to derive the account from, and says which
    /// account it acts on through the request context instead.
    #[test]
    fn the_request_context_supplies_the_resource_account_without_resources() {
        let (_, session_data) = user_identity();

        let session_data =
            request_session_data(&session_data, &bare_metadata(), &[], &resource_account_context(OTHER_ACCOUNT_ID));

        assert_eq!(
            session_data.get(SESSION_KEY_AWS_RESOURCE_ACCOUNT),
            Some(&SessionValue::String(OTHER_ACCOUNT_ID.to_string()))
        );
    }

    /// Resources within one request belong to the same account. If they somehow disagree, no
    /// single account describes the request, so the key is left as the request context had it
    /// rather than guessed at.
    #[test]
    fn resources_in_different_accounts_supply_no_resource_account() {
        let (_, session_data) = user_identity();
        let resources = [user_arn(TEST_ACCOUNT_ID), user_arn(OTHER_ACCOUNT_ID)];

        let session_data = request_session_data(&session_data, &bare_metadata(), &resources, &SessionData::new());

        assert_eq!(session_data.get(SESSION_KEY_AWS_RESOURCE_ACCOUNT), None);
    }

    /// Tag keys are compared case-insensitively, which `SessionData` provides by lower-casing
    /// keys as they are inserted.
    #[test]
    fn resource_tags_become_condition_keys() {
        let context = resource_tag_context([("Department", "Engineering"), ("Project", "Scratchstack")]);

        assert_eq!(context.get("aws:resourcetag/department"), Some(&SessionValue::String("Engineering".to_string())));
        assert_eq!(
            context.get(&format!("{SESSION_KEY_PREFIX_AWS_RESOURCE_TAG}Project")),
            Some(&SessionValue::String("Scratchstack".to_string()))
        );
    }

    /// The denial names the caller by the ARN the session reports, and the resource it asked
    /// for.
    #[test]
    fn the_denial_names_the_caller_and_the_resource() {
        let (principal, session_data) = user_identity();

        assert_eq!(
            access_denied_message(&session_data, &principal, "iam", "GetUser", &[user_arn(TEST_ACCOUNT_ID)]),
            format!(
                "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Alice is not authorized to perform: iam:GetUser on \
                 resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Bob"
            )
        );
    }

    /// An operation without resource-level permissions names no resource, so the denial reports
    /// the wildcard the policies would have had to grant.
    #[test]
    fn a_denial_without_resources_names_the_wildcard() {
        let (principal, session_data) = user_identity();

        assert_eq!(
            access_denied_message(&session_data, &principal, "iam", "ListUsers", &[]),
            format!(
                "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Alice is not authorized to perform: iam:ListUsers on \
                 resource: *"
            )
        );
    }

    /// Session data that does not report the caller's ARN leaves the principal itself to name
    /// the caller.
    #[test]
    fn a_denial_falls_back_to_the_principal_arn() {
        let (principal, _) = user_identity();

        assert_eq!(
            access_denied_message(&SessionData::new(), &principal, "sts", "AssumeRole", &[]),
            format!(
                "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Alice is not authorized to perform: sts:AssumeRole on \
                 resource: *"
            )
        );
    }
}
