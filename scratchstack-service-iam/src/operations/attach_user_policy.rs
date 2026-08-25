use {
    crate::{
        authz::{check_authorization, policy_arn_context, resource_tag_context},
        constants::*,
        operations::user_resource,
        service::{RequestMetadata, ServiceState, internal_failure, malformed_input},
    },
    scratchstack_aws_principal::{Principal, SessionData, SessionValue},
    scratchstack_aws_signature::SessionPolicies,
    scratchstack_core::{
        RequestId,
        axum::{body::Body, response::Response},
        query::from_query_str,
        response::Responder as _,
    },
    scratchstack_iam_database::RequestExecutor as _,
    scratchstack_shapes_iam::{
        action::Action,
        operation::{AttachUserPolicyInternalRequest, AttachUserPolicyRequest, AttachUserPolicyResponseEnvelope},
    },
};

/// Handle an `AttachUserPolicy` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:AttachUserPolicy` on the user the policy is attached to;
/// the account root user is implicitly allowed.
///
/// A managed policy is a resource of its own, unlike the inline policies
/// [`crate::operations::put_user_policy`] writes, but it is not the resource this action acts on:
/// IAM gives `iam:AttachUserPolicy` the user as its resource type, so the action is authorized
/// against the user's ARN alone. The policy being attached is named by the `iam:PolicyARN`
/// condition key instead, which is what lets a grant say which policies a caller may hand out
/// without saying anything about which users may receive them, or the reverse.
///
/// Both halves matter, because attaching a managed policy grants its permissions to the user:
/// `iam:AttachUserPolicy` on a user is a privilege escalation unless it is confined by
/// `iam:PolicyARN` to policies no more privileged than the caller. Nothing here checks that the
/// caller holds the permissions the policy grants; IAM does not either.
///
/// The policy may belong to the caller's account or be an AWS-managed policy; the attachment
/// itself is idempotent, so attaching a policy the user already carries succeeds and changes
/// nothing.
pub(crate) async fn attach_user_policy(
    svc_state: ServiceState,
    request_id: RequestId,
    principal: Principal,
    session_data: SessionData,
    session_policies: SessionPolicies,
    request_metadata: RequestMetadata,
    parameters: &str,
) -> Response<Body> {
    let Some(SessionValue::String(account_id)) = session_data.get(SESSION_KEY_AWS_PRINCIPAL_ACCOUNT) else {
        log::error!("{request_id}: Missing or non-string {SESSION_KEY_AWS_PRINCIPAL_ACCOUNT} in session data");
        return internal_failure(request_id);
    };
    let account_id = account_id.clone();

    let request: AttachUserPolicyRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse AttachUserPolicy parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let user_name = request.user_name;

    // Building the internal request validates the user name and the length of the policy ARN, so
    // a malformed request is rejected before it is authorized. Whether the ARN names a policy at
    // all -- or names one that exists -- is settled by the attachment itself, after
    // authorization, so an unauthorized caller is told no more than that.
    let request = match AttachUserPolicyInternalRequest::builder()
        .account_id(account_id.clone())
        .policy_arn(request.policy_arn)
        .user_name(user_name.clone())
        .build()
    {
        Ok(request) => request,
        Err(mut e) => {
            e.request_id = Some(request_id.to_string());
            return e.respond();
        }
    };

    let mut tx = match svc_state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            log::error!("{request_id}: Could not begin database transaction: {e}");
            return internal_failure(request_id);
        }
    };

    let (resource_arn, resource_tags) = match user_resource(&mut tx, request_id, &account_id, &user_name).await {
        Ok(resource) => resource,
        Err(response) => return *response,
    };

    // The policy being attached and the user receiving it are distinct facts, exposed through
    // distinct condition keys, so both are supplied: a policy can be conditioned on what is being
    // attached, on who is receiving it, or on both at once.
    let mut request_context = policy_arn_context(&request.policy_arn);
    request_context.extend(&resource_tag_context(&resource_tags));

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::AttachUserPolicy,
        &[resource_arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The attachment reports a user or a policy that does not exist as `NoSuchEntity` itself, so
    // neither missing case needs separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => AttachUserPolicyResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial write.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
