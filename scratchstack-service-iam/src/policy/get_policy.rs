use {
    crate::{
        authz::{check_authorization, resource_tag_context},
        constants::*,
        policy::{no_such_policy, policy_is_visible, policy_resource_arn},
        service::{RequestMetadata, ServiceState, internal_failure, malformed_input},
    },
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{Principal, SessionData, SessionValue},
    scratchstack_aws_signature::SessionPolicies,
    scratchstack_core::{
        RequestId,
        axum::{body::Body, response::Response},
        query::from_query_str,
        response::Responder as _,
    },
    scratchstack_iam_database::policy::get_policy as read_policy,
    scratchstack_shapes_iam::{
        action::Action,
        error_meta::Error as IamError,
        operation::{GetPolicyRequest, GetPolicyResponse, GetPolicyResponseEnvelope},
    },
    std::str::FromStr as _,
};

/// Handle a `GetPolicy` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:GetPolicy` on the policy being read; the account root
/// user is implicitly allowed.
///
/// `PolicyArn` is required and names the policy outright, so there is no account to infer from
/// the caller: the ARN says which account the policy belongs to. A caller reaches only its own
/// account's policies and the AWS-managed ones; an ARN naming any other account is reported as
/// naming no policy, since a managed policy is not shared across customer accounts and a lookup
/// by ARN alone would otherwise hand another account's policy to any caller holding a grant
/// written against `Resource: "*"`.
///
/// This reports the policy's metadata and the identifier of its default version, not the document
/// itself; `GetPolicyVersion` reports the document.
pub(crate) async fn get_policy(
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

    let request: GetPolicyRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse GetPolicy parameters: {e}");
            return malformed_input(request_id);
        }
    };

    // Rebuilding the request validates the length of the ARN, and parsing it settles that it
    // names a policy at all, so a malformed request is rejected before it is authorized -- as it
    // is for every other operation, and as AWS does.
    let request = match GetPolicyRequest::builder().policy_arn(request.policy_arn).build() {
        Ok(request) => request,
        Err(mut e) => {
            e.request_id = Some(request_id.to_string());
            return e.respond();
        }
    };

    let policy_arn = match policy_resource_arn(request_id, &request.policy_arn) {
        Ok(policy_arn) => policy_arn,
        Err(response) => return *response,
    };

    let mut tx = match svc_state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            log::error!("{request_id}: Could not begin database transaction: {e}");
            return internal_failure(request_id);
        }
    };

    // Read the policy before authorizing: the resource ARN carries the policy's path and the
    // stored spelling of its name, and the caller's policies may be conditioned on the policy's
    // tags, none of which the request itself supplies. A policy the caller cannot reach is not
    // looked up at all, and is treated exactly as one that does not exist.
    //
    // The caller's account is what the reported attachment counts are counted within, so the read
    // names it: an AWS-managed policy is attachable in every account, and what this caller is
    // told is how many of its own entities carry the policy.
    let result: Option<GetPolicyResponse> = if policy_is_visible(&account_id, &policy_arn) {
        match read_policy(&mut tx, &account_id, &request.policy_arn, request_id).await {
            Ok(response) => Some(response),
            Err(IamError::NoSuchEntityException(_)) => None,
            Err(e) => return e.respond(),
        }
    } else {
        log::debug!("{request_id}: GetPolicy for {policy_arn}, which account {account_id} cannot reach");
        None
    };

    // Authorization is still evaluated when no such policy exists, so that a caller allowed
    // `iam:GetPolicy` broadly is told the policy does not exist while one allowed it only on
    // specific policies learns nothing at all. There is no policy to read tags from in that case,
    // and the ARN the request named is the only one to authorize against.
    let (resource_arn, resource_tags) = match result.as_ref().and_then(|response| response.policy.as_ref()) {
        Some(policy) => match policy.arn.as_deref().map(Arn::from_str) {
            Some(Ok(arn)) => (arn, policy.tags.as_slice()),
            other => {
                log::error!("{request_id}: Policy {policy_arn} has a missing or unparseable ARN: {other:?}");
                return internal_failure(request_id);
            }
        },
        None => (policy_arn.clone(), [].as_slice()),
    };

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::GetPolicy,
        &[resource_arn],
        &resource_tag_context(resource_tags),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    let response = match result {
        Some(response) => {
            GetPolicyResponseEnvelope::builder().result(response).request_id(request_id).build().respond()
        }
        None => no_such_policy(request_id, &request.policy_arn),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
