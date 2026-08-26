use {
    crate::{
        authz::{check_authorization, resource_tag_context},
        constants::*,
        policy::{no_such_policy, policy_is_owned, policy_resource, policy_resource_arn},
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
        operation::{DeletePolicyRequest, DeletePolicyResponseEnvelope},
    },
};

/// Handle a `DeletePolicy` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:DeletePolicy` on the policy being deleted; the account
/// root user is implicitly allowed.
///
/// `PolicyArn` is required and names the policy outright, so there is no account to infer from
/// the caller: the ARN says which account the policy belongs to. Only the caller's own account's
/// policies can be deleted, and an ARN naming any other account -- including an AWS-managed
/// policy, which every account shares and none owns -- is reported as naming no policy.
///
/// A policy that is still attached to a user, group, or role, that is still serving as a
/// permissions boundary, or that still has versions other than its default cannot be deleted, and
/// the attempt is reported as a `DeleteConflict`. The default version and the policy's tags go
/// with the policy itself.
pub(crate) async fn delete_policy(
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

    let request: DeletePolicyRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse DeletePolicy parameters: {e}");
            return malformed_input(request_id);
        }
    };

    // Rebuilding the request validates the length of the ARN, and parsing it settles that it
    // names a policy at all, so a malformed request is rejected before it is authorized -- as it
    // is for every other operation, and as AWS does.
    let request = match DeletePolicyRequest::builder().policy_arn(request.policy_arn).build() {
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

    // A policy the caller does not own is not looked up, and is treated exactly as one that does
    // not exist: the caller learns nothing about it, and nothing deletes it.
    let owned = policy_is_owned(&account_id, &policy_arn);
    let (resource_arn, resource_tags) = if owned {
        match policy_resource(&mut tx, request_id, &account_id, &policy_arn).await {
            Ok(resource) => resource,
            Err(response) => return *response,
        }
    } else {
        log::debug!("{request_id}: DeletePolicy for {policy_arn}, which account {account_id} does not own");
        (policy_arn.clone(), Vec::new())
    };

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::DeletePolicy,
        &[resource_arn],
        &resource_tag_context(&resource_tags),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    if !owned {
        return no_such_policy(request_id, &request.policy_arn);
    }

    // The delete reports a policy that does not exist as `NoSuchEntity` itself, so the missing
    // case needs no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => DeletePolicyResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial delete.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
