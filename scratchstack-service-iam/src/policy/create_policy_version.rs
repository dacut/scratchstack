use {
    crate::{
        authz::{check_authorization, resource_tag_context},
        constants::*,
        policy::{no_such_policy, policy_is_owned, policy_operand, policy_resource_arn},
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
        operation::{CreatePolicyVersionRequest, CreatePolicyVersionResponseEnvelope},
    },
};

/// Handle a `CreatePolicyVersion` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:CreatePolicyVersion` on the policy being versioned; the
/// account root user is implicitly allowed.
///
/// `PolicyArn` and `PolicyDocument` are required. Only the caller's own account's policies can be
/// versioned: an AWS-managed policy is shared by every account and versioned by none, and a policy
/// in another account is not the caller's to change, so an ARN naming either is reported as naming
/// no policy.
///
/// `SetAsDefault` makes the new version the one the policy grants by; it needs no second action,
/// since creating a version a policy immediately grants by is what this operation is for. A policy
/// that already has the maximum number of versions is reported as a `LimitExceeded`, and the
/// caller must delete a version before adding another.
///
/// The new version's document is not reported back. IAM returns a policy document only from
/// `GetPolicyVersion`, and this response carries the version's identity alone.
pub(crate) async fn create_policy_version(
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

    let request: CreatePolicyVersionRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse CreatePolicyVersion parameters: {e}");
            return malformed_input(request_id);
        }
    };

    // Rebuilding the request validates the length of the ARN and of the document, and parsing the
    // ARN settles that it names a policy at all, so a malformed request is rejected before it is
    // authorized -- as it is for every other operation, and as AWS does. Whether the document is a
    // policy is settled by the creation itself, after authorization.
    let request = match CreatePolicyVersionRequest::builder()
        .policy_arn(request.policy_arn)
        .policy_document(request.policy_document)
        .set_set_as_default(request.set_as_default)
        .build()
    {
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

    // The version is added to an existing policy, so the resource ARN and the tags a condition may
    // be written against are read from that policy rather than from the request.
    let owned = policy_is_owned(&account_id, &policy_arn);
    let (resource_arn, resource_tags) = match policy_operand(&mut tx, request_id, &account_id, &policy_arn, owned).await
    {
        Ok(resource) => resource,
        Err(response) => return *response,
    };

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::CreatePolicyVersion,
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

    // The creation reports a policy that does not exist as `NoSuchEntity` itself, so the missing
    // case needs no separate handling here.
    let mut response = match request.execute(&mut tx, request_id).await {
        Ok(response) => response,
        // Dropping the transaction rolls back the partial creation.
        Err(e) => return e.respond(),
    };

    // The database reports the document it stored, since a caller inside the service may want it;
    // IAM does not report one here, so it is dropped on the way out rather than percent-encoded.
    if let Some(policy_version) = response.policy_version.as_mut() {
        policy_version.document = None;
    }

    let response =
        CreatePolicyVersionResponseEnvelope::builder().result(response).request_id(request_id).build().respond();

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
