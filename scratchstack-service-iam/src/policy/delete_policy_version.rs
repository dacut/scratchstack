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
        operation::{DeletePolicyVersionRequest, DeletePolicyVersionResponseEnvelope},
    },
};

/// Handle a `DeletePolicyVersion` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:DeletePolicyVersion` on the policy the version belongs
/// to; the account root user is implicitly allowed.
///
/// `PolicyArn` and `VersionId` are required. Only the caller's own account's policies can be
/// versioned, so an ARN naming another account -- or the AWS-managed policies, which every account
/// shares and none owns -- is reported as naming no policy.
///
/// A policy's default version cannot be deleted, and the attempt is reported as a
/// `DeleteConflict`; another version must be made the default first. Deleting a version does not
/// delete the policy, which keeps the versions it still has.
pub(crate) async fn delete_policy_version(
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

    let request: DeletePolicyVersionRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse DeletePolicyVersion parameters: {e}");
            return malformed_input(request_id);
        }
    };

    // Rebuilding the request validates the length of the ARN and the shape of the version id, and
    // parsing the ARN settles that it names a policy at all, so a malformed request is rejected
    // before it is authorized -- as it is for every other operation, and as AWS does.
    let request = match DeletePolicyVersionRequest::builder()
        .policy_arn(request.policy_arn)
        .version_id(request.version_id)
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

    // A version is not a resource of its own: `iam:DeletePolicyVersion` is authorized against the
    // policy the version belongs to, so the resource ARN and its tags are read from that policy.
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
        Action::DeletePolicyVersion,
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

    // The delete reports a policy or a version that does not exist as `NoSuchEntity` itself, so
    // neither missing case needs separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => DeletePolicyVersionResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial delete.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
