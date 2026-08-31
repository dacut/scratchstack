use {
    crate::{
        authz::check_authorization,
        constants::*,
        group::group_resource,
        policy::encode_policy_document,
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
        operation::{GetGroupPolicyInternalRequest, GetGroupPolicyRequest, GetGroupPolicyResponseEnvelope},
    },
};

/// Handle a `GetGroupPolicy` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:GetGroupPolicy` on the group the policy is embedded in;
/// the account root user is implicitly allowed.
///
/// An inline policy is not a resource of its own -- it is part of the group carrying it -- so the
/// action is authorized against the group's ARN, and `PolicyName` narrows nothing. A caller
/// allowed to read one inline policy on a group is allowed to read every one of them.
///
/// The group ARN is the whole of what a policy can condition on here: a group is not taggable,
/// IAM having no group-tagging operation, and is not a principal, so it carries no permissions
/// boundary. The request context is therefore empty, matching `GetGroup` and the rest of the
/// group operations.
///
/// `GroupName` and `PolicyName` are both required; neither defaults.
///
/// The policy document is reported percent-encoded rather than as the JSON it is stored as, which
/// is what IAM does; a client URL-decodes it to read the policy back.
pub(crate) async fn get_group_policy(
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

    let request: GetGroupPolicyRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse GetGroupPolicy parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let group_name = request.group_name;

    // Building the internal request validates the group name and the policy name, so a malformed
    // request is rejected before it is authorized.
    let request = match GetGroupPolicyInternalRequest::builder()
        .account_id(account_id.clone())
        .group_name(group_name.clone())
        .policy_name(request.policy_name)
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

    let resource_arn = match group_resource(&mut tx, request_id, &account_id, &group_name).await {
        Ok(arn) => arn,
        Err(response) => return *response,
    };

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::GetGroupPolicy,
        &[resource_arn],
        &SessionData::new(),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The read reports a group or a policy that does not exist as `NoSuchEntity` itself, so the
    // missing cases need no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(mut response) => {
            // The database returns the document as it was stored; IAM reports it percent-encoded.
            response.policy_document = encode_policy_document(&response.policy_document);
            GetGroupPolicyResponseEnvelope::builder().result(response).request_id(request_id).build().respond()
        }
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
