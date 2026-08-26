use {
    crate::{
        authz::{check_authorization, request_tag_context},
        constants::*,
        policy::policy_arn,
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
        operation::{CreatePolicyInternalRequest, CreatePolicyRequest, CreatePolicyResponseEnvelope},
    },
};

/// Handle a `CreatePolicy` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:CreatePolicy` on the policy being created; the account
/// root user is implicitly allowed.
///
/// A request that asks for tags must also be allowed `iam:TagPolicy`: creating a policy does not
/// carry permission to tag one.
///
/// The policy is created in the caller's own account, so a caller cannot add to the AWS-managed
/// policies or to another account's. `PolicyName` and `PolicyDocument` are required; `Path`
/// defaults to the root path, and the policy carries the description and tags the request names.
/// The document becomes the policy's first version, `v1`, which is also its default version.
///
/// Nothing here checks that the caller holds the permissions the document grants; IAM does not
/// either. Creating a policy grants nothing on its own -- the permissions reach a principal only
/// once the policy is attached, which `iam:AttachUserPolicy` and its siblings govern.
pub(crate) async fn create_policy(
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

    let request: CreatePolicyRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse CreatePolicy parameters: {e}");
            return malformed_input(request_id);
        }
    };

    // Building the internal request validates the policy name, the path, the description, and the
    // tags, so a malformed request is rejected before it is authorized -- as it is for every other
    // operation, and as AWS does. Whether the document is a policy at all is settled by the
    // creation itself, after authorization.
    let request = match CreatePolicyInternalRequest::builder()
        .account_id(account_id.clone())
        .set_description(request.description)
        .set_path(request.path)
        .policy_document(request.policy_document)
        .policy_name(request.policy_name)
        .set_tags(request.tags)
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

    // The policy does not exist yet, so the ARN it will be created under is built from the request
    // rather than read back: the path the request asks for is part of that ARN, which lets a
    // policy confine a caller to creating policies under a particular path.
    let resource_arn = match policy_arn(
        &mut tx,
        request_id,
        &account_id,
        request.path.as_deref().unwrap_or("/"),
        &request.policy_name,
    )
    .await
    {
        Ok(arn) => arn,
        Err(response) => return *response,
    };

    // The tags are properties the request asks for rather than properties of an existing
    // resource, so they back `aws:RequestTag/${TagKey}` and `aws:TagKeys`.
    let request_context = request_tag_context(request.tags.iter().map(|tag| (tag.key.as_str(), tag.value.as_str())));

    // Tagging a policy is a separately authorized action, and doing it as part of creating the
    // policy does not change that: a caller allowed to create policies is not thereby allowed to
    // tag them. So a request that asks for tags must be allowed iam:TagPolicy as well, against
    // the same policy and the same request context.
    let mut actions = Vec::with_capacity(2);
    actions.push(Action::CreatePolicy);
    if !request.tags.is_empty() {
        actions.push(Action::TagPolicy);
    }

    let resources = [resource_arn];

    for action in actions {
        if let Err(response) = check_authorization(
            &mut tx,
            request_id,
            &principal,
            &session_data,
            &session_policies,
            &request_metadata,
            action,
            &resources,
            &request_context,
        )
        .await
        {
            // Dropping the transaction rolls it back.
            return *response;
        }
    }

    let response = match request.execute(&mut tx, request_id).await {
        Ok(response) => {
            CreatePolicyResponseEnvelope::builder().result(response).request_id(request_id).build().respond()
        }
        // Dropping the transaction rolls back the partial creation.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
