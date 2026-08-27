use {
    crate::{
        constants::*,
        group::{
            add_user_to_group, attach_group_policy, create_group, delete_group, delete_group_policy,
            detach_group_policy, get_group, put_group_policy, remove_user_from_group, update_group,
        },
        policy::{
            create_policy, create_policy_version, delete_policy, delete_policy_version, get_policy, get_policy_version,
            list_entities_for_policy, list_policies, list_policy_tags, list_policy_versions,
            set_default_policy_version, tag_policy, untag_policy,
        },
        role::{
            attach_role_policy, create_role, delete_role, delete_role_permissions_boundary, delete_role_policy,
            detach_role_policy, get_role, list_attached_role_policies, list_role_policies, list_role_tags, list_roles,
            put_role_permissions_boundary, put_role_policy, tag_role, untag_role, update_role, update_role_description,
        },
        user::{
            attach_user_policy, create_access_key, create_user, delete_access_key, delete_user,
            delete_user_permissions_boundary, delete_user_policy, detach_user_policy, get_user, get_user_policy,
            list_access_keys, list_attached_user_policies, list_user_policies, list_user_tags, list_users,
            put_user_permissions_boundary, put_user_policy, tag_user, untag_user, update_access_key, update_user,
        },
    },
    scratchstack_aws_principal::{Principal, SessionData},
    scratchstack_aws_signature::SessionPolicies,
    scratchstack_core::{
        RequestId,
        axum::{
            body::{Body, Bytes},
            extract::{ConnectInfo, Extension, RawQuery, State},
            http::HeaderMap,
            response::Response,
        },
        response::Responder as _,
    },
    scratchstack_service_common::query::{join_parameters, scan_action_version},
    scratchstack_shapes_iam::{
        action::{Action, VERSION as IAM_VERSION},
        types::error::{InternalFailure, InvalidAction, MalformedInput},
    },
    std::{net::SocketAddr, str::from_utf8},
};

pub(crate) use scratchstack_service_common::{RequestMetadata, ServiceState};

// A handler's parameters are its extractors: each one pulls a different piece of the request out
// of the pipeline, so there is nothing to bundle.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_request(
    State(svc_state): State<ServiceState>,
    request_id: RequestId,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Extension(principal): Extension<Principal>,
    Extension(session_data): Extension<SessionData>,
    Extension(session_policies): Extension<SessionPolicies>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response<Body> {
    // Policies may be conditioned on the connection the request arrived on, and a missing
    // aws:SourceIp silently satisfies a NotIpAddress condition; a request whose peer address is
    // unknown cannot be evaluated safely, so fail closed.
    let Some(request_metadata) = RequestMetadata::from_request(
        svc_state.secure_transport,
        svc_state.forwarded_for.as_deref(),
        connect_info,
        &headers,
    ) else {
        log::error!("{request_id}: Request carries no connection information");
        return internal_failure(request_id);
    };

    let body = match from_utf8(&body) {
        Ok(body) => body,
        Err(e) => {
            log::debug!("{request_id}: Request body is not valid UTF-8: {e}");
            return malformed_input(request_id);
        }
    };

    let parameters = join_parameters(query.as_deref().unwrap_or_default(), body);
    let (action, version) = scan_action_version(&parameters);

    if version != IAM_VERSION {
        return invalid_action(request_id, &action, &version);
    }

    match action.parse::<Action>() {
        Ok(Action::AddUserToGroup) => {
            add_user_to_group(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::AttachGroupPolicy) => {
            attach_group_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::AttachRolePolicy) => {
            attach_role_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::AttachUserPolicy) => {
            attach_user_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::CreateAccessKey) => {
            create_access_key(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::CreateGroup) => {
            create_group(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::CreatePolicy) => {
            create_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::CreatePolicyVersion) => {
            create_policy_version(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::CreateRole) => {
            create_role(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::CreateUser) => {
            create_user(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::DeleteAccessKey) => {
            delete_access_key(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::DeleteGroup) => {
            delete_group(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::DeleteGroupPolicy) => {
            delete_group_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::DeletePolicy) => {
            delete_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::DeletePolicyVersion) => {
            delete_policy_version(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::DeleteRole) => {
            delete_role(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::DeleteRolePermissionsBoundary) => {
            delete_role_permissions_boundary(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::DeleteRolePolicy) => {
            delete_role_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::DeleteUser) => {
            delete_user(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::DeleteUserPermissionsBoundary) => {
            delete_user_permissions_boundary(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::DeleteUserPolicy) => {
            delete_user_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::DetachGroupPolicy) => {
            detach_group_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::DetachRolePolicy) => {
            detach_role_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::DetachUserPolicy) => {
            detach_user_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::GetGroup) => {
            get_group(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::GetPolicy) => {
            get_policy(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::GetPolicyVersion) => {
            get_policy_version(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::GetRole) => {
            get_role(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::GetUser) => {
            get_user(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::GetUserPolicy) => {
            get_user_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::ListAccessKeys) => {
            list_access_keys(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::ListAttachedRolePolicies) => {
            list_attached_role_policies(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::ListAttachedUserPolicies) => {
            list_attached_user_policies(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::ListEntitiesForPolicy) => {
            list_entities_for_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::ListPolicies) => {
            list_policies(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::ListPolicyTags) => {
            list_policy_tags(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::ListPolicyVersions) => {
            list_policy_versions(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::ListRolePolicies) => {
            list_role_policies(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::ListRoleTags) => {
            list_role_tags(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::ListRoles) => {
            list_roles(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::ListUserPolicies) => {
            list_user_policies(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::ListUserTags) => {
            list_user_tags(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::ListUsers) => {
            list_users(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::PutGroupPolicy) => {
            put_group_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::PutRolePermissionsBoundary) => {
            put_role_permissions_boundary(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::PutRolePolicy) => {
            put_role_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::PutUserPermissionsBoundary) => {
            put_user_permissions_boundary(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::PutUserPolicy) => {
            put_user_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::RemoveUserFromGroup) => {
            remove_user_from_group(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::SetDefaultPolicyVersion) => {
            set_default_policy_version(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::TagPolicy) => {
            tag_policy(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::TagRole) => {
            tag_role(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::TagUser) => {
            tag_user(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::UntagPolicy) => {
            untag_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::UntagRole) => {
            untag_role(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::UntagUser) => {
            untag_user(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::UpdateAccessKey) => {
            update_access_key(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::UpdateGroup) => {
            update_group(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::UpdateRole) => {
            update_role(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::UpdateRoleDescription) => {
            update_role_description(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::UpdateUser) => {
            update_user(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        _ => invalid_action(request_id, &action, &version),
    }
}

/// Generate an `InternalFailure` error response.
pub(crate) fn internal_failure(request_id: RequestId) -> Response<Body> {
    InternalFailure::builder().message(MSG_INTERNAL_FAILURE).request_id(request_id).build().respond()
}

/// Generate an `InvalidAction` error response.
fn invalid_action(request_id: RequestId, action: &str, version: &str) -> Response<Body> {
    InvalidAction::builder()
        .message(format!("Could not find operation {action} for version {version}"))
        .request_id(request_id)
        .build()
        .respond()
}

/// Generate a `MalformedInput` error response.
///
/// IAM does not report a message with this error, so neither do we.
pub(crate) fn malformed_input(request_id: RequestId) -> Response<Body> {
    MalformedInput::builder().request_id(request_id).build().respond()
}

#[cfg(test)]
mod tests;
