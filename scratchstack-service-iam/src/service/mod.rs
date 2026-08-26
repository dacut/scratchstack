use {
    crate::{
        constants::*,
        operations::{
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
        Ok(Action::TagUser) => {
            tag_user(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
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
