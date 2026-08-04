use {
    crate::{constants::*, operations::get_caller_identity},
    axum::{
        body::Body,
        extract::{Extension, Form},
        response::Response,
    },
    lazy_static::lazy_static,
    scratchstack_aws_principal::{Principal, SessionData},
    scratchstack_core::{request_id::RequestId, response::Responder},
    scratchstack_shapes_sts::types::error::InvalidAction,
    std::collections::{HashMap, HashSet},
};

lazy_static! {
    /// A set of known actions
    static ref VALID_ACTIONS: HashSet<&'static str> = HashSet::from([ACTION_GET_CALLER_IDENTITY]);
}

#[axum::debug_handler]
pub(crate) async fn serve_request(
    request_id: RequestId,
    Extension(principal): Extension<Principal>,
    Extension(session_data): Extension<SessionData>,
    Form(parameters): Form<HashMap<String, String>>,
) -> Response<Body> {
    let action = parameters.get(QP_ACTION).map(String::as_str).unwrap_or(NO_ACTION_SPECIFIED);
    let version = parameters.get(QP_VERSION).map(String::as_str).unwrap_or(NO_VERSION_SPECIFIED);

    if version != STS_VERSION_20110615 {
        return InvalidAction::builder()
            .message(format!("Could not find operation {action} for version {version}"))
            .request_id(&request_id)
            .build()
            .respond();
    }

    if !VALID_ACTIONS.contains(action) {
        return InvalidAction::builder()
            .message(format!("Could not find operation {action} for version {version}"))
            .request_id(&request_id)
            .build()
            .respond();
    }

    match action {
        ACTION_GET_CALLER_IDENTITY => get_caller_identity(request_id, principal, session_data),
        _ => todo!(),
    }
}
