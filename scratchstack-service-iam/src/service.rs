use {
    crate::{constants::*, operations::list_users},
    axum::{
        body::{Body, Bytes},
        extract::{Extension, RawQuery, State},
        response::Response,
    },
    scratchstack_aws_principal::{Principal, SessionData},
    scratchstack_core::{RequestId, response::Responder as _},
    scratchstack_shapes_iam::{
        action::{Action, VERSION as IAM_VERSION},
        types::error::{InternalFailure, InvalidAction, MalformedInput},
    },
    sqlx::postgres::PgPool,
    std::{borrow::Cow, str::from_utf8, sync::Arc},
};

/// Service state for handling requests.
#[derive(Clone)]
pub(crate) struct ServiceState {
    /// Connection to the IAM database.
    pub(crate) db: Arc<PgPool>,
}

#[axum::debug_handler]
pub(crate) async fn serve_request(
    State(svc_state): State<ServiceState>,
    request_id: RequestId,
    Extension(principal): Extension<Principal>,
    Extension(session_data): Extension<SessionData>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response<Body> {
    let body = match from_utf8(&body) {
        Ok(body) => body,
        Err(e) => {
            log::debug!("{request_id}: Request body is not valid UTF-8: {e}");
            return malformed_input(request_id);
        }
    };

    // The AWS query protocol carries parameters in the query string, in the body, or split across
    // both; SigV4 signs both, so we join them into a single parameter list. Body parameters are
    // appended last so they win if a parameter appears in both places. These are left url-encoded
    // here; each operation deserializes the parameters into its own request type.
    let query = query.as_deref().unwrap_or_default();
    let parameters: Cow<'_, str> = match (query, body) {
        ("", body) => Cow::Borrowed(body),
        (query, "") => Cow::Borrowed(query),
        (query, body) => Cow::Owned(format!("{query}&{body}")),
    };

    let mut action: Cow<'_, str> = Cow::Borrowed(NO_ACTION_SPECIFIED);
    let mut version: Cow<'_, str> = Cow::Borrowed(NO_VERSION_SPECIFIED);

    for (key, value) in form_urlencoded::parse(parameters.as_bytes()) {
        match key.as_ref() {
            QP_ACTION => action = value,
            QP_VERSION => version = value,
            _ => (),
        }
    }

    if version != IAM_VERSION {
        return invalid_action(request_id, &action, &version);
    }

    match action.parse::<Action>() {
        Ok(Action::ListUsers) => list_users(svc_state, request_id, principal, session_data, &parameters).await,
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
