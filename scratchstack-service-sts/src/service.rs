use {
    crate::{constants::*, model},
    axum::{body::Body, extract::Form, http::StatusCode, response::Response},
    scratchstack_http_framework::RequestId,
    std::collections::HashMap,
};

#[axum::debug_handler]
pub(crate) async fn serve_request(
    request_id: RequestId,
    Form(parameters): Form<HashMap<String, String>>,
) -> Response<Body> {
    let action = parameters.get(QP_ACTION).map(String::as_str).unwrap_or(NO_ACTION_SPECIFIED);
    let version = parameters.get(QP_VERSION).map(String::as_str).unwrap_or(NO_VERSION_SPECIFIED);

    if version != STS_VERSION_20110615 {
        return model::ServiceError::builder()
            .code(ERR_CODE_INVALID_ACTION)
            .r#type(ERR_TYPE_SENDER)
            .message(format!("Could not find operation {action} for version {version}"))
            .build()
            .expect("Failed to build error response")
            .respond(StatusCode::BAD_REQUEST, request_id)
            .expect("Failed to build error response");
    }

    todo!()
}
