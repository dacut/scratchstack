use {
    crate::{constants::*, operations::get_caller_identity},
    axum::{
        body::Body,
        extract::{Extension, Form},
        response::Response,
    },
    scratchstack_aws_principal::{Principal, SessionData},
    scratchstack_core::{RequestId, response::Responder as _},
    scratchstack_shapes_sts::types::error::InvalidAction,
    std::collections::HashMap,
};

#[axum::debug_handler]
pub(crate) async fn serve_request(
    request_id: RequestId,
    Extension(principal): Extension<Principal>,
    Extension(session_data): Extension<SessionData>,
    Form(parameters): Form<HashMap<String, String>>,
) -> Response<Body> {
    let action = parameters.get(QP_ACTION).map(String::as_str).unwrap_or(NO_ACTION_SPECIFIED);
    let version = parameters.get(QP_VERSION).map(String::as_str).unwrap_or(NO_VERSION_SPECIFIED);

    // AWS reports an unknown action and an unknown version the same way: it cannot find the
    // operation for that (action, version) pair.
    if version != STS_VERSION_20110615 {
        return invalid_action(request_id, action, version);
    }

    match action {
        ACTION_GET_CALLER_IDENTITY => get_caller_identity(request_id, &principal, &session_data),
        _ => invalid_action(request_id, action, version),
    }
}

/// Generate an `InvalidAction` error response.
fn invalid_action(request_id: RequestId, action: &str, version: &str) -> Response<Body> {
    InvalidAction::builder()
        .message(format!("Could not find operation {action} for version {version}"))
        .request_id(request_id)
        .build()
        .respond()
}

#[cfg(test)]
mod tests {
    use {
        super::serve_request,
        crate::constants::*,
        axum::{
            body::Body,
            extract::{Extension, Form},
            http::StatusCode,
            response::Response,
        },
        http_body_util::BodyExt as _,
        pretty_assertions::assert_eq,
        scratchstack_aws_principal::{Principal, SessionData, SessionValue, User},
        scratchstack_core::RequestId,
        std::collections::HashMap,
    };

    const TEST_ACCOUNT_ID: &str = "123456789012";
    const TEST_USER_ID: &str = "AIDAQXZEAEXAMPLEUSER";
    const TEST_REQUEST_ID: &str = "11111111-2222-3333-4444-555555555555";

    fn test_principal() -> Principal {
        User::new("aws", TEST_ACCOUNT_ID, "/", "alice").expect("failed to build user").into()
    }

    fn test_session_data() -> SessionData {
        let mut session_data = SessionData::new();
        session_data.insert(SESSION_KEY_AWS_USERID, SessionValue::String(TEST_USER_ID.to_string()));
        session_data
    }

    fn request_id() -> RequestId {
        TEST_REQUEST_ID.parse().expect("failed to parse request id")
    }

    async fn call(parameters: &[(&str, &str)]) -> (StatusCode, String) {
        let parameters: HashMap<String, String> =
            parameters.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect();

        let response: Response<Body> =
            serve_request(request_id(), Extension(test_principal()), Extension(test_session_data()), Form(parameters))
                .await;

        let status = response.status();
        let body = response.into_body().collect().await.expect("failed to read body").to_bytes();
        (status, String::from_utf8(body.to_vec()).expect("body is not UTF-8"))
    }

    #[test_log::test(tokio::test)]
    async fn get_caller_identity_returns_the_signed_in_principal() {
        let (status, body) = call(&[("Action", ACTION_GET_CALLER_IDENTITY), ("Version", STS_VERSION_20110615)]).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            format!(
                r#"<GetCallerIdentityResponse xmlns="{XML_NS_STS}"><GetCallerIdentityResult><Account>{TEST_ACCOUNT_ID}</Account><Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/alice</Arn><UserId>{TEST_USER_ID}</UserId></GetCallerIdentityResult><ResponseMetadata><RequestId>{TEST_REQUEST_ID}</RequestId></ResponseMetadata></GetCallerIdentityResponse>"#
            )
        );
    }

    #[test_log::test(tokio::test)]
    async fn unknown_action_is_rejected() {
        let (status, body) = call(&[("Action", "NoSuchOperation"), ("Version", STS_VERSION_20110615)]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body,
            format!(
                r#"<ErrorResponse xmlns="{XML_NS_STS}"><Error><Type>Sender</Type><Code>InvalidAction</Code><Message>Could not find operation NoSuchOperation for version {STS_VERSION_20110615}</Message></Error><RequestId>{TEST_REQUEST_ID}</RequestId></ErrorResponse>"#
            )
        );
    }

    /// An unknown version is reported the same way AWS reports it: as an unfindable operation.
    #[test_log::test(tokio::test)]
    async fn unknown_version_is_rejected() {
        let (status, body) = call(&[("Action", ACTION_GET_CALLER_IDENTITY), ("Version", "1999-01-01")]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("Could not find operation GetCallerIdentity for version 1999-01-01"),
            "unexpected body: {body}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn missing_action_and_version_are_rejected() {
        let (status, body) = call(&[]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains(&format!(
                "Could not find operation {NO_ACTION_SPECIFIED} for version {NO_VERSION_SPECIFIED}"
            )),
            "unexpected body: {body}"
        );
    }
}
