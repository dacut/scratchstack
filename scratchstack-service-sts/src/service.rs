use {
    crate::{constants::*, operations::get_caller_identity},
    axum::{
        body::{Body, Bytes},
        extract::{Extension, RawQuery},
        response::Response,
    },
    scratchstack_aws_principal::{Principal, SessionData},
    scratchstack_core::{RequestId, response::Responder as _},
    scratchstack_shapes_sts::{
        action::{Action, VERSION as STS_VERSION},
        types::error::{InternalFailure, InvalidAction, MalformedInput},
    },
    std::{borrow::Cow, str::from_utf8},
};

#[axum::debug_handler]
pub(crate) async fn serve_request(
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

    if version != STS_VERSION {
        return invalid_action(request_id, &action, &version);
    }

    match action.parse::<Action>() {
        Ok(Action::GetCallerIdentity) => get_caller_identity(request_id, &principal, &session_data),
        _ => invalid_action(request_id, &action, &version),
    }
}

/// Generate an `InternalFailure` error response.
pub(crate) fn internal_failure(request_id: RequestId) -> Response<Body> {
    InternalFailure::builder().message(MSG_INTERNAL_FAILURE).request_id(request_id).build().respond()
}

/// Generate an `InvalidAction` error response.
pub(crate) fn invalid_action(request_id: RequestId, action: &str, version: &str) -> Response<Body> {
    InvalidAction::builder()
        .message(format!("Could not find operation {action} for version {version}"))
        .request_id(request_id)
        .build()
        .respond()
}

/// Generate a `MalformedInput` error response.
pub(crate) fn malformed_input(request_id: RequestId) -> Response<Body> {
    MalformedInput::builder().request_id(request_id).build().respond()
}

#[cfg(test)]
mod tests {
    use {
        super::serve_request,
        crate::constants::*,
        axum::{
            body::{Body, Bytes},
            extract::{Extension, RawQuery},
            http::StatusCode,
            response::Response,
        },
        http_body_util::BodyExt as _,
        pretty_assertions::assert_eq,
        scratchstack_aws_principal::{Principal, SessionData, SessionValue, User},
        scratchstack_core::RequestId,
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
        let mut body = Vec::new();

        for (key, value) in parameters {
            if !body.is_empty() {
                body.push(b'&');
            }
            body.extend(form_urlencoded::byte_serialize(key.as_bytes()).flat_map(str::bytes));
            body.push(b'=');
            body.extend(form_urlencoded::byte_serialize(value.as_bytes()).flat_map(str::bytes));
        }

        let response: Response<Body> = serve_request(
            request_id(),
            Extension(test_principal()),
            Extension(test_session_data()),
            RawQuery(None),
            Bytes::from(body),
        )
        .await;

        let status = response.status();
        let body = response.into_body().collect().await.expect("failed to read body").to_bytes();
        (status, String::from_utf8(body.to_vec()).expect("body is not UTF-8"))
    }

    #[test_log::test(tokio::test)]
    async fn get_caller_identity_returns_the_signed_in_principal() {
        let (status, body) = call(&[("Action", "GetCallerIdentity"), ("Version", "2011-06-15")]).await;

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
        let (status, body) = call(&[("Action", "NoSuchOperation"), ("Version", "2011-06-15")]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body,
            format!(
                r#"<ErrorResponse xmlns="{XML_NS_STS}"><Error><Type>Sender</Type><Code>InvalidAction</Code><Message>Could not find operation NoSuchOperation for version 2011-06-15</Message></Error><RequestId>{TEST_REQUEST_ID}</RequestId></ErrorResponse>"#
            )
        );
    }

    /// An unknown version is reported the same way AWS reports it: as an unfindable operation.
    #[test_log::test(tokio::test)]
    async fn unknown_version_is_rejected() {
        let (status, body) = call(&[("Action", "GetCallerIdentity"), ("Version", "1999-01-01")]).await;

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
