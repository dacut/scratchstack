use {
    crate::{constants::*, operations::list_users},
    axum::{
        body::{Body, Bytes},
        extract::{Extension, RawQuery, State},
        response::Response,
    },
    scratchstack_aws_principal::{Principal, SessionData},
    scratchstack_aws_signature::SessionPolicies,
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

    /// Whether the listener terminates TLS; supplies the `aws:SecureTransport` condition key.
    pub(crate) secure_transport: bool,
}

#[axum::debug_handler]
pub(crate) async fn serve_request(
    State(svc_state): State<ServiceState>,
    request_id: RequestId,
    Extension(principal): Extension<Principal>,
    Extension(session_data): Extension<SessionData>,
    Extension(session_policies): Extension<SessionPolicies>,
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
        Ok(Action::ListUsers) => {
            list_users(svc_state, request_id, principal, session_data, session_policies, &parameters).await
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
mod tests {
    use {
        super::{ServiceState, serve_request},
        axum::{
            body::{Body, Bytes},
            extract::{Extension, RawQuery, State},
            http::StatusCode,
            response::Response,
        },
        http_body_util::BodyExt as _,
        pretty_assertions::assert_eq,
        scratchstack_aspen::Policy as AspenPolicy,
        scratchstack_aws_principal::{AssumedRole, Principal, RootUser, SessionData, SessionValue, User},
        scratchstack_aws_signature::SessionPolicies,
        scratchstack_core::RequestId,
        scratchstack_iam_database::{migrate::MIGRATOR, utils::TempDatabase},
        sqlx::raw_sql,
        std::{str::FromStr as _, sync::Arc},
    };

    const TEST_ACCOUNT_ID: &str = "123456789012";

    /// Seed data for the authorization tests: one user whose inline policy allows
    /// `iam:ListUsers`, one user with no policies at all, and users whose grants are gated on
    /// the request-time condition keys (`aws:SecureTransport`, `aws:CurrentTime`,
    /// `aws:EpochTime`) that `check_authorization` injects.
    const AUTHZ_TEST_DATA: &str = r#"
        INSERT INTO iam.partition(partition) VALUES ('aws');

        INSERT INTO iam.accounts(account_id, email, alias) VALUES
        ('123456789012', 'authz-test@example.com', 'authz-test');

        INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
        ('SVCTESTALLOWUSER', '123456789012', 'allowed-user', 'Allowed-User', '/'),
        ('SVCTESTDENYUSER1', '123456789012', 'denied-user', 'Denied-User', '/'),
        ('SVCTESTTLSUSER01', '123456789012', 'tls-user', 'Tls-User', '/'),
        ('SVCTESTTIMEUSER1', '123456789012', 'time-user', 'Time-User', '/'),
        ('SVCTESTPASTUSER1', '123456789012', 'past-user', 'Past-User', '/'),
        ('SVCTESTEPOCHUSR1', '123456789012', 'epoch-user', 'Epoch-User', '/');

        INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
        ('SVCTESTALLOWUSER', 'allow-list-users', 'Allow-List-Users',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*"}]}'),
        ('SVCTESTTLSUSER01', 'allow-if-tls', 'Allow-If-Tls',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
           "Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}'),
        ('SVCTESTTIMEUSER1', 'allow-after-2020', 'Allow-After-2020',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
           "Condition":{"DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}}]}'),
        ('SVCTESTPASTUSER1', 'allow-before-2020', 'Allow-Before-2020',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
           "Condition":{"DateLessThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}}]}'),
        ('SVCTESTEPOCHUSR1', 'allow-after-2020-epoch', 'Allow-After-2020-Epoch',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
           "Condition":{"NumericGreaterThan":{"aws:EpochTime":"1577836800"}}}]}');

        INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
        ('SVCTESTROLE00001', '123456789012', 'session-role', 'Session-Role', '/',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

        INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
        ('SVCTESTROLE00001', 'allow-list-users', 'Allow-List-Users',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*"}]}');

        INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
            managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
        ('SVCTESTSESSPOL01', '123456789012', 'session-allow-iam', 'Session-Allow-Iam', '/', 1, false, 1);

        INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
        ('SVCTESTSESSPOL01', 1, '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}');
    "#;

    /// Build the principal and session data the SigV4 layer would produce for a seeded user.
    fn user_identity(user_id: &str, user_name: &str) -> (Principal, SessionData) {
        let principal =
            Principal::from(User::new("aws", TEST_ACCOUNT_ID, "/", user_name).expect("failed to build user"));
        let mut session_data = SessionData::new();
        session_data.insert("aws:PrincipalAccount", SessionValue::String(TEST_ACCOUNT_ID.to_string()));
        session_data.insert(
            "aws:PrincipalArn",
            SessionValue::String(format!("arn:aws:iam::{TEST_ACCOUNT_ID}:user/{user_name}")),
        );
        session_data.insert("aws:userid", SessionValue::String(format!("AIDA{user_id}")));
        session_data.insert("aws:username", SessionValue::String(user_name.to_string()));
        session_data.insert("aws:PrincipalType", SessionValue::String("User".to_string()));
        (principal, session_data)
    }

    /// Build the principal and session data the SigV4 layer would produce for a session on the
    /// seeded role.
    fn role_identity(role_id: &str, role_name: &str) -> (Principal, SessionData) {
        let principal = Principal::from(
            AssumedRole::new("aws", TEST_ACCOUNT_ID, role_name, "test-session").expect("failed to build assumed role"),
        );
        let mut session_data = SessionData::new();
        session_data.insert("aws:PrincipalAccount", SessionValue::String(TEST_ACCOUNT_ID.to_string()));
        session_data.insert(
            "aws:PrincipalArn",
            SessionValue::String(format!("arn:aws:sts::{TEST_ACCOUNT_ID}:assumed-role/{role_name}/test-session")),
        );
        session_data.insert("aws:userid", SessionValue::String(format!("AROA{role_id}:test-session")));
        session_data.insert("aws:PrincipalType", SessionValue::String("AssumedRole".to_string()));
        (principal, session_data)
    }

    /// Invoke `serve_request` directly with the given identity and return the status and body.
    async fn call(
        svc_state: &ServiceState,
        principal: Principal,
        session_data: SessionData,
        parameters: &str,
    ) -> (StatusCode, String) {
        call_with_session_policies(svc_state, principal, session_data, SessionPolicies::default(), parameters).await
    }

    /// Invoke `serve_request` directly with the given identity and session policies and return
    /// the status and body.
    async fn call_with_session_policies(
        svc_state: &ServiceState,
        principal: Principal,
        session_data: SessionData,
        session_policies: SessionPolicies,
        parameters: &str,
    ) -> (StatusCode, String) {
        let response: Response<Body> = serve_request(
            State(svc_state.clone()),
            RequestId::new(),
            Extension(principal),
            Extension(session_data),
            Extension(session_policies),
            RawQuery(None),
            Bytes::from(parameters.as_bytes().to_vec()),
        )
        .await;

        let status = response.status();
        let body = response.into_body().collect().await.expect("failed to read body").to_bytes();
        (status, String::from_utf8(body.to_vec()).expect("body is not UTF-8"))
    }

    /// End-to-end authorization checks through `serve_request` against an embedded PostgreSQL
    /// database. A single test function is used because the database is stateful and expensive
    /// to start.
    #[test_log::test(tokio::test)]
    async fn test_list_users_authorization() {
        let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
        database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
        let pool = database
            .get_scratchstack_pool()
            .await
            .expect("Failed to get PostgreSQL connection pool for scratchstack user");

        let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
        MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
        raw_sql(AUTHZ_TEST_DATA).execute(&mut *c).await.expect("Failed to load test data into database");
        drop(c);

        let svc_state = ServiceState {
            db: Arc::new(pool),
            secure_transport: true,
        };
        let parameters = "Action=ListUsers&Version=2010-05-08";

        // A user whose inline policy allows iam:ListUsers gets a successful response.
        let (principal, session_data) = user_identity("SVCTESTALLOWUSER", "Allowed-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // A user with no policies is denied with a 403 AccessDenied error.
        let (principal, session_data) = user_identity("SVCTESTDENYUSER1", "Denied-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
        assert!(
            body.contains(&format!(
                "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Denied-User is not authorized to perform: \
                 iam:ListUsers on resource: *"
            )),
            "unexpected body: {body}"
        );

        // The account root user is implicitly allowed.
        let principal = Principal::from(RootUser::new("aws", TEST_ACCOUNT_ID).expect("failed to build root user"));
        let mut session_data = SessionData::new();
        session_data.insert("aws:PrincipalAccount", SessionValue::String(TEST_ACCOUNT_ID.to_string()));
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // aws:SecureTransport reflects the listener's TLS configuration: a grant conditioned on
        // it succeeds on a TLS listener and fails on a plaintext one.
        let (principal, session_data) = user_identity("SVCTESTTLSUSER01", "Tls-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        let insecure_state = ServiceState {
            db: svc_state.db.clone(),
            secure_transport: false,
        };
        let (principal, session_data) = user_identity("SVCTESTTLSUSER01", "Tls-User");
        let (status, body) = call(&insecure_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // aws:CurrentTime carries the evaluation time as a timestamp: a DateGreaterThan
        // condition against a past instant passes, and a DateLessThan against it fails.
        let (principal, session_data) = user_identity("SVCTESTTIMEUSER1", "Time-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        let (principal, session_data) = user_identity("SVCTESTPASTUSER1", "Past-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // aws:EpochTime carries the evaluation time in integer seconds, satisfying a
        // NumericGreaterThan condition against a past epoch value.
        let (principal, session_data) = user_identity("SVCTESTEPOCHUSR1", "Epoch-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // An assumed-role session with no session policies is governed by the role's inline
        // policy, which allows iam:ListUsers.
        let (principal, session_data) = role_identity("SVCTESTROLE00001", "session-role");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // An inline session policy that also allows iam:ListUsers leaves the intersection
        // intact.
        let allow_iam = AspenPolicy::from_str(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}"#,
        )
        .expect("failed to parse policy");
        let session_policies = SessionPolicies::builder().inline_policy(allow_iam).build();
        let (principal, session_data) = role_identity("SVCTESTROLE00001", "session-role");
        let (status, body) =
            call_with_session_policies(&svc_state, principal, session_data, session_policies, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // An inline session policy that does not allow iam:ListUsers removes it from the
        // intersection even though the role's own policy allows it.
        let allow_s3_only = AspenPolicy::from_str(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#,
        )
        .expect("failed to parse policy");
        let session_policies = SessionPolicies::builder().inline_policy(allow_s3_only).build();
        let (principal, session_data) = role_identity("SVCTESTROLE00001", "session-role");
        let (status, body) =
            call_with_session_policies(&svc_state, principal, session_data, session_policies, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
        assert!(
            body.contains(&format!(
                "User: arn:aws:sts::{TEST_ACCOUNT_ID}:assumed-role/session-role/test-session is not \
                 authorized to perform: iam:ListUsers on resource: * because no session policy allows \
                 the iam:ListUsers action"
            )),
            "unexpected body: {body}"
        );

        // A managed session policy resolves to its current default version, which allows iam:*.
        let session_policies =
            SessionPolicies::builder().managed_policy_ids(["ANPASVCTESTSESSPOL01".to_string()]).build();
        let (principal, session_data) = role_identity("SVCTESTROLE00001", "session-role");
        let (status, body) =
            call_with_session_policies(&svc_state, principal, session_data, session_policies, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // A managed session policy that no longer resolves cannot be reconstructed; the request
        // is denied (not an internal failure).
        let session_policies =
            SessionPolicies::builder().managed_policy_ids(["ANPADOESNOTEXIST0000".to_string()]).build();
        let (principal, session_data) = role_identity("SVCTESTROLE00001", "session-role");
        let (status, body) =
            call_with_session_policies(&svc_state, principal, session_data, session_policies, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
        assert!(body.contains("because no session policy allows the iam:ListUsers action"), "unexpected body: {body}");
    }
}
