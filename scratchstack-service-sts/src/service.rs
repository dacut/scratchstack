use {
    crate::{
        constants::*,
        operations::{assume_role, get_caller_identity},
    },
    scratchstack_aws_principal::{Principal, SessionData},
    scratchstack_core::{
        RequestId,
        axum::{
            body::{Body, Bytes},
            extract::{Extension, RawQuery, State},
            response::Response,
        },
        response::Responder as _,
    },
    scratchstack_shapes_sts::{
        action::{Action, VERSION as STS_VERSION},
        types::error::{InternalFailure, InvalidAction, InvalidClientTokenId, MalformedInput},
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

    if version != STS_VERSION {
        return invalid_action(request_id, &action, &version);
    }

    match action.parse::<Action>() {
        Ok(Action::AssumeRole) => assume_role(svc_state, request_id, principal, session_data, &parameters).await,
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

/// Generate an `InvalidClientTokenId` error response.
pub(crate) fn security_token_invalid(request_id: RequestId) -> Response<Body> {
    InvalidClientTokenId::builder().message(MSG_SECURITY_TOKEN_INVALID).request_id(request_id).build().respond()
}

#[cfg(test)]
mod tests {
    use {
        super::{ServiceState, serve_request},
        crate::constants::*,
        chrono::Utc,
        http_body_util::BodyExt as _,
        pretty_assertions::assert_eq,
        scratchstack_aws_principal::{Principal, RootUser, SessionData, SessionValue, User},
        scratchstack_core::{
            RequestId,
            axum::{
                body::{Body, Bytes},
                extract::{Extension, RawQuery, State},
                http::StatusCode,
                response::Response,
            },
        },
        scratchstack_iam_database::{RequestExecutor as _, migrate::MIGRATOR, utils::TempDatabase},
        scratchstack_shapes_iam::operation::CreateSessionTokenEncryptionKeyRequest,
        sqlx::{postgres::PgPoolOptions, raw_sql},
        std::sync::Arc,
    };

    const TEST_ACCOUNT_ID: &str = "123456789012";
    const TEST_USER_ID: &str = "AIDAQXZEAEXAMPLEUSER";
    const TEST_REQUEST_ID: &str = "11111111-2222-3333-4444-555555555555";

    /// Seed data for the AssumeRole tests: users whose grants exercise each authorization path,
    /// three roles (one trusting the whole account, one naming a user directly, one requiring an
    /// external id), and a managed policy usable as a session policy.
    const ASSUME_ROLE_TEST_DATA: &str = r#"
        INSERT INTO iam.partition(partition) VALUES ('aws');

        INSERT INTO iam.accounts(account_id, email, alias) VALUES
        ('123456789012', 'sts-test@example.com', 'sts-test');

        INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
        ('STSTESTALLOWUSER', '123456789012', 'allowed-user', 'Allowed-User', '/'),
        ('STSTESTDENYUSER1', '123456789012', 'denied-user', 'Denied-User', '/'),
        ('STSTESTNAMEDUSER', '123456789012', 'named-user', 'Named-User', '/'),
        ('STSTESTEXTIDUSER', '123456789012', 'extid-user', 'Extid-User', '/');

        INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
        ('STSTESTALLOWUSER', 'allow-assume-role', 'Allow-Assume-Role',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole",
           "Resource":"arn:aws:iam::123456789012:role/account-trusted-role"}]}'),
        ('STSTESTEXTIDUSER', 'allow-assume-extid', 'Allow-Assume-Extid',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole",
           "Resource":"arn:aws:iam::123456789012:role/external-id-role"}]}');

        INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
            permissions_boundary_managed_policy_id, assume_role_policy_document) VALUES
        ('STSTESTACCTROLE1', '123456789012', 'account-trusted-role', 'account-trusted-role', '/', NULL,
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
           "Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}'),
        ('STSTESTNAMEDROLE', '123456789012', 'named-user-role', 'named-user-role', '/', NULL,
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
           "Principal":{"AWS":"arn:aws:iam::123456789012:user/Named-User"},"Action":"sts:AssumeRole"}]}'),
        ('STSTESTEXTIDROLE', '123456789012', 'external-id-role', 'external-id-role', '/', NULL,
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
           "Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole",
           "Condition":{"StringEquals":{"sts:ExternalId":"expected-external-id"}}}]}');

        INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
            managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
        ('STSTESTSESSPOLCY', '123456789012', 'session-policy', 'Session-Policy', '/', 1, false, 1);

        INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
        ('STSTESTSESSPOLCY', 1,
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}');
    "#;

    fn test_principal() -> Principal {
        User::builder()
            .partition("aws")
            .account_id(TEST_ACCOUNT_ID)
            .path("/")
            .user_name("alice")
            .build()
            .expect("failed to build user")
            .into()
    }

    fn test_session_data() -> SessionData {
        let mut session_data = SessionData::new();
        session_data.insert(SESSION_KEY_AWS_USERID, SessionValue::String(TEST_USER_ID.to_string()));
        session_data
    }

    fn request_id() -> RequestId {
        TEST_REQUEST_ID.parse().expect("failed to parse request id")
    }

    /// Service state whose pool never connects, for tests that do not reach the database.
    fn lazy_state() -> ServiceState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/scratchstack-sts-test-unused")
            .expect("failed to build lazy pool");
        ServiceState {
            db: Arc::new(pool),
            secure_transport: true,
        }
    }

    /// Build the principal and session data the SigV4 layer would produce for a seeded user.
    fn user_identity(user_id: &str, user_name: &str) -> (Principal, SessionData) {
        let principal = Principal::from(
            User::builder()
                .partition("aws")
                .account_id(TEST_ACCOUNT_ID)
                .path("/")
                .user_name(user_name)
                .build()
                .expect("failed to build user"),
        );
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

    /// Invoke `serve_request` with the given identity and parameters and return the status and
    /// body.
    async fn call_as(
        svc_state: &ServiceState,
        principal: Principal,
        session_data: SessionData,
        parameters: &[(&str, &str)],
    ) -> (StatusCode, String) {
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
            State(svc_state.clone()),
            request_id(),
            Extension(principal),
            Extension(session_data),
            RawQuery(None),
            Bytes::from(body),
        )
        .await;

        let status = response.status();
        let body = response.into_body().collect().await.expect("failed to read body").to_bytes();
        (status, String::from_utf8(body.to_vec()).expect("body is not UTF-8"))
    }

    /// Invoke `serve_request` with the default test identity.
    async fn call(parameters: &[(&str, &str)]) -> (StatusCode, String) {
        call_as(&lazy_state(), test_principal(), test_session_data(), parameters).await
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

    /// AssumeRole requests that fail before authorization does not require the database.
    #[test_log::test(tokio::test)]
    async fn assume_role_rejects_bad_requests_before_authorization() {
        // A non-integer DurationSeconds cannot deserialize into the request shape.
        let (status, body) = call(&[
            ("Action", "AssumeRole"),
            ("Version", "2011-06-15"),
            ("RoleArn", "arn:aws:iam::123456789012:role/example"),
            ("RoleSessionName", "test-session"),
            ("DurationSeconds", "not-a-number"),
        ])
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

        // A RoleArn that is not an ARN at all is a validation error.
        let (status, body) = call(&[
            ("Action", "AssumeRole"),
            ("Version", "2011-06-15"),
            ("RoleArn", "not-an-arn"),
            ("RoleSessionName", "test-session"),
        ])
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("Invalid role ARN"), "unexpected body: {body}");

        // A syntactically valid IAM ARN that is not a role is also a validation error.
        let (status, body) = call(&[
            ("Action", "AssumeRole"),
            ("Version", "2011-06-15"),
            ("RoleArn", "arn:aws:iam::123456789012:user/example"),
            ("RoleSessionName", "test-session"),
        ])
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("ARN must be for a role"), "unexpected body: {body}");
    }

    /// End-to-end AssumeRole authorization and credential issuance checks through
    /// `serve_request` against an embedded PostgreSQL database. A single test function is used
    /// because the database is stateful and expensive to start.
    #[test_log::test(tokio::test)]
    async fn test_assume_role_end_to_end() {
        let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
        database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
        let pool = database
            .get_scratchstack_pool()
            .await
            .expect("Failed to get PostgreSQL connection pool for scratchstack user");

        let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
        MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
        raw_sql(ASSUME_ROLE_TEST_DATA).execute(&mut *c).await.expect("Failed to load test data into database");
        drop(c);

        // AssumeRole needs a session token encryption key to encrypt the session token with.
        let mut tx = pool.begin().await.expect("Failed to begin transaction");
        CreateSessionTokenEncryptionKeyRequest::builder()
            .issue_valid_from(Utc::now())
            .build()
            .expect("Failed to build CreateSessionTokenEncryptionKeyRequest")
            .execute(&mut tx, RequestId::new())
            .await
            .expect("Failed to create session token encryption key");
        tx.commit().await.expect("Failed to commit transaction");

        let svc_state = ServiceState {
            db: Arc::new(pool),
            secure_transport: true,
        };

        const ACCOUNT_TRUSTED_ROLE_ARN: &str = "arn:aws:iam::123456789012:role/account-trusted-role";
        const NAMED_USER_ROLE_ARN: &str = "arn:aws:iam::123456789012:role/named-user-role";
        const EXTERNAL_ID_ROLE_ARN: &str = "arn:aws:iam::123456789012:role/external-id-role";

        // A user whose identity policy allows sts:AssumeRole on a role whose trust policy
        // trusts the whole account receives credentials.
        let (principal, session_data) = user_identity("STSTESTALLOWUSER", "Allowed-User");
        let (status, body) = call_as(
            &svc_state,
            principal,
            session_data,
            &[
                ("Action", "AssumeRole"),
                ("Version", "2011-06-15"),
                ("RoleArn", ACCOUNT_TRUSTED_ROLE_ARN),
                ("RoleSessionName", "test-session"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<AssumeRoleResult>"), "unexpected body: {body}");
        assert!(body.contains("<AccessKeyId>ASIA"), "unexpected body: {body}");
        assert!(
            body.contains(&format!(
                "<Arn>arn:aws:sts::{TEST_ACCOUNT_ID}:assumed-role/account-trusted-role/test-session</Arn>"
            )),
            "unexpected body: {body}"
        );

        // A user with no identity policy is denied even though the trust policy trusts the
        // account: account trust delegates to identity-based policies.
        let (principal, session_data) = user_identity("STSTESTDENYUSER1", "Denied-User");
        let (status, body) = call_as(
            &svc_state,
            principal,
            session_data,
            &[
                ("Action", "AssumeRole"),
                ("Version", "2011-06-15"),
                ("RoleArn", ACCOUNT_TRUSTED_ROLE_ARN),
                ("RoleSessionName", "test-session"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
        assert!(
            body.contains(&format!(
                "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Denied-User is not authorized to perform: \
                 sts:AssumeRole on resource: {ACCOUNT_TRUSTED_ROLE_ARN}"
            )),
            "unexpected body: {body}"
        );

        // A same-account user named directly in the trust policy needs no identity policy. The
        // request also exercises the query-protocol list parameters end to end.
        let (principal, session_data) = user_identity("STSTESTNAMEDUSER", "Named-User");
        let (status, body) = call_as(
            &svc_state,
            principal,
            session_data,
            &[
                ("Action", "AssumeRole"),
                ("Version", "2011-06-15"),
                ("RoleArn", NAMED_USER_ROLE_ARN),
                ("RoleSessionName", "named-session"),
                ("DurationSeconds", "900"),
                ("PolicyArns.member.1.arn", "arn:aws:iam::123456789012:policy/Session-Policy"),
                ("Tags.member.1.Key", "Project"),
                ("Tags.member.1.Value", "scratchstack"),
                ("TransitiveTagKeys.member.1", "Project"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<AssumeRoleResult>"), "unexpected body: {body}");
        assert!(body.contains("<AccessKeyId>ASIA"), "unexpected body: {body}");

        // A user who is neither named in the trust policy nor granted sts:AssumeRole on this
        // role by an identity policy is denied.
        let (principal, session_data) = user_identity("STSTESTALLOWUSER", "Allowed-User");
        let (status, body) = call_as(
            &svc_state,
            principal,
            session_data,
            &[
                ("Action", "AssumeRole"),
                ("Version", "2011-06-15"),
                ("RoleArn", NAMED_USER_ROLE_ARN),
                ("RoleSessionName", "test-session"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // The account root user may not assume roles at all.
        let principal = Principal::from(
            RootUser::builder()
                .partition("aws")
                .account_id(TEST_ACCOUNT_ID)
                .build()
                .expect("failed to build root user"),
        );
        let mut session_data = SessionData::new();
        session_data.insert("aws:PrincipalAccount", SessionValue::String(TEST_ACCOUNT_ID.to_string()));
        let (status, body) = call_as(
            &svc_state,
            principal,
            session_data,
            &[
                ("Action", "AssumeRole"),
                ("Version", "2011-06-15"),
                ("RoleArn", ACCOUNT_TRUSTED_ROLE_ARN),
                ("RoleSessionName", "test-session"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains(MSG_ROOT_CANNOT_ASSUME_ROLE), "unexpected body: {body}");

        // A nonexistent role is reported exactly like a denial, not as a missing entity.
        let (principal, session_data) = user_identity("STSTESTALLOWUSER", "Allowed-User");
        let (status, body) = call_as(
            &svc_state,
            principal,
            session_data,
            &[
                ("Action", "AssumeRole"),
                ("Version", "2011-06-15"),
                ("RoleArn", "arn:aws:iam::123456789012:role/does-not-exist"),
                ("RoleSessionName", "test-session"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A trust policy conditioned on sts:ExternalId admits a caller presenting the expected
        // external id and rejects one who omits it.
        let (principal, session_data) = user_identity("STSTESTEXTIDUSER", "Extid-User");
        let (status, body) = call_as(
            &svc_state,
            principal,
            session_data,
            &[
                ("Action", "AssumeRole"),
                ("Version", "2011-06-15"),
                ("RoleArn", EXTERNAL_ID_ROLE_ARN),
                ("RoleSessionName", "test-session"),
                ("ExternalId", "expected-external-id"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<AssumeRoleResult>"), "unexpected body: {body}");

        let (principal, session_data) = user_identity("STSTESTEXTIDUSER", "Extid-User");
        let (status, body) = call_as(
            &svc_state,
            principal,
            session_data,
            &[
                ("Action", "AssumeRole"),
                ("Version", "2011-06-15"),
                ("RoleArn", EXTERNAL_ID_ROLE_ARN),
                ("RoleSessionName", "test-session"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
    }
}
