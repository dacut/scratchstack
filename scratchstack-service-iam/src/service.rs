use {
    crate::{
        constants::*,
        operations::{get_user, list_users},
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
        Ok(Action::GetUser) => {
            get_user(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::ListUsers) => {
            list_users(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
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
mod tests {
    use {
        super::{ServiceState, serve_request},
        chrono::{DateTime, Utc},
        http_body_util::BodyExt as _,
        pretty_assertions::assert_eq,
        scratchstack_aspen::Policy as AspenPolicy,
        scratchstack_aws_principal::{AssumedRole, Principal, RootUser, SessionData, SessionValue, User},
        scratchstack_aws_signature::SessionPolicies,
        scratchstack_config::{ForwardedForConfig, Resolvable as _},
        scratchstack_core::{
            RequestId,
            axum::{
                body::{Body, Bytes},
                extract::{ConnectInfo, Extension, RawQuery, State},
                http::{HeaderMap, StatusCode},
                response::Response,
            },
        },
        scratchstack_iam_database::{migrate::MIGRATOR, utils::TempDatabase},
        sqlx::raw_sql,
        std::{
            net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
            str::FromStr as _,
            sync::Arc,
        },
    };

    const TEST_ACCOUNT_ID: &str = "123456789012";

    /// The region test requests are signed for; the signing-key provider records it as
    /// `aws:RequestedRegion` for both long-term and temporary credentials.
    const TEST_REGION: &str = "us-east-1";

    /// The peer address test requests arrive from unless a test names another, backing the
    /// `aws:SourceIp` condition key. The addresses used here come from the documentation ranges
    /// reserved by RFC 5737 and RFC 3849.
    const TEST_SOURCE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

    /// A peer address outside the CIDR block the source-IP test policies grant.
    const OUTSIDE_SOURCE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

    /// A peer address inside the IPv6 CIDR block the source-IP test policies grant.
    const TEST_SOURCE_IPV6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    /// The address of the load balancer in the forwarded-header tests, inside the CIDR block
    /// [`proxied_state`] trusts.
    const TEST_PROXY_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    /// Seed data for the authorization tests: one user whose inline policy allows
    /// `iam:ListUsers`, one user with no policies at all, and users whose grants are gated on
    /// the request-time condition keys (`aws:SecureTransport`, `aws:CurrentTime`,
    /// `aws:EpochTime`, `aws:SourceIp`, `aws:referer`, `aws:UserAgent`) that
    /// `check_authorization` injects, and on the `aws:TokenIssueTime` the session token carries.
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
        ('SVCTESTEPOCHUSR1', '123456789012', 'epoch-user', 'Epoch-User', '/'),
        ('SVCTESTIPV4USER1', '123456789012', 'ipv4-user', 'Ipv4-User', '/'),
        ('SVCTESTIPV6USER1', '123456789012', 'ipv6-user', 'Ipv6-User', '/'),
        ('SVCTESTDENYIPUSR', '123456789012', 'deny-ip-user', 'Deny-Ip-User', '/'),
        ('SVCTESTTOKENUSER', '123456789012', 'token-user', 'Token-User', '/'),
        ('SVCTESTREGIONUSR', '123456789012', 'region-user', 'Region-User', '/'),
        ('SVCTESTOTHERRGN1', '123456789012', 'other-region-user', 'Other-Region-User', '/'),
        ('SVCTESTDIRECTUSR', '123456789012', 'direct-call-user', 'Direct-Call-User', '/'),
        ('SVCTESTAGENTUSR1', '123456789012', 'agent-user', 'Agent-User', '/');

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
           "Condition":{"NumericGreaterThan":{"aws:EpochTime":"1577836800"}}}]}'),
        ('SVCTESTIPV4USER1', 'allow-from-ipv4-block', 'Allow-From-Ipv4-Block',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
           "Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}'),
        ('SVCTESTIPV6USER1', 'allow-from-ipv6-block', 'Allow-From-Ipv6-Block',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
           "Condition":{"IpAddress":{"aws:SourceIp":"2001:db8::/32"}}}]}'),
        ('SVCTESTAGENTUSR1', 'allow-known-clients', 'Allow-Known-Clients',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
           "Condition":{"StringLike":{"aws:UserAgent":"aws-cli/*"},
                        "StringEquals":{"aws:referer":"https://console.example.com/"}}}]}'),
        ('SVCTESTDIRECTUSR', 'allow-direct-calls', 'Allow-Direct-Calls',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
           "Condition":{"Bool":{"aws:ViaAWSService":"false","aws:PrincipalIsAWSService":"false"}}}]}'),
        ('SVCTESTREGIONUSR', 'allow-in-us-east-1', 'Allow-In-Us-East-1',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
           "Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}'),
        ('SVCTESTOTHERRGN1', 'allow-in-eu-west-1', 'Allow-In-Eu-West-1',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
           "Condition":{"StringEquals":{"aws:RequestedRegion":"eu-west-1"}}}]}'),
        ('SVCTESTTOKENUSER', 'allow-recent-sessions', 'Allow-Recent-Sessions',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
           "Condition":{"DateGreaterThan":{"aws:TokenIssueTime":"2020-01-01T00:00:00Z"}}}]}'),
        ('SVCTESTDENYIPUSR', 'deny-outside-ipv4-block', 'Deny-Outside-Ipv4-Block',
         '{"Version":"2012-10-17","Statement":[
           {"Effect":"Allow","Action":"iam:ListUsers","Resource":"*"},
           {"Effect":"Deny","Action":"iam:ListUsers","Resource":"*",
            "Condition":{"NotIpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}');

        INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
        ('SVCTESTROLE00001', '123456789012', 'session-role', 'Session-Role', '/',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
        ('SVCTESTTOKENROLE', '123456789012', 'token-role', 'Token-Role', '/',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
        ('SVCTESTRGNROLE01', '123456789012', 'region-role', 'Region-Role', '/',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
        ('SVCTESTDIRROLE01', '123456789012', 'direct-call-role', 'Direct-Call-Role', '/',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

        INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
        ('SVCTESTROLE00001', 'allow-list-users', 'Allow-List-Users',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*"}]}'),
        ('SVCTESTTOKENROLE', 'allow-recent-sessions', 'Allow-Recent-Sessions',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
           "Condition":{"DateGreaterThan":{"aws:TokenIssueTime":"2020-01-01T00:00:00Z"}}}]}'),
        ('SVCTESTRGNROLE01', 'allow-in-us-east-1', 'Allow-In-Us-East-1',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
           "Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}'),
        ('SVCTESTDIRROLE01', 'allow-direct-calls', 'Allow-Direct-Calls',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
           "Condition":{"Bool":{"aws:ViaAWSService":"false","aws:PrincipalIsAWSService":"false"}}}]}');

        INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
            managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
        ('SVCTESTSESSPOL01', '123456789012', 'session-allow-iam', 'Session-Allow-Iam', '/', 1, false, 1);

        INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
        ('SVCTESTSESSPOL01', 1, '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}');
    "#;

    /// Seed data for the `GetUser` authorization tests. The users being read carry the paths and
    /// tags the resource ARN and the `aws:ResourceTag`/`iam:ResourceTag` condition keys are
    /// derived from; the callers carry grants scoped by principal variable, by resource path, and
    /// by resource tag.
    const GET_USER_TEST_DATA: &str = r#"
        INSERT INTO iam.partition(partition) VALUES ('aws');

        INSERT INTO iam.accounts(account_id, email, alias) VALUES
        ('123456789012', 'get-user-test@example.com', 'get-user-test');

        INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
        ('SVCGETUSERSELF01', '123456789012', 'self-user', 'Self-User', '/'),
        ('SVCGETUSERPATH01', '123456789012', 'path-user', 'Path-User', '/'),
        ('SVCGETUSERTAG001', '123456789012', 'tag-user', 'Tag-User', '/'),
        ('SVCGETUSERIAMTG1', '123456789012', 'iam-tag-user', 'Iam-Tag-User', '/'),
        ('SVCGETUSERBROAD1', '123456789012', 'broad-user', 'Broad-User', '/'),
        ('SVCGETUSERNARROW', '123456789012', 'narrow-user', 'Narrow-User', '/'),
        ('SVCGETUSERDIVSN1', '123456789012', 'division-user', 'Division-User', '/division/'),
        ('SVCGETUSERENGNR1', '123456789012', 'engineering-user', 'Engineering-User', '/'),
        ('SVCGETUSERSALES1', '123456789012', 'sales-user', 'Sales-User', '/');

        INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
        ('SVCGETUSERENGNR1', 'department', 'Department', 'Engineering'),
        ('SVCGETUSERSALES1', 'department', 'Department', 'Sales');

        INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
        ('SVCGETUSERSELF01', 'allow-get-self', 'Allow-Get-Self',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser",
           "Resource":"arn:aws:iam::123456789012:user/${aws:username}"}]}'),
        ('SVCGETUSERPATH01', 'allow-get-division', 'Allow-Get-Division',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser",
           "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
        ('SVCGETUSERTAG001', 'allow-get-engineering', 'Allow-Get-Engineering',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*",
           "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
        ('SVCGETUSERIAMTG1', 'allow-get-engineering-iam', 'Allow-Get-Engineering-Iam',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*",
           "Condition":{"StringEquals":{"iam:ResourceTag/Department":"Engineering"}}}]}'),
        ('SVCGETUSERBROAD1', 'allow-get-any', 'Allow-Get-Any',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}'),
        ('SVCGETUSERNARROW', 'allow-get-broad-user', 'Allow-Get-Broad-User',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser",
           "Resource":"arn:aws:iam::123456789012:user/Broad-User"}]}');

        INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
        ('SVCGETUSERROLE01', '123456789012', 'get-user-role', 'Get-User-Role', '/',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

        INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
        ('SVCGETUSERROLE01', 'allow-get-any', 'Allow-Get-Any',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}');
    "#;

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
        session_data.insert("aws:PrincipalIsAWSService", SessionValue::Bool(false));
        session_data.insert("aws:RequestedRegion", SessionValue::String(TEST_REGION.to_string()));
        session_data.insert("aws:ViaAWSService", SessionValue::Bool(false));
        (principal, session_data)
    }

    /// Build the principal and session data the SigV4 layer would produce for a session on the
    /// seeded role, issued just now.
    fn role_identity(role_id: &str, role_name: &str) -> (Principal, SessionData) {
        role_identity_issued_at(role_id, role_name, Utc::now())
    }

    /// Build the principal and session data the SigV4 layer would produce for a session on the
    /// seeded role that `sts:AssumeRole` minted at `issued_at`.
    ///
    /// The keys here mirror the session metadata `AssumeRole` records in the session token, which
    /// the signing-key provider hands back verbatim as the session data for a request signed with
    /// the resulting temporary credentials.
    fn role_identity_issued_at(role_id: &str, role_name: &str, issued_at: DateTime<Utc>) -> (Principal, SessionData) {
        let principal = Principal::from(
            AssumedRole::builder()
                .partition("aws")
                .account_id(TEST_ACCOUNT_ID)
                .role_name(role_name)
                .session_name("test-session")
                .build()
                .expect("failed to build assumed role"),
        );
        let mut session_data = SessionData::new();
        session_data.insert("aws:PrincipalAccount", SessionValue::String(TEST_ACCOUNT_ID.to_string()));
        session_data.insert(
            "aws:PrincipalArn",
            SessionValue::String(format!("arn:aws:sts::{TEST_ACCOUNT_ID}:assumed-role/{role_name}/test-session")),
        );
        session_data.insert("aws:userid", SessionValue::String(format!("AROA{role_id}:test-session")));
        session_data.insert("aws:PrincipalType", SessionValue::String("AssumedRole".to_string()));
        session_data.insert("aws:MultiFactorAuthPresent", SessionValue::Bool(false));
        session_data.insert("aws:PrincipalIsAWSService", SessionValue::Bool(false));
        session_data.insert("aws:RequestedRegion", SessionValue::String(TEST_REGION.to_string()));
        session_data.insert("aws:TokenIssueTime", SessionValue::Timestamp(issued_at));
        session_data.insert("aws:ViaAWSService", SessionValue::Bool(false));
        (principal, session_data)
    }

    /// Build the principal and session data the SigV4 layer would produce for the account root
    /// user.
    fn root_identity() -> (Principal, SessionData) {
        let principal = Principal::from(
            RootUser::builder()
                .partition("aws")
                .account_id(TEST_ACCOUNT_ID)
                .build()
                .expect("failed to build root user"),
        );
        let mut session_data = SessionData::new();
        session_data.insert("aws:PrincipalAccount", SessionValue::String(TEST_ACCOUNT_ID.to_string()));
        (principal, session_data)
    }

    /// Build the query parameters for a `GetUser` request, naming a user or leaving `UserName`
    /// off so it defaults to the caller.
    fn get_user_parameters(user_name: Option<&str>) -> String {
        match user_name {
            Some(user_name) => format!("Action=GetUser&Version=2010-05-08&UserName={user_name}"),
            None => "Action=GetUser&Version=2010-05-08".to_string(),
        }
    }

    /// A copy of `svc_state` configured to believe the `X-Forwarded-For` header of proxies in
    /// `10.0.0.0/8`, standing in for a deployment behind a load balancer.
    fn proxied_state(svc_state: &ServiceState) -> ServiceState {
        let forwarded_for = ForwardedForConfig::builder()
            .trusted_proxies(vec!["10.0.0.0/8".to_string()])
            .build()
            .resolve()
            .expect("failed to resolve forwarded_for configuration");

        ServiceState::builder()
            .db(svc_state.db.clone())
            .forwarded_for(Arc::new(forwarded_for))
            .secure_transport(true)
            .build()
    }

    /// Invoke `serve_request` directly with the given identity and return the status and body.
    async fn call(
        svc_state: &ServiceState,
        principal: Principal,
        session_data: SessionData,
        parameters: &str,
    ) -> (StatusCode, String) {
        call_as(
            svc_state,
            principal,
            session_data,
            SessionPolicies::default(),
            TEST_SOURCE_IP,
            HeaderMap::new(),
            parameters,
        )
        .await
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
        call_as(svc_state, principal, session_data, session_policies, TEST_SOURCE_IP, HeaderMap::new(), parameters)
            .await
    }

    /// Invoke `serve_request` directly with the given identity from the given peer address and
    /// return the status and body.
    async fn call_from(
        svc_state: &ServiceState,
        principal: Principal,
        session_data: SessionData,
        source_ip: IpAddr,
        parameters: &str,
    ) -> (StatusCode, String) {
        call_as(svc_state, principal, session_data, SessionPolicies::default(), source_ip, HeaderMap::new(), parameters)
            .await
    }

    /// Invoke `serve_request` directly for a request carrying the given headers.
    async fn call_with_headers(
        svc_state: &ServiceState,
        principal: Principal,
        session_data: SessionData,
        headers: HeaderMap,
        parameters: &str,
    ) -> (StatusCode, String) {
        call_as(svc_state, principal, session_data, SessionPolicies::default(), TEST_SOURCE_IP, headers, parameters)
            .await
    }

    /// Build a header map carrying a `Referer`, a `User-Agent`, or both.
    fn client_headers(referer: Option<&str>, user_agent: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(referer) = referer {
            headers.append("referer", referer.parse().expect("invalid header value"));
        }
        if let Some(user_agent) = user_agent {
            headers.append("user-agent", user_agent.parse().expect("invalid header value"));
        }
        headers
    }

    /// Invoke `serve_request` directly for a request that arrived from `source_ip` carrying
    /// `forwarded_for` in its `X-Forwarded-For` header.
    async fn call_forwarded(
        svc_state: &ServiceState,
        principal: Principal,
        session_data: SessionData,
        source_ip: IpAddr,
        forwarded_for: &str,
        parameters: &str,
    ) -> (StatusCode, String) {
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", forwarded_for.parse().expect("invalid header value"));

        call_as(svc_state, principal, session_data, SessionPolicies::default(), source_ip, headers, parameters).await
    }

    /// Invoke `serve_request` directly with every facet of the request spelled out, standing in
    /// for the connection information and identity the pipeline would otherwise supply.
    #[allow(clippy::too_many_arguments)]
    async fn call_as(
        svc_state: &ServiceState,
        principal: Principal,
        session_data: SessionData,
        session_policies: SessionPolicies,
        source_ip: IpAddr,
        headers: HeaderMap,
        parameters: &str,
    ) -> (StatusCode, String) {
        let response: Response<Body> = serve_request(
            State(svc_state.clone()),
            RequestId::new(),
            Some(Extension(ConnectInfo(SocketAddr::new(source_ip, 49152)))),
            headers,
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

        let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();
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
        let (principal, session_data) = root_identity();
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // aws:SecureTransport reflects the listener's TLS configuration: a grant conditioned on
        // it succeeds on a TLS listener and fails on a plaintext one.
        let (principal, session_data) = user_identity("SVCTESTTLSUSER01", "Tls-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        let insecure_state = ServiceState::builder().db(svc_state.db.clone()).secure_transport(false).build();
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

        // aws:SourceIp carries the address the request arrived from: a grant conditioned on a
        // CIDR block admits a caller inside the block...
        let (principal, session_data) = user_identity("SVCTESTIPV4USER1", "Ipv4-User");
        let (status, body) = call_from(&svc_state, principal, session_data, TEST_SOURCE_IP, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // ...and refuses one outside it.
        let (principal, session_data) = user_identity("SVCTESTIPV4USER1", "Ipv4-User");
        let (status, body) = call_from(&svc_state, principal, session_data, OUTSIDE_SOURCE_IP, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A dual-stack listener reports an IPv4 peer as an IPv4-mapped IPv6 address. The mapping
        // is unwrapped before evaluation, so an IPv4 grant still matches such a caller.
        let mapped_source_ip = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 10).to_ipv6_mapped());
        let (principal, session_data) = user_identity("SVCTESTIPV4USER1", "Ipv4-User");
        let (status, body) = call_from(&svc_state, principal, session_data, mapped_source_ip, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // IPv6 CIDR blocks are matched the same way, and do not match an IPv4 caller.
        let (principal, session_data) = user_identity("SVCTESTIPV6USER1", "Ipv6-User");
        let (status, body) = call_from(&svc_state, principal, session_data, TEST_SOURCE_IPV6, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        let (principal, session_data) = user_identity("SVCTESTIPV6USER1", "Ipv6-User");
        let (status, body) = call_from(&svc_state, principal, session_data, TEST_SOURCE_IP, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A NotIpAddress condition on an explicit Deny statement leaves callers inside the block
        // alone and stops everyone else.
        let (principal, session_data) = user_identity("SVCTESTDENYIPUSR", "Deny-Ip-User");
        let (status, body) = call_from(&svc_state, principal, session_data, TEST_SOURCE_IP, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        let (principal, session_data) = user_identity("SVCTESTDENYIPUSR", "Deny-Ip-User");
        let (status, body) = call_from(&svc_state, principal, session_data, OUTSIDE_SOURCE_IP, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("with an explicit deny in an identity-based policy"), "unexpected body: {body}");

        // A listener that trusts no proxy does not read the X-Forwarded-For header, so a caller
        // outside the granted block cannot talk its way inside one.
        let (principal, session_data) = user_identity("SVCTESTIPV4USER1", "Ipv4-User");
        let (status, body) =
            call_forwarded(&svc_state, principal, session_data, OUTSIDE_SOURCE_IP, "203.0.113.10", parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A listener behind a load balancer takes the address that balancer reports, so the same
        // grant is evaluated against the client rather than against the balancer...
        let proxied_state = proxied_state(&svc_state);
        let (principal, session_data) = user_identity("SVCTESTIPV4USER1", "Ipv4-User");
        let (status, body) =
            call_forwarded(&proxied_state, principal, session_data, TEST_PROXY_IP, "203.0.113.10", parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // ...including when the client the balancer names is outside the block.
        let (principal, session_data) = user_identity("SVCTESTIPV4USER1", "Ipv4-User");
        let (status, body) =
            call_forwarded(&proxied_state, principal, session_data, TEST_PROXY_IP, "198.51.100.7", parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // aws:RequestedRegion names the region the request was signed for, so a grant scoped to
        // one region admits a request in it and a grant scoped to another does not.
        let (principal, session_data) = user_identity("SVCTESTREGIONUSR", "Region-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        let (principal, session_data) = user_identity("SVCTESTOTHERRGN1", "Other-Region-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A role session carries the key too, now that the signing-key provider records it for
        // temporary credentials rather than leaving it to the session token.
        let (principal, session_data) = role_identity("SVCTESTRGNROLE01", "Region-Role");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // aws:referer and aws:UserAgent carry the headers the caller sent, so a grant gated on
        // both admits a request that announces itself as expected...
        let headers = client_headers(Some("https://console.example.com/"), Some("aws-cli/2.15.0"));
        let (principal, session_data) = user_identity("SVCTESTAGENTUSR1", "Agent-User");
        let (status, body) = call_with_headers(&svc_state, principal, session_data, headers, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // ...refuses one whose User-Agent does not match the pattern...
        let headers = client_headers(Some("https://console.example.com/"), Some("curl/8.4.0"));
        let (principal, session_data) = user_identity("SVCTESTAGENTUSR1", "Agent-User");
        let (status, body) = call_with_headers(&svc_state, principal, session_data, headers, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // ...and refuses one that sends neither header, since a condition on an absent key does
        // not match.
        let (principal, session_data) = user_identity("SVCTESTAGENTUSR1", "Agent-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A caller that sends only the User-Agent still fails the Referer half of the grant,
        // confirming both keys are read rather than one standing in for the other.
        let headers = client_headers(None, Some("aws-cli/2.15.0"));
        let (principal, session_data) = user_identity("SVCTESTAGENTUSR1", "Agent-User");
        let (status, body) = call_with_headers(&svc_state, principal, session_data, headers, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // aws:ViaAWSService and aws:PrincipalIsAWSService are both false for a request a
        // principal makes for itself. A plain Bool condition does not match an absent key, so a
        // grant gated on them proves they reach evaluation -- for user credentials and, now that
        // the signing-key provider records them for temporary credentials too, for role
        // sessions.
        let (principal, session_data) = user_identity("SVCTESTDIRECTUSR", "Direct-Call-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        let (principal, session_data) = role_identity("SVCTESTDIRROLE01", "Direct-Call-Role");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // aws:TokenIssueTime comes from the session token rather than the request, carrying the
        // moment sts:AssumeRole minted the credentials: a grant restricted to sessions issued
        // after a cutoff admits a session minted now...
        let (principal, session_data) = role_identity("SVCTESTTOKENROLE", "Token-Role");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // ...and refuses one minted before it.
        let issued_at =
            DateTime::parse_from_rfc3339("2019-06-01T00:00:00Z").expect("bad timestamp").with_timezone(&Utc);
        let (principal, session_data) = role_identity_issued_at("SVCTESTTOKENROLE", "Token-Role", issued_at);
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // Long-term IAM user credentials are not a session and carry no aws:TokenIssueTime at
        // all, so the same condition never matches for them -- as on AWS.
        let (principal, session_data) = user_identity("SVCTESTTOKENUSER", "Token-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

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

    /// End-to-end `GetUser` authorization checks through `serve_request` against an embedded
    /// PostgreSQL database. As with the `ListUsers` test, one test function covers every case
    /// because the database is stateful and expensive to start.
    #[test_log::test(tokio::test)]
    async fn test_get_user_authorization() {
        let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
        database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
        let pool = database
            .get_scratchstack_pool()
            .await
            .expect("Failed to get PostgreSQL connection pool for scratchstack user");

        let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
        MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
        raw_sql(GET_USER_TEST_DATA).execute(&mut *c).await.expect("Failed to load test data into database");
        drop(c);

        let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();

        // An omitted UserName names the calling user. The grant here is scoped to the caller's
        // own ARN through the aws:username policy variable, so it covers exactly that lookup.
        let (principal, session_data) = user_identity("SVCGETUSERSELF01", "Self-User");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(None)).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Self-User</Arn>")),
            "unexpected body: {body}"
        );

        // The same grant does not reach any other user.
        let (principal, session_data) = user_identity("SVCGETUSERSELF01", "Self-User");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Broad-User"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(
            body.contains(&format!(
                "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Self-User is not authorized to perform: \
                 iam:GetUser on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Broad-User"
            )),
            "unexpected body: {body}"
        );

        // The resource ARN carries the target user's path, so a grant scoped to a path prefix
        // reaches users under that path...
        let (principal, session_data) = user_identity("SVCGETUSERPATH01", "Path-User");
        let (status, body) =
            call(&svc_state, principal, session_data, &get_user_parameters(Some("Division-User"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/division/Division-User</Arn>")),
            "unexpected body: {body}"
        );
        assert!(body.contains("<Path>/division/</Path>"), "unexpected body: {body}");

        // ...and no further.
        let (principal, session_data) = user_identity("SVCGETUSERPATH01", "Path-User");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Broad-User"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // The target user's tags back the aws:ResourceTag condition keys. The policy spells the
        // tag key in lower case while the tag itself is stored as "Department", confirming that
        // tag keys are matched case-insensitively.
        let (principal, session_data) = user_identity("SVCGETUSERTAG001", "Tag-User");
        let (status, body) =
            call(&svc_state, principal, session_data, &get_user_parameters(Some("Engineering-User"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Engineering-User</Arn>")),
            "unexpected body: {body}"
        );

        // A user carrying the tag with a different value does not satisfy the condition.
        let (principal, session_data) = user_identity("SVCGETUSERTAG001", "Tag-User");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Sales-User"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // Neither does a user carrying no tags at all: the condition key is absent.
        let (principal, session_data) = user_identity("SVCGETUSERTAG001", "Tag-User");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Broad-User"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // IAM's own iam:ResourceTag condition key carries the same values.
        let (principal, session_data) = user_identity("SVCGETUSERIAMTG1", "Iam-Tag-User");
        let (status, body) =
            call(&svc_state, principal, session_data, &get_user_parameters(Some("Engineering-User"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Engineering-User</Arn>")),
            "unexpected body: {body}"
        );

        // A user that does not exist is still authorized against the ARN the request names, so a
        // caller allowed iam:GetUser on any user is told the user is missing...
        let (principal, session_data) = user_identity("SVCGETUSERBROAD1", "Broad-User");
        let (status, body) =
            call(&svc_state, principal, session_data, &get_user_parameters(Some("No-Such-User"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

        // ...while a caller allowed it only on specific users learns nothing about it.
        let (principal, session_data) = user_identity("SVCGETUSERNARROW", "Narrow-User");
        let (status, body) =
            call(&svc_state, principal, session_data, &get_user_parameters(Some("No-Such-User"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // An assumed-role session has no user to default UserName to.
        let (principal, session_data) = role_identity("SVCGETUSERROLE01", "Get-User-Role");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
        assert!(
            body.contains("Must specify userName when calling with non-User credentials"),
            "unexpected body: {body}"
        );

        // Naming the user explicitly works, governed by the role's own policy.
        let (principal, session_data) = role_identity("SVCGETUSERROLE01", "Get-User-Role");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Broad-User"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Broad-User</Arn>")),
            "unexpected body: {body}"
        );

        // The account root user is implicitly allowed, but is not an IAM user either, so it must
        // also name the user explicitly.
        let (principal, session_data) = root_identity();
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

        let (principal, session_data) = root_identity();
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Sales-User"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Sales-User</Arn>")),
            "unexpected body: {body}"
        );
    }
}
