use {
    crate::service::{ServiceState, tests::*},
    chrono::{DateTime, Utc},
    pretty_assertions::assert_eq,
    scratchstack_aspen::Policy as AspenPolicy,
    scratchstack_aws_signature::SessionPolicies,
    scratchstack_core::axum::http::StatusCode,
    std::net::{IpAddr, Ipv4Addr},
};

/// End-to-end authorization checks through `serve_request` against an embedded PostgreSQL
/// database. A single test function covers every case so that they share one seeded database,
/// rather than migrating and seeding one apiece.
#[test_log::test(tokio::test)]
async fn test_list_users_authorization() {
    let database = TestDatabase::new(AUTHZ_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
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

    // iam:ListUsers names no resource ARN, so the account it lists supplies
    // aws:ResourceAccount: a grant scoped to that account admits the request, and one scoped
    // to another account does not.
    let (principal, session_data) = user_identity("SVCTESTACCTUSER1", "Account-User");
    let (status, body) = call(&svc_state, principal, session_data, parameters).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

    let (principal, session_data) = user_identity("SVCTESTOTHRACCT1", "Other-Account-User");
    let (status, body) = call(&svc_state, principal, session_data, parameters).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

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
    let issued_at = DateTime::parse_from_rfc3339("2019-06-01T00:00:00Z").expect("bad timestamp").with_timezone(&Utc);
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
    let session_policies = SessionPolicies::builder().managed_policy_ids(["ANPASVCTESTSESSPOL01".to_string()]).build();
    let (principal, session_data) = role_identity("SVCTESTROLE00001", "session-role");
    let (status, body) =
        call_with_session_policies(&svc_state, principal, session_data, session_policies, parameters).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

    // A managed session policy that no longer resolves cannot be reconstructed; the request
    // is denied (not an internal failure).
    let session_policies = SessionPolicies::builder().managed_policy_ids(["ANPADOESNOTEXIST0000".to_string()]).build();
    let (principal, session_data) = role_identity("SVCTESTROLE00001", "session-role");
    let (status, body) =
        call_with_session_policies(&svc_state, principal, session_data, session_policies, parameters).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
    assert!(body.contains("because no session policy allows the iam:ListUsers action"), "unexpected body: {body}");
}
