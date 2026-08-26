use {
    crate::service::{ServiceState, tests::*},
    pretty_assertions::assert_eq,
    scratchstack_core::axum::http::StatusCode,
    scratchstack_iam_database::{migrate::MIGRATOR, utils::TempDatabase},
    sqlx::raw_sql,
    std::sync::Arc,
};

/// Seed data for the `PutUserPermissionsBoundary` authorization tests. The callers carry
/// grants scoped by the boundary being imposed (`iam:PermissionsBoundary`), by the path of the
/// user receiving it, by that user's tags, and by the user itself; the managed policies give
/// those grants something to distinguish, with `Safe-Boundary` under a path of its own and
/// `Aws-Managed-Boundary` owned by the AWS account rather than by this one.
const PUT_USER_PERMISSIONS_BOUNDARY_TEST_DATA: &str = r#"
    INSERT INTO iam.partition(partition) VALUES ('aws');

    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('123456789012', 'put-user-permissions-boundary-test@example.com', 'put-user-permissions-boundary-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCPUBBROADSET01', '123456789012', 'broad-setter', 'Broad-Setter', '/'),
    ('SVCPUBSAFESET001', '123456789012', 'safe-setter', 'Safe-Setter', '/'),
    ('SVCPUBAWSSET0001', '123456789012', 'aws-setter', 'Aws-Setter', '/'),
    ('SVCPUBPATHSET001', '123456789012', 'path-setter', 'Path-Setter', '/'),
    ('SVCPUBTAGSET0001', '123456789012', 'tag-setter', 'Tag-Setter', '/'),
    ('SVCPUBNARROWS001', '123456789012', 'narrow-setter', 'Narrow-Setter', '/'),
    ('SVCPUBNOGRANTS01', '123456789012', 'no-grant-setter', 'No-Grant-Setter', '/'),
    ('SVCPUBTGTPLAIN01', '123456789012', 'boundary-target', 'Boundary-Target', '/'),
    ('SVCPUBTGTDIVSN01', '123456789012', 'division-target', 'Division-Target', '/division/'),
    ('SVCPUBTGTENGNR01', '123456789012', 'engineering-target', 'Engineering-Target', '/'),
    ('SVCPUBTGTSALES01', '123456789012', 'sales-target', 'Sales-Target', '/'),
    ('SVCPUBTGTROOT001', '123456789012', 'root-target', 'Root-Target', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCPUBTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCPUBTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCPUBPOLSAFE001', '123456789012', 'safe-boundary', 'Safe-Boundary', '/safe/', 1, false, 1),
    ('SVCPUBPOLWIDE001', '123456789012', 'wide-boundary', 'Wide-Boundary', '/', 1, false, 1),
    ('SVCPUBPOLAWSMG01', '000000000000', 'aws-managed-boundary', 'Aws-Managed-Boundary', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCPUBPOLSAFE001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCPUBPOLWIDE001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'),
    ('SVCPUBPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCPUBBROADSET01', 'allow-set-any-boundary', 'Allow-Set-Any-Boundary',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutUserPermissionsBoundary",
        "Resource":"*"}]}'),
    ('SVCPUBSAFESET001', 'allow-set-safe-boundaries', 'Allow-Set-Safe-Boundaries',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutUserPermissionsBoundary",
        "Resource":"*","Condition":{"ArnLike":
            {"iam:PermissionsBoundary":"arn:aws:iam::123456789012:policy/safe/*"}}}]}'),
    ('SVCPUBAWSSET0001', 'allow-set-aws-boundaries', 'Allow-Set-Aws-Boundaries',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutUserPermissionsBoundary",
        "Resource":"*","Condition":{"ArnLike":{"iam:PermissionsBoundary":"arn:aws:iam::aws:policy/*"}}}]}'),
    ('SVCPUBPATHSET001', 'allow-set-on-division', 'Allow-Set-On-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutUserPermissionsBoundary",
        "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
    ('SVCPUBTAGSET0001', 'allow-set-on-engineering', 'Allow-Set-On-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutUserPermissionsBoundary",
        "Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCPUBNARROWS001', 'allow-set-on-target', 'Allow-Set-On-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutUserPermissionsBoundary",
        "Resource":"arn:aws:iam::123456789012:user/Boundary-Target"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCPUBROLE000001', '123456789012', 'put-user-permissions-boundary-role', 'Put-User-Permissions-Boundary-Role',
        '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCPUBROLE000001', 'allow-set-any-boundary', 'Allow-Set-Any-Boundary',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutUserPermissionsBoundary",
        "Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `PutUserPermissionsBoundary` through `serve_request`
/// against an embedded PostgreSQL database. A single test function is used because the
/// database is stateful and expensive to start.
#[test_log::test(tokio::test)]
async fn test_put_user_permissions_boundary_authorization() {
    const SAFE_BOUNDARY_ARN: &str = "arn:aws:iam::123456789012:policy/safe/Safe-Boundary";
    const WIDE_BOUNDARY_ARN: &str = "arn:aws:iam::123456789012:policy/Wide-Boundary";
    const AWS_MANAGED_BOUNDARY_ARN: &str = "arn:aws:iam::aws:policy/Aws-Managed-Boundary";

    let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
    database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
    let pool =
        database.get_scratchstack_pool().await.expect("Failed to get PostgreSQL connection pool for scratchstack user");

    let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
    MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
    raw_sql(PUT_USER_PERMISSIONS_BOUNDARY_TEST_DATA)
        .execute(&mut *c)
        .await
        .expect("Failed to load test data into database");
    drop(c);

    let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();

    // A caller allowed iam:PutUserPermissionsBoundary on any user imposes a boundary on one.
    let (principal, session_data) = user_identity("SVCPUBBROADSET01", "Broad-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("Boundary-Target"), Some(WIDE_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PutUserPermissionsBoundaryResponse"), "unexpected body: {body}");

    // The boundary took: the root user, implicitly allowed everything, reads it back.
    let (principal, session_data) = root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Boundary-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<PermissionsBoundaryArn>{WIDE_BOUNDARY_ARN}</PermissionsBoundaryArn>")),
        "unexpected body: {body}"
    );

    // Naming the boundary the user already carries succeeds and changes nothing.
    let (principal, session_data) = user_identity("SVCPUBBROADSET01", "Broad-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("Boundary-Target"), Some(WIDE_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // Naming another one replaces it: a user carries at most one boundary.
    let (principal, session_data) = user_identity("SVCPUBBROADSET01", "Broad-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("Boundary-Target"), Some(SAFE_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Boundary-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<PermissionsBoundaryArn>{SAFE_BOUNDARY_ARN}</PermissionsBoundaryArn>")),
        "unexpected body: {body}"
    );
    assert!(!body.contains(WIDE_BOUNDARY_ARN), "unexpected body: {body}");

    // The boundary being imposed backs iam:PermissionsBoundary, so a grant confined to a
    // policy path reaches the policies under it...
    let (principal, session_data) = user_identity("SVCPUBSAFESET001", "Safe-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("Boundary-Target"), Some(SAFE_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further, however broadly the users it may impose them on are named. This is
    // what keeps such a caller from widening a user's permissions by swapping its boundary
    // for a laxer one.
    let (principal, session_data) = user_identity("SVCPUBSAFESET001", "Safe-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("Boundary-Target"), Some(WIDE_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // An AWS-owned policy is named through the aws account alias, and iam:PermissionsBoundary
    // carries the ARN as the request spelled it, so that is what the condition compares.
    let (principal, session_data) = user_identity("SVCPUBAWSSET0001", "Aws-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("Boundary-Target"), Some(AWS_MANAGED_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The boundary is reported under the numeric account behind the alias, which is the
    // account it is stored under and the account it is reported under everywhere else.
    let (principal, session_data) = root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Boundary-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(
            "<PermissionsBoundaryArn>arn:aws:iam::000000000000:policy/Aws-Managed-Boundary\
                 </PermissionsBoundaryArn>"
        ),
        "unexpected body: {body}"
    );

    // The same policy named through the numeric account this implementation stores it under is
    // a different string, and the condition compares the string it was given.
    let (principal, session_data) = user_identity("SVCPUBAWSSET0001", "Aws-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(
            Some("Boundary-Target"),
            Some("arn:aws:iam::000000000000:policy/Aws-Managed-Boundary"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The resource ARN carries the receiving user's path, so a grant scoped to a path prefix
    // reaches users under that path...
    let (principal, session_data) = user_identity("SVCPUBPATHSET001", "Path-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("Division-Target"), Some(SAFE_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = user_identity("SVCPUBPATHSET001", "Path-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("Boundary-Target"), Some(SAFE_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the receiving user back the aws:ResourceTag condition keys.
    let (principal, session_data) = user_identity("SVCPUBTAGSET0001", "Tag-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("Engineering-Target"), Some(SAFE_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = user_identity("SVCPUBTAGSET0001", "Tag-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("Sales-Target"), Some(SAFE_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single user and no boundary reaches every policy in the account -- so
    // such a caller can hand that user whatever boundary it likes -- and reaches no other
    // user.
    let (principal, session_data) = user_identity("SVCPUBNARROWS001", "Narrow-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("Boundary-Target"), Some(WIDE_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = user_identity("SVCPUBNARROWS001", "Narrow-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("Sales-Target"), Some(WIDE_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = user_identity("SVCPUBNOGRANTS01", "No-Grant-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("Boundary-Target"), Some(WIDE_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/No-Grant-Setter is not authorized to perform: \
                 iam:PutUserPermissionsBoundary on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Boundary-Target"
        )),
        "unexpected body: {body}"
    );

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:PutUserPermissionsBoundary on any user is told the user is missing...
    let (principal, session_data) = user_identity("SVCPUBBROADSET01", "Broad-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("No-Such-User"), Some(WIDE_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = user_identity("SVCPUBNARROWS001", "Narrow-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("No-Such-User"), Some(WIDE_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A boundary policy that does not exist is reported the same way, once the caller is
    // allowed to have asked.
    let (principal, session_data) = user_identity("SVCPUBBROADSET01", "Broad-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(
            Some("Boundary-Target"),
            Some("arn:aws:iam::123456789012:policy/No-Such-Policy"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // That rolled its transaction back, so the boundary the user already carried is still the
    // one it carries.
    let (principal, session_data) = root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Boundary-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<PermissionsBoundaryArn>{WIDE_BOUNDARY_ARN}</PermissionsBoundaryArn>")),
        "unexpected body: {body}"
    );

    // UserName and PermissionsBoundary are both required.
    for parameters in [
        put_user_permissions_boundary_parameters(None, Some(WIDE_BOUNDARY_ARN)),
        put_user_permissions_boundary_parameters(Some("Boundary-Target"), None),
    ] {
        let (principal, session_data) = user_identity("SVCPUBBROADSET01", "Broad-Setter");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // A boundary ARN too short to be one is rejected before the request is authorized; one
    // long enough to reach the update -- whether it is not an ARN at all, or an ARN naming
    // something that is not a policy -- is rejected by it, after.
    for permissions_boundary in
        ["arn:aws:iam::1:p", "not-an-arn-but-long-enough-to-pass", "arn:aws:iam::123456789012:user/Boundary-Target"]
    {
        let (principal, session_data) = user_identity("SVCPUBBROADSET01", "Broad-Setter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &put_user_permissions_boundary_parameters(Some("Boundary-Target"), Some(permissions_boundary)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // A caller whose grant is confined by iam:PermissionsBoundary never gets that far: a value
    // that is not an ARN at all matches none of the ARNs the policy lists, so it is denied
    // rather than told the ARN is malformed.
    let (principal, session_data) = user_identity("SVCPUBSAFESET001", "Safe-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("Boundary-Target"), Some("not-an-arn-but-long-enough-to-pass")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = role_identity("SVCPUBROLE000001", "Put-User-Permissions-Boundary-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("Division-Target"), Some(WIDE_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_permissions_boundary_parameters(Some("Root-Target"), Some(SAFE_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Root-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<PermissionsBoundaryArn>{SAFE_BOUNDARY_ARN}</PermissionsBoundaryArn>")),
        "unexpected body: {body}"
    );
}
