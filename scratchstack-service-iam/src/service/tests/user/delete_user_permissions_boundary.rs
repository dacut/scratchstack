use {
    crate::service::{ServiceState, tests::*},
    pretty_assertions::assert_eq,
    scratchstack_core::axum::http::StatusCode,
    scratchstack_iam_database::{migrate::MIGRATOR, utils::TempDatabase},
    sqlx::raw_sql,
    std::sync::Arc,
};

/// Seed data for the `DeleteUserPermissionsBoundary` authorization tests. Every target but
/// `Unbounded-Target` already carries `Boundary-Policy` as its boundary, so each caller has
/// something to take away and a user with no boundary can be told apart from one that does not
/// exist. The callers carry grants scoped by the path of the user losing its boundary, by that
/// user's tags, and by the user itself; the boundary being cleared is not named by the
/// request, so there is nothing here for a grant to scope by it.
const DELETE_USER_PERMISSIONS_BOUNDARY_TEST_DATA: &str = r#"
    INSERT INTO iam.partition(partition) VALUES ('aws');

    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('123456789012', 'delete-user-permissions-boundary-test@example.com',
        'delete-user-permissions-boundary-test');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCDPBPOLBND0001', '123456789012', 'boundary-policy', 'Boundary-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCDPBPOLBND0001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path,
        permissions_boundary_managed_policy_id) VALUES
    ('SVCDPBBROADDEL01', '123456789012', 'broad-clearer', 'Broad-Clearer', '/', NULL),
    ('SVCDPBPATHDEL001', '123456789012', 'path-clearer', 'Path-Clearer', '/', NULL),
    ('SVCDPBTAGDEL0001', '123456789012', 'tag-clearer', 'Tag-Clearer', '/', NULL),
    ('SVCDPBNARROWD001', '123456789012', 'narrow-clearer', 'Narrow-Clearer', '/', NULL),
    ('SVCDPBNOGRANTD01', '123456789012', 'no-grant-clearer', 'No-Grant-Clearer', '/', NULL),
    ('SVCDPBTGTPLAIN01', '123456789012', 'boundary-target', 'Boundary-Target', '/', 'SVCDPBPOLBND0001'),
    ('SVCDPBTGTEMPTY01', '123456789012', 'unbounded-target', 'Unbounded-Target', '/', NULL),
    ('SVCDPBTGTDIVSN01', '123456789012', 'division-target', 'Division-Target', '/division/', 'SVCDPBPOLBND0001'),
    ('SVCDPBTGTENGNR01', '123456789012', 'engineering-target', 'Engineering-Target', '/', 'SVCDPBPOLBND0001'),
    ('SVCDPBTGTSALES01', '123456789012', 'sales-target', 'Sales-Target', '/', 'SVCDPBPOLBND0001'),
    ('SVCDPBTGTROLE001', '123456789012', 'role-target', 'Role-Target', '/', 'SVCDPBPOLBND0001'),
    ('SVCDPBTGTROOT001', '123456789012', 'root-target', 'Root-Target', '/', 'SVCDPBPOLBND0001');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCDPBTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCDPBTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDPBBROADDEL01', 'allow-clear-any-boundary', 'Allow-Clear-Any-Boundary',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUserPermissionsBoundary",
        "Resource":"*"}]}'),
    ('SVCDPBPATHDEL001', 'allow-clear-on-division', 'Allow-Clear-On-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUserPermissionsBoundary",
        "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
    ('SVCDPBTAGDEL0001', 'allow-clear-on-engineering', 'Allow-Clear-On-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUserPermissionsBoundary",
        "Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCDPBNARROWD001', 'allow-clear-on-target', 'Allow-Clear-On-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUserPermissionsBoundary",
        "Resource":"arn:aws:iam::123456789012:user/Boundary-Target"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCDPBROLE000001', '123456789012', 'delete-user-permissions-boundary-role',
        'Delete-User-Permissions-Boundary-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDPBROLE000001', 'allow-clear-any-boundary', 'Allow-Clear-Any-Boundary',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUserPermissionsBoundary",
        "Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `DeleteUserPermissionsBoundary` through
/// `serve_request` against an embedded PostgreSQL database. A single test function is used
/// because the database is stateful and expensive to start.
#[test_log::test(tokio::test)]
async fn test_delete_user_permissions_boundary_authorization() {
    const BOUNDARY_ARN: &str = "arn:aws:iam::123456789012:policy/Boundary-Policy";

    let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
    database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
    let pool =
        database.get_scratchstack_pool().await.expect("Failed to get PostgreSQL connection pool for scratchstack user");

    let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
    MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
    raw_sql(DELETE_USER_PERMISSIONS_BOUNDARY_TEST_DATA)
        .execute(&mut *c)
        .await
        .expect("Failed to load test data into database");
    drop(c);

    let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();

    // A caller allowed iam:DeleteUserPermissionsBoundary on any user clears the boundary on
    // one.
    let (principal, session_data) = user_identity("SVCDPBBROADDEL01", "Broad-Clearer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_permissions_boundary_parameters(Some("Boundary-Target")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DeleteUserPermissionsBoundaryResponse"), "unexpected body: {body}");

    // The boundary is gone: the root user, implicitly allowed everything, reads the user back.
    // The managed policy serving as the boundary is untouched, so it can be imposed again.
    let (principal, session_data) = root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Boundary-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<PermissionsBoundary"), "unexpected body: {body}");

    // Clearing a boundary that is already gone succeeds and changes nothing, and so does
    // clearing one from a user that never carried one.
    for user_name in ["Boundary-Target", "Unbounded-Target"] {
        let (principal, session_data) = user_identity("SVCDPBBROADDEL01", "Broad-Clearer");
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_user_permissions_boundary_parameters(Some(user_name)))
                .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    }

    // The resource ARN carries the user's path, so a grant scoped to a path prefix reaches
    // users under that path...
    let (principal, session_data) = user_identity("SVCDPBPATHDEL001", "Path-Clearer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_permissions_boundary_parameters(Some("Division-Target")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = user_identity("SVCDPBPATHDEL001", "Path-Clearer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_permissions_boundary_parameters(Some("Boundary-Target")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the user back the aws:ResourceTag condition keys.
    let (principal, session_data) = user_identity("SVCDPBTAGDEL0001", "Tag-Clearer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_permissions_boundary_parameters(Some("Engineering-Target")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = user_identity("SVCDPBTAGDEL0001", "Tag-Clearer");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_user_permissions_boundary_parameters(Some("Sales-Target")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled its transaction back, so that user still carries its boundary.
    let (principal, session_data) = root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Sales-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<PermissionsBoundaryArn>{BOUNDARY_ARN}</PermissionsBoundaryArn>")),
        "unexpected body: {body}"
    );

    // A grant naming a single user reaches that user's boundary, whichever policy is serving
    // as it, and reaches no other user.
    let (principal, session_data) = user_identity("SVCDPBNARROWD001", "Narrow-Clearer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_permissions_boundary_parameters(Some("Boundary-Target")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = user_identity("SVCDPBNARROWD001", "Narrow-Clearer");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_user_permissions_boundary_parameters(Some("Sales-Target")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = user_identity("SVCDPBNOGRANTD01", "No-Grant-Clearer");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_user_permissions_boundary_parameters(Some("Sales-Target")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/No-Grant-Clearer is not authorized to perform: \
                 iam:DeleteUserPermissionsBoundary on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Sales-Target"
        )),
        "unexpected body: {body}"
    );

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:DeleteUserPermissionsBoundary on any user is told the user is
    // missing...
    let (principal, session_data) = user_identity("SVCDPBBROADDEL01", "Broad-Clearer");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_user_permissions_boundary_parameters(Some("No-Such-User")))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = user_identity("SVCDPBNARROWD001", "Narrow-Clearer");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_user_permissions_boundary_parameters(Some("No-Such-User")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // UserName is required.
    let (principal, session_data) = user_identity("SVCDPBBROADDEL01", "Broad-Clearer");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_user_permissions_boundary_parameters(None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // A user name that cannot name a user is rejected before the request is authorized, so
    // even a caller with no grant is told the name is malformed rather than denied.
    let (principal, session_data) = user_identity("SVCDPBNOGRANTD01", "No-Grant-Clearer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_permissions_boundary_parameters(Some("Not/A/User-Name")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = role_identity("SVCDPBROLE000001", "Delete-User-Permissions-Boundary-Role");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_user_permissions_boundary_parameters(Some("Role-Target")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_user_permissions_boundary_parameters(Some("Root-Target")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Root-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<PermissionsBoundary"), "unexpected body: {body}");
}
