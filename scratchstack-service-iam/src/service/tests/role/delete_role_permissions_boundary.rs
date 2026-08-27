use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `DeleteRolePermissionsBoundary` authorization tests. Every target but
/// `Unbounded-Target` already carries `Boundary-Policy` as its boundary, so each caller has
/// something to take away and a role with no boundary can be told apart from one that does not
/// exist. The callers carry grants scoped by the path of the role losing its boundary, by that
/// role's tags, by the role itself, and by the boundary being cleared -- which the request does
/// not name, but which the role carries and which backs `iam:PermissionsBoundary`.
const DELETE_ROLE_PERMISSIONS_BOUNDARY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'delete-role-permissions-boundary-test@example.com',
        'delete-role-permissions-boundary-test');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCDRBPOLBND0001', '%ACCOUNT_ID%', 'boundary-policy', 'Boundary-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCDRBPOLBND0001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCDRBBROADDEL01', '%ACCOUNT_ID%', 'broad-clearer', 'Broad-Clearer', '/'),
    ('SVCDRBPATHDEL001', '%ACCOUNT_ID%', 'path-clearer', 'Path-Clearer', '/'),
    ('SVCDRBTAGDEL0001', '%ACCOUNT_ID%', 'tag-clearer', 'Tag-Clearer', '/'),
    ('SVCDRBNARROWD001', '%ACCOUNT_ID%', 'narrow-clearer', 'Narrow-Clearer', '/'),
    ('SVCDRBNOGRANTD01', '%ACCOUNT_ID%', 'no-grant-clearer', 'No-Grant-Clearer', '/'),
    ('SVCDRBBOUNDCLR01', '%ACCOUNT_ID%', 'bounded-clearer', 'Bounded-Clearer', '/');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document, permissions_boundary_managed_policy_id) VALUES
    ('SVCDRBTGTPLAIN01', '%ACCOUNT_ID%', 'boundary-target', 'Boundary-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        'SVCDRBPOLBND0001'),
    ('SVCDRBTGTEMPTY01', '%ACCOUNT_ID%', 'unbounded-target', 'Unbounded-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        NULL),
    ('SVCDRBTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        'SVCDRBPOLBND0001'),
    ('SVCDRBTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        'SVCDRBPOLBND0001'),
    ('SVCDRBTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        'SVCDRBPOLBND0001'),
    ('SVCDRBTGTROLE001', '%ACCOUNT_ID%', 'role-target', 'Role-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        'SVCDRBPOLBND0001'),
    ('SVCDRBTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        'SVCDRBPOLBND0001'),
    ('SVCDRBTGTBOUND01', '%ACCOUNT_ID%', 'bounded-target', 'Bounded-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        'SVCDRBPOLBND0001'),
    ('SVCDRBROLE000001', '%ACCOUNT_ID%', 'delete-role-permissions-boundary-role',
        'Delete-Role-Permissions-Boundary-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        NULL);

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCDRBTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCDRBTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDRBBROADDEL01', 'allow-clear-any-boundary', 'Allow-Clear-Any-Boundary',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteRolePermissionsBoundary",
        "Resource":"*"}]}'),
    ('SVCDRBPATHDEL001', 'allow-clear-on-division', 'Allow-Clear-On-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteRolePermissionsBoundary",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/division/*"}]}'),
    ('SVCDRBTAGDEL0001', 'allow-clear-on-engineering', 'Allow-Clear-On-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteRolePermissionsBoundary",
        "Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCDRBNARROWD001', 'allow-clear-on-target', 'Allow-Clear-On-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteRolePermissionsBoundary",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/Boundary-Target"}]}'),
    ('SVCDRBBOUNDCLR01', 'allow-clear-known-boundary', 'Allow-Clear-Known-Boundary',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteRolePermissionsBoundary",
        "Resource":"*","Condition":{"StringEquals":{"iam:PermissionsBoundary":
        "arn:aws:iam::%ACCOUNT_ID%:policy/Boundary-Policy"}}}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDRBROLE000001', 'allow-clear-any-boundary', 'Allow-Clear-Any-Boundary',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteRolePermissionsBoundary",
        "Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `DeleteRolePermissionsBoundary` through `serve_request`
/// against an embedded PostgreSQL database. A single test function covers every case: the cases
/// run in order against one account, and several of them read the state the cases before them
/// left behind.
#[test_log::test(tokio::test)]
async fn test_delete_role_permissions_boundary_authorization() {
    let database = TestDatabase::new(DELETE_ROLE_PERMISSIONS_BOUNDARY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let boundary_arn = database.arn("policy/Boundary-Policy");

    // A caller allowed iam:DeleteRolePermissionsBoundary on any role clears the boundary on one.
    let (principal, session_data) = database.user_identity("SVCDRBBROADDEL01", "Broad-Clearer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_permissions_boundary_parameters(Some("Boundary-Target")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DeleteRolePermissionsBoundaryResponse"), "unexpected body: {body}");

    // The boundary is gone: the root user, implicitly allowed everything, reads the role back.
    // The managed policy serving as the boundary is untouched, so it can be imposed again.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Boundary-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<PermissionsBoundary"), "unexpected body: {body}");

    // Clearing a boundary that is already gone succeeds and changes nothing, and so does clearing
    // one from a role that never carried one.
    for role_name in ["Boundary-Target", "Unbounded-Target"] {
        let (principal, session_data) = database.user_identity("SVCDRBBROADDEL01", "Broad-Clearer");
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_role_permissions_boundary_parameters(Some(role_name)))
                .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    }

    // The resource ARN carries the role's path, so a grant scoped to a path prefix reaches roles
    // under that path...
    let (principal, session_data) = database.user_identity("SVCDRBPATHDEL001", "Path-Clearer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_permissions_boundary_parameters(Some("Division-Target")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCDRBPATHDEL001", "Path-Clearer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_permissions_boundary_parameters(Some("Boundary-Target")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the role back the aws:ResourceTag condition keys.
    let (principal, session_data) = database.user_identity("SVCDRBTAGDEL0001", "Tag-Clearer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_permissions_boundary_parameters(Some("Engineering-Target")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A role carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCDRBTAGDEL0001", "Tag-Clearer");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_role_permissions_boundary_parameters(Some("Sales-Target")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled its transaction back, so that role still carries its boundary.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Sales-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<PermissionsBoundaryArn>{boundary_arn}</PermissionsBoundaryArn>")),
        "unexpected body: {body}"
    );

    // A grant naming a single role reaches that role's boundary, whichever policy is serving as
    // it, and reaches no other role.
    let (principal, session_data) = database.user_identity("SVCDRBNARROWD001", "Narrow-Clearer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_permissions_boundary_parameters(Some("Boundary-Target")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCDRBNARROWD001", "Narrow-Clearer");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_role_permissions_boundary_parameters(Some("Sales-Target")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The boundary the role carries backs iam:PermissionsBoundary even though the request does not
    // name it, so a grant confined to clearing one particular boundary reaches a role under it.
    // This is the operation such a condition matters most on: without it, a grant to clear
    // boundaries is a grant to clear every boundary.
    let (principal, session_data) = database.user_identity("SVCDRBBOUNDCLR01", "Bounded-Clearer");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_role_permissions_boundary_parameters(Some("Bounded-Target")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The key describes the role as it stands when the request is authorized, so once the boundary
    // is gone the same caller can no longer reach that role at all.
    let (principal, session_data) = database.user_identity("SVCDRBBOUNDCLR01", "Bounded-Clearer");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_role_permissions_boundary_parameters(Some("Bounded-Target")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A role that never carried a boundary supplies no key, so the condition does not match rather
    // than matching an empty string.
    let (principal, session_data) = database.user_identity("SVCDRBBOUNDCLR01", "Bounded-Clearer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_permissions_boundary_parameters(Some("Unbounded-Target")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCDRBNOGRANTD01", "No-Grant-Clearer");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_role_permissions_boundary_parameters(Some("Sales-Target")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Clearer is not authorized to perform: \
                 iam:DeleteRolePermissionsBoundary on resource: arn:aws:iam::{account_id}:role/Sales-Target"
        )),
        "unexpected body: {body}"
    );

    // A role that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:DeleteRolePermissionsBoundary on any role is told the role is missing...
    let (principal, session_data) = database.user_identity("SVCDRBBROADDEL01", "Broad-Clearer");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_role_permissions_boundary_parameters(Some("No-Such-Role")))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific role learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCDRBNARROWD001", "Narrow-Clearer");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_role_permissions_boundary_parameters(Some("No-Such-Role")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // RoleName is required.
    let (principal, session_data) = database.user_identity("SVCDRBBROADDEL01", "Broad-Clearer");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_role_permissions_boundary_parameters(None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // A role name that cannot name a role is rejected before the request is authorized, so even a
    // caller with no grant is told the name is malformed rather than denied.
    let (principal, session_data) = database.user_identity("SVCDRBNOGRANTD01", "No-Grant-Clearer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_permissions_boundary_parameters(Some("Not/A/Role-Name")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCDRBROLE000001", "Delete-Role-Permissions-Boundary-Role");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_role_permissions_boundary_parameters(Some("Role-Target")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_role_permissions_boundary_parameters(Some("Root-Target")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Root-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<PermissionsBoundary"), "unexpected body: {body}");
}
