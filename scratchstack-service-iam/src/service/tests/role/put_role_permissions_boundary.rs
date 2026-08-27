use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `PutRolePermissionsBoundary` authorization tests. The callers carry grants
/// scoped by the boundary being imposed (`iam:PermissionsBoundary`), by the path of the role
/// receiving it, by that role's tags, and by the role itself; the managed policies give those
/// grants something to distinguish, with `Safe-Boundary` under a path of its own and
/// `Role-Aws-Managed-Boundary` owned by the AWS account rather than by this one.
const PUT_ROLE_PERMISSIONS_BOUNDARY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'put-role-permissions-boundary-test@example.com', 'put-role-permissions-boundary-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCPRBBROADSET01', '%ACCOUNT_ID%', 'broad-setter', 'Broad-Setter', '/'),
    ('SVCPRBSAFESET001', '%ACCOUNT_ID%', 'safe-setter', 'Safe-Setter', '/'),
    ('SVCPRBAWSSET0001', '%ACCOUNT_ID%', 'aws-setter', 'Aws-Setter', '/'),
    ('SVCPRBPATHSET001', '%ACCOUNT_ID%', 'path-setter', 'Path-Setter', '/'),
    ('SVCPRBTAGSET0001', '%ACCOUNT_ID%', 'tag-setter', 'Tag-Setter', '/'),
    ('SVCPRBNARROWS001', '%ACCOUNT_ID%', 'narrow-setter', 'Narrow-Setter', '/'),
    ('SVCPRBNOGRANTS01', '%ACCOUNT_ID%', 'no-grant-setter', 'No-Grant-Setter', '/');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCPRBPOLSAFE001', '%ACCOUNT_ID%', 'safe-boundary', 'Safe-Boundary', '/safe/', 1, false, 1),
    ('SVCPRBPOLWIDE001', '%ACCOUNT_ID%', 'wide-boundary', 'Wide-Boundary', '/', 1, false, 1),
    ('SVCPRBPOLAWSMG01', '000000000000', 'role-aws-managed-boundary', 'Role-Aws-Managed-Boundary', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCPRBPOLSAFE001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCPRBPOLWIDE001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'),
    ('SVCPRBPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCPRBBROADSET01', 'allow-set-any-boundary', 'Allow-Set-Any-Boundary',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutRolePermissionsBoundary",
        "Resource":"*"}]}'),
    ('SVCPRBSAFESET001', 'allow-set-safe-boundaries', 'Allow-Set-Safe-Boundaries',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutRolePermissionsBoundary",
        "Resource":"*","Condition":{"ArnLike":
            {"iam:PermissionsBoundary":"arn:aws:iam::%ACCOUNT_ID%:policy/safe/*"}}}]}'),
    ('SVCPRBAWSSET0001', 'allow-set-aws-boundaries', 'Allow-Set-Aws-Boundaries',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutRolePermissionsBoundary",
        "Resource":"*","Condition":{"ArnLike":{"iam:PermissionsBoundary":"arn:aws:iam::aws:policy/*"}}}]}'),
    ('SVCPRBPATHSET001', 'allow-set-on-division', 'Allow-Set-On-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutRolePermissionsBoundary",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/division/*"}]}'),
    ('SVCPRBTAGSET0001', 'allow-set-on-engineering', 'Allow-Set-On-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutRolePermissionsBoundary",
        "Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCPRBNARROWS001', 'allow-set-on-target', 'Allow-Set-On-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutRolePermissionsBoundary",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/Boundary-Target"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCPRBTGTPLAIN01', '%ACCOUNT_ID%', 'boundary-target', 'Boundary-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCPRBTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCPRBTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCPRBTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCPRBTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCPRBROLE000001', '%ACCOUNT_ID%', 'put-role-permissions-boundary-role', 'Put-Role-Permissions-Boundary-Role',
        '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCPRBTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCPRBTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCPRBROLE000001', 'allow-set-any-boundary', 'Allow-Set-Any-Boundary',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutRolePermissionsBoundary",
        "Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `PutRolePermissionsBoundary` through `serve_request`
/// against an embedded PostgreSQL database. A single test function covers every case: the cases
/// run in order against one account, and several of them read the state the cases before them
/// left behind.
#[test_log::test(tokio::test)]
async fn test_put_role_permissions_boundary_authorization() {
    const AWS_MANAGED_BOUNDARY_ARN: &str = "arn:aws:iam::aws:policy/Role-Aws-Managed-Boundary";

    let database = TestDatabase::new(PUT_ROLE_PERMISSIONS_BOUNDARY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let safe_boundary_arn = database.arn("policy/safe/Safe-Boundary");
    let wide_boundary_arn = database.arn("policy/Wide-Boundary");

    // A caller allowed iam:PutRolePermissionsBoundary on any role imposes a boundary on one.
    let (principal, session_data) = database.user_identity("SVCPRBBROADSET01", "Broad-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Boundary-Target"), Some(wide_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PutRolePermissionsBoundaryResponse"), "unexpected body: {body}");

    // The boundary took: the root user, implicitly allowed everything, reads it back.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Boundary-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<PermissionsBoundaryArn>{wide_boundary_arn}</PermissionsBoundaryArn>")),
        "unexpected body: {body}"
    );

    // Naming the boundary the role already carries succeeds and changes nothing.
    let (principal, session_data) = database.user_identity("SVCPRBBROADSET01", "Broad-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Boundary-Target"), Some(wide_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // Naming another one replaces it: a role carries at most one boundary.
    let (principal, session_data) = database.user_identity("SVCPRBBROADSET01", "Broad-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Boundary-Target"), Some(safe_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Boundary-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<PermissionsBoundaryArn>{safe_boundary_arn}</PermissionsBoundaryArn>")),
        "unexpected body: {body}"
    );
    assert!(!body.contains(&wide_boundary_arn), "unexpected body: {body}");

    // The boundary being imposed backs iam:PermissionsBoundary, so a grant confined to a policy
    // path reaches the policies under it...
    let (principal, session_data) = database.user_identity("SVCPRBSAFESET001", "Safe-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Boundary-Target"), Some(safe_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further, however broadly the roles it may impose them on are named. This is what
    // keeps such a caller from widening a role's permissions -- and with them the permissions of
    // everyone who can assume it -- by swapping its boundary for a laxer one.
    let (principal, session_data) = database.user_identity("SVCPRBSAFESET001", "Safe-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Boundary-Target"), Some(wide_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // An AWS-owned policy is named through the aws account alias, and iam:PermissionsBoundary
    // carries the ARN as the request spelled it, so that is what the condition compares.
    let (principal, session_data) = database.user_identity("SVCPRBAWSSET0001", "Aws-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Boundary-Target"), Some(AWS_MANAGED_BOUNDARY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The boundary is reported under the numeric account behind the alias, which is the account
    // it is stored under and the account it is reported under everywhere else.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Boundary-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(
            "<PermissionsBoundaryArn>arn:aws:iam::000000000000:policy/Role-Aws-Managed-Boundary\
                 </PermissionsBoundaryArn>"
        ),
        "unexpected body: {body}"
    );

    // The same policy named through the numeric account this implementation stores it under is a
    // different string, and the condition compares the string it was given.
    let (principal, session_data) = database.user_identity("SVCPRBAWSSET0001", "Aws-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(
            Some("Boundary-Target"),
            Some("arn:aws:iam::000000000000:policy/Role-Aws-Managed-Boundary"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The resource ARN carries the receiving role's path, so a grant scoped to a path prefix
    // reaches roles under that path...
    let (principal, session_data) = database.user_identity("SVCPRBPATHSET001", "Path-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Division-Target"), Some(safe_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCPRBPATHSET001", "Path-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Boundary-Target"), Some(safe_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the receiving role back the aws:ResourceTag condition keys.
    let (principal, session_data) = database.user_identity("SVCPRBTAGSET0001", "Tag-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Engineering-Target"), Some(safe_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A role carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCPRBTAGSET0001", "Tag-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Sales-Target"), Some(safe_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled its transaction back, so that role still carries no boundary.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Sales-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<PermissionsBoundary"), "unexpected body: {body}");

    // A grant naming a single role and no boundary reaches every policy in the account -- so such
    // a caller can hand that role whatever boundary it likes -- and reaches no other role.
    let (principal, session_data) = database.user_identity("SVCPRBNARROWS001", "Narrow-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Boundary-Target"), Some(wide_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCPRBNARROWS001", "Narrow-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Sales-Target"), Some(wide_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCPRBNOGRANTS01", "No-Grant-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Boundary-Target"), Some(wide_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Setter is not authorized to perform: \
                 iam:PutRolePermissionsBoundary on resource: arn:aws:iam::{account_id}:role/Boundary-Target"
        )),
        "unexpected body: {body}"
    );

    // A role that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:PutRolePermissionsBoundary on any role is told the role is missing...
    let (principal, session_data) = database.user_identity("SVCPRBBROADSET01", "Broad-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("No-Such-Role"), Some(wide_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific role learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCPRBNARROWS001", "Narrow-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("No-Such-Role"), Some(wide_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A boundary policy that does not exist is reported the same way, once the caller is allowed
    // to have asked.
    let (principal, session_data) = database.user_identity("SVCPRBBROADSET01", "Broad-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(
            Some("Boundary-Target"),
            Some(database.arn("policy/No-Such-Policy").as_str()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // That rolled its transaction back, so the boundary the role already carried is still the one
    // it carries.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Boundary-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<PermissionsBoundaryArn>{wide_boundary_arn}</PermissionsBoundaryArn>")),
        "unexpected body: {body}"
    );

    // RoleName and PermissionsBoundary are both required.
    for parameters in [
        put_role_permissions_boundary_parameters(None, Some(wide_boundary_arn.as_str())),
        put_role_permissions_boundary_parameters(Some("Boundary-Target"), None),
    ] {
        let (principal, session_data) = database.user_identity("SVCPRBBROADSET01", "Broad-Setter");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // A boundary ARN too short to be one is rejected before the request is authorized; one long
    // enough to reach the update -- whether it is not an ARN at all, or an ARN naming something
    // that is not a policy -- is rejected by it, after.
    for permissions_boundary in [
        "arn:aws:iam::1:p".to_string(),
        "not-an-arn-but-long-enough-to-pass".to_string(),
        database.arn("role/Boundary-Target"),
    ] {
        let (principal, session_data) = database.user_identity("SVCPRBBROADSET01", "Broad-Setter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &put_role_permissions_boundary_parameters(Some("Boundary-Target"), Some(permissions_boundary.as_str())),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // A caller whose grant is confined by iam:PermissionsBoundary never gets that far: a value
    // that is not an ARN at all matches none of the ARNs the policy lists, so it is denied rather
    // than told the ARN is malformed.
    let (principal, session_data) = database.user_identity("SVCPRBSAFESET001", "Safe-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Boundary-Target"), Some("not-an-arn-but-long-enough-to-pass")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A role name that cannot name a role is rejected before the request is authorized, so even a
    // caller with no grant is told the name is malformed rather than denied.
    let (principal, session_data) = database.user_identity("SVCPRBNOGRANTS01", "No-Grant-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Not/A/Role-Name"), Some(wide_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCPRBROLE000001", "Put-Role-Permissions-Boundary-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Division-Target"), Some(wide_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_permissions_boundary_parameters(Some("Root-Target"), Some(safe_boundary_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Root-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<PermissionsBoundaryArn>{safe_boundary_arn}</PermissionsBoundaryArn>")),
        "unexpected body: {body}"
    );
}
