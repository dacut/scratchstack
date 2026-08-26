use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `DetachUserPolicy` authorization tests. This mirrors
/// [`ATTACH_USER_POLICY_TEST_DATA`] with the attachments already in place, so that each caller
/// has something to take away: `Detach-Target` carries three policies, and every other target
/// carries `Admin-Policy`.
const DETACH_USER_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.partition(partition) VALUES ('aws');

    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('123456789012', 'detach-user-policy-test@example.com', 'detach-user-policy-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCDUPBROADDET01', '123456789012', 'broad-detacher', 'Broad-Detacher', '/'),
    ('SVCDUPSAFEDET001', '123456789012', 'safe-detacher', 'Safe-Detacher', '/'),
    ('SVCDUPPATHDET001', '123456789012', 'path-detacher', 'Path-Detacher', '/'),
    ('SVCDUPTAGDET0001', '123456789012', 'tag-detacher', 'Tag-Detacher', '/'),
    ('SVCDUPNARROWD001', '123456789012', 'narrow-detacher', 'Narrow-Detacher', '/'),
    ('SVCDUPNOGRANTD01', '123456789012', 'no-grant-detacher', 'No-Grant-Detacher', '/'),
    ('SVCDUPTGTPLAIN01', '123456789012', 'detach-target', 'Detach-Target', '/'),
    ('SVCDUPTGTDIVSN01', '123456789012', 'division-target', 'Division-Target', '/division/'),
    ('SVCDUPTGTENGNR01', '123456789012', 'engineering-target', 'Engineering-Target', '/'),
    ('SVCDUPTGTSALES01', '123456789012', 'sales-target', 'Sales-Target', '/'),
    ('SVCDUPTGTROLE001', '123456789012', 'role-target', 'Role-Target', '/'),
    ('SVCDUPTGTROOT001', '123456789012', 'root-target', 'Root-Target', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCDUPTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCDUPTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCDUPPOLSAFE001', '123456789012', 'safe-policy', 'Safe-Policy', '/safe/', 1, false, 1),
    ('SVCDUPPOLADMIN01', '123456789012', 'admin-policy', 'Admin-Policy', '/', 1, false, 1),
    ('SVCDUPPOLEXTRA01', '123456789012', 'extra-policy', 'Extra-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCDUPPOLSAFE001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDUPPOLADMIN01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'),
    ('SVCDUPPOLEXTRA01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}');

    INSERT INTO iam.user_attached_policies(user_id, managed_policy_id) VALUES
    ('SVCDUPTGTPLAIN01', 'SVCDUPPOLADMIN01'),
    ('SVCDUPTGTPLAIN01', 'SVCDUPPOLSAFE001'),
    ('SVCDUPTGTPLAIN01', 'SVCDUPPOLEXTRA01'),
    ('SVCDUPTGTDIVSN01', 'SVCDUPPOLADMIN01'),
    ('SVCDUPTGTENGNR01', 'SVCDUPPOLADMIN01'),
    ('SVCDUPTGTSALES01', 'SVCDUPPOLADMIN01'),
    ('SVCDUPTGTROLE001', 'SVCDUPPOLADMIN01'),
    ('SVCDUPTGTROOT001', 'SVCDUPPOLADMIN01');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDUPBROADDET01', 'allow-detach-any-policy', 'Allow-Detach-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DetachUserPolicy","Resource":"*"}]}'),
    ('SVCDUPSAFEDET001', 'allow-detach-safe-policies', 'Allow-Detach-Safe-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DetachUserPolicy","Resource":"*",
        "Condition":{"ArnLike":{"iam:PolicyARN":"arn:aws:iam::123456789012:policy/safe/*"}}}]}'),
    ('SVCDUPPATHDET001', 'allow-detach-from-division', 'Allow-Detach-From-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DetachUserPolicy",
        "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
    ('SVCDUPTAGDET0001', 'allow-detach-from-engineering', 'Allow-Detach-From-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DetachUserPolicy","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCDUPNARROWD001', 'allow-detach-from-target', 'Allow-Detach-From-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DetachUserPolicy",
        "Resource":"arn:aws:iam::123456789012:user/Detach-Target"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCDUPROLE000001', '123456789012', 'detach-user-policy-role', 'Detach-User-Policy-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDUPROLE000001', 'allow-detach-any-policy', 'Allow-Detach-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DetachUserPolicy","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `DetachUserPolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one database, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_detach_user_policy_authorization() {
    const ADMIN_POLICY_ARN: &str = "arn:aws:iam::123456789012:policy/Admin-Policy";
    const EXTRA_POLICY_ARN: &str = "arn:aws:iam::123456789012:policy/Extra-Policy";
    const SAFE_POLICY_ARN: &str = "arn:aws:iam::123456789012:policy/safe/Safe-Policy";

    let database = TestDatabase::new(DETACH_USER_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();

    // The policy being detached backs iam:PolicyARN here as it does when attaching, so a grant
    // confined to a policy path reaches the policies under it...
    let (principal, session_data) = user_identity("SVCDUPSAFEDET001", "Safe-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("Detach-Target"), Some(SAFE_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DetachUserPolicyResponse"), "unexpected body: {body}");

    // ...and no further: a caller able to detach a policy can strip a user of the grants that
    // hold it in check, so which policies it may take away is worth confining.
    let (principal, session_data) = user_identity("SVCDUPSAFEDET001", "Safe-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("Detach-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Only the attachment was removed; the other two remain, and the managed policy itself is
    // untouched.
    let (principal, session_data) = root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Detach-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Admin-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>Extra-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(!body.contains("Safe-Policy"), "unexpected body: {body}");

    // A caller allowed iam:DetachUserPolicy on any user detaches any of them.
    let (principal, session_data) = user_identity("SVCDUPBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("Detach-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // Detaching is not idempotent the way attaching is: a policy the user does not carry is
    // reported as missing rather than as already detached.
    let (principal, session_data) = user_identity("SVCDUPBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("Detach-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // The resource ARN carries the losing user's path, so a grant scoped to a path prefix
    // reaches users under that path...
    let (principal, session_data) = user_identity("SVCDUPPATHDET001", "Path-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("Division-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = user_identity("SVCDUPPATHDET001", "Path-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("Detach-Target"), Some(EXTRA_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the losing user back the aws:ResourceTag condition keys.
    let (principal, session_data) = user_identity("SVCDUPTAGDET0001", "Tag-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("Engineering-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = user_identity("SVCDUPTAGDET0001", "Tag-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("Sales-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single user and no policy reaches every policy attached to it, and
    // reaches no other user.
    let (principal, session_data) = user_identity("SVCDUPNARROWD001", "Narrow-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("Detach-Target"), Some(EXTRA_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = user_identity("SVCDUPNARROWD001", "Narrow-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("Sales-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Detach-Target is now left carrying nothing.
    let (principal, session_data) = root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Detach-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains("<ListAttachedUserPoliciesResult><AttachedPolicies/></ListAttachedUserPoliciesResult>"),
        "unexpected body: {body}"
    );

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = user_identity("SVCDUPNOGRANTD01", "No-Grant-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("Sales-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/No-Grant-Detacher is not authorized to perform: \
                 iam:DetachUserPolicy on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Sales-Target"
        )),
        "unexpected body: {body}"
    );

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:DetachUserPolicy on any user is told the user is missing...
    let (principal, session_data) = user_identity("SVCDUPBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("No-Such-User"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = user_identity("SVCDUPNARROWD001", "Narrow-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("No-Such-User"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A policy that does not exist is reported the same way, once the caller is allowed to
    // have asked.
    let (principal, session_data) = user_identity("SVCDUPBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("Sales-Target"), Some("arn:aws:iam::123456789012:policy/No-Such-Policy")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // UserName and PolicyArn are both required.
    for parameters in [
        detach_user_policy_parameters(None, Some(ADMIN_POLICY_ARN)),
        detach_user_policy_parameters(Some("Sales-Target"), None),
    ] {
        let (principal, session_data) = user_identity("SVCDUPBROADDET01", "Broad-Detacher");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // A policy ARN too short to be one is rejected before the request is authorized; one long
    // enough to reach the detachment is rejected by it, after.
    for policy_arn in ["arn:aws:iam::1:p", "not-an-arn-but-long-enough-to-pass"] {
        let (principal, session_data) = user_identity("SVCDUPBROADDET01", "Broad-Detacher");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &detach_user_policy_parameters(Some("Sales-Target"), Some(policy_arn)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // A caller whose grant is confined by iam:PolicyARN never gets that far.
    let (principal, session_data) = user_identity("SVCDUPSAFEDET001", "Safe-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("Sales-Target"), Some("not-an-arn-but-long-enough-to-pass")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = role_identity("SVCDUPROLE000001", "Detach-User-Policy-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("Role-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_user_policy_parameters(Some("Root-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
}
