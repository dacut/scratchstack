use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `DetachGroupPolicy` authorization tests. Every group starts carrying the
/// policies the cases below take away, so each caller has something to detach and a policy that
/// is not attached can be told apart from one that does not exist. The callers are scoped by the
/// policy being detached (`iam:PolicyARN`), by the group's path, by the group itself, and not at
/// all.
const DETACH_GROUP_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'detach-group-policy-test@example.com', 'detach-group-policy-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCDGDBROADDET01', '%ACCOUNT_ID%', 'broad-detacher', 'Broad-Detacher', '/'),
    ('SVCDGDSAFEDET001', '%ACCOUNT_ID%', 'safe-detacher', 'Safe-Detacher', '/'),
    ('SVCDGDPATHDET001', '%ACCOUNT_ID%', 'path-detacher', 'Path-Detacher', '/'),
    ('SVCDGDNARROWDT01', '%ACCOUNT_ID%', 'narrow-detacher', 'Narrow-Detacher', '/'),
    ('SVCDGDNOGRANTD01', '%ACCOUNT_ID%', 'no-grant-detacher', 'No-Grant-Detacher', '/');

    INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) VALUES
    ('SVCDGDTGTPLAIN01', '%ACCOUNT_ID%', 'plain-group', 'Plain-Group', '/'),
    ('SVCDGDTGTDIVSN01', '%ACCOUNT_ID%', 'division-group', 'Division-Group', '/division/'),
    ('SVCDGDTGTNARRW01', '%ACCOUNT_ID%', 'narrow-group', 'Narrow-Group', '/'),
    ('SVCDGDTGTOTHER01', '%ACCOUNT_ID%', 'other-group', 'Other-Group', '/'),
    ('SVCDGDTGTBARE001', '%ACCOUNT_ID%', 'bare-group', 'Bare-Group', '/'),
    ('SVCDGDTGTROLE001', '%ACCOUNT_ID%', 'role-group', 'Role-Group', '/'),
    ('SVCDGDTGTROOT001', '%ACCOUNT_ID%', 'root-group', 'Root-Group', '/');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCDGDPOLSAFE001', '%ACCOUNT_ID%', 'safe-policy', 'Safe-Policy', '/safe/', 1, false, 1),
    ('SVCDGDPOLWIDE001', '%ACCOUNT_ID%', 'wide-policy', 'Wide-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCDGDPOLSAFE001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDGDPOLWIDE001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}');

    INSERT INTO iam.group_attached_policies(group_id, managed_policy_id) VALUES
    ('SVCDGDTGTPLAIN01', 'SVCDGDPOLSAFE001'),
    ('SVCDGDTGTPLAIN01', 'SVCDGDPOLWIDE001'),
    ('SVCDGDTGTDIVSN01', 'SVCDGDPOLWIDE001'),
    ('SVCDGDTGTNARRW01', 'SVCDGDPOLWIDE001'),
    ('SVCDGDTGTOTHER01', 'SVCDGDPOLSAFE001'),
    ('SVCDGDTGTOTHER01', 'SVCDGDPOLWIDE001'),
    ('SVCDGDTGTROLE001', 'SVCDGDPOLSAFE001'),
    ('SVCDGDTGTROOT001', 'SVCDGDPOLSAFE001');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDGDBROADDET01', 'allow-detach-anything', 'Allow-Detach-Anything',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DetachGroupPolicy","Resource":"*"}]}'),
    ('SVCDGDSAFEDET001', 'allow-detach-safe-policies', 'Allow-Detach-Safe-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DetachGroupPolicy",
        "Resource":"*","Condition":{"ArnLike":{"iam:PolicyARN":"arn:aws:iam::%ACCOUNT_ID%:policy/safe/*"}}}]}'),
    ('SVCDGDPATHDET001', 'allow-detach-on-division', 'Allow-Detach-On-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DetachGroupPolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/division/*"}]}'),
    ('SVCDGDNARROWDT01', 'allow-detach-on-target', 'Allow-Detach-On-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DetachGroupPolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/Narrow-Group"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCDGDROLE000001', '%ACCOUNT_ID%', 'detach-group-policy-role', 'Detach-Group-Policy-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDGDROLE000001', 'allow-detach-anything', 'Allow-Detach-Anything',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DetachGroupPolicy","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `DetachGroupPolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_detach_group_policy_authorization() {
    let database = TestDatabase::new(DETACH_GROUP_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let safe_policy_arn = database.arn("policy/safe/Safe-Policy");
    let wide_policy_arn = database.arn("policy/Wide-Policy");

    // A caller allowed iam:DetachGroupPolicy on any group takes a policy off one, leaving the
    // group's other policies alone.
    let (principal, session_data) = database.user_identity("SVCDGDBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_group_policy_parameters(Some("Plain-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DetachGroupPolicyResponse"), "unexpected body: {body}");
    assert_eq!(database.group_attached_policy_names("Plain-Group").await, vec!["Safe-Policy"]);

    // The managed policy itself is untouched: it is still attached to the other groups carrying
    // it, and can be attached again.
    assert_eq!(database.group_attached_policy_names("Division-Group").await, vec!["Wide-Policy"]);

    // Detaching a policy the group does not carry is reported as NoSuchEntity, whether it was
    // just removed or was never there.
    for group_name in ["Plain-Group", "Bare-Group"] {
        let (principal, session_data) = database.user_identity("SVCDGDBROADDET01", "Broad-Detacher");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &detach_group_policy_parameters(Some(group_name), Some(wide_policy_arn.as_str())),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");
    }

    // The policy being detached backs iam:PolicyARN, so a grant confined to a policy path reaches
    // the policies under it...
    let (principal, session_data) = database.user_identity("SVCDGDSAFEDET001", "Safe-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_group_policy_parameters(Some("Other-Group"), Some(safe_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further, so such a caller cannot strip a group of the policies it was not
    // trusted with.
    let (principal, session_data) = database.user_identity("SVCDGDSAFEDET001", "Safe-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_group_policy_parameters(Some("Other-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled its transaction back, so that policy is still attached.
    assert_eq!(database.group_attached_policy_names("Other-Group").await, vec!["Wide-Policy"]);

    // The resource ARN carries the group's path, so a grant scoped to a path prefix reaches
    // groups under that path...
    let (principal, session_data) = database.user_identity("SVCDGDPATHDET001", "Path-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_group_policy_parameters(Some("Division-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(database.group_attached_policy_names("Division-Group").await.is_empty());

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCDGDPATHDET001", "Path-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_group_policy_parameters(Some("Other-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single group and no policy reaches every policy that group carries, and
    // reaches no other group.
    let (principal, session_data) = database.user_identity("SVCDGDNARROWDT01", "Narrow-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_group_policy_parameters(Some("Narrow-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCDGDNARROWDT01", "Narrow-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_group_policy_parameters(Some("Other-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied -- named by the
    // group, since that is the resource the action acts on.
    let (principal, session_data) = database.user_identity("SVCDGDNOGRANTD01", "No-Grant-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_group_policy_parameters(Some("Other-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Detacher is not authorized to perform: \
                 iam:DetachGroupPolicy on resource: arn:aws:iam::{account_id}:group/Other-Group"
        )),
        "unexpected body: {body}"
    );

    // A group that does not exist is still authorized against the ARN the request names, so a
    // caller allowed the action on any group is told the group is missing...
    let (principal, session_data) = database.user_identity("SVCDGDBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_group_policy_parameters(Some("No-Such-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...and so is a policy that does not exist, once the caller is allowed to have asked.
    let (principal, session_data) = database.user_identity("SVCDGDBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_group_policy_parameters(Some("Other-Group"), Some(database.arn("policy/No-Such-Policy").as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A caller allowed the action only on a specific group learns nothing about either.
    let (principal, session_data) = database.user_identity("SVCDGDNARROWDT01", "Narrow-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_group_policy_parameters(Some("No-Such-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // GroupName and PolicyArn are both required.
    for parameters in [
        detach_group_policy_parameters(None, Some(wide_policy_arn.as_str())),
        detach_group_policy_parameters(Some("Other-Group"), None),
    ] {
        let (principal, session_data) = database.user_identity("SVCDGDBROADDET01", "Broad-Detacher");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // A malformed policy ARN or group name is rejected before the request is authorized, so even
    // a caller with no grant is told the request is malformed rather than denied.
    for parameters in [
        detach_group_policy_parameters(Some("Other-Group"), Some("arn:aws:iam::1:p")),
        detach_group_policy_parameters(Some("Not/A/Group-Name"), Some(wide_policy_arn.as_str())),
    ] {
        let (principal, session_data) = database.user_identity("SVCDGDNOGRANTD01", "No-Grant-Detacher");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCDGDROLE000001", "Detach-Group-Policy-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_group_policy_parameters(Some("Role-Group"), Some(safe_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(database.group_attached_policy_names("Role-Group").await.is_empty());

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_group_policy_parameters(Some("Root-Group"), Some(safe_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(database.group_attached_policy_names("Root-Group").await.is_empty());
}
