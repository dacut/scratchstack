use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `RemoveUserFromGroup` authorization tests. Every group starts with the
/// members the cases below take away, so each caller has something to remove and a user that is
/// not a member can be told apart from one that does not exist. The group is the only resource
/// IAM names for this action, so the callers are scoped by the group's path, by the group itself,
/// and not at all.
const REMOVE_USER_FROM_GROUP_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'remove-user-from-group-test@example.com', 'remove-user-from-group-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCRUGBROADREM01', '%ACCOUNT_ID%', 'broad-remover', 'Broad-Remover', '/'),
    ('SVCRUGPATHREM001', '%ACCOUNT_ID%', 'path-remover', 'Path-Remover', '/'),
    ('SVCRUGNARROWRM01', '%ACCOUNT_ID%', 'narrow-remover', 'Narrow-Remover', '/'),
    ('SVCRUGNOGRANTR01', '%ACCOUNT_ID%', 'no-grant-remover', 'No-Grant-Remover', '/'),
    ('SVCRUGMEMBALICE1', '%ACCOUNT_ID%', 'rug-alice', 'RUG-Alice', '/'),
    ('SVCRUGMEMBBOB001', '%ACCOUNT_ID%', 'rug-bob', 'RUG-Bob', '/'),
    ('SVCRUGMEMBCAROL1', '%ACCOUNT_ID%', 'rug-carol', 'RUG-Carol', '/'),
    ('SVCRUGOUTSIDER01', '%ACCOUNT_ID%', 'rug-outsider', 'RUG-Outsider', '/');

    INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) VALUES
    ('SVCRUGTGTPLAIN01', '%ACCOUNT_ID%', 'plain-group', 'Plain-Group', '/'),
    ('SVCRUGTGTDIVSN01', '%ACCOUNT_ID%', 'division-group', 'Division-Group', '/division/'),
    ('SVCRUGTGTNARRW01', '%ACCOUNT_ID%', 'narrow-group', 'Narrow-Group', '/'),
    ('SVCRUGTGTOTHER01', '%ACCOUNT_ID%', 'other-group', 'Other-Group', '/'),
    ('SVCRUGTGTCASE001', '%ACCOUNT_ID%', 'case-group', 'Case-Group', '/'),
    ('SVCRUGTGTROLE001', '%ACCOUNT_ID%', 'role-group', 'Role-Group', '/'),
    ('SVCRUGTGTROOT001', '%ACCOUNT_ID%', 'root-group', 'Root-Group', '/');

    INSERT INTO iam.group_memberships(group_id, user_id) VALUES
    ('SVCRUGTGTPLAIN01', 'SVCRUGMEMBALICE1'),
    ('SVCRUGTGTPLAIN01', 'SVCRUGMEMBBOB001'),
    ('SVCRUGTGTDIVSN01', 'SVCRUGMEMBALICE1'),
    ('SVCRUGTGTNARRW01', 'SVCRUGMEMBALICE1'),
    ('SVCRUGTGTNARRW01', 'SVCRUGMEMBBOB001'),
    ('SVCRUGTGTNARRW01', 'SVCRUGMEMBCAROL1'),
    ('SVCRUGTGTOTHER01', 'SVCRUGMEMBCAROL1'),
    ('SVCRUGTGTCASE001', 'SVCRUGMEMBCAROL1'),
    ('SVCRUGTGTROLE001', 'SVCRUGMEMBBOB001'),
    ('SVCRUGTGTROOT001', 'SVCRUGMEMBBOB001');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCRUGBROADREM01', 'allow-remove-from-any-group', 'Allow-Remove-From-Any-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:RemoveUserFromGroup",
        "Resource":"*"}]}'),
    ('SVCRUGPATHREM001', 'allow-remove-on-division', 'Allow-Remove-On-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:RemoveUserFromGroup",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/division/*"}]}'),
    ('SVCRUGNARROWRM01', 'allow-remove-from-one-group', 'Allow-Remove-From-One-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:RemoveUserFromGroup",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/Narrow-Group"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCRUGROLE000001', '%ACCOUNT_ID%', 'remove-user-from-group-role', 'Remove-User-From-Group-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCRUGROLE000001', 'allow-remove-from-any-group', 'Allow-Remove-From-Any-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:RemoveUserFromGroup",
        "Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `RemoveUserFromGroup` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_remove_user_from_group_authorization() {
    let database = TestDatabase::new(REMOVE_USER_FROM_GROUP_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:RemoveUserFromGroup on any group takes a user out of one.
    let (principal, session_data) = database.user_identity("SVCRUGBROADREM01", "Broad-Remover");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &remove_user_from_group_parameters(Some("Plain-Group"), Some("RUG-Alice")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<RemoveUserFromGroupResponse"), "unexpected body: {body}");

    // The user is out, and the group's other members are untouched: the root user reads it back.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Plain-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<UserName>RUG-Alice</UserName>"), "unexpected body: {body}");
    assert!(body.contains("<UserName>RUG-Bob</UserName>"), "unexpected body: {body}");

    // The user itself is untouched -- only the membership was removed -- and its other group
    // memberships are left alone.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("RUG-Alice"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>RUG-Alice</UserName>"), "unexpected body: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Division-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>RUG-Alice</UserName>"), "unexpected body: {body}");

    // Unlike the add, this is not idempotent: removing a user that is not in the group is
    // reported as NoSuchEntity rather than succeeding.
    let (principal, session_data) = database.user_identity("SVCRUGBROADREM01", "Broad-Remover");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &remove_user_from_group_parameters(Some("Plain-Group"), Some("RUG-Alice")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A user that exists but was never in the group is reported the same way.
    let (principal, session_data) = database.user_identity("SVCRUGBROADREM01", "Broad-Remover");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &remove_user_from_group_parameters(Some("Plain-Group"), Some("RUG-Outsider")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // The resource ARN carries the group's path, so a grant scoped to a path prefix reaches
    // groups under that path...
    let (principal, session_data) = database.user_identity("SVCRUGPATHREM001", "Path-Remover");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &remove_user_from_group_parameters(Some("Division-Group"), Some("RUG-Alice")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCRUGPATHREM001", "Path-Remover");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &remove_user_from_group_parameters(Some("Other-Group"), Some("RUG-Carol")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled its transaction back, so that membership is still there.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Other-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>RUG-Carol</UserName>"), "unexpected body: {body}");

    // A grant naming a single group reaches that group and no other -- but it reaches every
    // member of it, since IAM gives this action no way to name the user being removed.
    for user_name in ["RUG-Alice", "RUG-Bob", "RUG-Carol"] {
        let (principal, session_data) = database.user_identity("SVCRUGNARROWRM01", "Narrow-Remover");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &remove_user_from_group_parameters(Some("Narrow-Group"), Some(user_name)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    }

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Narrow-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Users/>"), "unexpected body: {body}");

    let (principal, session_data) = database.user_identity("SVCRUGNARROWRM01", "Narrow-Remover");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &remove_user_from_group_parameters(Some("Other-Group"), Some("RUG-Carol")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied -- named by the
    // group, since that is the resource the action acts on.
    let (principal, session_data) = database.user_identity("SVCRUGNOGRANTR01", "No-Grant-Remover");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &remove_user_from_group_parameters(Some("Other-Group"), Some("RUG-Carol")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Remover is not authorized to perform: \
                 iam:RemoveUserFromGroup on resource: arn:aws:iam::{account_id}:group/Other-Group"
        )),
        "unexpected body: {body}"
    );

    // A group that does not exist is still authorized against the ARN the request names, so a
    // caller allowed the action on any group is told the group is missing...
    let (principal, session_data) = database.user_identity("SVCRUGBROADREM01", "Broad-Remover");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &remove_user_from_group_parameters(Some("No-Such-Group"), Some("RUG-Carol")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...and so is a user that does not exist, once the caller is allowed to have asked.
    let (principal, session_data) = database.user_identity("SVCRUGBROADREM01", "Broad-Remover");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &remove_user_from_group_parameters(Some("Other-Group"), Some("No-Such-User")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A caller allowed the action only on a specific group learns nothing about either.
    let (principal, session_data) = database.user_identity("SVCRUGNARROWRM01", "Narrow-Remover");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &remove_user_from_group_parameters(Some("No-Such-Group"), Some("RUG-Carol")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // GroupName and UserName are both required.
    for parameters in [
        remove_user_from_group_parameters(None, Some("RUG-Carol")),
        remove_user_from_group_parameters(Some("Other-Group"), None),
    ] {
        let (principal, session_data) = database.user_identity("SVCRUGBROADREM01", "Broad-Remover");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // A name that cannot name a group or a user is rejected before the request is authorized, so
    // even a caller with no grant is told the name is malformed rather than denied.
    for parameters in [
        remove_user_from_group_parameters(Some("Not/A/Group-Name"), Some("RUG-Carol")),
        remove_user_from_group_parameters(Some("Other-Group"), Some("Not/A/User-Name")),
    ] {
        let (principal, session_data) = database.user_identity("SVCRUGNOGRANTR01", "No-Grant-Remover");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // Both names are matched case-insensitively.
    let (principal, session_data) = database.user_identity("SVCRUGBROADREM01", "Broad-Remover");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &remove_user_from_group_parameters(Some("cAsE-gRoUp"), Some("rUg-CaRoL")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Case-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Users/>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCRUGROLE000001", "Remove-User-From-Group-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &remove_user_from_group_parameters(Some("Role-Group"), Some("RUG-Bob")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &remove_user_from_group_parameters(Some("Root-Group"), Some("RUG-Bob")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Root-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Users/>"), "unexpected body: {body}");
}
