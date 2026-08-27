use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `AddUserToGroup` authorization tests. The group is the only resource IAM
/// names for this action, so the callers are scoped by the path of that group, by the group
/// itself, and not at all -- there is deliberately no caller scoped by the user being added,
/// because no such scoping exists.
const ADD_USER_TO_GROUP_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'add-user-to-group-test@example.com', 'add-user-to-group-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCAUGBROADADD01', '%ACCOUNT_ID%', 'broad-adder', 'Broad-Adder', '/'),
    ('SVCAUGPATHADD001', '%ACCOUNT_ID%', 'path-adder', 'Path-Adder', '/'),
    ('SVCAUGNARROWAD01', '%ACCOUNT_ID%', 'narrow-adder', 'Narrow-Adder', '/'),
    ('SVCAUGNOGRANTA01', '%ACCOUNT_ID%', 'no-grant-adder', 'No-Grant-Adder', '/'),
    ('SVCAUGMEMBALICE1', '%ACCOUNT_ID%', 'aug-alice', 'AUG-Alice', '/'),
    ('SVCAUGMEMBBOB001', '%ACCOUNT_ID%', 'aug-bob', 'AUG-Bob', '/'),
    ('SVCAUGMEMBCAROL1', '%ACCOUNT_ID%', 'aug-carol', 'AUG-Carol', '/');

    INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) VALUES
    ('SVCAUGTGTPLAIN01', '%ACCOUNT_ID%', 'plain-group', 'Plain-Group', '/'),
    ('SVCAUGTGTDIVSN01', '%ACCOUNT_ID%', 'division-group', 'Division-Group', '/division/'),
    ('SVCAUGTGTNARRW01', '%ACCOUNT_ID%', 'narrow-group', 'Narrow-Group', '/'),
    ('SVCAUGTGTOTHER01', '%ACCOUNT_ID%', 'other-group', 'Other-Group', '/'),
    ('SVCAUGTGTROLE001', '%ACCOUNT_ID%', 'role-group', 'Role-Group', '/'),
    ('SVCAUGTGTROOT001', '%ACCOUNT_ID%', 'root-group', 'Root-Group', '/');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCAUGBROADADD01', 'allow-add-to-any-group', 'Allow-Add-To-Any-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AddUserToGroup","Resource":"*"}]}'),
    ('SVCAUGPATHADD001', 'allow-add-on-division', 'Allow-Add-On-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AddUserToGroup",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/division/*"}]}'),
    ('SVCAUGNARROWAD01', 'allow-add-to-one-group', 'Allow-Add-To-One-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AddUserToGroup",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/Narrow-Group"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCAUGROLE000001', '%ACCOUNT_ID%', 'add-user-to-group-role', 'Add-User-To-Group-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCAUGROLE000001', 'allow-add-to-any-group', 'Allow-Add-To-Any-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AddUserToGroup","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `AddUserToGroup` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_add_user_to_group_authorization() {
    let database = TestDatabase::new(ADD_USER_TO_GROUP_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:AddUserToGroup on any group adds a user to one.
    let (principal, session_data) = database.user_identity("SVCAUGBROADADD01", "Broad-Adder");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &add_user_to_group_parameters(Some("Plain-Group"), Some("AUG-Alice")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<AddUserToGroupResponse"), "unexpected body: {body}");

    // The membership took: the root user, implicitly allowed everything, reads the group back and
    // finds the user in it.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Plain-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>AUG-Alice</UserName>"), "unexpected body: {body}");

    // The membership is idempotent, so adding a user the group already holds succeeds and changes
    // nothing.
    let (principal, session_data) = database.user_identity("SVCAUGBROADADD01", "Broad-Adder");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &add_user_to_group_parameters(Some("Plain-Group"), Some("AUG-Alice")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Plain-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(body.matches("<UserName>AUG-Alice</UserName>").count(), 1, "unexpected body: {body}");

    // A user may belong to more than one group, and a group to more than one user.
    let (principal, session_data) = database.user_identity("SVCAUGBROADADD01", "Broad-Adder");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &add_user_to_group_parameters(Some("Other-Group"), Some("AUG-Alice")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCAUGBROADADD01", "Broad-Adder");
    let (status, body) =
        call(&svc_state, principal, session_data, &add_user_to_group_parameters(Some("Plain-Group"), Some("AUG-Bob")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Plain-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>AUG-Alice</UserName>"), "unexpected body: {body}");
    assert!(body.contains("<UserName>AUG-Bob</UserName>"), "unexpected body: {body}");

    // The resource ARN carries the group's path, so a grant scoped to a path prefix reaches
    // groups under that path...
    let (principal, session_data) = database.user_identity("SVCAUGPATHADD001", "Path-Adder");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &add_user_to_group_parameters(Some("Division-Group"), Some("AUG-Carol")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCAUGPATHADD001", "Path-Adder");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &add_user_to_group_parameters(Some("Other-Group"), Some("AUG-Carol")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled its transaction back, so no membership was written.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Other-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<UserName>AUG-Carol</UserName>"), "unexpected body: {body}");

    // A grant naming a single group reaches that group and no other -- but it reaches every user
    // in the account, since IAM gives this action no way to name the user being added. Whoever
    // may add someone to a group may add anyone to it.
    for user_name in ["AUG-Alice", "AUG-Bob", "AUG-Carol"] {
        let (principal, session_data) = database.user_identity("SVCAUGNARROWAD01", "Narrow-Adder");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &add_user_to_group_parameters(Some("Narrow-Group"), Some(user_name)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    }

    let (principal, session_data) = database.user_identity("SVCAUGNARROWAD01", "Narrow-Adder");
    let (status, body) =
        call(&svc_state, principal, session_data, &add_user_to_group_parameters(Some("Other-Group"), Some("AUG-Bob")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied -- named by the
    // group, since that is the resource the action acts on.
    let (principal, session_data) = database.user_identity("SVCAUGNOGRANTA01", "No-Grant-Adder");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &add_user_to_group_parameters(Some("Plain-Group"), Some("AUG-Carol")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Adder is not authorized to perform: \
                 iam:AddUserToGroup on resource: arn:aws:iam::{account_id}:group/Plain-Group"
        )),
        "unexpected body: {body}"
    );

    // A group that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:AddUserToGroup on any group is told the group is missing...
    let (principal, session_data) = database.user_identity("SVCAUGBROADADD01", "Broad-Adder");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &add_user_to_group_parameters(Some("No-Such-Group"), Some("AUG-Alice")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...and so is a user that does not exist, once the caller is allowed to have asked.
    let (principal, session_data) = database.user_identity("SVCAUGBROADADD01", "Broad-Adder");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &add_user_to_group_parameters(Some("Plain-Group"), Some("No-Such-User")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A caller allowed the action only on a specific group learns nothing about either.
    let (principal, session_data) = database.user_identity("SVCAUGNARROWAD01", "Narrow-Adder");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &add_user_to_group_parameters(Some("No-Such-Group"), Some("AUG-Alice")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // GroupName and UserName are both required.
    for parameters in
        [add_user_to_group_parameters(None, Some("AUG-Alice")), add_user_to_group_parameters(Some("Plain-Group"), None)]
    {
        let (principal, session_data) = database.user_identity("SVCAUGBROADADD01", "Broad-Adder");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // A name that cannot name a group or a user is rejected before the request is authorized, so
    // even a caller with no grant is told the name is malformed rather than denied.
    for parameters in [
        add_user_to_group_parameters(Some("Not/A/Group-Name"), Some("AUG-Alice")),
        add_user_to_group_parameters(Some("Plain-Group"), Some("Not/A/User-Name")),
    ] {
        let (principal, session_data) = database.user_identity("SVCAUGNOGRANTA01", "No-Grant-Adder");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // Both names are matched case-insensitively.
    let (principal, session_data) = database.user_identity("SVCAUGBROADADD01", "Broad-Adder");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &add_user_to_group_parameters(Some("pLaIn-gRoUp"), Some("aUg-CaRoL")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Plain-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>AUG-Carol</UserName>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCAUGROLE000001", "Add-User-To-Group-Role");
    let (status, body) =
        call(&svc_state, principal, session_data, &add_user_to_group_parameters(Some("Role-Group"), Some("AUG-Bob")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &add_user_to_group_parameters(Some("Root-Group"), Some("AUG-Bob")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Root-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>AUG-Bob</UserName>"), "unexpected body: {body}");
}
