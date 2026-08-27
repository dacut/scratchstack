use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `CreateGroup` authorization tests. IAM defines no condition keys of its own
/// for this action, so the path the request asks for -- which is part of the ARN the group will
/// carry -- is the whole of what a grant has to work with; the callers are scoped by it, by the
/// group name, and not at all.
const CREATE_GROUP_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'create-group-test@example.com', 'create-group-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCCGPBROADCRT01', '%ACCOUNT_ID%', 'broad-creator', 'Broad-Creator', '/'),
    ('SVCCGPPATHCRT001', '%ACCOUNT_ID%', 'path-creator', 'Path-Creator', '/'),
    ('SVCCGPNARROWCR01', '%ACCOUNT_ID%', 'narrow-creator', 'Narrow-Creator', '/'),
    ('SVCCGPNOGRANTC01', '%ACCOUNT_ID%', 'no-grant-creator', 'No-Grant-Creator', '/');

    INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) VALUES
    ('SVCCGPEXISTING01', '%ACCOUNT_ID%', 'existing-group', 'Existing-Group', '/');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCCGPBROADCRT01', 'allow-create-any-group', 'Allow-Create-Any-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateGroup","Resource":"*"}]}'),
    ('SVCCGPPATHCRT001', 'allow-create-on-division', 'Allow-Create-On-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateGroup",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/division/*"}]}'),
    ('SVCCGPNARROWCR01', 'allow-create-one-group', 'Allow-Create-One-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateGroup",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/Allowed-Group"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCCGPROLE000001', '%ACCOUNT_ID%', 'create-group-role', 'Create-Group-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCCGPROLE000001', 'allow-create-any-group', 'Allow-Create-Any-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateGroup","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `CreateGroup` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_create_group_authorization() {
    let database = TestDatabase::new(CREATE_GROUP_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:CreateGroup on any group creates one, and the response reports the
    // group it created.
    let (principal, session_data) = database.user_identity("SVCCGPBROADCRT01", "Broad-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_group_parameters(Some("Platform"), None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Platform</GroupName>"), "unexpected body: {body}");
    assert!(body.contains("<Path>/</Path>"), "unexpected body: {body}");
    assert!(body.contains(&format!("<Arn>arn:aws:iam::{account_id}:group/Platform</Arn>")), "unexpected body: {body}");
    assert!(body.contains("<GroupId>AGPA"), "unexpected body: {body}");

    // The group is really there: the root user, implicitly allowed everything, reads it back.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Platform"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Platform</GroupName>"), "unexpected body: {body}");

    // A newly created group carries no members, and nothing else needs to be true for it to be a
    // group: unlike a user or a role, it takes neither tags nor a permissions boundary.
    assert!(body.contains("<Users/>"), "unexpected body: {body}");

    // The path is part of the ARN the group is created under, so a grant scoped to a path prefix
    // reaches groups created under that path...
    let (principal, session_data) = database.user_identity("SVCCGPPATHCRT001", "Path-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_group_parameters(Some("Divisional"), Some("/division/")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:group/division/Divisional</Arn>")),
        "unexpected body: {body}"
    );
    assert!(body.contains("<Path>/division/</Path>"), "unexpected body: {body}");

    // ...and no further: the same name at the root path is a different ARN.
    let (principal, session_data) = database.user_identity("SVCCGPPATHCRT001", "Path-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_group_parameters(Some("Divisional"), None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled its transaction back, so no group was created under the root path.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Divisional"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Path>/division/</Path>"), "unexpected body: {body}");

    // A grant naming a single group reaches that name and no other.
    let (principal, session_data) = database.user_identity("SVCCGPNARROWCR01", "Narrow-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_group_parameters(Some("Allowed-Group"), None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCCGPNARROWCR01", "Narrow-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_group_parameters(Some("Other-Group"), None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCCGPNOGRANTC01", "No-Grant-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_group_parameters(Some("Platform-Two"), None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Creator is not authorized to perform: \
                 iam:CreateGroup on resource: arn:aws:iam::{account_id}:group/Platform-Two"
        )),
        "unexpected body: {body}"
    );

    // A name already taken in the account is reported as EntityAlreadyExists, once the caller is
    // allowed to have asked. Names are compared case-insensitively, so a different casing of an
    // existing name collides with it.
    for group_name in ["Existing-Group", "existing-group"] {
        let (principal, session_data) = database.user_identity("SVCCGPBROADCRT01", "Broad-Creator");
        let (status, body) =
            call(&svc_state, principal, session_data, &create_group_parameters(Some(group_name), None)).await;
        assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
        assert!(body.contains("<Code>EntityAlreadyExists</Code>"), "unexpected body: {body}");
    }

    // A caller not allowed to create that group learns nothing about whether it exists.
    let (principal, session_data) = database.user_identity("SVCCGPNOGRANTC01", "No-Grant-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_group_parameters(Some("Existing-Group"), None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // GroupName is required.
    let (principal, session_data) = database.user_identity("SVCCGPBROADCRT01", "Broad-Creator");
    let (status, body) = call(&svc_state, principal, session_data, &create_group_parameters(None, None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // A group name that cannot name a group, and a path that is not a path, are both rejected
    // before the request is authorized, so even a caller with no grant is told the request is
    // malformed rather than denied.
    for parameters in [
        create_group_parameters(Some("Not/A/Group-Name"), None),
        create_group_parameters(Some("Fine-Name"), Some("no-leading-slash/")),
    ] {
        let (principal, session_data) = database.user_identity("SVCCGPNOGRANTC01", "No-Grant-Creator");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCCGPROLE000001", "Create-Group-Role");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_group_parameters(Some("Role-Made-Group"), None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &create_group_parameters(Some("Root-Made-Group"), None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Root-Made-Group</GroupName>"), "unexpected body: {body}");
}
