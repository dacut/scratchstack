use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `UpdateGroup` authorization tests. A group's name and path are both part of
/// its ARN, so the callers here are scoped to the ARN before the change, to the ARN after it, and
/// to both -- which is what the two-sided authorization has to distinguish.
const UPDATE_GROUP_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'update-group-test@example.com', 'update-group-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCUGPBROADUPD01', '%ACCOUNT_ID%', 'broad-updater', 'Broad-Updater', '/'),
    ('SVCUGPOLDONLY001', '%ACCOUNT_ID%', 'old-only-updater', 'Old-Only-Updater', '/'),
    ('SVCUGPNEWONLY001', '%ACCOUNT_ID%', 'new-only-updater', 'New-Only-Updater', '/'),
    ('SVCUGPBOTHUPD001', '%ACCOUNT_ID%', 'both-updater', 'Both-Updater', '/'),
    ('SVCUGPNOGRANTU01', '%ACCOUNT_ID%', 'no-grant-updater', 'No-Grant-Updater', '/'),
    ('SVCUGPMEMBER0001', '%ACCOUNT_ID%', 'ug-member', 'UG-Member', '/');

    INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) VALUES
    ('SVCUGPTGTPLAIN01', '%ACCOUNT_ID%', 'plain-group', 'Plain-Group', '/'),
    ('SVCUGPTGTMEMBER1', '%ACCOUNT_ID%', 'member-group', 'Member-Group', '/'),
    ('SVCUGPTGTONESID1', '%ACCOUNT_ID%', 'one-sided-group', 'One-Sided-Group', '/'),
    ('SVCUGPTGTBOTH001', '%ACCOUNT_ID%', 'both-group', 'Both-Group', '/'),
    ('SVCUGPTGTTAKEN01', '%ACCOUNT_ID%', 'taken-group', 'Taken-Group', '/'),
    ('SVCUGPTGTCOLLID1', '%ACCOUNT_ID%', 'collide-group', 'Collide-Group', '/'),
    ('SVCUGPTGTCASE001', '%ACCOUNT_ID%', 'case-group', 'Case-Group', '/'),
    ('SVCUGPTGTROLE001', '%ACCOUNT_ID%', 'role-group', 'Role-Group', '/'),
    ('SVCUGPTGTROOT001', '%ACCOUNT_ID%', 'root-group', 'Root-Group', '/');

    INSERT INTO iam.group_memberships(group_id, user_id) VALUES
    ('SVCUGPTGTMEMBER1', 'SVCUGPMEMBER0001');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCUGPBROADUPD01', 'allow-update-any-group', 'Allow-Update-Any-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateGroup","Resource":"*"}]}'),
    ('SVCUGPOLDONLY001', 'allow-update-old-name', 'Allow-Update-Old-Name',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateGroup",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/One-Sided-Group"}]}'),
    ('SVCUGPNEWONLY001', 'allow-update-new-name', 'Allow-Update-New-Name',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateGroup",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/Renamed-Group"}]}'),
    ('SVCUGPBOTHUPD001', 'allow-update-both-names', 'Allow-Update-Both-Names',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateGroup",
        "Resource":["arn:aws:iam::%ACCOUNT_ID%:group/Both-Group",
            "arn:aws:iam::%ACCOUNT_ID%:group/moved/Both-Group"]}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCUGPROLE000001', '%ACCOUNT_ID%', 'update-group-role', 'Update-Group-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCUGPROLE000001', 'allow-update-any-group', 'Allow-Update-Any-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateGroup","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `UpdateGroup` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_update_group_authorization() {
    let database = TestDatabase::new(UPDATE_GROUP_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:UpdateGroup on any group renames one.
    let (principal, session_data) = database.user_identity("SVCUGPBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_group_parameters(Some("Plain-Group"), Some("Plain-Renamed"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UpdateGroupResponse"), "unexpected body: {body}");

    // The rename took, and the old name names nothing: the root user reads both back.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Plain-Renamed"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:group/Plain-Renamed</Arn>")),
        "unexpected body: {body}"
    );

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Plain-Group"), None, None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");

    // The path can be replaced on its own, and it moves the group without renaming it.
    let (principal, session_data) = database.user_identity("SVCUGPBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_group_parameters(Some("Plain-Renamed"), None, Some("/relocated/")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Plain-Renamed"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:group/relocated/Plain-Renamed</Arn>")),
        "unexpected body: {body}"
    );

    // A request supplying neither replacement succeeds and changes nothing, and is authorized
    // once rather than twice: the ARN before and after are the same.
    let (principal, session_data) = database.user_identity("SVCUGPBROADUPD01", "Broad-Updater");
    let (status, body) =
        call(&svc_state, principal, session_data, &update_group_parameters(Some("Plain-Renamed"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // Nothing the group carries is disturbed by a rename: its members follow it, since they are
    // keyed on the group id rather than on the name.
    let (principal, session_data) = database.user_identity("SVCUGPBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_group_parameters(Some("Member-Group"), Some("Member-Renamed"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Member-Renamed"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>UG-Member</UserName>"), "unexpected body: {body}");

    // A grant reaching only the name the group is being renamed away from is not enough: the
    // caller must be allowed the action on the ARN the group will carry afterwards too, or it
    // could move the group out of the reach of the very policy that constrained it.
    let (principal, session_data) = database.user_identity("SVCUGPOLDONLY001", "Old-Only-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_group_parameters(Some("One-Sided-Group"), Some("Renamed-Group"), None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!("on resource: arn:aws:iam::{account_id}:group/Renamed-Group")),
        "the denial must name the ARN the caller could not reach: {body}"
    );

    // A grant reaching only the name the group is being renamed to is not enough either.
    let (principal, session_data) = database.user_identity("SVCUGPNEWONLY001", "New-Only-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_group_parameters(Some("One-Sided-Group"), Some("Renamed-Group"), None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!("on resource: arn:aws:iam::{account_id}:group/One-Sided-Group")),
        "the denial must name the ARN the caller could not reach: {body}"
    );

    // Neither denial changed anything.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("One-Sided-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A grant reaching both ARNs is enough, and here the change is a move rather than a rename --
    // the path is part of the ARN just as the name is.
    let (principal, session_data) = database.user_identity("SVCUGPBOTHUPD001", "Both-Updater");
    let (status, body) =
        call(&svc_state, principal, session_data, &update_group_parameters(Some("Both-Group"), None, Some("/moved/")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Both-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:group/moved/Both-Group</Arn>")),
        "unexpected body: {body}"
    );

    // Renaming a group to a name already taken in the account is reported as EntityAlreadyExists,
    // once the caller is allowed to have asked.
    let (principal, session_data) = database.user_identity("SVCUGPBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_group_parameters(Some("Collide-Group"), Some("Taken-Group"), None),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
    assert!(body.contains("<Code>EntityAlreadyExists</Code>"), "unexpected body: {body}");

    // That rolled its transaction back, so the group still carries the name it had.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Collide-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // Names are compared case-insensitively, so a rename that only changes the casing of the
    // group's own name is a rename to itself rather than a collision.
    let (principal, session_data) = database.user_identity("SVCUGPBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_group_parameters(Some("Case-Group"), Some("CASE-GROUP"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("case-group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>CASE-GROUP</GroupName>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCUGPNOGRANTU01", "No-Grant-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_group_parameters(Some("Taken-Group"), Some("Whatever-Group"), None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Updater is not authorized to perform: \
                 iam:UpdateGroup on resource: arn:aws:iam::{account_id}:group/Taken-Group"
        )),
        "unexpected body: {body}"
    );

    // A group that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:UpdateGroup on any group is told the group is missing...
    let (principal, session_data) = database.user_identity("SVCUGPBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_group_parameters(Some("No-Such-Group"), Some("Still-Nothing"), None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on specific groups learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCUGPOLDONLY001", "Old-Only-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_group_parameters(Some("No-Such-Group"), Some("Still-Nothing"), None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // GroupName is required.
    let (principal, session_data) = database.user_identity("SVCUGPBROADUPD01", "Broad-Updater");
    let (status, body) =
        call(&svc_state, principal, session_data, &update_group_parameters(None, Some("Nameless"), None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // A malformed group name, new name, or new path is rejected before the request is authorized,
    // so even a caller with no grant is told the request is malformed rather than denied.
    for parameters in [
        update_group_parameters(Some("Not/A/Group-Name"), None, None),
        update_group_parameters(Some("Taken-Group"), Some("Not/A/Group-Name"), None),
        update_group_parameters(Some("Taken-Group"), None, Some("no-leading-slash/")),
    ] {
        let (principal, session_data) = database.user_identity("SVCUGPNOGRANTU01", "No-Grant-Updater");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCUGPROLE000001", "Update-Group-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_group_parameters(Some("Role-Group"), Some("Role-Renamed"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_group_parameters(Some("Root-Group"), Some("Root-Renamed"), Some("/root-moved/")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Root-Renamed"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:group/root-moved/Root-Renamed</Arn>")),
        "unexpected body: {body}"
    );
}
