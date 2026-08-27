use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `DeleteGroup` authorization tests. The callers are scoped by the path of the
/// group being deleted, by the group itself, and not at all; `Policy-Group` still carries an
/// inline policy and `Attached-Group` an attached managed policy, so a group that cannot be
/// deleted can be told apart from one the caller may not delete. `Member-Group` has a member,
/// which is not an obstacle -- the membership goes with the group.
const DELETE_GROUP_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'delete-group-test@example.com', 'delete-group-test');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCDGPPOLICY0001', '%ACCOUNT_ID%', 'attached-policy', 'Attached-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCDGPPOLICY0001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCDGPBROADDEL01', '%ACCOUNT_ID%', 'broad-deleter', 'Broad-Deleter', '/'),
    ('SVCDGPPATHDEL001', '%ACCOUNT_ID%', 'path-deleter', 'Path-Deleter', '/'),
    ('SVCDGPNARROWDL01', '%ACCOUNT_ID%', 'narrow-deleter', 'Narrow-Deleter', '/'),
    ('SVCDGPNOGRANTD01', '%ACCOUNT_ID%', 'no-grant-deleter', 'No-Grant-Deleter', '/'),
    ('SVCDGPMEMBER0001', '%ACCOUNT_ID%', 'group-member', 'Group-Member', '/');

    INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) VALUES
    ('SVCDGPTGTPLAIN01', '%ACCOUNT_ID%', 'plain-group', 'Plain-Group', '/'),
    ('SVCDGPTGTDIVSN01', '%ACCOUNT_ID%', 'division-group', 'Division-Group', '/division/'),
    ('SVCDGPTGTNARRW01', '%ACCOUNT_ID%', 'narrow-group', 'Narrow-Group', '/'),
    ('SVCDGPTGTOTHER01', '%ACCOUNT_ID%', 'other-group', 'Other-Group', '/'),
    ('SVCDGPTGTPOLICY1', '%ACCOUNT_ID%', 'policy-group', 'Policy-Group', '/'),
    ('SVCDGPTGTATTACH1', '%ACCOUNT_ID%', 'attached-group', 'Attached-Group', '/'),
    ('SVCDGPTGTMEMBER1', '%ACCOUNT_ID%', 'member-group', 'Member-Group', '/'),
    ('SVCDGPTGTROLE001', '%ACCOUNT_ID%', 'role-group', 'Role-Group', '/'),
    ('SVCDGPTGTROOT001', '%ACCOUNT_ID%', 'root-group', 'Root-Group', '/');

    INSERT INTO iam.group_memberships(group_id, user_id) VALUES
    ('SVCDGPTGTMEMBER1', 'SVCDGPMEMBER0001');

    INSERT INTO iam.group_inline_policies(group_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDGPTGTPOLICY1', 'group-inline-policy', 'Group-Inline-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');

    INSERT INTO iam.group_attached_policies(group_id, managed_policy_id) VALUES
    ('SVCDGPTGTATTACH1', 'SVCDGPPOLICY0001');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDGPBROADDEL01', 'allow-delete-any-group', 'Allow-Delete-Any-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteGroup","Resource":"*"}]}'),
    ('SVCDGPPATHDEL001', 'allow-delete-on-division', 'Allow-Delete-On-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteGroup",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/division/*"}]}'),
    ('SVCDGPNARROWDL01', 'allow-delete-one-group', 'Allow-Delete-One-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteGroup",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/Narrow-Group"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCDGPROLE000001', '%ACCOUNT_ID%', 'delete-group-role', 'Delete-Group-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDGPROLE000001', 'allow-delete-any-group', 'Allow-Delete-Any-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteGroup","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `DeleteGroup` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_delete_group_authorization() {
    let database = TestDatabase::new(DELETE_GROUP_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:DeleteGroup on any group deletes one.
    let (principal, session_data) = database.user_identity("SVCDGPBROADDEL01", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_group_parameters(Some("Plain-Group"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DeleteGroupResponse"), "unexpected body: {body}");

    // The group is gone: the root user, implicitly allowed everything, is told so.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Plain-Group"), None, None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // The resource ARN carries the group's path, so a grant scoped to a path prefix reaches
    // groups under that path...
    let (principal, session_data) = database.user_identity("SVCDGPPATHDEL001", "Path-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_group_parameters(Some("Division-Group"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCDGPPATHDEL001", "Path-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_group_parameters(Some("Other-Group"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled its transaction back, so that group is still there.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Other-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A grant naming a single group reaches that group and no other.
    let (principal, session_data) = database.user_identity("SVCDGPNARROWDL01", "Narrow-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_group_parameters(Some("Narrow-Group"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCDGPNARROWDL01", "Narrow-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_group_parameters(Some("Other-Group"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A group still carrying policies cannot be deleted, so a caller cannot discard a group's
    // policies by discarding the group. Both an inline policy and an attached managed policy
    // block it.
    for group_name in ["Policy-Group", "Attached-Group"] {
        let (principal, session_data) = database.user_identity("SVCDGPBROADDEL01", "Broad-Deleter");
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_group_parameters(Some(group_name))).await;
        assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
        assert!(body.contains("<Code>DeleteConflict</Code>"), "unexpected body: {body}");

        // That rolled its transaction back, so the group is still there.
        let (principal, session_data) = database.root_identity();
        let (status, body) =
            call(&svc_state, principal, session_data, &get_group_parameters(Some(group_name), None, None)).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    }

    // Members are not an obstacle in the same way: the membership goes with the group, and the
    // member itself is untouched.
    let (principal, session_data) = database.user_identity("SVCDGPBROADDEL01", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_group_parameters(Some("Member-Group"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Group-Member"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>Group-Member</UserName>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCDGPNOGRANTD01", "No-Grant-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_group_parameters(Some("Other-Group"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Deleter is not authorized to perform: \
                 iam:DeleteGroup on resource: arn:aws:iam::{account_id}:group/Other-Group"
        )),
        "unexpected body: {body}"
    );

    // A group that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:DeleteGroup on any group is told the group is missing...
    let (principal, session_data) = database.user_identity("SVCDGPBROADDEL01", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_group_parameters(Some("No-Such-Group"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific group learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCDGPNARROWDL01", "Narrow-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_group_parameters(Some("No-Such-Group"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // GroupName is required.
    let (principal, session_data) = database.user_identity("SVCDGPBROADDEL01", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_group_parameters(None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // A group name that cannot name a group is rejected before the request is authorized, so even
    // a caller with no grant is told the name is malformed rather than denied.
    let (principal, session_data) = database.user_identity("SVCDGPNOGRANTD01", "No-Grant-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_group_parameters(Some("Not/A/Group-Name"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCDGPROLE000001", "Delete-Group-Role");
    let (status, body) = call(&svc_state, principal, session_data, &delete_group_parameters(Some("Role-Group"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &delete_group_parameters(Some("Root-Group"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
}
