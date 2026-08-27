use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `GetGroup` authorization tests. `Member-Group` carries several members, so
/// the membership listing can be paged through; `Empty-Group` carries none, so a group without
/// members can be told apart from one that does not exist. The callers are scoped by the path of
/// the group being read, by the group itself, and not at all.
const GET_GROUP_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'get-group-test@example.com', 'get-group-test');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCGGPBOUNDARY01', '%ACCOUNT_ID%', 'member-boundary', 'Member-Boundary', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCGGPBOUNDARY01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path,
        permissions_boundary_managed_policy_id) VALUES
    ('SVCGGPBROADRDR01', '%ACCOUNT_ID%', 'broad-reader', 'Broad-Reader', '/', NULL),
    ('SVCGGPPATHRDR001', '%ACCOUNT_ID%', 'path-reader', 'Path-Reader', '/', NULL),
    ('SVCGGPNARROWRD01', '%ACCOUNT_ID%', 'narrow-reader', 'Narrow-Reader', '/', NULL),
    ('SVCGGPNOGRANTR01', '%ACCOUNT_ID%', 'no-grant-reader', 'No-Grant-Reader', '/', NULL),
    ('SVCGGPMEMBALICE1', '%ACCOUNT_ID%', 'gg-alice', 'GG-Alice', '/', 'SVCGGPBOUNDARY01'),
    ('SVCGGPMEMBBOB001', '%ACCOUNT_ID%', 'gg-bob', 'GG-Bob', '/engineering/', NULL),
    ('SVCGGPMEMBCAROL1', '%ACCOUNT_ID%', 'gg-carol', 'GG-Carol', '/', NULL);

    INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) VALUES
    ('SVCGGPTGTMEMBER1', '%ACCOUNT_ID%', 'member-group', 'Member-Group', '/'),
    ('SVCGGPTGTEMPTY01', '%ACCOUNT_ID%', 'empty-group', 'Empty-Group', '/'),
    ('SVCGGPTGTDIVSN01', '%ACCOUNT_ID%', 'division-group', 'Division-Group', '/division/'),
    ('SVCGGPTGTOTHER01', '%ACCOUNT_ID%', 'other-group', 'Other-Group', '/'),
    ('SVCGGPTGTROLE001', '%ACCOUNT_ID%', 'role-group', 'Role-Group', '/'),
    ('SVCGGPTGTROOT001', '%ACCOUNT_ID%', 'root-group', 'Root-Group', '/');

    INSERT INTO iam.group_memberships(group_id, user_id) VALUES
    ('SVCGGPTGTMEMBER1', 'SVCGGPMEMBALICE1'),
    ('SVCGGPTGTMEMBER1', 'SVCGGPMEMBBOB001'),
    ('SVCGGPTGTMEMBER1', 'SVCGGPMEMBCAROL1');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCGGPBROADRDR01', 'allow-read-any-group', 'Allow-Read-Any-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetGroup","Resource":"*"}]}'),
    ('SVCGGPPATHRDR001', 'allow-read-on-division', 'Allow-Read-On-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetGroup",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/division/*"}]}'),
    ('SVCGGPNARROWRD01', 'allow-read-one-group', 'Allow-Read-One-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetGroup",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/Member-Group"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCGGPROLE000001', '%ACCOUNT_ID%', 'get-group-role', 'Get-Group-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCGGPROLE000001', 'allow-read-any-group', 'Allow-Read-Any-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetGroup","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `GetGroup` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case so that they share one seeded
/// account, rather than seeding one apiece.
#[test_log::test(tokio::test)]
async fn test_get_group_authorization() {
    let database = TestDatabase::new(GET_GROUP_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:GetGroup on any group reads one, and gets the group's members along
    // with the group itself -- ordered by name, cased as they were stored, and each carrying the
    // path and permissions boundary it was created with.
    let (principal, session_data) = database.user_identity("SVCGGPBROADRDR01", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Member-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Member-Group</GroupName>"), "unexpected body: {body}");
    assert!(body.contains("<UserName>GG-Alice</UserName>"), "unexpected body: {body}");
    assert!(body.contains("<UserName>GG-Bob</UserName>"), "unexpected body: {body}");
    assert!(body.contains("<UserName>GG-Carol</UserName>"), "unexpected body: {body}");

    // A member's ARN carries that member's own path, not the group's.
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:user/engineering/GG-Bob</Arn>")),
        "unexpected body: {body}"
    );

    // A member's permissions boundary is reported the way every other listing reports it.
    assert!(
        body.contains(&format!(
            "<PermissionsBoundaryArn>arn:aws:iam::{account_id}:policy/Member-Boundary</PermissionsBoundaryArn>"
        )),
        "unexpected body: {body}"
    );

    // The members are ordered by name, so the order they appear in is settled rather than
    // whatever the database happened to return.
    let alice = body.find("GG-Alice").expect("GG-Alice missing");
    let bob = body.find("GG-Bob").expect("GG-Bob missing");
    let carol = body.find("GG-Carol").expect("GG-Carol missing");
    assert!(alice < bob && bob < carol, "members out of order: {body}");

    // A group nobody belongs to is an empty membership listing rather than a missing group.
    let (principal, session_data) = database.user_identity("SVCGGPBROADRDR01", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Empty-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Empty-Group</GroupName>"), "unexpected body: {body}");
    assert!(body.contains("<Users/>"), "unexpected body: {body}");

    // MaxItems bounds a page of members, and a bounded page reports the marker the next one
    // continues from. The group itself is reported in full on every page.
    let (principal, session_data) = database.user_identity("SVCGGPBROADRDR01", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Member-Group"), Some(2), None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<IsTruncated>true</IsTruncated>"), "unexpected body: {body}");
    assert!(body.contains("<GroupName>Member-Group</GroupName>"), "unexpected body: {body}");
    assert!(body.contains("<UserName>GG-Alice</UserName>"), "unexpected body: {body}");
    assert!(body.contains("<UserName>GG-Bob</UserName>"), "unexpected body: {body}");
    assert!(!body.contains("<UserName>GG-Carol</UserName>"), "unexpected body: {body}");
    let marker = pagination_marker(&body);

    // ...which reports the rest, and reports itself as the last page.
    let (principal, session_data) = database.user_identity("SVCGGPBROADRDR01", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Member-Group"), Some(2), Some(&marker)))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>GG-Carol</UserName>"), "unexpected body: {body}");
    assert!(!body.contains("<UserName>GG-Alice</UserName>"), "unexpected body: {body}");
    assert!(!body.contains("<IsTruncated>"), "unexpected body: {body}");
    assert!(body.contains("<GroupName>Member-Group</GroupName>"), "unexpected body: {body}");

    // The resource ARN carries the group's path, so a grant scoped to a path prefix reaches
    // groups under that path...
    let (principal, session_data) = database.user_identity("SVCGGPPATHRDR001", "Path-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Division-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Path>/division/</Path>"), "unexpected body: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCGGPPATHRDR001", "Path-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Other-Group"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single group reaches that group and no other. Reading a group is reading
    // its membership, so such a grant is also a grant to learn which users are in that group.
    let (principal, session_data) = database.user_identity("SVCGGPNARROWRD01", "Narrow-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Member-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>GG-Alice</UserName>"), "unexpected body: {body}");

    let (principal, session_data) = database.user_identity("SVCGGPNARROWRD01", "Narrow-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Other-Group"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCGGPNOGRANTR01", "No-Grant-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Member-Group"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Reader is not authorized to perform: \
                 iam:GetGroup on resource: arn:aws:iam::{account_id}:group/Member-Group"
        )),
        "unexpected body: {body}"
    );

    // A group that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:GetGroup on any group is told the group is missing...
    let (principal, session_data) = database.user_identity("SVCGGPBROADRDR01", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("No-Such-Group"), None, None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific group learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCGGPNARROWRD01", "Narrow-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("No-Such-Group"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // GroupName is required; unlike GetUser there is no calling group to fall back to.
    let (principal, session_data) = database.user_identity("SVCGGPBROADRDR01", "Broad-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_group_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // A MaxItems outside the range a page may take is rejected, and so is a marker that is not
    // shaped like a pagination token; both are settled before the request is authorized.
    for parameters in [
        get_group_parameters(Some("Member-Group"), Some(0), None),
        get_group_parameters(Some("Member-Group"), Some(1001), None),
        get_group_parameters(Some("Member-Group"), None, Some("")),
    ] {
        let (principal, session_data) = database.user_identity("SVCGGPBROADRDR01", "Broad-Reader");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // A marker this service did not issue is the caller's to fix rather than ours, so it is
    // reported as invalid input rather than as an internal failure.
    let (principal, session_data) = database.user_identity("SVCGGPBROADRDR01", "Broad-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_group_parameters(Some("Member-Group"), None, Some(FOREIGN_PAGINATION_TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>InvalidInput</Code>"), "unexpected body: {body}");

    // A group name that cannot name a group is rejected before the request is authorized, so even
    // a caller with no grant is told the name is malformed rather than denied.
    let (principal, session_data) = database.user_identity("SVCGGPNOGRANTR01", "No-Grant-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Not/A/Group-Name"), None, None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A group is matched case-insensitively, and is reported with the casing it was created
    // under.
    let (principal, session_data) = database.user_identity("SVCGGPBROADRDR01", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("mEmBeR-gRoUp"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Member-Group</GroupName>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCGGPROLE000001", "Get-Group-Role");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Role-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_parameters(Some("Root-Group"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Root-Group</GroupName>"), "unexpected body: {body}");
}
