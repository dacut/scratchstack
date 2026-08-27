use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `ListGroupsForUser` authorization tests. The resource here is the user
/// rather than the groups reported, so the callers are scoped by the path of that user, by that
/// user's tags, by the user itself, and not at all. `Many-Member` belongs to several groups so a
/// listing can be paged through, and `Lonely-Member` to none.
const LIST_GROUPS_FOR_USER_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'list-groups-for-user-test@example.com', 'list-groups-for-user-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCLGUBROADLST01', '%ACCOUNT_ID%', 'broad-lister', 'Broad-Lister', '/'),
    ('SVCLGUPATHLST001', '%ACCOUNT_ID%', 'path-lister', 'Path-Lister', '/'),
    ('SVCLGURESLST0001', '%ACCOUNT_ID%', 'resource-tag-lister', 'Resource-Tag-Lister', '/'),
    ('SVCLGUNARROWLS01', '%ACCOUNT_ID%', 'narrow-lister', 'Narrow-Lister', '/'),
    ('SVCLGUNOGRANTL01', '%ACCOUNT_ID%', 'no-grant-lister', 'No-Grant-Lister', '/'),
    ('SVCLGUTGTMANY001', '%ACCOUNT_ID%', 'many-member', 'Many-Member', '/'),
    ('SVCLGUTGTLONELY1', '%ACCOUNT_ID%', 'lonely-member', 'Lonely-Member', '/'),
    ('SVCLGUTGTDIVSN01', '%ACCOUNT_ID%', 'division-member', 'Division-Member', '/division/'),
    ('SVCLGUTGTENGNR01', '%ACCOUNT_ID%', 'engineering-member', 'Engineering-Member', '/'),
    ('SVCLGUTGTSALES01', '%ACCOUNT_ID%', 'sales-member', 'Sales-Member', '/'),
    ('SVCLGUTGTROLE001', '%ACCOUNT_ID%', 'role-member', 'Role-Member', '/'),
    ('SVCLGUTGTROOT001', '%ACCOUNT_ID%', 'root-member', 'Root-Member', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCLGUTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCLGUTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) VALUES
    ('SVCLGUGRPALPHA01', '%ACCOUNT_ID%', 'alpha-group', 'Alpha-Group', '/'),
    ('SVCLGUGRPBETA001', '%ACCOUNT_ID%', 'beta-group', 'Beta-Group', '/engineering/'),
    ('SVCLGUGRPGAMMA01', '%ACCOUNT_ID%', 'gamma-group', 'Gamma-Group', '/'),
    ('SVCLGUGRPDELTA01', '%ACCOUNT_ID%', 'delta-group', 'Delta-Group', '/');

    INSERT INTO iam.group_memberships(group_id, user_id) VALUES
    ('SVCLGUGRPALPHA01', 'SVCLGUTGTMANY001'),
    ('SVCLGUGRPBETA001', 'SVCLGUTGTMANY001'),
    ('SVCLGUGRPGAMMA01', 'SVCLGUTGTMANY001'),
    ('SVCLGUGRPALPHA01', 'SVCLGUTGTDIVSN01'),
    ('SVCLGUGRPBETA001', 'SVCLGUTGTENGNR01'),
    ('SVCLGUGRPGAMMA01', 'SVCLGUTGTSALES01'),
    ('SVCLGUGRPDELTA01', 'SVCLGUTGTROLE001'),
    ('SVCLGUGRPALPHA01', 'SVCLGUTGTROOT001');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLGUBROADLST01', 'allow-list-any-user', 'Allow-List-Any-User',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListGroupsForUser","Resource":"*"}]}'),
    ('SVCLGUPATHLST001', 'allow-list-on-division', 'Allow-List-On-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListGroupsForUser",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/division/*"}]}'),
    ('SVCLGURESLST0001', 'allow-list-on-engineering', 'Allow-List-On-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListGroupsForUser","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCLGUNARROWLS01', 'allow-list-on-target', 'Allow-List-On-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListGroupsForUser",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/Many-Member"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCLGUROLE000001', '%ACCOUNT_ID%', 'list-groups-for-user-role', 'List-Groups-For-User-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLGUROLE000001', 'allow-list-any-user', 'Allow-List-Any-User',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListGroupsForUser","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `ListGroupsForUser` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case so that they share one
/// seeded account, rather than seeding one apiece.
#[test_log::test(tokio::test)]
async fn test_list_groups_for_user_authorization() {
    let database = TestDatabase::new(LIST_GROUPS_FOR_USER_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:ListGroupsForUser on any user reads that user's memberships, ordered
    // by group name, each group described with the path it carries.
    let (principal, session_data) = database.user_identity("SVCLGUBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_for_user_parameters(Some("Many-Member"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Alpha-Group</GroupName>"), "unexpected body: {body}");
    assert!(body.contains("<GroupName>Beta-Group</GroupName>"), "unexpected body: {body}");
    assert!(body.contains("<GroupName>Gamma-Group</GroupName>"), "unexpected body: {body}");
    assert!(!body.contains("<GroupName>Delta-Group</GroupName>"), "unexpected body: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:group/engineering/Beta-Group</Arn>")),
        "unexpected body: {body}"
    );

    // A user belonging to no group is an empty listing rather than a missing user.
    let (principal, session_data) = database.user_identity("SVCLGUBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_for_user_parameters(Some("Lonely-Member"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Groups/>"), "unexpected body: {body}");

    // MaxItems bounds a page, and a bounded page reports the marker the next one continues
    // from...
    let (principal, session_data) = database.user_identity("SVCLGUBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_for_user_parameters(Some("Many-Member"), Some(2), None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<IsTruncated>true</IsTruncated>"), "unexpected body: {body}");
    assert!(body.contains("<GroupName>Alpha-Group</GroupName>"), "unexpected body: {body}");
    assert!(body.contains("<GroupName>Beta-Group</GroupName>"), "unexpected body: {body}");
    assert!(!body.contains("<GroupName>Gamma-Group</GroupName>"), "unexpected body: {body}");
    let marker = pagination_marker(&body);

    // ...which reports the rest, and reports itself as the last page.
    let (principal, session_data) = database.user_identity("SVCLGUBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_groups_for_user_parameters(Some("Many-Member"), Some(2), Some(&marker)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Gamma-Group</GroupName>"), "unexpected body: {body}");
    assert!(!body.contains("<GroupName>Alpha-Group</GroupName>"), "unexpected body: {body}");

    // The resource ARN carries the *user's* path, not the groups', so a grant scoped to a path
    // prefix reaches users under that path...
    let (principal, session_data) = database.user_identity("SVCLGUPATHLST001", "Path-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_groups_for_user_parameters(Some("Division-Member"), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Alpha-Group</GroupName>"), "unexpected body: {body}");

    // ...and no further -- even though the group reported is the same one, because the grant is
    // scoped by whose memberships may be read rather than by which groups may be reported.
    let (principal, session_data) = database.user_identity("SVCLGUPATHLST001", "Path-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_for_user_parameters(Some("Many-Member"), None, None))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The user is the resource, so the tags on that user back the aws:ResourceTag condition keys.
    let (principal, session_data) = database.user_identity("SVCLGURESLST0001", "Resource-Tag-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_groups_for_user_parameters(Some("Engineering-Member"), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Beta-Group</GroupName>"), "unexpected body: {body}");

    // A user carrying the tag with a different value does not satisfy the condition, and neither
    // does one carrying no tags at all.
    for user_name in ["Sales-Member", "Many-Member"] {
        let (principal, session_data) = database.user_identity("SVCLGURESLST0001", "Resource-Tag-Lister");
        let (status, body) =
            call(&svc_state, principal, session_data, &list_groups_for_user_parameters(Some(user_name), None, None))
                .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
    }

    // A grant naming a single user reaches every group that user belongs to, and reaches no other
    // user.
    let (principal, session_data) = database.user_identity("SVCLGUNARROWLS01", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_for_user_parameters(Some("Many-Member"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Gamma-Group</GroupName>"), "unexpected body: {body}");

    let (principal, session_data) = database.user_identity("SVCLGUNARROWLS01", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_for_user_parameters(Some("Sales-Member"), None, None))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied -- named by the
    // user, since that is the resource this action acts on.
    let (principal, session_data) = database.user_identity("SVCLGUNOGRANTL01", "No-Grant-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_for_user_parameters(Some("Many-Member"), None, None))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Lister is not authorized to perform: \
                 iam:ListGroupsForUser on resource: arn:aws:iam::{account_id}:user/Many-Member"
        )),
        "unexpected body: {body}"
    );

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed the action on any user is told the user is missing...
    let (principal, session_data) = database.user_identity("SVCLGUBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_for_user_parameters(Some("No-Such-User"), None, None))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCLGUNARROWLS01", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_for_user_parameters(Some("No-Such-User"), None, None))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // UserName is required; it does not default to the calling user.
    let (principal, session_data) = database.user_identity("SVCLGUBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_for_user_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // A malformed user name or pagination argument is rejected before the request is authorized,
    // so even a caller with no grant is told the request is malformed.
    for parameters in [
        list_groups_for_user_parameters(Some("Not/A/User-Name"), None, None),
        list_groups_for_user_parameters(Some("Many-Member"), Some(0), None),
        list_groups_for_user_parameters(Some("Many-Member"), Some(1001), None),
    ] {
        let (principal, session_data) = database.user_identity("SVCLGUNOGRANTL01", "No-Grant-Lister");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // A marker this service did not issue is the caller's to fix rather than ours.
    let (principal, session_data) = database.user_identity("SVCLGUBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_groups_for_user_parameters(Some("Many-Member"), None, Some(FOREIGN_PAGINATION_TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>InvalidInput</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCLGUROLE000001", "List-Groups-For-User-Role");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_for_user_parameters(Some("Role-Member"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Delta-Group</GroupName>"), "unexpected body: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_for_user_parameters(Some("Root-Member"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Alpha-Group</GroupName>"), "unexpected body: {body}");
}
