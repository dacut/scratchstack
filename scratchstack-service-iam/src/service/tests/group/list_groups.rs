use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `ListGroups` authorization tests. This action names no resource at all, so
/// there is nothing for a grant to be scoped by: the callers are one allowed it with
/// `Resource: "*"`, one whose grant names a particular group and therefore does not reach it at
/// all, and one with no grant. Several groups spread across two paths give the listing something
/// to page through and filter.
const LIST_GROUPS_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'list-groups-test@example.com', 'list-groups-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCLGSBROADLST01', '%ACCOUNT_ID%', 'broad-lister', 'Broad-Lister', '/'),
    ('SVCLGSNAMEDLST01', '%ACCOUNT_ID%', 'named-lister', 'Named-Lister', '/'),
    ('SVCLGSNOGRANTL01', '%ACCOUNT_ID%', 'no-grant-lister', 'No-Grant-Lister', '/');

    INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) VALUES
    ('SVCLGSGRPALPHA01', '%ACCOUNT_ID%', 'alpha-group', 'Alpha-Group', '/'),
    ('SVCLGSGRPBETA001', '%ACCOUNT_ID%', 'beta-group', 'Beta-Group', '/division/'),
    ('SVCLGSGRPGAMMA01', '%ACCOUNT_ID%', 'gamma-group', 'Gamma-Group', '/division/'),
    ('SVCLGSGRPDELTA01', '%ACCOUNT_ID%', 'delta-group', 'Delta-Group', '/');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLGSBROADLST01', 'allow-list-groups', 'Allow-List-Groups',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListGroups","Resource":"*"}]}'),
    ('SVCLGSNAMEDLST01', 'allow-list-one-group', 'Allow-List-One-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListGroups",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/Alpha-Group"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCLGSROLE000001', '%ACCOUNT_ID%', 'list-groups-role', 'List-Groups-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLGSROLE000001', 'allow-list-groups', 'Allow-List-Groups',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListGroups","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `ListGroups` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case so that they share one seeded
/// account, rather than seeding one apiece.
#[test_log::test(tokio::test)]
async fn test_list_groups_authorization() {
    let database = TestDatabase::new(LIST_GROUPS_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:ListGroups sees every group in the account, ordered by name, each
    // described with the path and ARN it carries.
    let (principal, session_data) = database.user_identity("SVCLGSBROADLST01", "Broad-Lister");
    let (status, body) = call(&svc_state, principal, session_data, &list_groups_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    for group_name in ["Alpha-Group", "Beta-Group", "Delta-Group", "Gamma-Group"] {
        assert!(body.contains(&format!("<GroupName>{group_name}</GroupName>")), "unexpected body: {body}");
    }
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:group/division/Beta-Group</Arn>")),
        "unexpected body: {body}"
    );

    // A listing reports groups, not their members: the membership is read with GetGroup, which is
    // granted separately.
    assert!(!body.contains("<Users>"), "a group listing must not report members: {body}");

    // PathPrefix filters which groups are reported.
    let (principal, session_data) = database.user_identity("SVCLGSBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_parameters(Some("/division/"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Beta-Group</GroupName>"), "unexpected body: {body}");
    assert!(body.contains("<GroupName>Gamma-Group</GroupName>"), "unexpected body: {body}");
    assert!(!body.contains("<GroupName>Alpha-Group</GroupName>"), "unexpected body: {body}");

    // A path prefix matching nothing is an empty listing rather than an error.
    let (principal, session_data) = database.user_identity("SVCLGSBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_parameters(Some("/nothing-here/"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Groups/>"), "unexpected body: {body}");

    // MaxItems bounds a page, and a bounded page reports the marker the next one continues
    // from...
    let (principal, session_data) = database.user_identity("SVCLGSBROADLST01", "Broad-Lister");
    let (status, body) = call(&svc_state, principal, session_data, &list_groups_parameters(None, Some(2), None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<IsTruncated>true</IsTruncated>"), "unexpected body: {body}");
    assert!(body.contains("<GroupName>Alpha-Group</GroupName>"), "unexpected body: {body}");
    assert!(body.contains("<GroupName>Beta-Group</GroupName>"), "unexpected body: {body}");
    assert!(!body.contains("<GroupName>Gamma-Group</GroupName>"), "unexpected body: {body}");
    let marker = pagination_marker(&body);

    // ...which reports the rest, and reports itself as the last page.
    let (principal, session_data) = database.user_identity("SVCLGSBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_parameters(None, Some(2), Some(&marker))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Delta-Group</GroupName>"), "unexpected body: {body}");
    assert!(body.contains("<GroupName>Gamma-Group</GroupName>"), "unexpected body: {body}");
    assert!(!body.contains("<GroupName>Alpha-Group</GroupName>"), "unexpected body: {body}");

    // The action names no resource, so a grant naming a particular group does not reach it: this
    // is the one group listing that a policy must grant with Resource "*" or not at all. Such a
    // caller cannot enumerate even the group its grant names.
    let (principal, session_data) = database.user_identity("SVCLGSNAMEDLST01", "Named-Lister");
    let (status, body) = call(&svc_state, principal, session_data, &list_groups_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Narrowing the listing with PathPrefix does not help, since the prefix is not a condition
    // key and narrows what is reported rather than what is authorized.
    let (principal, session_data) = database.user_identity("SVCLGSNAMEDLST01", "Named-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_parameters(Some("/"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied -- naming no
    // resource, since the action has none.
    let (principal, session_data) = database.user_identity("SVCLGSNOGRANTL01", "No-Grant-Lister");
    let (status, body) = call(&svc_state, principal, session_data, &list_groups_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Lister is not authorized to perform: iam:ListGroups"
        )),
        "unexpected body: {body}"
    );

    // A malformed path prefix or pagination argument is rejected before the request is
    // authorized, so even a caller with no grant is told the request is malformed.
    for parameters in [
        list_groups_parameters(Some("no-leading-slash/"), None, None),
        list_groups_parameters(None, Some(0), None),
        list_groups_parameters(None, Some(1001), None),
    ] {
        let (principal, session_data) = database.user_identity("SVCLGSNOGRANTL01", "No-Grant-Lister");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // A marker this service did not issue is the caller's to fix rather than ours.
    let (principal, session_data) = database.user_identity("SVCLGSBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_groups_parameters(None, None, Some(FOREIGN_PAGINATION_TOKEN)))
            .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>InvalidInput</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCLGSROLE000001", "List-Groups-Role");
    let (status, body) = call(&svc_state, principal, session_data, &list_groups_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Alpha-Group</GroupName>"), "unexpected body: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &list_groups_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Delta-Group</GroupName>"), "unexpected body: {body}");
}
