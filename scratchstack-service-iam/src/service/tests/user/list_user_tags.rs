use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `ListUserTags` authorization tests. `Tag-Target` carries several tags, so
/// a listing can be paged through; `Empty-Target` carries none, so a user without tags can be
/// told apart from one that does not exist. The remaining targets carry the paths and tags the
/// resource ARN and the `aws:ResourceTag` condition keys are derived from -- and here the tags
/// governing the listing are the very tags being listed.
const LIST_USER_TAGS_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'list-user-tags-test@example.com', 'list-user-tags-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCLUTBROADLST01', '%ACCOUNT_ID%', 'broad-lister', 'Broad-Lister', '/'),
    ('SVCLUTPATHLST001', '%ACCOUNT_ID%', 'path-lister', 'Path-Lister', '/'),
    ('SVCLUTRESLST0001', '%ACCOUNT_ID%', 'resource-tag-lister', 'Resource-Tag-Lister', '/'),
    ('SVCLUTNARROWLS01', '%ACCOUNT_ID%', 'narrow-lister', 'Narrow-Lister', '/'),
    ('SVCLUTNOGRANTL01', '%ACCOUNT_ID%', 'no-grant-lister', 'No-Grant-Lister', '/'),
    ('SVCLUTTGTPLAIN01', '%ACCOUNT_ID%', 'tag-target', 'Tag-Target', '/'),
    ('SVCLUTTGTEMPTY01', '%ACCOUNT_ID%', 'empty-target', 'Empty-Target', '/'),
    ('SVCLUTTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/'),
    ('SVCLUTTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/'),
    ('SVCLUTTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/'),
    ('SVCLUTTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCLUTTGTPLAIN01', 'costcenter', 'CostCenter', '1234'),
    ('SVCLUTTGTPLAIN01', 'project', 'Project', 'Scratchstack'),
    ('SVCLUTTGTPLAIN01', 'zone', 'Zone', 'West'),
    ('SVCLUTTGTDIVSN01', 'project', 'Project', 'Division'),
    ('SVCLUTTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCLUTTGTENGNR01', 'costcenter', 'CostCenter', '5678'),
    ('SVCLUTTGTSALES01', 'department', 'Department', 'Sales'),
    ('SVCLUTTGTROOT001', 'root', 'Root', 'Tag');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLUTBROADLST01', 'allow-list-any-tags', 'Allow-List-Any-Tags',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUserTags","Resource":"*"}]}'),
    ('SVCLUTPATHLST001', 'allow-list-division-tags', 'Allow-List-Division-Tags',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUserTags",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/division/*"}]}'),
    ('SVCLUTRESLST0001', 'allow-list-engineering-tags', 'Allow-List-Engineering-Tags',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUserTags","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCLUTNARROWLS01', 'allow-list-target-tags', 'Allow-List-Target-Tags',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUserTags",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/Tag-Target"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCLUTROLE000001', '%ACCOUNT_ID%', 'list-user-tags-role', 'List-User-Tags-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLUTROLE000001', 'allow-list-any-tags', 'Allow-List-Any-Tags',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUserTags","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `ListUserTags` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case so that they share one seeded
/// account, rather than seeding one apiece.
#[test_log::test(tokio::test)]
async fn test_list_user_tags_authorization() {
    let database = TestDatabase::new(LIST_USER_TAGS_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:ListUserTags on any user reads the tags off one, ordered by key and
    // cased as they were stored.
    let (principal, session_data) = database.user_identity("SVCLUTBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_user_tags_parameters(Some("Tag-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(
            "<Tags><member><Key>CostCenter</Key><Value>1234</Value></member>\
                 <member><Key>Project</Key><Value>Scratchstack</Value></member>\
                 <member><Key>Zone</Key><Value>West</Value></member></Tags>"
        ),
        "unexpected body: {body}"
    );

    // A user carrying no tags at all is an empty listing rather than a missing user.
    let (principal, session_data) = database.user_identity("SVCLUTBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_user_tags_parameters(Some("Empty-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<ListUserTagsResult><Tags/></ListUserTagsResult>"), "unexpected body: {body}");

    // MaxItems bounds a page, and a bounded page reports the marker the next one continues
    // from...
    let (principal, session_data) = database.user_identity("SVCLUTBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_user_tags_parameters(Some("Tag-Target"), Some(2), None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<IsTruncated>true</IsTruncated>"), "unexpected body: {body}");
    assert!(body.contains("<Key>CostCenter</Key><Value>1234</Value>"), "unexpected body: {body}");
    assert!(body.contains("<Key>Project</Key><Value>Scratchstack</Value>"), "unexpected body: {body}");
    assert!(!body.contains("<Key>Zone</Key>"), "unexpected body: {body}");
    let marker = pagination_marker(&body);

    // ...which reports the rest, and reports itself as the last page.
    let (principal, session_data) = database.user_identity("SVCLUTBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_user_tags_parameters(Some("Tag-Target"), Some(2), Some(&marker)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Zone</Key><Value>West</Value>"), "unexpected body: {body}");
    assert!(!body.contains("<Key>CostCenter</Key>"), "unexpected body: {body}");
    assert!(!body.contains("<IsTruncated>"), "unexpected body: {body}");

    // The resource ARN carries the target user's path, so a grant scoped to a path prefix
    // reaches users under that path...
    let (principal, session_data) = database.user_identity("SVCLUTPATHLST001", "Path-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_user_tags_parameters(Some("Division-Target"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Project</Key><Value>Division</Value>"), "unexpected body: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCLUTPATHLST001", "Path-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_user_tags_parameters(Some("Tag-Target"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags being listed are the tags backing the aws:ResourceTag condition keys, so a
    // grant conditioned on a tag reaches the request that reads that very tag back.
    let (principal, session_data) = database.user_identity("SVCLUTRESLST0001", "Resource-Tag-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_user_tags_parameters(Some("Engineering-Target"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Department</Key><Value>Engineering</Value>"), "unexpected body: {body}");
    assert!(body.contains("<Key>CostCenter</Key><Value>5678</Value>"), "unexpected body: {body}");

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCLUTRESLST0001", "Resource-Tag-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_user_tags_parameters(Some("Sales-Target"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Neither does a user carrying other tags but not that one, nor one carrying no tags at
    // all: the condition key is absent in both cases.
    for user_name in ["Tag-Target", "Empty-Target"] {
        let (principal, session_data) = database.user_identity("SVCLUTRESLST0001", "Resource-Tag-Lister");
        let (status, body) =
            call(&svc_state, principal, session_data, &list_user_tags_parameters(Some(user_name), None, None)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
    }

    // A grant naming a single user reaches every tag on it, and reaches no other user.
    let (principal, session_data) = database.user_identity("SVCLUTNARROWLS01", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_user_tags_parameters(Some("Tag-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Zone</Key><Value>West</Value>"), "unexpected body: {body}");

    let (principal, session_data) = database.user_identity("SVCLUTNARROWLS01", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_user_tags_parameters(Some("Sales-Target"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCLUTNOGRANTL01", "No-Grant-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_user_tags_parameters(Some("Tag-Target"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Lister is not authorized to perform: \
                 iam:ListUserTags on resource: arn:aws:iam::{account_id}:user/Tag-Target"
        )),
        "unexpected body: {body}"
    );

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:ListUserTags on any user is told the user is missing...
    let (principal, session_data) = database.user_identity("SVCLUTBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_user_tags_parameters(Some("No-Such-User"), None, None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCLUTNARROWLS01", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_user_tags_parameters(Some("No-Such-User"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // UserName is required; it does not default to the calling user.
    let (principal, session_data) = database.user_identity("SVCLUTBROADLST01", "Broad-Lister");
    let (status, body) = call(&svc_state, principal, session_data, &list_user_tags_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // A MaxItems outside the range a page may take is rejected, and so is a marker that is not
    // shaped like a pagination token; both are settled before the request is authorized.
    for parameters in [
        list_user_tags_parameters(Some("Tag-Target"), Some(0), None),
        list_user_tags_parameters(Some("Tag-Target"), Some(1001), None),
        list_user_tags_parameters(Some("Tag-Target"), None, Some("")),
    ] {
        let (principal, session_data) = database.user_identity("SVCLUTBROADLST01", "Broad-Lister");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // A marker this service did not issue is the caller's to fix rather than ours, so it is
    // reported as invalid input rather than as an internal failure.
    let (principal, session_data) = database.user_identity("SVCLUTBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_user_tags_parameters(Some("Tag-Target"), None, Some(FOREIGN_PAGINATION_TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>InvalidInput</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCLUTROLE000001", "List-User-Tags-Role");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_user_tags_parameters(Some("Tag-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Project</Key><Value>Scratchstack</Value>"), "unexpected body: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_user_tags_parameters(Some("Root-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Root</Key><Value>Tag</Value>"), "unexpected body: {body}");
}
