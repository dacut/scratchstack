use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `ListRoleTags` authorization tests. `Tag-Target` carries several tags, so a
/// listing can be paged through; `Empty-Target` carries none, so a role without tags can be told
/// apart from one that does not exist. The remaining targets carry the paths and tags the
/// resource ARN and the `aws:ResourceTag` condition keys are derived from -- and here the tags
/// governing the listing are the very tags being listed.
const LIST_ROLE_TAGS_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'list-role-tags-test@example.com', 'list-role-tags-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCLRTBROADLST01', '%ACCOUNT_ID%', 'broad-lister', 'Broad-Lister', '/'),
    ('SVCLRTPATHLST001', '%ACCOUNT_ID%', 'path-lister', 'Path-Lister', '/'),
    ('SVCLRTRESLST0001', '%ACCOUNT_ID%', 'resource-tag-lister', 'Resource-Tag-Lister', '/'),
    ('SVCLRTNARROWLS01', '%ACCOUNT_ID%', 'narrow-lister', 'Narrow-Lister', '/'),
    ('SVCLRTNOGRANTL01', '%ACCOUNT_ID%', 'no-grant-lister', 'No-Grant-Lister', '/');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCLRTTGTPLAIN01', '%ACCOUNT_ID%', 'tag-target', 'Tag-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCLRTTGTEMPTY01', '%ACCOUNT_ID%', 'empty-target', 'Empty-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCLRTTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCLRTTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCLRTTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCLRTTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCLRTROLE000001', '%ACCOUNT_ID%', 'list-role-tags-role', 'List-Role-Tags-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCLRTTGTPLAIN01', 'costcenter', 'CostCenter', '1234'),
    ('SVCLRTTGTPLAIN01', 'project', 'Project', 'Scratchstack'),
    ('SVCLRTTGTPLAIN01', 'zone', 'Zone', 'West'),
    ('SVCLRTTGTDIVSN01', 'project', 'Project', 'Division'),
    ('SVCLRTTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCLRTTGTENGNR01', 'costcenter', 'CostCenter', '5678'),
    ('SVCLRTTGTSALES01', 'department', 'Department', 'Sales'),
    ('SVCLRTTGTROOT001', 'root', 'Root', 'Tag');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLRTBROADLST01', 'allow-list-any-tags', 'Allow-List-Any-Tags',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRoleTags","Resource":"*"}]}'),
    ('SVCLRTPATHLST001', 'allow-list-division-tags', 'Allow-List-Division-Tags',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRoleTags",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/division/*"}]}'),
    ('SVCLRTRESLST0001', 'allow-list-engineering-tags', 'Allow-List-Engineering-Tags',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRoleTags","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCLRTNARROWLS01', 'allow-list-target-tags', 'Allow-List-Target-Tags',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRoleTags",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/Tag-Target"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLRTROLE000001', 'allow-list-any-tags', 'Allow-List-Any-Tags',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRoleTags","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `ListRoleTags` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case so that they share one seeded
/// account, rather than seeding one apiece.
#[test_log::test(tokio::test)]
async fn test_list_role_tags_authorization() {
    let database = TestDatabase::new(LIST_ROLE_TAGS_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:ListRoleTags on any role reads the tags off one, ordered by key and
    // cased as they were stored.
    let (principal, session_data) = database.user_identity("SVCLRTBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_tags_parameters(Some("Tag-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(
            "<Tags><member><Key>CostCenter</Key><Value>1234</Value></member>\
                 <member><Key>Project</Key><Value>Scratchstack</Value></member>\
                 <member><Key>Zone</Key><Value>West</Value></member></Tags>"
        ),
        "unexpected body: {body}"
    );

    // A role carrying no tags at all is an empty listing rather than a missing role.
    let (principal, session_data) = database.user_identity("SVCLRTBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_tags_parameters(Some("Empty-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<ListRoleTagsResult><Tags/></ListRoleTagsResult>"), "unexpected body: {body}");

    // MaxItems bounds a page, and a bounded page reports the marker the next one continues
    // from...
    let (principal, session_data) = database.user_identity("SVCLRTBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_tags_parameters(Some("Tag-Target"), Some(2), None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<IsTruncated>true</IsTruncated>"), "unexpected body: {body}");
    assert!(body.contains("<Key>CostCenter</Key><Value>1234</Value>"), "unexpected body: {body}");
    assert!(body.contains("<Key>Project</Key><Value>Scratchstack</Value>"), "unexpected body: {body}");
    assert!(!body.contains("<Key>Zone</Key>"), "unexpected body: {body}");
    let marker = pagination_marker(&body);

    // ...which reports the rest, and reports itself as the last page.
    let (principal, session_data) = database.user_identity("SVCLRTBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_role_tags_parameters(Some("Tag-Target"), Some(2), Some(&marker)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Zone</Key><Value>West</Value>"), "unexpected body: {body}");
    assert!(!body.contains("<Key>CostCenter</Key>"), "unexpected body: {body}");
    assert!(!body.contains("<IsTruncated>"), "unexpected body: {body}");

    // The resource ARN carries the target role's path, so a grant scoped to a path prefix reaches
    // roles under that path...
    let (principal, session_data) = database.user_identity("SVCLRTPATHLST001", "Path-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_tags_parameters(Some("Division-Target"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Project</Key><Value>Division</Value>"), "unexpected body: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCLRTPATHLST001", "Path-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_tags_parameters(Some("Tag-Target"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags being listed are the tags backing the aws:ResourceTag condition keys, so a grant
    // conditioned on a tag reaches the request that reads that very tag back.
    let (principal, session_data) = database.user_identity("SVCLRTRESLST0001", "Resource-Tag-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_tags_parameters(Some("Engineering-Target"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Department</Key><Value>Engineering</Value>"), "unexpected body: {body}");
    assert!(body.contains("<Key>CostCenter</Key><Value>5678</Value>"), "unexpected body: {body}");

    // A role carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCLRTRESLST0001", "Resource-Tag-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_tags_parameters(Some("Sales-Target"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Neither does a role carrying other tags but not that one, nor one carrying no tags at all:
    // the condition key is absent in both cases.
    for role_name in ["Tag-Target", "Empty-Target"] {
        let (principal, session_data) = database.user_identity("SVCLRTRESLST0001", "Resource-Tag-Lister");
        let (status, body) =
            call(&svc_state, principal, session_data, &list_role_tags_parameters(Some(role_name), None, None)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
    }

    // A grant naming a single role reaches every tag on it, and reaches no other role.
    let (principal, session_data) = database.user_identity("SVCLRTNARROWLS01", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_tags_parameters(Some("Tag-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Zone</Key><Value>West</Value>"), "unexpected body: {body}");

    let (principal, session_data) = database.user_identity("SVCLRTNARROWLS01", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_tags_parameters(Some("Sales-Target"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCLRTNOGRANTL01", "No-Grant-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_tags_parameters(Some("Tag-Target"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Lister is not authorized to perform: \
                 iam:ListRoleTags on resource: arn:aws:iam::{account_id}:role/Tag-Target"
        )),
        "unexpected body: {body}"
    );

    // A role that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:ListRoleTags on any role is told the role is missing...
    let (principal, session_data) = database.user_identity("SVCLRTBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_tags_parameters(Some("No-Such-Role"), None, None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific role learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCLRTNARROWLS01", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_tags_parameters(Some("No-Such-Role"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // RoleName is required.
    let (principal, session_data) = database.user_identity("SVCLRTBROADLST01", "Broad-Lister");
    let (status, body) = call(&svc_state, principal, session_data, &list_role_tags_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // A MaxItems outside the range a page may take is rejected, and so is a marker that is not
    // shaped like a pagination token; both are settled before the request is authorized.
    for parameters in [
        list_role_tags_parameters(Some("Tag-Target"), Some(0), None),
        list_role_tags_parameters(Some("Tag-Target"), Some(1001), None),
        list_role_tags_parameters(Some("Tag-Target"), None, Some("")),
    ] {
        let (principal, session_data) = database.user_identity("SVCLRTBROADLST01", "Broad-Lister");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // A role name that cannot name a role is rejected before the request is authorized, so even a
    // caller with no grant is told the name is malformed rather than denied.
    let (principal, session_data) = database.user_identity("SVCLRTNOGRANTL01", "No-Grant-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_tags_parameters(Some("Not/A/Role-Name"), None, None))
            .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A marker this service did not issue is the caller's to fix rather than ours, so it is
    // reported as invalid input rather than as an internal failure.
    let (principal, session_data) = database.user_identity("SVCLRTBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_role_tags_parameters(Some("Tag-Target"), None, Some(FOREIGN_PAGINATION_TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>InvalidInput</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCLRTROLE000001", "List-Role-Tags-Role");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_tags_parameters(Some("Tag-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Project</Key><Value>Scratchstack</Value>"), "unexpected body: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_tags_parameters(Some("Root-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Root</Key><Value>Tag</Value>"), "unexpected body: {body}");
}
