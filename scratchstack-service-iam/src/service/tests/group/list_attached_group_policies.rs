use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `ListAttachedGroupPolicies` authorization tests. `Many-Group` carries
/// several attached policies so a listing can be paged through and filtered by path;
/// `Bare-Group` carries none, so a group with no attachments can be told apart from one that does
/// not exist. IAM defines no condition key for this action, so the callers are scoped by the
/// group's path, by the group itself, and not at all.
const LIST_ATTACHED_GROUP_POLICIES_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'list-attached-group-policies-test@example.com', 'list-attached-group-policies-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCLGABROADLST01', '%ACCOUNT_ID%', 'broad-lister', 'Broad-Lister', '/'),
    ('SVCLGAPATHLST001', '%ACCOUNT_ID%', 'path-lister', 'Path-Lister', '/'),
    ('SVCLGANARROWLS01', '%ACCOUNT_ID%', 'narrow-lister', 'Narrow-Lister', '/'),
    ('SVCLGANOGRANTL01', '%ACCOUNT_ID%', 'no-grant-lister', 'No-Grant-Lister', '/');

    INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) VALUES
    ('SVCLGATGTMANY001', '%ACCOUNT_ID%', 'many-group', 'Many-Group', '/'),
    ('SVCLGATGTBARE001', '%ACCOUNT_ID%', 'bare-group', 'Bare-Group', '/'),
    ('SVCLGATGTDIVSN01', '%ACCOUNT_ID%', 'division-group', 'Division-Group', '/division/'),
    ('SVCLGATGTOTHER01', '%ACCOUNT_ID%', 'other-group', 'Other-Group', '/'),
    ('SVCLGATGTROLE001', '%ACCOUNT_ID%', 'role-group', 'Role-Group', '/'),
    ('SVCLGATGTROOT001', '%ACCOUNT_ID%', 'root-group', 'Root-Group', '/');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCLGAPOLALPHA01', '%ACCOUNT_ID%', 'alpha-policy', 'Alpha-Policy', '/', 1, false, 1),
    ('SVCLGAPOLBETA001', '%ACCOUNT_ID%', 'beta-policy', 'Beta-Policy', '/safe/', 1, false, 1),
    ('SVCLGAPOLGAMMA01', '%ACCOUNT_ID%', 'gamma-policy', 'Gamma-Policy', '/safe/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCLGAPOLALPHA01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLGAPOLBETA001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}'),
    ('SVCLGAPOLGAMMA01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}');

    INSERT INTO iam.group_attached_policies(group_id, managed_policy_id) VALUES
    ('SVCLGATGTMANY001', 'SVCLGAPOLALPHA01'),
    ('SVCLGATGTMANY001', 'SVCLGAPOLBETA001'),
    ('SVCLGATGTMANY001', 'SVCLGAPOLGAMMA01'),
    ('SVCLGATGTDIVSN01', 'SVCLGAPOLALPHA01'),
    ('SVCLGATGTOTHER01', 'SVCLGAPOLBETA001'),
    ('SVCLGATGTROLE001', 'SVCLGAPOLALPHA01'),
    ('SVCLGATGTROOT001', 'SVCLGAPOLGAMMA01');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLGABROADLST01', 'allow-list-any-group', 'Allow-List-Any-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAttachedGroupPolicies",
        "Resource":"*"}]}'),
    ('SVCLGAPATHLST001', 'allow-list-on-division', 'Allow-List-On-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAttachedGroupPolicies",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/division/*"}]}'),
    ('SVCLGANARROWLS01', 'allow-list-on-target', 'Allow-List-On-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAttachedGroupPolicies",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/Many-Group"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCLGAROLE000001', '%ACCOUNT_ID%', 'list-attached-group-policies-role', 'List-Attached-Group-Policies-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLGAROLE000001', 'allow-list-any-group', 'Allow-List-Any-Group',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAttachedGroupPolicies",
        "Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `ListAttachedGroupPolicies` through `serve_request`
/// against an embedded PostgreSQL database. A single test function covers every case so that they
/// share one seeded account, rather than seeding one apiece.
#[test_log::test(tokio::test)]
async fn test_list_attached_group_policies_authorization() {
    let database = TestDatabase::new(LIST_ATTACHED_GROUP_POLICIES_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:ListAttachedGroupPolicies on any group reads the attachments off one:
    // the name and ARN of each policy, ordered by name, and never a document.
    let (principal, session_data) = database.user_identity("SVCLGABROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_group_policies_parameters(Some("Many-Group"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Alpha-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>Beta-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>Gamma-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(
        body.contains(&format!("<PolicyArn>arn:aws:iam::{account_id}:policy/safe/Beta-Policy</PolicyArn>")),
        "unexpected body: {body}"
    );
    assert!(!body.contains("<PolicyDocument>"), "a listing must not report documents: {body}");

    // A group carrying no attachments is an empty listing rather than a missing group.
    let (principal, session_data) = database.user_identity("SVCLGABROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_group_policies_parameters(Some("Bare-Group"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<AttachedPolicies/>"), "unexpected body: {body}");

    // PathPrefix filters by the path of the policy rather than of the group.
    let (principal, session_data) = database.user_identity("SVCLGABROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_group_policies_parameters(Some("Many-Group"), Some("/safe/"), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Beta-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>Gamma-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(!body.contains("<PolicyName>Alpha-Policy</PolicyName>"), "unexpected body: {body}");

    // MaxItems bounds a page, and a bounded page reports the marker the next one continues
    // from...
    let (principal, session_data) = database.user_identity("SVCLGABROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_group_policies_parameters(Some("Many-Group"), None, Some(2), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<IsTruncated>true</IsTruncated>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>Alpha-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>Beta-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(!body.contains("<PolicyName>Gamma-Policy</PolicyName>"), "unexpected body: {body}");
    let marker = pagination_marker(&body);

    // ...which reports the rest, and reports itself as the last page.
    let (principal, session_data) = database.user_identity("SVCLGABROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_group_policies_parameters(Some("Many-Group"), None, Some(2), Some(&marker)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Gamma-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(!body.contains("<PolicyName>Alpha-Policy</PolicyName>"), "unexpected body: {body}");

    // The resource ARN carries the group's path, so a grant scoped to a path prefix reaches
    // groups under that path...
    let (principal, session_data) = database.user_identity("SVCLGAPATHLST001", "Path-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_group_policies_parameters(Some("Division-Group"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Alpha-Policy</PolicyName>"), "unexpected body: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCLGAPATHLST001", "Path-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_group_policies_parameters(Some("Other-Group"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single group reaches every policy attached to it -- PathPrefix narrows the
    // listing but not the grant -- and reaches no other group.
    let (principal, session_data) = database.user_identity("SVCLGANARROWLS01", "Narrow-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_group_policies_parameters(Some("Many-Group"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Gamma-Policy</PolicyName>"), "unexpected body: {body}");

    let (principal, session_data) = database.user_identity("SVCLGANARROWLS01", "Narrow-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_group_policies_parameters(Some("Other-Group"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCLGANOGRANTL01", "No-Grant-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_group_policies_parameters(Some("Many-Group"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Lister is not authorized to perform: \
                 iam:ListAttachedGroupPolicies on resource: arn:aws:iam::{account_id}:group/Many-Group"
        )),
        "unexpected body: {body}"
    );

    // A group that does not exist is still authorized against the ARN the request names, so a
    // caller allowed the action on any group is told the group is missing...
    let (principal, session_data) = database.user_identity("SVCLGABROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_group_policies_parameters(Some("No-Such-Group"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific group learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCLGANARROWLS01", "Narrow-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_group_policies_parameters(Some("No-Such-Group"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // GroupName is required.
    let (principal, session_data) = database.user_identity("SVCLGABROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_attached_group_policies_parameters(None, None, None, None))
            .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // A malformed group name, path prefix, or pagination argument is rejected before the request
    // is authorized, so even a caller with no grant is told the request is malformed.
    for parameters in [
        list_attached_group_policies_parameters(Some("Not/A/Group-Name"), None, None, None),
        list_attached_group_policies_parameters(Some("Many-Group"), Some("no-leading-slash/"), None, None),
        list_attached_group_policies_parameters(Some("Many-Group"), None, Some(0), None),
        list_attached_group_policies_parameters(Some("Many-Group"), None, Some(1001), None),
    ] {
        let (principal, session_data) = database.user_identity("SVCLGANOGRANTL01", "No-Grant-Lister");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // A marker this service did not issue is the caller's to fix rather than ours.
    let (principal, session_data) = database.user_identity("SVCLGABROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_group_policies_parameters(Some("Many-Group"), None, None, Some(FOREIGN_PAGINATION_TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>InvalidInput</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCLGAROLE000001", "List-Attached-Group-Policies-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_group_policies_parameters(Some("Role-Group"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Alpha-Policy</PolicyName>"), "unexpected body: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_group_policies_parameters(Some("Root-Group"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Gamma-Policy</PolicyName>"), "unexpected body: {body}");
}
