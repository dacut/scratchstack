use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The ARN of the AWS-managed policy this test seeds. It is carried by entities in this test's
/// account *and* in an unrelated one, which is the case where a listing has something to leave
/// out: the policy is shared by every account, but who attached it is each account's own business.
const AWS_MANAGED_POLICY_ARN: &str = "arn:aws:iam::000000000000:policy/List-Entities-Aws-Managed";

/// A policy in an account that is not the caller's.
const FOREIGN_POLICY_ARN: &str = "arn:aws:iam::350987654321:policy/Foreign-Policy";

/// Seed data for the `ListEntitiesForPolicy` authorization tests. `Main-Policy` is carried by a
/// user, a group, and a role of this account and bounds another user; the AWS-managed policy is
/// carried by one entity here and two in the unrelated account.
const LIST_ENTITIES_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'list-entities-test@example.com', 'list-entities-test'),
    ('350987654321', 'list-entities-foreign@example.com', 'list-entities-foreign');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCLEPPOLMAIN001', '%ACCOUNT_ID%', 'main-policy', 'Main-Policy', '/', 1, false, 1),
    ('SVCLEPPOLOTHER01', '%ACCOUNT_ID%', 'other-policy', 'Other-Policy', '/', 1, false, 1),
    ('SVCLEPPOLTAGGED1', '%ACCOUNT_ID%', 'tagged-policy', 'Tagged-Policy', '/', 1, false, 1),
    ('SVCLEPPOLBOUND01', '%ACCOUNT_ID%', 'boundary-policy', 'Boundary-Policy', '/', 1, false, 1),
    ('SVCLEPPOLAWSMG01', '000000000000', 'list-entities-aws-managed', 'List-Entities-Aws-Managed', '/', 1, false, 1),
    ('SVCLEPPOLFOREGN1', '350987654321', 'foreign-policy', 'Foreign-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCLEPPOLMAIN001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLEPPOLOTHER01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLEPPOLTAGGED1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLEPPOLBOUND01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLEPPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}'),
    ('SVCLEPPOLFOREGN1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}');

    INSERT INTO iam.managed_policy_tags(managed_policy_id, key_lower, key_cased, value) VALUES
    ('SVCLEPPOLTAGGED1', 'environment', 'Environment', 'Sandbox');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path,
        permissions_boundary_managed_policy_id) VALUES
    ('SVCLEPBROAD00001', '%ACCOUNT_ID%', 'broad-lister', 'Broad-Lister', '/', NULL),
    ('SVCLEPNARROW0001', '%ACCOUNT_ID%', 'narrow-lister', 'Narrow-Lister', '/', NULL),
    ('SVCLEPTAG0000001', '%ACCOUNT_ID%', 'tag-lister', 'Tag-Lister', '/', NULL),
    ('SVCLEPNONE000001', '%ACCOUNT_ID%', 'no-grant-lister', 'No-Grant-Lister', '/', NULL),
    ('SVCLEPCARRIER001', '%ACCOUNT_ID%', 'carrier-user', 'Carrier-User', '/', NULL),
    ('SVCLEPDIVISION01', '%ACCOUNT_ID%', 'division-user', 'Division-User', '/division/', NULL),
    ('SVCLEPBOUNDED001', '%ACCOUNT_ID%', 'bounded-user', 'Bounded-User', '/', 'SVCLEPPOLBOUND01'),
    ('SVCLEPAWSCARRY01', '%ACCOUNT_ID%', 'aws-carrier-user', 'Aws-Carrier-User', '/', NULL),
    ('SVCLEPFOREIGNUSR', '350987654321', 'foreign-user', 'Foreign-User', '/', NULL);

    INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) VALUES
    ('SVCLEPCARRIERGRP', '%ACCOUNT_ID%', 'carrier-group', 'Carrier-Group', '/'),
    ('SVCLEPFOREIGNGRP', '350987654321', 'foreign-group', 'Foreign-Group', '/');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCLEPCARRIERROL', '%ACCOUNT_ID%', 'carrier-role', 'Carrier-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.user_attached_policies(user_id, managed_policy_id) VALUES
    ('SVCLEPCARRIER001', 'SVCLEPPOLMAIN001'),
    ('SVCLEPDIVISION01', 'SVCLEPPOLMAIN001'),
    ('SVCLEPAWSCARRY01', 'SVCLEPPOLAWSMG01'),
    ('SVCLEPFOREIGNUSR', 'SVCLEPPOLAWSMG01');

    INSERT INTO iam.group_attached_policies(group_id, managed_policy_id) VALUES
    ('SVCLEPCARRIERGRP', 'SVCLEPPOLMAIN001'),
    ('SVCLEPFOREIGNGRP', 'SVCLEPPOLAWSMG01');

    INSERT INTO iam.role_attached_policies(role_id, managed_policy_id) VALUES
    ('SVCLEPCARRIERROL', 'SVCLEPPOLMAIN001');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLEPBROAD00001', 'allow-list-entities-any', 'Allow-List-Entities-Any',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListEntitiesForPolicy",
        "Resource":"*"}]}'),
    ('SVCLEPNARROW0001', 'allow-list-entities-main', 'Allow-List-Entities-Main',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListEntitiesForPolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:policy/Main-Policy"}]}'),
    ('SVCLEPTAG0000001', 'allow-list-entities-sandbox', 'Allow-List-Entities-Sandbox',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListEntitiesForPolicy","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/environment":"Sandbox"}}}]}');
"#;

/// End-to-end authorization checks for `ListEntitiesForPolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account.
#[test_log::test(tokio::test)]
async fn test_list_entities_for_policy_authorization() {
    let database = TestDatabase::new(LIST_ENTITIES_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let main_policy = database.arn("policy/Main-Policy");
    let other_policy = database.arn("policy/Other-Policy");

    // A caller allowed iam:ListEntitiesForPolicy on any policy is told which of its entities carry
    // that policy, in every section.
    let (principal, session_data) = database.user_identity("SVCLEPBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(Some(&main_policy), None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Carrier-Group</GroupName>"), "unexpected body: {body}");
    assert!(body.contains("<RoleName>Carrier-Role</RoleName>"), "unexpected body: {body}");
    assert!(body.contains("<UserName>Carrier-User</UserName>"), "unexpected body: {body}");
    assert!(body.contains("<UserName>Division-User</UserName>"), "unexpected body: {body}");
    assert!(body.contains("<IsTruncated>false</IsTruncated>"), "unexpected body: {body}");

    // An AWS-managed policy is carried by entities in every account that attached it, and this
    // caller is told about its own account's and no others'.
    let (principal, session_data) = database.user_identity("SVCLEPBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(Some(AWS_MANAGED_POLICY_ARN), None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>Aws-Carrier-User</UserName>"), "unexpected body: {body}");
    assert!(!body.contains("Foreign-User"), "unexpected body: {body}");
    assert!(!body.contains("Foreign-Group"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 1, "unexpected body: {body}");

    // EntityFilter reports one kind of entity and leaves the other sections empty.
    for (entity_filter, present, absent) in [
        ("User", "<UserName>Carrier-User</UserName>", "<GroupName>Carrier-Group</GroupName>"),
        ("Group", "<GroupName>Carrier-Group</GroupName>", "<RoleName>Carrier-Role</RoleName>"),
        ("Role", "<RoleName>Carrier-Role</RoleName>", "<UserName>Carrier-User</UserName>"),
    ] {
        let (principal, session_data) = database.user_identity("SVCLEPBROAD00001", "Broad-Lister");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &list_entities_for_policy_parameters(Some(&main_policy), Some(entity_filter), None, None, None, None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response for {entity_filter}: {body}");
        assert!(body.contains(present), "unexpected body for {entity_filter}: {body}");
        assert!(!body.contains(absent), "unexpected body for {entity_filter}: {body}");
    }

    // PolicyUsageFilter chooses between the entities carrying the policy and the ones it bounds.
    let (principal, session_data) = database.user_identity("SVCLEPBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(
            Some(&database.arn("policy/Boundary-Policy")),
            None,
            None,
            Some("PermissionsBoundary"),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>Bounded-User</UserName>"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 1, "unexpected body: {body}");

    // A path prefix narrows the listing to the entities under it.
    let (principal, session_data) = database.user_identity("SVCLEPBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(Some(&main_policy), Some("User"), Some("/division/"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>Division-User</UserName>"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 1, "unexpected body: {body}");

    // A listing longer than MaxItems reports itself as truncated and hands back a marker...
    let (principal, session_data) = database.user_identity("SVCLEPBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(Some(&main_policy), None, None, None, Some(1), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<IsTruncated>true</IsTruncated>"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 1, "unexpected body: {body}");
    let marker = pagination_marker(&body);

    // ...which picks the listing up where it left off, in the next section.
    let (principal, session_data) = database.user_identity("SVCLEPBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(Some(&main_policy), None, None, None, Some(1), Some(&marker)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<RoleName>Carrier-Role</RoleName>"), "unexpected body: {body}");
    assert!(!body.contains("<GroupName>Carrier-Group</GroupName>"), "unexpected body: {body}");

    // A grant naming one policy reaches that policy...
    let (principal, session_data) = database.user_identity("SVCLEPNARROW0001", "Narrow-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(Some(&main_policy), None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no other.
    let (principal, session_data) = database.user_identity("SVCLEPNARROW0001", "Narrow-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(Some(&other_policy), None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Narrow-Lister is not authorized to perform: \
                 iam:ListEntitiesForPolicy on resource: {other_policy}"
        )),
        "unexpected body: {body}"
    );

    // The policy is read before the request is authorized, so a grant conditioned on the tags the
    // policy carries can be evaluated at all.
    let (principal, session_data) = database.user_identity("SVCLEPTAG0000001", "Tag-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(Some(&database.arn("policy/Tagged-Policy")), None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A policy without that tag leaves the condition key absent, so the grant does not apply.
    let (principal, session_data) = database.user_identity("SVCLEPTAG0000001", "Tag-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(Some(&other_policy), None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCLEPNONE000001", "No-Grant-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(Some(&main_policy), None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A policy in another account is reported as no policy at all, so nothing of its entities is
    // revealed either.
    let (principal, session_data) = database.user_identity("SVCLEPBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(Some(FOREIGN_POLICY_ARN), None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Message>Policy {FOREIGN_POLICY_ARN} was not found.</Message>")),
        "unexpected body: {body}"
    );

    // A policy that does not exist is reported as missing to a caller allowed the action broadly,
    // and tells one allowed it only on particular policies nothing at all.
    let missing_policy = database.arn("policy/Missing-Policy");
    let (principal, session_data) = database.user_identity("SVCLEPBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(Some(&missing_policy), None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCLEPNARROW0001", "Narrow-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(Some(&missing_policy), None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");

    // An ARN that is not a policy ARN is rejected before the request is authorized.
    let (principal, session_data) = database.user_identity("SVCLEPNONE000001", "No-Grant-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(Some("not-an-arn-but-long-enough"), None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // An EntityFilter naming no kind of entity there is never becomes a value the request can
    // carry, so it is reported as malformed input rather than as a validation failure.
    let (principal, session_data) = database.user_identity("SVCLEPBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(Some(&main_policy), Some("Sandwich"), None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // A request leaving off the ARN never becomes a request at all.
    let (principal, session_data) = database.user_identity("SVCLEPBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(None, None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // The account root user is implicitly allowed, and is confined to its own account's entities
    // exactly as any other caller is.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_entities_for_policy_parameters(Some(AWS_MANAGED_POLICY_ARN), None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>Aws-Carrier-User</UserName>"), "unexpected body: {body}");
    assert!(!body.contains("Foreign-User"), "unexpected body: {body}");
}
