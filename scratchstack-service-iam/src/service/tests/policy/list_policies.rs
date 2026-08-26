use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The path this test seeds a policy of its own and an AWS-managed policy under.
///
/// The AWS-managed policies live in an account every test shares, so a listing that reaches them
/// reaches every other test's as well. A path no other test uses is what makes such a listing
/// something this test can count.
const SHARED_PATH: &str = "/list-policies-test/";

/// Seed data for the `ListPolicies` authorization tests. The policies differ in the ways the
/// listing can be filtered -- by path, by whether anything has them attached, and by whether they
/// serve as a permissions boundary -- and one of them is owned by the AWS account rather than by
/// this one.
const LIST_POLICIES_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'list-policies-test@example.com', 'list-policies-test');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCLSTPOL0000001', '%ACCOUNT_ID%', 'alpha-policy', 'Alpha-Policy', '/', 1, false, 1),
    ('SVCLSTPOL0000002', '%ACCOUNT_ID%', 'beta-policy', 'Beta-Policy', '/team/', 1, false, 1),
    ('SVCLSTPOL0000003', '%ACCOUNT_ID%', 'gamma-policy', 'Gamma-Policy', '/team/', 1, false, 1),
    ('SVCLSTPOL0000004', '%ACCOUNT_ID%', 'delta-policy', 'Delta-Policy', '/', 1, false, 1),
    ('SVCLSTPOL0000005', '%ACCOUNT_ID%', 'epsilon-policy', 'Epsilon-Policy', '/', 1, false, 1),
    ('SVCLSTPOL0000006', '%ACCOUNT_ID%', 'shared-path-policy', 'Shared-Path-Policy', '/list-policies-test/',
        1, false, 1),
    ('SVCLSTPOLAWSMG01', '000000000000', 'list-policies-aws-managed', 'List-Policies-Aws-Managed',
        '/list-policies-test/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCLSTPOL0000001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLSTPOL0000002', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLSTPOL0000003', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLSTPOL0000004', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLSTPOL0000005', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLSTPOL0000006', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLSTPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path,
        permissions_boundary_managed_policy_id) VALUES
    ('SVCLSTPOLBROAD01', '%ACCOUNT_ID%', 'broad-lister', 'Broad-Lister', '/', NULL),
    ('SVCLSTPOLNONE001', '%ACCOUNT_ID%', 'no-grant-lister', 'No-Grant-Lister', '/', NULL),
    ('SVCLSTPOLHOLDER1', '%ACCOUNT_ID%', 'policy-holder', 'Policy-Holder', '/', NULL),
    ('SVCLSTPOLBOUNDED', '%ACCOUNT_ID%', 'bounded-user', 'Bounded-User', '/', 'SVCLSTPOL0000005');

    INSERT INTO iam.user_attached_policies(user_id, managed_policy_id) VALUES
    ('SVCLSTPOLHOLDER1', 'SVCLSTPOL0000004');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLSTPOLBROAD01', 'allow-list-policies', 'Allow-List-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListPolicies","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `ListPolicies` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account.
#[test_log::test(tokio::test)]
async fn test_list_policies_authorization() {
    let database = TestDatabase::new(LIST_POLICIES_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:ListPolicies lists the policies of its own account, wherever they
    // live, and nothing of the AWS account's.
    let (principal, session_data) = database.user_identity("SVCLSTPOLBROAD01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policies_parameters(Some("Local"), None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    for policy_name in
        ["Alpha-Policy", "Beta-Policy", "Gamma-Policy", "Delta-Policy", "Epsilon-Policy", "Shared-Path-Policy"]
    {
        assert!(body.contains(&format!("<PolicyName>{policy_name}</PolicyName>")), "unexpected body: {body}");
    }
    assert!(!body.contains("List-Policies-Aws-Managed"), "unexpected body: {body}");
    assert!(body.contains("<IsTruncated>false</IsTruncated>"), "unexpected body: {body}");

    // The listing reports what each policy records, including the attachment counts that are the
    // caller's own account's to answer.
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:policy/team/Beta-Policy</Arn>")),
        "unexpected body: {body}"
    );
    assert!(body.contains("<PolicyId>ANPASVCLSTPOL0000001</PolicyId>"), "unexpected body: {body}");
    assert!(body.contains("<DefaultVersionId>v1</DefaultVersionId>"), "unexpected body: {body}");

    // The AWS-managed policies are listed on their own by asking for that scope. Every account
    // shares them, so the listing is confined to the path this test seeds its own under.
    let (principal, session_data) = database.user_identity("SVCLSTPOLBROAD01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policies_parameters(Some("AWS"), Some(SHARED_PATH), None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>List-Policies-Aws-Managed</PolicyName>"), "unexpected body: {body}");
    assert!(!body.contains("Shared-Path-Policy"), "unexpected body: {body}");

    // Asking for neither scope reports both, so the same path prefix reports the caller's policy
    // alongside the AWS-managed one.
    let (principal, session_data) = database.user_identity("SVCLSTPOLBROAD01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policies_parameters(None, Some(SHARED_PATH), None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>List-Policies-Aws-Managed</PolicyName>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>Shared-Path-Policy</PolicyName>"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 2, "unexpected body: {body}");

    // A path prefix narrows the listing to the policies under it.
    let (principal, session_data) = database.user_identity("SVCLSTPOLBROAD01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policies_parameters(Some("Local"), Some("/team/"), None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Beta-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>Gamma-Policy</PolicyName>"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 2, "unexpected body: {body}");

    // OnlyAttached reports the policies something in the account actually carries.
    let (principal, session_data) = database.user_identity("SVCLSTPOLBROAD01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policies_parameters(Some("Local"), None, Some(true), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Delta-Policy</PolicyName>"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 1, "unexpected body: {body}");
    assert!(body.contains("<AttachmentCount>1</AttachmentCount>"), "unexpected body: {body}");

    // PolicyUsageFilter chooses between the two ways a policy can be in use: carried by an entity
    // as a permissions policy...
    let (principal, session_data) = database.user_identity("SVCLSTPOLBROAD01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policies_parameters(Some("Local"), None, None, Some("PermissionsPolicy"), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Delta-Policy</PolicyName>"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 1, "unexpected body: {body}");

    // ...or imposed on one as its permissions boundary.
    let (principal, session_data) = database.user_identity("SVCLSTPOLBROAD01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policies_parameters(Some("Local"), None, None, Some("PermissionsBoundary"), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Epsilon-Policy</PolicyName>"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 1, "unexpected body: {body}");
    assert!(
        body.contains("<PermissionsBoundaryUsageCount>1</PermissionsBoundaryUsageCount>"),
        "unexpected body: {body}"
    );

    // A listing longer than MaxItems reports itself as truncated and hands back a marker...
    let (principal, session_data) = database.user_identity("SVCLSTPOLBROAD01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policies_parameters(Some("Local"), None, None, None, Some(2), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<IsTruncated>true</IsTruncated>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>Alpha-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>Beta-Policy</PolicyName>"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 2, "unexpected body: {body}");
    let marker = pagination_marker(&body);

    // ...which picks the listing up where it left off.
    let (principal, session_data) = database.user_identity("SVCLSTPOLBROAD01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policies_parameters(Some("Local"), None, None, None, Some(2), Some(&marker)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Gamma-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>Delta-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(!body.contains("<PolicyName>Alpha-Policy</PolicyName>"), "unexpected body: {body}");

    // A marker this service never issued cannot be decrypted, and that is the caller's to fix, so
    // it is reported as invalid input rather than as an internal failure.
    let (principal, session_data) = database.user_identity("SVCLSTPOLBROAD01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policies_parameters(Some("Local"), None, None, None, None, Some(FOREIGN_PAGINATION_TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>InvalidInput</Code>"), "unexpected body: {body}");

    // A MaxItems outside the range the listing accepts is a validation failure.
    for max_items in [0, 1001] {
        let (principal, session_data) = database.user_identity("SVCLSTPOLBROAD01", "Broad-Lister");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &list_policies_parameters(Some("Local"), None, None, None, Some(max_items), None),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response for {max_items}: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body for {max_items}: {body}");
    }

    // A path prefix that is not a path is a validation failure as well.
    let (principal, session_data) = database.user_identity("SVCLSTPOLBROAD01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policies_parameters(Some("Local"), Some("team"), None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A Scope naming none of the scopes there are never becomes a value the request can carry, so
    // it is reported as malformed input rather than as a validation failure.
    let (principal, session_data) = database.user_identity("SVCLSTPOLBROAD01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policies_parameters(Some("Everything"), None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // iam:ListPolicies names no resource, so a caller with no grant is refused against the
    // wildcard resource.
    let (principal, session_data) = database.user_identity("SVCLSTPOLNONE001", "No-Grant-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policies_parameters(Some("Local"), None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Lister is not authorized to perform: \
                 iam:ListPolicies on resource: *"
        )),
        "unexpected body: {body}"
    );

    // The account root user is implicitly allowed, and carries no policies of its own.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policies_parameters(Some("Local"), None, None, None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Alpha-Policy</PolicyName>"), "unexpected body: {body}");
}
