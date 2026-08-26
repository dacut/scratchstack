use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The document each new version carries, for the requests whose subject is something other than
/// the document itself.
const NEW_DOCUMENT: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}"#;

/// The ARN of the AWS-managed policy this test seeds, which no account owns and none may version.
const AWS_MANAGED_POLICY_ARN: &str = "arn:aws:iam::000000000000:policy/Create-Version-Aws-Managed";

/// Seed data for the `CreatePolicyVersion` authorization tests. The callers carry grants scoped by
/// the policy being versioned and by that policy's tags. `Full-Policy` already carries the five
/// versions a managed policy is allowed, so it has no room for another.
const CREATE_POLICY_VERSION_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'create-policy-version-test@example.com', 'create-policy-version-test');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCCPVPOLMAIN001', '%ACCOUNT_ID%', 'main-policy', 'Main-Policy', '/', 1, false, 1),
    ('SVCCPVPOLOTHER01', '%ACCOUNT_ID%', 'other-policy', 'Other-Policy', '/', 1, false, 1),
    ('SVCCPVPOLTAGGED1', '%ACCOUNT_ID%', 'tagged-policy', 'Tagged-Policy', '/', 1, false, 1),
    ('SVCCPVPOLFULL001', '%ACCOUNT_ID%', 'full-policy', 'Full-Policy', '/', 1, false, 5),
    ('SVCCPVPOLROOT001', '%ACCOUNT_ID%', 'root-policy', 'Root-Policy', '/', 1, false, 1),
    ('SVCCPVPOLAWSMG01', '000000000000', 'create-version-aws-managed', 'Create-Version-Aws-Managed', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCCPVPOLMAIN001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCCPVPOLOTHER01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCCPVPOLTAGGED1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCCPVPOLFULL001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCCPVPOLFULL001', 2,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCCPVPOLFULL001', 3,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCCPVPOLFULL001', 4,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCCPVPOLFULL001', 5,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCCPVPOLROOT001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCCPVPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}');

    INSERT INTO iam.managed_policy_tags(managed_policy_id, key_lower, key_cased, value) VALUES
    ('SVCCPVPOLTAGGED1', 'environment', 'Environment', 'Sandbox');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCCPVBROAD00001', '%ACCOUNT_ID%', 'broad-versioner', 'Broad-Versioner', '/'),
    ('SVCCPVNARROW0001', '%ACCOUNT_ID%', 'narrow-versioner', 'Narrow-Versioner', '/'),
    ('SVCCPVTAG0000001', '%ACCOUNT_ID%', 'tag-versioner', 'Tag-Versioner', '/'),
    ('SVCCPVNONE000001', '%ACCOUNT_ID%', 'no-grant-versioner', 'No-Grant-Versioner', '/');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCCPVBROAD00001', 'allow-version-any', 'Allow-Version-Any',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Action":["iam:CreatePolicyVersion","iam:GetPolicy","iam:GetPolicyVersion","iam:ListPolicyVersions"],
        "Resource":"*"}]}'),
    ('SVCCPVNARROW0001', 'allow-version-main-policy', 'Allow-Version-Main-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreatePolicyVersion",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:policy/Main-Policy"}]}'),
    ('SVCCPVTAG0000001', 'allow-version-sandbox', 'Allow-Version-Sandbox',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreatePolicyVersion","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/environment":"Sandbox"}}}]}');
"#;

/// End-to-end authorization checks for `CreatePolicyVersion` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_create_policy_version_authorization() {
    let database = TestDatabase::new(CREATE_POLICY_VERSION_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let main_policy = database.arn("policy/Main-Policy");
    let other_policy = database.arn("policy/Other-Policy");

    // A caller allowed iam:CreatePolicyVersion on any policy adds a version to one. The new
    // version is not made the default unless the request asks for it.
    let (principal, session_data) = database.user_identity("SVCCPVBROAD00001", "Broad-Versioner");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_version_parameters(Some(&main_policy), Some(NEW_DOCUMENT), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<VersionId>v2</VersionId>"), "unexpected body: {body}");
    assert!(body.contains("<IsDefaultVersion>false</IsDefaultVersion>"), "unexpected body: {body}");

    // IAM reports a policy document only from GetPolicyVersion, so the version just created does
    // not carry the document it was created from.
    assert!(!body.contains("<Document>"), "unexpected body: {body}");

    // The version is readable, so the create was committed rather than rolled back, and the
    // document it carries is the one the request supplied.
    let (principal, session_data) = database.user_identity("SVCCPVBROAD00001", "Broad-Versioner");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&main_policy), Some("v2"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(decoded_policy_version_document(&body), NEW_DOCUMENT);

    // The policy still grants by the version it did before, since the new one was not made the
    // default.
    let (principal, session_data) = database.user_identity("SVCCPVBROAD00001", "Broad-Versioner");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&main_policy))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DefaultVersionId>v1</DefaultVersionId>"), "unexpected body: {body}");

    // A request that asks for it makes the new version the one the policy grants by...
    let (principal, session_data) = database.user_identity("SVCCPVBROAD00001", "Broad-Versioner");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_version_parameters(Some(&main_policy), Some(NEW_DOCUMENT), Some(true)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<VersionId>v3</VersionId>"), "unexpected body: {body}");
    assert!(body.contains("<IsDefaultVersion>true</IsDefaultVersion>"), "unexpected body: {body}");

    // ...which the policy itself now reports.
    let (principal, session_data) = database.user_identity("SVCCPVBROAD00001", "Broad-Versioner");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&main_policy))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DefaultVersionId>v3</DefaultVersionId>"), "unexpected body: {body}");

    // A grant naming one policy reaches that policy...
    let (principal, session_data) = database.user_identity("SVCCPVNARROW0001", "Narrow-Versioner");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_version_parameters(Some(&main_policy), Some(NEW_DOCUMENT), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<VersionId>v4</VersionId>"), "unexpected body: {body}");

    // ...and no other.
    let (principal, session_data) = database.user_identity("SVCCPVNARROW0001", "Narrow-Versioner");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_version_parameters(Some(&other_policy), Some(NEW_DOCUMENT), None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Narrow-Versioner is not authorized to perform: \
                 iam:CreatePolicyVersion on resource: {other_policy}"
        )),
        "unexpected body: {body}"
    );

    // The policy is read before the request is authorized, so a grant conditioned on the tags the
    // policy carries can be evaluated at all.
    let (principal, session_data) = database.user_identity("SVCCPVTAG0000001", "Tag-Versioner");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_version_parameters(Some(&database.arn("policy/Tagged-Policy")), Some(NEW_DOCUMENT), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A policy without that tag leaves the condition key absent, so the grant does not apply.
    let (principal, session_data) = database.user_identity("SVCCPVTAG0000001", "Tag-Versioner");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_version_parameters(Some(&other_policy), Some(NEW_DOCUMENT), None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCCPVNONE000001", "No-Grant-Versioner");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_version_parameters(Some(&main_policy), Some(NEW_DOCUMENT), None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A policy carrying every version it is allowed has no room for another, and the caller must
    // delete one before adding one.
    let (principal, session_data) = database.user_identity("SVCCPVBROAD00001", "Broad-Versioner");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_version_parameters(Some(&database.arn("policy/Full-Policy")), Some(NEW_DOCUMENT), None),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
    assert!(body.contains("<Code>LimitExceeded</Code>"), "unexpected body: {body}");

    // A document that is not a policy at all is the caller's error, and is reported as one --
    // after authorization, since the caller here is allowed to version policies.
    let (principal, session_data) = database.user_identity("SVCCPVBROAD00001", "Broad-Versioner");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_version_parameters(Some(&other_policy), Some("not a policy document"), None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedPolicyDocument</Code>"), "unexpected body: {body}");

    // The rejection rolled its transaction back, so the policy still has only the version it had.
    let (principal, session_data) = database.user_identity("SVCCPVBROAD00001", "Broad-Versioner");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&other_policy), Some("v2")))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");

    // An AWS-managed policy is shared by every account and versioned by none, so it is reported as
    // no policy at all -- even to a caller allowed the action on every resource.
    let (principal, session_data) = database.user_identity("SVCCPVBROAD00001", "Broad-Versioner");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_version_parameters(Some(AWS_MANAGED_POLICY_ARN), Some(NEW_DOCUMENT), None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Message>Policy {AWS_MANAGED_POLICY_ARN} was not found.</Message>")),
        "unexpected body: {body}"
    );

    // And it is untouched afterwards: the refusal is not a version that quietly failed to appear.
    let (principal, session_data) = database.user_identity("SVCCPVBROAD00001", "Broad-Versioner");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policy_versions_parameters(Some(AWS_MANAGED_POLICY_ARN), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(body.matches("<member>").count(), 1, "unexpected body: {body}");

    // A policy in another account is not the caller's to version either.
    const FOREIGN_POLICY_ARN: &str = "arn:aws:iam::310987654321:policy/Foreign-Policy";
    let (principal, session_data) = database.user_identity("SVCCPVBROAD00001", "Broad-Versioner");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_version_parameters(Some(FOREIGN_POLICY_ARN), Some(NEW_DOCUMENT), None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A policy that does not exist is reported as missing to a caller allowed the action broadly.
    let (principal, session_data) = database.user_identity("SVCCPVBROAD00001", "Broad-Versioner");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_version_parameters(Some(&database.arn("policy/Missing-Policy")), Some(NEW_DOCUMENT), None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // An ARN that is not a policy ARN is rejected before the request is authorized, so a caller
    // with no grant sees the same rejection as one with a grant.
    let (principal, session_data) = database.user_identity("SVCCPVNONE000001", "No-Grant-Versioner");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_version_parameters(Some("not-an-arn-but-long-enough"), Some(NEW_DOCUMENT), None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A request leaving off a parameter the operation requires never becomes a request at all.
    for parameters in [
        create_policy_version_parameters(None, Some(NEW_DOCUMENT), None),
        create_policy_version_parameters(Some(&main_policy), None, None),
    ] {
        let (principal, session_data) = database.user_identity("SVCCPVBROAD00001", "Broad-Versioner");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // The account root user is implicitly allowed, and carries no policies of its own.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_version_parameters(Some(&database.arn("policy/Root-Policy")), Some(NEW_DOCUMENT), Some(true)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<VersionId>v2</VersionId>"), "unexpected body: {body}");
    assert!(body.contains("<IsDefaultVersion>true</IsDefaultVersion>"), "unexpected body: {body}");
}
