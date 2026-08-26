use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The document seeded as the default version of `Main-Policy`, to be read back out.
const DEFAULT_DOCUMENT: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;

/// The document seeded as a later, non-default version of `Main-Policy`. It carries the JSON
/// punctuation a percent-encoded document has to survive.
const LATER_DOCUMENT: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:DeleteObject"],"Resource":"arn:aws:s3:::example/*"}]}"#;

/// The ARN of the AWS-managed policy this test seeds, which every account may read.
const AWS_MANAGED_POLICY_ARN: &str = "arn:aws:iam::000000000000:policy/Get-Version-Aws-Managed";

/// A policy in an account that is not the caller's, seeded so that a caller trying to read across
/// accounts has something real to fail to reach.
const FOREIGN_POLICY_ARN: &str = "arn:aws:iam::320987654321:policy/Foreign-Policy";

/// Seed data for the `GetPolicyVersion` authorization tests. `Main-Policy` carries two versions so
/// that a default and a non-default one can be told apart, and the callers carry grants scoped by
/// the policy being read and by that policy's tags.
const GET_POLICY_VERSION_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'get-policy-version-test@example.com', 'get-policy-version-test'),
    ('320987654321', 'get-policy-version-foreign@example.com', 'get-policy-version-foreign');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCGPVPOLMAIN001', '%ACCOUNT_ID%', 'main-policy', 'Main-Policy', '/', 1, false, 2),
    ('SVCGPVPOLOTHER01', '%ACCOUNT_ID%', 'other-policy', 'Other-Policy', '/', 1, false, 1),
    ('SVCGPVPOLTAGGED1', '%ACCOUNT_ID%', 'tagged-policy', 'Tagged-Policy', '/', 1, false, 1),
    ('SVCGPVPOLAWSMG01', '000000000000', 'get-version-aws-managed', 'Get-Version-Aws-Managed', '/', 1, false, 1),
    ('SVCGPVPOLFOREGN1', '320987654321', 'foreign-policy', 'Foreign-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCGPVPOLMAIN001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCGPVPOLMAIN001', 2,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:DeleteObject"],"Resource":"arn:aws:s3:::example/*"}]}'),
    ('SVCGPVPOLOTHER01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCGPVPOLTAGGED1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCGPVPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}'),
    ('SVCGPVPOLFOREGN1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}');

    INSERT INTO iam.managed_policy_tags(managed_policy_id, key_lower, key_cased, value) VALUES
    ('SVCGPVPOLTAGGED1', 'environment', 'Environment', 'Sandbox');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCGPVBROAD00001', '%ACCOUNT_ID%', 'broad-reader', 'Broad-Reader', '/'),
    ('SVCGPVNARROW0001', '%ACCOUNT_ID%', 'narrow-reader', 'Narrow-Reader', '/'),
    ('SVCGPVTAG0000001', '%ACCOUNT_ID%', 'tag-reader', 'Tag-Reader', '/'),
    ('SVCGPVNONE000001', '%ACCOUNT_ID%', 'no-grant-reader', 'No-Grant-Reader', '/');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCGPVBROAD00001', 'allow-get-any-version', 'Allow-Get-Any-Version',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetPolicyVersion","Resource":"*"}]}'),
    ('SVCGPVNARROW0001', 'allow-get-main-policy-version', 'Allow-Get-Main-Policy-Version',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetPolicyVersion",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:policy/Main-Policy"}]}'),
    ('SVCGPVTAG0000001', 'allow-get-sandbox-versions', 'Allow-Get-Sandbox-Versions',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetPolicyVersion","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/environment":"Sandbox"}}}]}');
"#;

/// End-to-end authorization checks for `GetPolicyVersion` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account.
#[test_log::test(tokio::test)]
async fn test_get_policy_version_authorization() {
    let database = TestDatabase::new(GET_POLICY_VERSION_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let main_policy = database.arn("policy/Main-Policy");
    let other_policy = database.arn("policy/Other-Policy");

    // A caller allowed iam:GetPolicyVersion on any policy reads a version of one, and is given the
    // document, which is what tells this operation apart from GetPolicy.
    let (principal, session_data) = database.user_identity("SVCGPVBROAD00001", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&main_policy), Some("v1"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<VersionId>v1</VersionId>"), "unexpected body: {body}");
    assert!(body.contains("<IsDefaultVersion>true</IsDefaultVersion>"), "unexpected body: {body}");
    assert_eq!(decoded_policy_version_document(&body), DEFAULT_DOCUMENT);

    // The document is reported percent-encoded, as IAM reports it: what is between the tags is not
    // the JSON itself.
    assert!(!body.contains("<Document>{"), "unexpected body: {body}");
    assert!(body.contains("%7B%22Version%22"), "unexpected body: {body}");

    // A version that is not the policy's default says so, and carries its own document.
    let (principal, session_data) = database.user_identity("SVCGPVBROAD00001", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&main_policy), Some("v2"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<VersionId>v2</VersionId>"), "unexpected body: {body}");
    assert!(body.contains("<IsDefaultVersion>false</IsDefaultVersion>"), "unexpected body: {body}");
    assert_eq!(decoded_policy_version_document(&body), LATER_DOCUMENT);

    // A version the policy does not have is reported as missing.
    let (principal, session_data) = database.user_identity("SVCGPVBROAD00001", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&main_policy), Some("v9"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A grant naming one policy reaches every version of that policy...
    let (principal, session_data) = database.user_identity("SVCGPVNARROW0001", "Narrow-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&main_policy), Some("v2"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no version of any other, since the version is authorized against the policy it
    // belongs to.
    let (principal, session_data) = database.user_identity("SVCGPVNARROW0001", "Narrow-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&other_policy), Some("v1")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Narrow-Reader is not authorized to perform: \
                 iam:GetPolicyVersion on resource: {other_policy}"
        )),
        "unexpected body: {body}"
    );

    // The policy is read before the request is authorized, so a grant conditioned on the tags the
    // policy carries can be evaluated at all.
    let (principal, session_data) = database.user_identity("SVCGPVTAG0000001", "Tag-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_policy_version_parameters(Some(&database.arn("policy/Tagged-Policy")), Some("v1")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A policy without that tag leaves the condition key absent, so the grant does not apply.
    let (principal, session_data) = database.user_identity("SVCGPVTAG0000001", "Tag-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&other_policy), Some("v1")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCGPVNONE000001", "No-Grant-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&main_policy), Some("v1"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller allowed the action broadly is told that a policy does not exist...
    let missing_policy = database.arn("policy/Missing-Policy");
    let (principal, session_data) = database.user_identity("SVCGPVBROAD00001", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&missing_policy), Some("v1")))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");

    // ...while one allowed it only on particular policies learns nothing at all.
    let (principal, session_data) = database.user_identity("SVCGPVNARROW0001", "Narrow-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&missing_policy), Some("v1")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // AWS-managed policies belong to no customer account, and every account may read their
    // versions.
    let (principal, session_data) = database.user_identity("SVCGPVBROAD00001", "Broad-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_policy_version_parameters(Some(AWS_MANAGED_POLICY_ARN), Some("v1")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<VersionId>v1</VersionId>"), "unexpected body: {body}");

    // A managed policy is not shared across customer accounts, so a version of a policy in another
    // account is reported as no policy at all -- to a caller allowed the action on every resource,
    // which would otherwise be handed another account's document by naming its ARN.
    let (principal, session_data) = database.user_identity("SVCGPVBROAD00001", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(FOREIGN_POLICY_ARN), Some("v1")))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Message>Policy {FOREIGN_POLICY_ARN} was not found.</Message>")),
        "unexpected body: {body}"
    );
    assert!(!body.contains("<Document>"), "unexpected body: {body}");

    // Something that is not a version id at all is rejected before the request is authorized, so a
    // caller with no grant sees the same rejection as one with a grant.
    let (principal, session_data) = database.user_identity("SVCGPVNONE000001", "No-Grant-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&main_policy), Some("banana")))
            .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A request leaving off a parameter the operation requires never becomes a request at all.
    for parameters in
        [get_policy_version_parameters(None, Some("v1")), get_policy_version_parameters(Some(&main_policy), None)]
    {
        let (principal, session_data) = database.user_identity("SVCGPVBROAD00001", "Broad-Reader");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // The account root user is implicitly allowed, and carries no policies of its own.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&other_policy), Some("v1")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(decoded_policy_version_document(&body), DEFAULT_DOCUMENT);
}
