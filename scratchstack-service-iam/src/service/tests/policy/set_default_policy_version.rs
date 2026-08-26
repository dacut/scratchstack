use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The ARN of the AWS-managed policy this test seeds, whose default version no account may change.
const AWS_MANAGED_POLICY_ARN: &str = "arn:aws:iam::000000000000:policy/Set-Default-Aws-Managed";

/// A policy in an account that is not the caller's.
const FOREIGN_POLICY_ARN: &str = "arn:aws:iam::370987654321:policy/Foreign-Policy";

/// Seed data for the `SetDefaultPolicyVersion` authorization tests. `Main-Policy` carries three
/// versions with the first as its default, so there is somewhere else to point it.
const SET_DEFAULT_POLICY_VERSION_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'set-default-version-test@example.com', 'set-default-version-test'),
    ('370987654321', 'set-default-version-foreign@example.com', 'set-default-version-foreign');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCSDVPOLMAIN001', '%ACCOUNT_ID%', 'main-policy', 'Main-Policy', '/', 1, false, 3),
    ('SVCSDVPOLOTHER01', '%ACCOUNT_ID%', 'other-policy', 'Other-Policy', '/', 1, false, 2),
    ('SVCSDVPOLTAGGED1', '%ACCOUNT_ID%', 'tagged-policy', 'Tagged-Policy', '/', 1, false, 2),
    ('SVCSDVPOLROOT001', '%ACCOUNT_ID%', 'root-policy', 'Root-Policy', '/', 1, false, 2),
    ('SVCSDVPOLAWSMG01', '000000000000', 'set-default-aws-managed', 'Set-Default-Aws-Managed', '/', 1, false, 2),
    ('SVCSDVPOLFOREGN1', '370987654321', 'foreign-policy', 'Foreign-Policy', '/', 1, false, 2);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCSDVPOLMAIN001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCSDVPOLMAIN001', 2,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}'),
    ('SVCSDVPOLMAIN001', 3,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:DeleteObject","Resource":"*"}]}'),
    ('SVCSDVPOLOTHER01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCSDVPOLOTHER01', 2,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}'),
    ('SVCSDVPOLTAGGED1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCSDVPOLTAGGED1', 2,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}'),
    ('SVCSDVPOLROOT001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCSDVPOLROOT001', 2,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}'),
    ('SVCSDVPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}'),
    ('SVCSDVPOLAWSMG01', 2,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:GetMetricData","Resource":"*"}]}'),
    ('SVCSDVPOLFOREGN1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}'),
    ('SVCSDVPOLFOREGN1', 2,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Subscribe","Resource":"*"}]}');

    INSERT INTO iam.managed_policy_tags(managed_policy_id, key_lower, key_cased, value) VALUES
    ('SVCSDVPOLTAGGED1', 'environment', 'Environment', 'Sandbox');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCSDVBROAD00001', '%ACCOUNT_ID%', 'broad-setter', 'Broad-Setter', '/'),
    ('SVCSDVNARROW0001', '%ACCOUNT_ID%', 'narrow-setter', 'Narrow-Setter', '/'),
    ('SVCSDVTAG0000001', '%ACCOUNT_ID%', 'tag-setter', 'Tag-Setter', '/'),
    ('SVCSDVNONE000001', '%ACCOUNT_ID%', 'no-grant-setter', 'No-Grant-Setter', '/');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCSDVBROAD00001', 'allow-set-default-any', 'Allow-Set-Default-Any',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Action":["iam:SetDefaultPolicyVersion","iam:GetPolicy","iam:ListPolicyVersions"],"Resource":"*"}]}'),
    ('SVCSDVNARROW0001', 'allow-set-default-main', 'Allow-Set-Default-Main',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:SetDefaultPolicyVersion",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:policy/Main-Policy"}]}'),
    ('SVCSDVTAG0000001', 'allow-set-default-sandbox', 'Allow-Set-Default-Sandbox',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:SetDefaultPolicyVersion","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/environment":"Sandbox"}}}]}');
"#;

/// End-to-end authorization checks for `SetDefaultPolicyVersion` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_set_default_policy_version_authorization() {
    let database = TestDatabase::new(SET_DEFAULT_POLICY_VERSION_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let main_policy = database.arn("policy/Main-Policy");
    let other_policy = database.arn("policy/Other-Policy");

    // A caller allowed iam:SetDefaultPolicyVersion on any policy points one at another version.
    let (principal, session_data) = database.user_identity("SVCSDVBROAD00001", "Broad-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &set_default_policy_version_parameters(Some(&main_policy), Some("v3")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The policy now grants by that version, so the change was committed rather than rolled back.
    let (principal, session_data) = database.user_identity("SVCSDVBROAD00001", "Broad-Setter");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&main_policy))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DefaultVersionId>v3</DefaultVersionId>"), "unexpected body: {body}");

    // The listing marks the new default and nothing else.
    let (principal, session_data) = database.user_identity("SVCSDVBROAD00001", "Broad-Setter");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_versions_parameters(Some(&main_policy), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(body.matches("<IsDefaultVersion>true</IsDefaultVersion>").count(), 1, "unexpected body: {body}");
    let default_member = body
        .split("<member>")
        .find(|member| member.contains("<IsDefaultVersion>true</IsDefaultVersion>"))
        .expect("no default version in body");
    assert!(default_member.contains("<VersionId>v3</VersionId>"), "unexpected body: {body}");

    // Naming the version the policy already grants by is not an error: it asks for a state the
    // policy is already in.
    let (principal, session_data) = database.user_identity("SVCSDVBROAD00001", "Broad-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &set_default_policy_version_parameters(Some(&main_policy), Some("v3")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A version the policy does not have is reported as missing.
    let (principal, session_data) = database.user_identity("SVCSDVBROAD00001", "Broad-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &set_default_policy_version_parameters(Some(&main_policy), Some("v9")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A grant naming one policy reaches that policy...
    let (principal, session_data) = database.user_identity("SVCSDVNARROW0001", "Narrow-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &set_default_policy_version_parameters(Some(&main_policy), Some("v2")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no other.
    let (principal, session_data) = database.user_identity("SVCSDVNARROW0001", "Narrow-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &set_default_policy_version_parameters(Some(&other_policy), Some("v2")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Narrow-Setter is not authorized to perform: \
                 iam:SetDefaultPolicyVersion on resource: {other_policy}"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled its transaction back, so the policy still grants by what it did.
    let (principal, session_data) = database.user_identity("SVCSDVBROAD00001", "Broad-Setter");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&other_policy))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DefaultVersionId>v1</DefaultVersionId>"), "unexpected body: {body}");

    // The policy is read before the request is authorized, so a grant conditioned on the tags the
    // policy carries can be evaluated at all.
    let (principal, session_data) = database.user_identity("SVCSDVTAG0000001", "Tag-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &set_default_policy_version_parameters(Some(&database.arn("policy/Tagged-Policy")), Some("v2")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A policy without that tag leaves the condition key absent, so the grant does not apply.
    let (principal, session_data) = database.user_identity("SVCSDVTAG0000001", "Tag-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &set_default_policy_version_parameters(Some(&other_policy), Some("v2")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCSDVNONE000001", "No-Grant-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &set_default_policy_version_parameters(Some(&main_policy), Some("v1")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // An AWS-managed policy is shared by every account and changed by none, so it is reported as
    // no policy at all.
    let (principal, session_data) = database.user_identity("SVCSDVBROAD00001", "Broad-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &set_default_policy_version_parameters(Some(AWS_MANAGED_POLICY_ARN), Some("v2")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Message>Policy {AWS_MANAGED_POLICY_ARN} was not found.</Message>")),
        "unexpected body: {body}"
    );

    // And it still grants by what it did: the refusal is not a change that quietly failed.
    let (principal, session_data) = database.user_identity("SVCSDVBROAD00001", "Broad-Setter");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_parameters(Some(AWS_MANAGED_POLICY_ARN))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DefaultVersionId>v1</DefaultVersionId>"), "unexpected body: {body}");

    // A policy in another account is not the caller's to change either.
    let (principal, session_data) = database.user_identity("SVCSDVBROAD00001", "Broad-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &set_default_policy_version_parameters(Some(FOREIGN_POLICY_ARN), Some("v2")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // Something that is not a version id at all is rejected before the request is authorized, so a
    // caller with no grant sees the same rejection as one with a grant.
    let (principal, session_data) = database.user_identity("SVCSDVNONE000001", "No-Grant-Setter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &set_default_policy_version_parameters(Some(&main_policy), Some("latest")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A request leaving off a parameter the operation requires never becomes a request at all.
    for parameters in [
        set_default_policy_version_parameters(None, Some("v1")),
        set_default_policy_version_parameters(Some(&main_policy), None),
    ] {
        let (principal, session_data) = database.user_identity("SVCSDVBROAD00001", "Broad-Setter");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // The account root user is implicitly allowed, and carries no policies of its own.
    let root_policy = database.arn("policy/Root-Policy");
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &set_default_policy_version_parameters(Some(&root_policy), Some("v2")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCSDVBROAD00001", "Broad-Setter");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&root_policy))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DefaultVersionId>v2</DefaultVersionId>"), "unexpected body: {body}");
}
