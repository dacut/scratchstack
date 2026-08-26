use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The ARN of the AWS-managed policy this test seeds, which no account may untag.
const AWS_MANAGED_POLICY_ARN: &str = "arn:aws:iam::000000000000:policy/Untag-Policy-Aws-Managed";

/// A policy in an account that is not the caller's.
const FOREIGN_POLICY_ARN: &str = "arn:aws:iam::390987654321:policy/Foreign-Policy";

/// Seed data for the `UntagPolicy` authorization tests. The callers carry grants scoped by the tag
/// keys the request may name and by the tags the policy already carries.
const UNTAG_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'untag-policy-test@example.com', 'untag-policy-test'),
    ('390987654321', 'untag-policy-foreign@example.com', 'untag-policy-foreign');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCUTPPOLMAIN001', '%ACCOUNT_ID%', 'main-policy', 'Main-Policy', '/', 1, false, 1),
    ('SVCUTPPOLSNDBX01', '%ACCOUNT_ID%', 'sandbox-policy', 'Sandbox-Policy', '/', 1, false, 1),
    ('SVCUTPPOLPROD001', '%ACCOUNT_ID%', 'prod-policy', 'Prod-Policy', '/', 1, false, 1),
    ('SVCUTPPOLROOT001', '%ACCOUNT_ID%', 'root-policy', 'Root-Policy', '/', 1, false, 1),
    ('SVCUTPPOLAWSMG01', '000000000000', 'untag-policy-aws-managed', 'Untag-Policy-Aws-Managed', '/', 1, false, 1),
    ('SVCUTPPOLFOREGN1', '390987654321', 'foreign-policy', 'Foreign-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCUTPPOLMAIN001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCUTPPOLSNDBX01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCUTPPOLPROD001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCUTPPOLROOT001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCUTPPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}'),
    ('SVCUTPPOLFOREGN1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}');

    INSERT INTO iam.managed_policy_tags(managed_policy_id, key_lower, key_cased, value) VALUES
    ('SVCUTPPOLMAIN001', 'costcenter', 'CostCenter', '1234'),
    ('SVCUTPPOLMAIN001', 'department', 'Department', 'Engineering'),
    ('SVCUTPPOLMAIN001', 'project', 'Project', 'Scratchstack'),
    ('SVCUTPPOLSNDBX01', 'environment', 'Environment', 'Sandbox'),
    ('SVCUTPPOLSNDBX01', 'owner', 'Owner', 'Platform'),
    ('SVCUTPPOLPROD001', 'environment', 'Environment', 'Production'),
    ('SVCUTPPOLPROD001', 'owner', 'Owner', 'Platform'),
    ('SVCUTPPOLROOT001', 'owner', 'Owner', 'Root'),
    ('SVCUTPPOLAWSMG01', 'origin', 'Origin', 'Aws');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCUTPBROAD00001', '%ACCOUNT_ID%', 'broad-untagger', 'Broad-Untagger', '/'),
    ('SVCUTPKEYS000001', '%ACCOUNT_ID%', 'keys-untagger', 'Keys-Untagger', '/'),
    ('SVCUTPRESOURCE01', '%ACCOUNT_ID%', 'sandbox-untagger', 'Sandbox-Untagger', '/'),
    ('SVCUTPNONE000001', '%ACCOUNT_ID%', 'no-grant-untagger', 'No-Grant-Untagger', '/');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCUTPBROAD00001', 'allow-untag-any-policy', 'Allow-Untag-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Action":["iam:UntagPolicy","iam:ListPolicyTags"],"Resource":"*"}]}'),
    ('SVCUTPKEYS000001', 'allow-untag-known-keys', 'Allow-Untag-Known-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UntagPolicy","Resource":"*",
        "Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["Department","Project"]}}}]}'),
    ('SVCUTPRESOURCE01', 'allow-untag-sandbox-policies', 'Allow-Untag-Sandbox-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UntagPolicy","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/environment":"Sandbox"}}}]}');
"#;

/// End-to-end authorization checks for `UntagPolicy` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_untag_policy_authorization() {
    let database = TestDatabase::new(UNTAG_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let main_policy = database.arn("policy/Main-Policy");
    let prod_policy = database.arn("policy/Prod-Policy");
    let sandbox_policy = database.arn("policy/Sandbox-Policy");

    // A caller allowed iam:UntagPolicy on any policy removes a tag from one, leaving the rest.
    let (principal, session_data) = database.user_identity("SVCUTPBROAD00001", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_policy_parameters(Some(&main_policy), &["CostCenter"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCUTPBROAD00001", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(Some(&main_policy), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<Key>CostCenter</Key>"), "unexpected body: {body}");
    assert!(body.contains("<Key>Department</Key>"), "unexpected body: {body}");
    assert!(body.contains("<Key>Project</Key>"), "unexpected body: {body}");

    // A key the policy does not carry is not an error: the request asks for the tag to be gone,
    // and it is.
    let (principal, session_data) = database.user_identity("SVCUTPBROAD00001", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_policy_parameters(Some(&main_policy), &["Nonexistent"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // Tag keys are matched case-insensitively, so a key spelled differently from the one stored
    // still names it.
    let (principal, session_data) = database.user_identity("SVCUTPBROAD00001", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_policy_parameters(Some(&main_policy), &["PROJECT"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCUTPBROAD00001", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(Some(&main_policy), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<Key>Project</Key>"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 1, "unexpected body: {body}");

    // The request names keys without naming values, so it backs aws:TagKeys and no
    // aws:RequestTag: a grant can limit which tags a caller may remove.
    let (principal, session_data) = database.user_identity("SVCUTPKEYS000001", "Keys-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_policy_parameters(Some(&main_policy), &["Department"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // One key outside the set the policy lists is enough to fail, even alongside keys that are in
    // it.
    let (principal, session_data) = database.user_identity("SVCUTPKEYS000001", "Keys-Untagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &untag_policy_parameters(Some(&sandbox_policy), &["Project", "Owner"]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled its transaction back, so neither tag was removed.
    let (principal, session_data) = database.user_identity("SVCUTPBROAD00001", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(Some(&sandbox_policy), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Owner</Key>"), "unexpected body: {body}");
    assert!(body.contains("<Key>Environment</Key>"), "unexpected body: {body}");

    // The tags the policy already carries back the iam:ResourceTag keys, so a grant conditioned on
    // them governs removing them -- which is what keeps a policy from being moved out of that
    // grant's reach...
    let (principal, session_data) = database.user_identity("SVCUTPRESOURCE01", "Sandbox-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_policy_parameters(Some(&sandbox_policy), &["Owner"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and a policy whose tag holds another value is out of that grant's reach to begin with.
    let (principal, session_data) = database.user_identity("SVCUTPRESOURCE01", "Sandbox-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_policy_parameters(Some(&prod_policy), &["Owner"])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCUTPNONE000001", "No-Grant-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_policy_parameters(Some(&prod_policy), &["Owner"])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Untagger is not authorized to perform: \
                 iam:UntagPolicy on resource: {prod_policy}"
        )),
        "unexpected body: {body}"
    );

    // An AWS-managed policy is shared by every account and untagged by none, so it is reported as
    // no policy at all.
    let (principal, session_data) = database.user_identity("SVCUTPBROAD00001", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_policy_parameters(Some(AWS_MANAGED_POLICY_ARN), &["Origin"]))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Message>Policy {AWS_MANAGED_POLICY_ARN} was not found.</Message>")),
        "unexpected body: {body}"
    );

    // And it still carries its tag afterwards: the refusal is not a removal that quietly failed.
    let (principal, session_data) = database.user_identity("SVCUTPBROAD00001", "Broad-Untagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policy_tags_parameters(Some(AWS_MANAGED_POLICY_ARN), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Origin</Key><Value>Aws</Value>"), "unexpected body: {body}");

    // A policy in another account is not the caller's to untag either.
    let (principal, session_data) = database.user_identity("SVCUTPBROAD00001", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_policy_parameters(Some(FOREIGN_POLICY_ARN), &["Owner"])).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A request naming no keys asks for nothing to be removed, and is reported as the caller's
    // error -- after authorization, since the caller here is allowed to untag policies.
    let (principal, session_data) = database.user_identity("SVCUTPBROAD00001", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_policy_parameters(Some(&main_policy), &[])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A policy that does not exist is reported as missing.
    let (principal, session_data) = database.user_identity("SVCUTPBROAD00001", "Broad-Untagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &untag_policy_parameters(Some(&database.arn("policy/Missing-Policy")), &["Owner"]),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");

    // An ARN that is not a policy ARN is rejected before the request is authorized.
    let (principal, session_data) = database.user_identity("SVCUTPNONE000001", "No-Grant-Untagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &untag_policy_parameters(Some("not-an-arn-but-long-enough"), &["Owner"]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A request leaving off the ARN never becomes a request at all.
    let (principal, session_data) = database.user_identity("SVCUTPBROAD00001", "Broad-Untagger");
    let (status, body) = call(&svc_state, principal, session_data, &untag_policy_parameters(None, &["Owner"])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // The account root user is implicitly allowed, and carries no policies of its own.
    let root_policy = database.arn("policy/Root-Policy");
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_policy_parameters(Some(&root_policy), &["Owner"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCUTPBROAD00001", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(Some(&root_policy), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(body.matches("<member>").count(), 0, "unexpected body: {body}");
}
