use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The ARN of the AWS-managed policy this test seeds, which no account may tag.
const AWS_MANAGED_POLICY_ARN: &str = "arn:aws:iam::000000000000:policy/Tag-Policy-Aws-Managed";

/// A policy in an account that is not the caller's.
const FOREIGN_POLICY_ARN: &str = "arn:aws:iam::380987654321:policy/Foreign-Policy";

/// Seed data for the `TagPolicy` authorization tests. The callers carry grants scoped by the tags
/// the request asks to apply, by the tag keys it may name at all, and by the tags the policy
/// already carries.
const TAG_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'tag-policy-test@example.com', 'tag-policy-test'),
    ('380987654321', 'tag-policy-foreign@example.com', 'tag-policy-foreign');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCTGPPOLMAIN001', '%ACCOUNT_ID%', 'main-policy', 'Main-Policy', '/', 1, false, 1),
    ('SVCTGPPOLSNDBX01', '%ACCOUNT_ID%', 'sandbox-policy', 'Sandbox-Policy', '/', 1, false, 1),
    ('SVCTGPPOLPROD001', '%ACCOUNT_ID%', 'prod-policy', 'Prod-Policy', '/', 1, false, 1),
    ('SVCTGPPOLROOT001', '%ACCOUNT_ID%', 'root-policy', 'Root-Policy', '/', 1, false, 1),
    ('SVCTGPPOLAWSMG01', '000000000000', 'tag-policy-aws-managed', 'Tag-Policy-Aws-Managed', '/', 1, false, 1),
    ('SVCTGPPOLFOREGN1', '380987654321', 'foreign-policy', 'Foreign-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCTGPPOLMAIN001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCTGPPOLSNDBX01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCTGPPOLPROD001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCTGPPOLROOT001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCTGPPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}'),
    ('SVCTGPPOLFOREGN1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}');

    INSERT INTO iam.managed_policy_tags(managed_policy_id, key_lower, key_cased, value) VALUES
    ('SVCTGPPOLMAIN001', 'costcenter', 'CostCenter', '1234'),
    ('SVCTGPPOLSNDBX01', 'environment', 'Environment', 'Sandbox'),
    ('SVCTGPPOLPROD001', 'environment', 'Environment', 'Production');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCTGPBROAD00001', '%ACCOUNT_ID%', 'broad-tagger', 'Broad-Tagger', '/'),
    ('SVCTGPVALUE00001', '%ACCOUNT_ID%', 'value-tagger', 'Value-Tagger', '/'),
    ('SVCTGPKEYS000001', '%ACCOUNT_ID%', 'keys-tagger', 'Keys-Tagger', '/'),
    ('SVCTGPRESOURCE01', '%ACCOUNT_ID%', 'sandbox-tagger', 'Sandbox-Tagger', '/'),
    ('SVCTGPNONE000001', '%ACCOUNT_ID%', 'no-grant-tagger', 'No-Grant-Tagger', '/');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCTGPBROAD00001', 'allow-tag-any-policy', 'Allow-Tag-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Action":["iam:TagPolicy","iam:ListPolicyTags"],"Resource":"*"}]}'),
    ('SVCTGPVALUE00001', 'allow-tag-engineering', 'Allow-Tag-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagPolicy","Resource":"*",
        "Condition":{"StringEquals":{"aws:RequestTag/department":"Engineering"}}}]}'),
    ('SVCTGPKEYS000001', 'allow-tag-known-keys', 'Allow-Tag-Known-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagPolicy","Resource":"*",
        "Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["Department","Project"]}}}]}'),
    ('SVCTGPRESOURCE01', 'allow-tag-sandbox-policies', 'Allow-Tag-Sandbox-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagPolicy","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/environment":"Sandbox"}}}]}');
"#;

/// End-to-end authorization checks for `TagPolicy` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_tag_policy_authorization() {
    let database = TestDatabase::new(TAG_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let main_policy = database.arn("policy/Main-Policy");
    let prod_policy = database.arn("policy/Prod-Policy");
    let sandbox_policy = database.arn("policy/Sandbox-Policy");

    // A caller allowed iam:TagPolicy on any policy adds a tag to one.
    let (principal, session_data) = database.user_identity("SVCTGPBROAD00001", "Broad-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_policy_parameters(Some(&main_policy), &[("Project", "Scratchstack")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The tag is there, so the write was committed rather than rolled back, and it did not
    // disturb the tag the policy already carried.
    let (principal, session_data) = database.user_identity("SVCTGPBROAD00001", "Broad-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(Some(&main_policy), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Project</Key><Value>Scratchstack</Value>"), "unexpected body: {body}");
    assert!(body.contains("<Key>CostCenter</Key><Value>1234</Value>"), "unexpected body: {body}");

    // A tag whose key is already on the policy replaces that tag's value rather than being added
    // alongside it. The key here differs in case, which IAM treats as the same key.
    let (principal, session_data) = database.user_identity("SVCTGPBROAD00001", "Broad-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_policy_parameters(Some(&main_policy), &[("costcenter", "5678")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCTGPBROAD00001", "Broad-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(Some(&main_policy), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>costcenter</Key><Value>5678</Value>"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 2, "unexpected body: {body}");

    // The tags the request asks to apply back the aws:RequestTag condition keys, so a grant can
    // limit what a caller may write...
    let (principal, session_data) = database.user_identity("SVCTGPVALUE00001", "Value-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_policy_parameters(Some(&main_policy), &[("Department", "Engineering")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and a request asking for the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCTGPVALUE00001", "Value-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_policy_parameters(Some(&main_policy), &[("Department", "Sales")]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant conditioned on aws:TagKeys limits which tags the request may name at all, whatever
    // values it asks to give them.
    let (principal, session_data) = database.user_identity("SVCTGPKEYS000001", "Keys-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_policy_parameters(Some(&main_policy), &[("Department", "Engineering"), ("Project", "Scratchstack")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // One tag key outside the set the policy lists is enough to fail, even alongside keys that are
    // in it.
    let (principal, session_data) = database.user_identity("SVCTGPKEYS000001", "Keys-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_policy_parameters(Some(&main_policy), &[("Department", "Engineering"), ("Cost-Center", "1234")]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags the policy already carries are a different set, and back the iam:ResourceTag keys:
    // a grant conditioned on them says which policies a caller may tag at all.
    let (principal, session_data) = database.user_identity("SVCTGPRESOURCE01", "Sandbox-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_policy_parameters(Some(&sandbox_policy), &[("Owner", "Platform")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A policy whose tag holds another value is out of that grant's reach.
    let (principal, session_data) = database.user_identity("SVCTGPRESOURCE01", "Sandbox-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_policy_parameters(Some(&prod_policy), &[("Owner", "Platform")]))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCTGPNONE000001", "No-Grant-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_policy_parameters(Some(&main_policy), &[("Owner", "Nobody")]))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Tagger is not authorized to perform: \
                 iam:TagPolicy on resource: {main_policy}"
        )),
        "unexpected body: {body}"
    );

    // An AWS-managed policy is shared by every account and tagged by none, so it is reported as no
    // policy at all.
    let (principal, session_data) = database.user_identity("SVCTGPBROAD00001", "Broad-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_policy_parameters(Some(AWS_MANAGED_POLICY_ARN), &[("Owner", "Nobody")]),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Message>Policy {AWS_MANAGED_POLICY_ARN} was not found.</Message>")),
        "unexpected body: {body}"
    );

    // And it carries no such tag afterwards: the refusal is not a write that quietly failed.
    let (principal, session_data) = database.user_identity("SVCTGPBROAD00001", "Broad-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policy_tags_parameters(Some(AWS_MANAGED_POLICY_ARN), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<Key>Owner</Key>"), "unexpected body: {body}");

    // A policy in another account is not the caller's to tag either.
    let (principal, session_data) = database.user_identity("SVCTGPBROAD00001", "Broad-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_policy_parameters(Some(FOREIGN_POLICY_ARN), &[("Owner", "Nobody")]),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A request naming no tags asks for nothing to be written, and is reported as the caller's
    // error -- after authorization, since the caller here is allowed to tag policies.
    let (principal, session_data) = database.user_identity("SVCTGPBROAD00001", "Broad-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_policy_parameters(Some(&main_policy), &[])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A policy that does not exist is reported as missing.
    let (principal, session_data) = database.user_identity("SVCTGPBROAD00001", "Broad-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_policy_parameters(Some(&database.arn("policy/Missing-Policy")), &[("Owner", "Nobody")]),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");

    // An ARN that is not a policy ARN is rejected before the request is authorized.
    let (principal, session_data) = database.user_identity("SVCTGPNONE000001", "No-Grant-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_policy_parameters(Some("not-an-arn-but-long-enough"), &[("Owner", "Nobody")]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A request leaving off the ARN never becomes a request at all.
    let (principal, session_data) = database.user_identity("SVCTGPBROAD00001", "Broad-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_policy_parameters(None, &[("Owner", "Nobody")])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // The account root user is implicitly allowed, and carries no policies of its own.
    let root_policy = database.arn("policy/Root-Policy");
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_policy_parameters(Some(&root_policy), &[("Owner", "Root")]))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCTGPBROAD00001", "Broad-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(Some(&root_policy), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Owner</Key><Value>Root</Value>"), "unexpected body: {body}");
}
