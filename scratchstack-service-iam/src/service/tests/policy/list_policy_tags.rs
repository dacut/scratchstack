use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The ARN of the AWS-managed policy this test seeds, whose tags every account may read.
const AWS_MANAGED_POLICY_ARN: &str = "arn:aws:iam::000000000000:policy/List-Tags-Aws-Managed";

/// A policy in an account that is not the caller's.
const FOREIGN_POLICY_ARN: &str = "arn:aws:iam::360987654321:policy/Foreign-Policy";

/// Seed data for the `ListPolicyTags` authorization tests. `Main-Policy` carries three tags so the
/// listing has something to page through and an order to report them in.
const LIST_POLICY_TAGS_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'list-policy-tags-test@example.com', 'list-policy-tags-test'),
    ('360987654321', 'list-policy-tags-foreign@example.com', 'list-policy-tags-foreign');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCLPTPOLMAIN001', '%ACCOUNT_ID%', 'main-policy', 'Main-Policy', '/', 1, false, 1),
    ('SVCLPTPOLOTHER01', '%ACCOUNT_ID%', 'other-policy', 'Other-Policy', '/', 1, false, 1),
    ('SVCLPTPOLBARE001', '%ACCOUNT_ID%', 'bare-policy', 'Bare-Policy', '/', 1, false, 1),
    ('SVCLPTPOLAWSMG01', '000000000000', 'list-tags-aws-managed', 'List-Tags-Aws-Managed', '/', 1, false, 1),
    ('SVCLPTPOLFOREGN1', '360987654321', 'foreign-policy', 'Foreign-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCLPTPOLMAIN001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLPTPOLOTHER01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLPTPOLBARE001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLPTPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}'),
    ('SVCLPTPOLFOREGN1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}');

    INSERT INTO iam.managed_policy_tags(managed_policy_id, key_lower, key_cased, value) VALUES
    ('SVCLPTPOLMAIN001', 'costcenter', 'CostCenter', '1234'),
    ('SVCLPTPOLMAIN001', 'environment', 'Environment', 'Sandbox'),
    ('SVCLPTPOLMAIN001', 'project', 'Project', 'Scratchstack'),
    ('SVCLPTPOLOTHER01', 'environment', 'Environment', 'Production'),
    ('SVCLPTPOLAWSMG01', 'origin', 'Origin', 'Aws');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCLPTBROAD00001', '%ACCOUNT_ID%', 'broad-lister', 'Broad-Lister', '/'),
    ('SVCLPTNARROW0001', '%ACCOUNT_ID%', 'narrow-lister', 'Narrow-Lister', '/'),
    ('SVCLPTTAG0000001', '%ACCOUNT_ID%', 'tag-lister', 'Tag-Lister', '/'),
    ('SVCLPTNONE000001', '%ACCOUNT_ID%', 'no-grant-lister', 'No-Grant-Lister', '/');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLPTBROAD00001', 'allow-list-policy-tags-any', 'Allow-List-Policy-Tags-Any',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListPolicyTags","Resource":"*"}]}'),
    ('SVCLPTNARROW0001', 'allow-list-policy-tags-main', 'Allow-List-Policy-Tags-Main',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListPolicyTags",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:policy/Main-Policy"}]}'),
    ('SVCLPTTAG0000001', 'allow-list-sandbox-policy-tags', 'Allow-List-Sandbox-Policy-Tags',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListPolicyTags","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/environment":"Sandbox"}}}]}');
"#;

/// End-to-end authorization checks for `ListPolicyTags` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account.
#[test_log::test(tokio::test)]
async fn test_list_policy_tags_authorization() {
    let database = TestDatabase::new(LIST_POLICY_TAGS_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let main_policy = database.arn("policy/Main-Policy");
    let other_policy = database.arn("policy/Other-Policy");

    // A caller allowed iam:ListPolicyTags on any policy is told the tags a policy carries, under
    // the spelling they were written with.
    let (principal, session_data) = database.user_identity("SVCLPTBROAD00001", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(Some(&main_policy), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>CostCenter</Key><Value>1234</Value>"), "unexpected body: {body}");
    assert!(body.contains("<Key>Environment</Key><Value>Sandbox</Value>"), "unexpected body: {body}");
    assert!(body.contains("<Key>Project</Key><Value>Scratchstack</Value>"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 3, "unexpected body: {body}");

    // A tag listing reports `IsTruncated` only when it is truncated, as `ListUserTags` does.
    assert!(!body.contains("<IsTruncated>"), "unexpected body: {body}");

    // A policy carrying no tags reports none rather than failing.
    let (principal, session_data) = database.user_identity("SVCLPTBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policy_tags_parameters(Some(&database.arn("policy/Bare-Policy")), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(body.matches("<member>").count(), 0, "unexpected body: {body}");

    // A listing longer than MaxItems reports itself as truncated and hands back a marker...
    let (principal, session_data) = database.user_identity("SVCLPTBROAD00001", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(Some(&main_policy), Some(2), None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<IsTruncated>true</IsTruncated>"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 2, "unexpected body: {body}");
    assert!(body.contains("<Key>CostCenter</Key>"), "unexpected body: {body}");
    assert!(body.contains("<Key>Environment</Key>"), "unexpected body: {body}");
    let marker = pagination_marker(&body);

    // ...which picks the listing up where it left off.
    let (principal, session_data) = database.user_identity("SVCLPTBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policy_tags_parameters(Some(&main_policy), Some(2), Some(&marker)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Project</Key>"), "unexpected body: {body}");
    assert!(!body.contains("<Key>CostCenter</Key>"), "unexpected body: {body}");

    // A grant naming one policy reaches that policy...
    let (principal, session_data) = database.user_identity("SVCLPTNARROW0001", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(Some(&main_policy), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no other.
    let (principal, session_data) = database.user_identity("SVCLPTNARROW0001", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(Some(&other_policy), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Narrow-Lister is not authorized to perform: \
                 iam:ListPolicyTags on resource: {other_policy}"
        )),
        "unexpected body: {body}"
    );

    // The tags being listed are also the tags a condition on this very request is evaluated
    // against, so a grant conditioned on them governs reading them...
    let (principal, session_data) = database.user_identity("SVCLPTTAG0000001", "Tag-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(Some(&main_policy), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and a policy whose tag holds another value is out of that grant's reach.
    let (principal, session_data) = database.user_identity("SVCLPTTAG0000001", "Tag-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(Some(&other_policy), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCLPTNONE000001", "No-Grant-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(Some(&main_policy), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // AWS-managed policies belong to no customer account, and every account may read their tags.
    let (principal, session_data) = database.user_identity("SVCLPTBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policy_tags_parameters(Some(AWS_MANAGED_POLICY_ARN), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Origin</Key><Value>Aws</Value>"), "unexpected body: {body}");

    // A policy in another account is reported as no policy at all, so nothing of its tags is
    // revealed either.
    let (principal, session_data) = database.user_identity("SVCLPTBROAD00001", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(Some(FOREIGN_POLICY_ARN), None, None))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Message>Policy {FOREIGN_POLICY_ARN} was not found.</Message>")),
        "unexpected body: {body}"
    );

    // A policy that does not exist is reported as missing to a caller allowed the action broadly.
    let (principal, session_data) = database.user_identity("SVCLPTBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policy_tags_parameters(Some(&database.arn("policy/Missing-Policy")), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");

    // A marker this service never issued cannot be decrypted, and that is the caller's to fix.
    let (principal, session_data) = database.user_identity("SVCLPTBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policy_tags_parameters(Some(&main_policy), None, Some(FOREIGN_PAGINATION_TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>InvalidInput</Code>"), "unexpected body: {body}");

    // A MaxItems outside the range the listing accepts is a validation failure, settled before the
    // request is authorized.
    for max_items in [0, 1001] {
        let (principal, session_data) = database.user_identity("SVCLPTNONE000001", "No-Grant-Lister");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &list_policy_tags_parameters(Some(&main_policy), Some(max_items), None),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response for {max_items}: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body for {max_items}: {body}");
    }

    // A request leaving off the ARN never becomes a request at all.
    let (principal, session_data) = database.user_identity("SVCLPTBROAD00001", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // The account root user is implicitly allowed, and carries no policies of its own.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_tags_parameters(Some(&other_policy), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Environment</Key><Value>Production</Value>"), "unexpected body: {body}");
}
