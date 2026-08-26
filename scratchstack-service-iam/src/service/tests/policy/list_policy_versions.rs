use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The ARN of the AWS-managed policy this test seeds, whose versions every account may list.
const AWS_MANAGED_POLICY_ARN: &str = "arn:aws:iam::000000000000:policy/List-Versions-Aws-Managed";

/// A policy in an account that is not the caller's, seeded so that a caller trying to list across
/// accounts has something real to fail to reach.
const FOREIGN_POLICY_ARN: &str = "arn:aws:iam::340987654321:policy/Foreign-Policy";

/// Seed data for the `ListPolicyVersions` authorization tests. `Main-Policy` carries four versions
/// with the second as its default, so the listing has an order to report and a default to mark,
/// and the callers carry grants scoped by the policy and by its tags.
const LIST_POLICY_VERSIONS_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'list-policy-versions-test@example.com', 'list-policy-versions-test'),
    ('340987654321', 'list-policy-versions-foreign@example.com', 'list-policy-versions-foreign');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCLPVPOLMAIN001', '%ACCOUNT_ID%', 'main-policy', 'Main-Policy', '/', 2, false, 4),
    ('SVCLPVPOLOTHER01', '%ACCOUNT_ID%', 'other-policy', 'Other-Policy', '/', 1, false, 1),
    ('SVCLPVPOLTAGGED1', '%ACCOUNT_ID%', 'tagged-policy', 'Tagged-Policy', '/', 1, false, 1),
    ('SVCLPVPOLAWSMG01', '000000000000', 'list-versions-aws-managed', 'List-Versions-Aws-Managed', '/', 1, false, 1),
    ('SVCLPVPOLFOREGN1', '340987654321', 'foreign-policy', 'Foreign-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCLPVPOLMAIN001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLPVPOLMAIN001', 2,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}'),
    ('SVCLPVPOLMAIN001', 3,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:DeleteObject","Resource":"*"}]}'),
    ('SVCLPVPOLMAIN001', 4,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}'),
    ('SVCLPVPOLOTHER01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLPVPOLTAGGED1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLPVPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}'),
    ('SVCLPVPOLFOREGN1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}');

    INSERT INTO iam.managed_policy_tags(managed_policy_id, key_lower, key_cased, value) VALUES
    ('SVCLPVPOLTAGGED1', 'environment', 'Environment', 'Sandbox');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCLPVBROAD00001', '%ACCOUNT_ID%', 'broad-lister', 'Broad-Lister', '/'),
    ('SVCLPVNARROW0001', '%ACCOUNT_ID%', 'narrow-lister', 'Narrow-Lister', '/'),
    ('SVCLPVTAG0000001', '%ACCOUNT_ID%', 'tag-lister', 'Tag-Lister', '/'),
    ('SVCLPVNONE000001', '%ACCOUNT_ID%', 'no-grant-lister', 'No-Grant-Lister', '/');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLPVBROAD00001', 'allow-list-any-versions', 'Allow-List-Any-Versions',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListPolicyVersions","Resource":"*"}]}'),
    ('SVCLPVNARROW0001', 'allow-list-main-policy-versions', 'Allow-List-Main-Policy-Versions',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListPolicyVersions",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:policy/Main-Policy"}]}'),
    ('SVCLPVTAG0000001', 'allow-list-sandbox-versions', 'Allow-List-Sandbox-Versions',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListPolicyVersions","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/environment":"Sandbox"}}}]}');
"#;

/// End-to-end authorization checks for `ListPolicyVersions` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account.
#[test_log::test(tokio::test)]
async fn test_list_policy_versions_authorization() {
    let database = TestDatabase::new(LIST_POLICY_VERSIONS_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let main_policy = database.arn("policy/Main-Policy");
    let other_policy = database.arn("policy/Other-Policy");

    // A caller allowed iam:ListPolicyVersions on any policy lists the versions of one, newest
    // first, with the version the policy grants by marked as its default.
    let (principal, session_data) = database.user_identity("SVCLPVBROAD00001", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_versions_parameters(Some(&main_policy), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(body.matches("<member>").count(), 4, "unexpected body: {body}");
    assert!(body.contains("<IsTruncated>false</IsTruncated>"), "unexpected body: {body}");
    assert!(
        body.contains("<VersionId>v4</VersionId>") && body.contains("<VersionId>v1</VersionId>"),
        "unexpected body: {body}"
    );

    // The newest version is reported first.
    let first = body.find("<VersionId>v4</VersionId>").expect("no v4 in body");
    let last = body.find("<VersionId>v1</VersionId>").expect("no v1 in body");
    assert!(first < last, "unexpected body: {body}");

    // Exactly one version is the default, and it is the one the policy grants by.
    assert_eq!(body.matches("<IsDefaultVersion>true</IsDefaultVersion>").count(), 1, "unexpected body: {body}");
    let default_member = body
        .split("<member>")
        .find(|member| member.contains("<IsDefaultVersion>true</IsDefaultVersion>"))
        .expect("no default version in body");
    assert!(default_member.contains("<VersionId>v2</VersionId>"), "unexpected body: {body}");

    // IAM reports a policy document only from GetPolicyVersion, so a listing names the versions
    // without carrying what is in them.
    assert!(!body.contains("<Document>"), "unexpected body: {body}");

    // A listing longer than MaxItems reports itself as truncated and hands back a marker...
    let (principal, session_data) = database.user_identity("SVCLPVBROAD00001", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_versions_parameters(Some(&main_policy), Some(2), None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<IsTruncated>true</IsTruncated>"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 2, "unexpected body: {body}");
    assert!(body.contains("<VersionId>v4</VersionId>"), "unexpected body: {body}");
    assert!(body.contains("<VersionId>v3</VersionId>"), "unexpected body: {body}");
    let marker = pagination_marker(&body);

    // ...which picks the listing up where it left off.
    let (principal, session_data) = database.user_identity("SVCLPVBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policy_versions_parameters(Some(&main_policy), Some(2), Some(&marker)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<VersionId>v2</VersionId>"), "unexpected body: {body}");
    assert!(body.contains("<VersionId>v1</VersionId>"), "unexpected body: {body}");
    assert!(!body.contains("<VersionId>v4</VersionId>"), "unexpected body: {body}");

    // A grant naming one policy reaches that policy's versions...
    let (principal, session_data) = database.user_identity("SVCLPVNARROW0001", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_versions_parameters(Some(&main_policy), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no other's.
    let (principal, session_data) = database.user_identity("SVCLPVNARROW0001", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_versions_parameters(Some(&other_policy), None, None))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Narrow-Lister is not authorized to perform: \
                 iam:ListPolicyVersions on resource: {other_policy}"
        )),
        "unexpected body: {body}"
    );

    // The policy is read before the request is authorized, so a grant conditioned on the tags the
    // policy carries can be evaluated at all.
    let (principal, session_data) = database.user_identity("SVCLPVTAG0000001", "Tag-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policy_versions_parameters(Some(&database.arn("policy/Tagged-Policy")), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A policy without that tag leaves the condition key absent, so the grant does not apply.
    let (principal, session_data) = database.user_identity("SVCLPVTAG0000001", "Tag-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_versions_parameters(Some(&other_policy), None, None))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCLPVNONE000001", "No-Grant-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_versions_parameters(Some(&main_policy), None, None))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller allowed the action broadly is told that a policy does not exist...
    let missing_policy = database.arn("policy/Missing-Policy");
    let (principal, session_data) = database.user_identity("SVCLPVBROAD00001", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_versions_parameters(Some(&missing_policy), None, None))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while one allowed it only on particular policies learns nothing at all.
    let (principal, session_data) = database.user_identity("SVCLPVNARROW0001", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_versions_parameters(Some(&missing_policy), None, None))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // AWS-managed policies belong to no customer account, and every account may list their
    // versions.
    let (principal, session_data) = database.user_identity("SVCLPVBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policy_versions_parameters(Some(AWS_MANAGED_POLICY_ARN), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(body.matches("<member>").count(), 1, "unexpected body: {body}");

    // A managed policy is not shared across customer accounts, so a policy in another account is
    // reported as no policy at all, and nothing of its versions is revealed.
    let (principal, session_data) = database.user_identity("SVCLPVBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policy_versions_parameters(Some(FOREIGN_POLICY_ARN), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Message>Policy {FOREIGN_POLICY_ARN} was not found.</Message>")),
        "unexpected body: {body}"
    );
    assert!(!body.contains("<VersionId>"), "unexpected body: {body}");

    // A marker this service never issued cannot be decrypted, and that is the caller's to fix, so
    // it is reported as invalid input rather than as an internal failure.
    let (principal, session_data) = database.user_identity("SVCLPVBROAD00001", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_policy_versions_parameters(Some(&main_policy), None, Some(FOREIGN_PAGINATION_TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>InvalidInput</Code>"), "unexpected body: {body}");

    // A MaxItems outside the range the listing accepts is a validation failure, and is settled
    // before the request is authorized.
    for max_items in [0, 1001] {
        let (principal, session_data) = database.user_identity("SVCLPVNONE000001", "No-Grant-Lister");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &list_policy_versions_parameters(Some(&main_policy), Some(max_items), None),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response for {max_items}: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body for {max_items}: {body}");
    }

    // A request leaving off the ARN never becomes a request at all.
    let (principal, session_data) = database.user_identity("SVCLPVBROAD00001", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_versions_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // The account root user is implicitly allowed, and carries no policies of its own.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_versions_parameters(Some(&other_policy), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<VersionId>v1</VersionId>"), "unexpected body: {body}");
}
