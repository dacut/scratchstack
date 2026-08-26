use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The ARN of the AWS-managed policy this test seeds, whose versions no account may delete.
const AWS_MANAGED_POLICY_ARN: &str = "arn:aws:iam::000000000000:policy/Delete-Version-Aws-Managed";

/// Seed data for the `DeletePolicyVersion` authorization tests. `Main-Policy` carries three
/// versions with the first as its default, so a deletable version and an undeletable one are both
/// at hand, and the callers carry grants scoped by the policy and by its tags.
const DELETE_POLICY_VERSION_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'delete-policy-version-test@example.com', 'delete-policy-version-test');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCDPVPOLMAIN001', '%ACCOUNT_ID%', 'main-policy', 'Main-Policy', '/', 1, false, 3),
    ('SVCDPVPOLOTHER01', '%ACCOUNT_ID%', 'other-policy', 'Other-Policy', '/', 1, false, 2),
    ('SVCDPVPOLTAGGED1', '%ACCOUNT_ID%', 'tagged-policy', 'Tagged-Policy', '/', 1, false, 2),
    ('SVCDPVPOLROOT001', '%ACCOUNT_ID%', 'root-policy', 'Root-Policy', '/', 1, false, 2),
    ('SVCDPVPOLAWSMG01', '000000000000', 'delete-version-aws-managed', 'Delete-Version-Aws-Managed', '/', 1, false, 2);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCDPVPOLMAIN001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDPVPOLMAIN001', 2,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}'),
    ('SVCDPVPOLMAIN001', 3,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:DeleteObject","Resource":"*"}]}'),
    ('SVCDPVPOLOTHER01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDPVPOLOTHER01', 2,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}'),
    ('SVCDPVPOLTAGGED1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDPVPOLTAGGED1', 2,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}'),
    ('SVCDPVPOLROOT001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDPVPOLROOT001', 2,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}'),
    ('SVCDPVPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}'),
    ('SVCDPVPOLAWSMG01', 2,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:GetMetricData","Resource":"*"}]}');

    INSERT INTO iam.managed_policy_tags(managed_policy_id, key_lower, key_cased, value) VALUES
    ('SVCDPVPOLTAGGED1', 'environment', 'Environment', 'Sandbox');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCDPVBROAD00001', '%ACCOUNT_ID%', 'broad-deleter', 'Broad-Deleter', '/'),
    ('SVCDPVNARROW0001', '%ACCOUNT_ID%', 'narrow-deleter', 'Narrow-Deleter', '/'),
    ('SVCDPVTAG0000001', '%ACCOUNT_ID%', 'tag-deleter', 'Tag-Deleter', '/'),
    ('SVCDPVNONE000001', '%ACCOUNT_ID%', 'no-grant-deleter', 'No-Grant-Deleter', '/');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDPVBROAD00001', 'allow-delete-any-version', 'Allow-Delete-Any-Version',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Action":["iam:DeletePolicyVersion","iam:GetPolicyVersion","iam:ListPolicyVersions"],"Resource":"*"}]}'),
    ('SVCDPVNARROW0001', 'allow-delete-main-policy-version', 'Allow-Delete-Main-Policy-Version',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeletePolicyVersion",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:policy/Main-Policy"}]}'),
    ('SVCDPVTAG0000001', 'allow-delete-sandbox-versions', 'Allow-Delete-Sandbox-Versions',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeletePolicyVersion","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/environment":"Sandbox"}}}]}');
"#;

/// End-to-end authorization checks for `DeletePolicyVersion` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_delete_policy_version_authorization() {
    let database = TestDatabase::new(DELETE_POLICY_VERSION_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let main_policy = database.arn("policy/Main-Policy");
    let other_policy = database.arn("policy/Other-Policy");

    // A caller allowed iam:DeletePolicyVersion on any policy deletes one of its versions.
    let (principal, session_data) = database.user_identity("SVCDPVBROAD00001", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_policy_version_parameters(Some(&main_policy), Some("v3")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The version is gone, so the delete was committed rather than rolled back...
    let (principal, session_data) = database.user_identity("SVCDPVBROAD00001", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&main_policy), Some("v3"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");

    // ...and the policy keeps the versions it still has.
    let (principal, session_data) = database.user_identity("SVCDPVBROAD00001", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_policy_versions_parameters(Some(&main_policy), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<VersionId>v1</VersionId>"), "unexpected body: {body}");
    assert!(body.contains("<VersionId>v2</VersionId>"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 2, "unexpected body: {body}");

    // Deleting it a second time reports that there is nothing to delete.
    let (principal, session_data) = database.user_identity("SVCDPVBROAD00001", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_policy_version_parameters(Some(&main_policy), Some("v3")))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // The version a policy grants by cannot be deleted: another version has to be made the default
    // first, which is what would leave the policy granting by something.
    let (principal, session_data) = database.user_identity("SVCDPVBROAD00001", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_policy_version_parameters(Some(&main_policy), Some("v1")))
            .await;
    assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
    assert!(body.contains("<Code>DeleteConflict</Code>"), "unexpected body: {body}");

    // The refusal rolled its transaction back, so the version is still there.
    let (principal, session_data) = database.user_identity("SVCDPVBROAD00001", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&main_policy), Some("v1"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A grant naming one policy reaches every version of that policy...
    let (principal, session_data) = database.user_identity("SVCDPVNARROW0001", "Narrow-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_policy_version_parameters(Some(&main_policy), Some("v2")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no version of any other.
    let (principal, session_data) = database.user_identity("SVCDPVNARROW0001", "Narrow-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_policy_version_parameters(Some(&other_policy), Some("v2")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Narrow-Deleter is not authorized to perform: \
                 iam:DeletePolicyVersion on resource: {other_policy}"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled its transaction back, so the version is still there.
    let (principal, session_data) = database.user_identity("SVCDPVBROAD00001", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&other_policy), Some("v2")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The policy is read before the request is authorized, so a grant conditioned on the tags the
    // policy carries can be evaluated at all.
    let (principal, session_data) = database.user_identity("SVCDPVTAG0000001", "Tag-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_policy_version_parameters(Some(&database.arn("policy/Tagged-Policy")), Some("v2")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A policy without that tag leaves the condition key absent, so the grant does not apply.
    let (principal, session_data) = database.user_identity("SVCDPVTAG0000001", "Tag-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_policy_version_parameters(Some(&other_policy), Some("v2")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCDPVNONE000001", "No-Grant-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_policy_version_parameters(Some(&other_policy), Some("v2")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // An AWS-managed policy is shared by every account and versioned by none, so its versions are
    // reported as belonging to no policy at all.
    let (principal, session_data) = database.user_identity("SVCDPVBROAD00001", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_policy_version_parameters(Some(AWS_MANAGED_POLICY_ARN), Some("v2")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Message>Policy {AWS_MANAGED_POLICY_ARN} was not found.</Message>")),
        "unexpected body: {body}"
    );

    // And the version is still there afterwards: the refusal is not a delete that quietly failed.
    let (principal, session_data) = database.user_identity("SVCDPVBROAD00001", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_policy_version_parameters(Some(AWS_MANAGED_POLICY_ARN), Some("v2")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A version of a policy in another account is not the caller's to delete either.
    const FOREIGN_POLICY_ARN: &str = "arn:aws:iam::330987654321:policy/Foreign-Policy";
    let (principal, session_data) = database.user_identity("SVCDPVBROAD00001", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_policy_version_parameters(Some(FOREIGN_POLICY_ARN), Some("v1")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // Something that is not a version id at all is rejected before the request is authorized, so a
    // caller with no grant sees the same rejection as one with a grant.
    let (principal, session_data) = database.user_identity("SVCDPVNONE000001", "No-Grant-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_policy_version_parameters(Some(&main_policy), Some("v0")))
            .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A request leaving off a parameter the operation requires never becomes a request at all.
    for parameters in
        [delete_policy_version_parameters(None, Some("v2")), delete_policy_version_parameters(Some(&main_policy), None)]
    {
        let (principal, session_data) = database.user_identity("SVCDPVBROAD00001", "Broad-Deleter");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // The account root user is implicitly allowed, and carries no policies of its own.
    let root_policy = database.arn("policy/Root-Policy");
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_policy_version_parameters(Some(&root_policy), Some("v2")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCDPVBROAD00001", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_version_parameters(Some(&root_policy), Some("v2"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
}
