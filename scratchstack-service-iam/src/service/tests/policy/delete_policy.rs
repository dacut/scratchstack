use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The ARN of the AWS-managed policy this test seeds, which no account owns and none may delete.
const AWS_MANAGED_POLICY_ARN: &str = "arn:aws:iam::000000000000:policy/Delete-Policy-Aws-Managed";

/// Seed data for the `DeletePolicy` authorization tests. The callers carry grants scoped by the
/// path of the policy being deleted and by that policy's tags. The policies give the delete
/// something to refuse: one is attached to a user, one is a user's permissions boundary, and one
/// has a version besides its default.
const DELETE_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'delete-policy-test@example.com', 'delete-policy-test');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCDELPOLPLAIN01', '%ACCOUNT_ID%', 'deletable-policy', 'Deletable-Policy', '/', 1, false, 1),
    ('SVCDELPOLATTACH1', '%ACCOUNT_ID%', 'attached-policy', 'Attached-Policy', '/', 1, false, 1),
    ('SVCDELPOLBOUND01', '%ACCOUNT_ID%', 'boundary-policy', 'Boundary-Policy', '/', 1, false, 1),
    ('SVCDELPOLVERSN01', '%ACCOUNT_ID%', 'versioned-policy', 'Versioned-Policy', '/', 1, false, 2),
    ('SVCDELPOLSAFE001', '%ACCOUNT_ID%', 'safe-policy', 'Safe-Policy', '/safe/', 1, false, 1),
    ('SVCDELPOLSPARE01', '%ACCOUNT_ID%', 'spare-policy', 'Spare-Policy', '/', 1, false, 1),
    ('SVCDELPOLSNDBX01', '%ACCOUNT_ID%', 'sandbox-policy', 'Sandbox-Policy', '/', 1, false, 1),
    ('SVCDELPOLPROD001', '%ACCOUNT_ID%', 'prod-policy', 'Prod-Policy', '/', 1, false, 1),
    ('SVCDELPOLROOT001', '%ACCOUNT_ID%', 'root-deletable-policy', 'Root-Deletable-Policy', '/', 1, false, 1),
    ('SVCDELPOLAWSMG01', '000000000000', 'delete-policy-aws-managed', 'Delete-Policy-Aws-Managed', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCDELPOLPLAIN01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDELPOLATTACH1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDELPOLBOUND01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDELPOLVERSN01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDELPOLVERSN01', 2,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}'),
    ('SVCDELPOLSAFE001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDELPOLSPARE01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDELPOLSNDBX01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDELPOLPROD001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDELPOLROOT001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDELPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}');

    INSERT INTO iam.managed_policy_tags(managed_policy_id, key_lower, key_cased, value) VALUES
    ('SVCDELPOLPLAIN01', 'department', 'Department', 'Engineering'),
    ('SVCDELPOLSNDBX01', 'environment', 'Environment', 'Sandbox');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path,
        permissions_boundary_managed_policy_id) VALUES
    ('SVCDELPOLBROAD01', '%ACCOUNT_ID%', 'broad-deleter', 'Broad-Deleter', '/', NULL),
    ('SVCDELPOLNARROW1', '%ACCOUNT_ID%', 'narrow-deleter', 'Narrow-Deleter', '/', NULL),
    ('SVCDELPOLTAG0001', '%ACCOUNT_ID%', 'tag-deleter', 'Tag-Deleter', '/', NULL),
    ('SVCDELPOLNONE001', '%ACCOUNT_ID%', 'no-grant-deleter', 'No-Grant-Deleter', '/', NULL),
    ('SVCDELPOLHOLDER1', '%ACCOUNT_ID%', 'policy-holder', 'Policy-Holder', '/', NULL),
    ('SVCDELPOLBOUNDED', '%ACCOUNT_ID%', 'bounded-user', 'Bounded-User', '/', 'SVCDELPOLBOUND01');

    INSERT INTO iam.user_attached_policies(user_id, managed_policy_id) VALUES
    ('SVCDELPOLHOLDER1', 'SVCDELPOLATTACH1');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDELPOLBROAD01', 'allow-delete-any-policy', 'Allow-Delete-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:DeletePolicy","iam:GetPolicy"],
        "Resource":"*"}]}'),
    ('SVCDELPOLNARROW1', 'allow-delete-safe-policies', 'Allow-Delete-Safe-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeletePolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:policy/safe/*"}]}'),
    ('SVCDELPOLTAG0001', 'allow-delete-sandbox-policies', 'Allow-Delete-Sandbox-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeletePolicy","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/environment":"Sandbox"}}}]}');
"#;

/// End-to-end authorization checks for `DeletePolicy` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_delete_policy_authorization() {
    let database = TestDatabase::new(DELETE_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let deletable_policy = database.arn("policy/Deletable-Policy");
    let spare_policy = database.arn("policy/Spare-Policy");

    // A caller allowed iam:DeletePolicy on any policy deletes one, tags and all.
    let (principal, session_data) = database.user_identity("SVCDELPOLBROAD01", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_policy_parameters(Some(&deletable_policy))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The policy is gone, so the delete was committed rather than rolled back.
    let (principal, session_data) = database.user_identity("SVCDELPOLBROAD01", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_parameters(Some(&deletable_policy))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");

    // Deleting it a second time reports that there is nothing to delete.
    let (principal, session_data) = database.user_identity("SVCDELPOLBROAD01", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_policy_parameters(Some(&deletable_policy))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A policy that something still depends on cannot be deleted, whichever kind of dependant it
    // is: an entity carrying it, an entity bounded by it, or a version of the policy itself.
    for (resource, policy_name) in [
        ("policy/Attached-Policy", "Attached-Policy"),
        ("policy/Boundary-Policy", "Boundary-Policy"),
        ("policy/Versioned-Policy", "Versioned-Policy"),
    ] {
        let policy_arn = database.arn(resource);
        let (principal, session_data) = database.user_identity("SVCDELPOLBROAD01", "Broad-Deleter");
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_policy_parameters(Some(&policy_arn))).await;
        assert_eq!(status, StatusCode::CONFLICT, "unexpected response for {policy_name}: {body}");
        assert!(body.contains("<Code>DeleteConflict</Code>"), "unexpected body for {policy_name}: {body}");

        // The refusal rolled its transaction back, so the policy is still there.
        let (principal, session_data) = database.user_identity("SVCDELPOLBROAD01", "Broad-Deleter");
        let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&policy_arn))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response for {policy_name}: {body}");
    }

    // A grant scoped to a path prefix reaches the policies under that path...
    let (principal, session_data) = database.user_identity("SVCDELPOLNARROW1", "Narrow-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_policy_parameters(Some(&database.arn("policy/safe/Safe-Policy"))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no others.
    let (principal, session_data) = database.user_identity("SVCDELPOLNARROW1", "Narrow-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_policy_parameters(Some(&spare_policy))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Narrow-Deleter is not authorized to perform: \
                 iam:DeletePolicy on resource: {spare_policy}"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled its transaction back, so the policy is still there.
    let (principal, session_data) = database.user_identity("SVCDELPOLBROAD01", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&spare_policy))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The policy is read before the request is authorized, so a grant conditioned on the tags the
    // policy carries can be evaluated at all.
    let (principal, session_data) = database.user_identity("SVCDELPOLTAG0001", "Tag-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_policy_parameters(Some(&database.arn("policy/Sandbox-Policy"))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A policy without that tag leaves the condition key absent, so the grant does not apply.
    let (principal, session_data) = database.user_identity("SVCDELPOLTAG0001", "Tag-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_policy_parameters(Some(&database.arn("policy/Prod-Policy"))))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCDELPOLNONE001", "No-Grant-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_policy_parameters(Some(&spare_policy))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // An AWS-managed policy is readable by every account and owned by none, so no account may
    // delete one: it is reported as no policy at all, even to a caller allowed the action on
    // every resource.
    let (principal, session_data) = database.user_identity("SVCDELPOLBROAD01", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_policy_parameters(Some(AWS_MANAGED_POLICY_ARN))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Message>Policy {AWS_MANAGED_POLICY_ARN} was not found.</Message>")),
        "unexpected body: {body}"
    );

    // And it is still there afterwards: the refusal is not a delete that quietly failed.
    let (principal, session_data) = database.user_identity("SVCDELPOLBROAD01", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_parameters(Some(AWS_MANAGED_POLICY_ARN))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // An ARN that is not a policy ARN is rejected before the request is authorized, so a caller
    // with no grant sees the same rejection as one with a grant.
    let (principal, session_data) = database.user_identity("SVCDELPOLNONE001", "No-Grant-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_policy_parameters(Some("not-an-arn-but-long-enough"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    assert!(body.contains("Invalid policy ARN"), "unexpected body: {body}");

    // A request leaving off the ARN never becomes a request at all.
    let (principal, session_data) = database.user_identity("SVCDELPOLBROAD01", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_policy_parameters(None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // The account root user is implicitly allowed, and carries no policies of its own.
    let root_policy = database.arn("policy/Root-Deletable-Policy");
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &delete_policy_parameters(Some(&root_policy))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCDELPOLBROAD01", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&root_policy))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
}
