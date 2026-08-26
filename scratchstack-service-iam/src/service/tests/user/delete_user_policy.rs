use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `DeleteUserPolicy` authorization tests. `Policy-Target` carries several
/// inline policies, so a grant reaching the user can be shown to reach all of them and a
/// denied delete can be shown to have left its policy behind; the other targets carry the
/// paths and tags the resource ARN and the `aws:ResourceTag` condition keys are derived from.
/// `Broad-Deleter` is also allowed `iam:GetUserPolicy`, so the tests can read back what a
/// delete did or did not remove.
const DELETE_USER_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.partition(partition) VALUES ('aws');

    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('123456789012', 'delete-user-policy-test@example.com', 'delete-user-policy-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCDUPBROADDEL01', '123456789012', 'broad-deleter', 'Broad-Deleter', '/'),
    ('SVCDUPPATHDEL001', '123456789012', 'path-deleter', 'Path-Deleter', '/'),
    ('SVCDUPTAGDEL0001', '123456789012', 'tag-deleter', 'Tag-Deleter', '/'),
    ('SVCDUPNARROWDEL1', '123456789012', 'narrow-deleter', 'Narrow-Deleter', '/'),
    ('SVCDUPNOGRANTDL1', '123456789012', 'no-grant-deleter', 'No-Grant-Deleter', '/'),
    ('SVCDUPTGTPOLICY1', '123456789012', 'policy-target', 'Policy-Target', '/'),
    ('SVCDUPTGTDIVSN01', '123456789012', 'division-target', 'Division-Target', '/division/'),
    ('SVCDUPTGTENGNR01', '123456789012', 'engineering-target', 'Engineering-Target', '/'),
    ('SVCDUPTGTSALES01', '123456789012', 'sales-target', 'Sales-Target', '/'),
    ('SVCDUPTGTROOT001', '123456789012', 'root-target', 'Root-Target', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCDUPTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCDUPTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDUPBROADDEL01', 'allow-delete-any-policy', 'Allow-Delete-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Action":["iam:DeleteUserPolicy","iam:GetUserPolicy"],"Resource":"*"}]}'),
    ('SVCDUPPATHDEL001', 'allow-delete-division-policy', 'Allow-Delete-Division-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUserPolicy",
        "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
    ('SVCDUPTAGDEL0001', 'allow-delete-engineering-policy', 'Allow-Delete-Engineering-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUserPolicy","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCDUPNARROWDEL1', 'allow-delete-target-policy', 'Allow-Delete-Target-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUserPolicy",
        "Resource":"arn:aws:iam::123456789012:user/Policy-Target"}]}'),
    ('SVCDUPTGTPOLICY1', 'app-access', 'App-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDUPTGTPOLICY1', 'db-access', 'Db-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"*"}]}'),
    ('SVCDUPTGTPOLICY1', 'keep-access', 'Keep-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}'),
    ('SVCDUPTGTDIVSN01', 'division-access', 'Division-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}'),
    ('SVCDUPTGTENGNR01', 'eng-access', 'Eng-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}'),
    ('SVCDUPTGTSALES01', 'sales-access', 'Sales-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ses:SendEmail","Resource":"*"}]}'),
    ('SVCDUPTGTROOT001', 'root-access', 'Root-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData",
        "Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `DeleteUserPolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one database, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_delete_user_policy_authorization() {
    let database = TestDatabase::new(DELETE_USER_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();

    // A caller allowed iam:DeleteUserPolicy on any user removes an inline policy from one.
    let (principal, session_data) = user_identity("SVCDUPBROADDEL01", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_policy_parameters(Some("Policy-Target"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DeleteUserPolicyResponse"), "unexpected body: {body}");

    // The delete was committed rather than rolled back, so the policy is gone. The same
    // caller is allowed iam:GetUserPolicy, so it is told the policy no longer exists.
    let (principal, session_data) = user_identity("SVCDUPBROADDEL01", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Policy-Target"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // Deleting it a second time reports that it no longer exists rather than succeeding
    // silently.
    let (principal, session_data) = user_identity("SVCDUPBROADDEL01", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_policy_parameters(Some("Policy-Target"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = user_identity("SVCDUPNOGRANTDL1", "No-Grant-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_policy_parameters(Some("Policy-Target"), Some("Keep-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/No-Grant-Deleter is not authorized to perform: \
                 iam:DeleteUserPolicy on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Policy-Target"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled the transaction back, so the policy is still there.
    let (principal, session_data) = user_identity("SVCDUPBROADDEL01", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Policy-Target"), Some("Keep-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(decoded_policy_document(&body).contains("sns:Publish"), "unexpected body: {body}");

    // The resource ARN carries the target user's path, so a grant scoped to a path prefix
    // reaches users under that path...
    let (principal, session_data) = user_identity("SVCDUPPATHDEL001", "Path-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_policy_parameters(Some("Division-Target"), Some("Division-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = user_identity("SVCDUPPATHDEL001", "Path-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_policy_parameters(Some("Policy-Target"), Some("Keep-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the user the policy is embedded in back the aws:ResourceTag condition keys.
    let (principal, session_data) = user_identity("SVCDUPTAGDEL0001", "Tag-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_policy_parameters(Some("Engineering-Target"), Some("Eng-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = user_identity("SVCDUPTAGDEL0001", "Tag-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_policy_parameters(Some("Sales-Target"), Some("Sales-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // An inline policy is part of the user carrying it rather than a resource of its own, so
    // PolicyName narrows nothing: a grant naming just the user reaches every inline policy on
    // it.
    let (principal, session_data) = user_identity("SVCDUPNARROWDEL1", "Narrow-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_policy_parameters(Some("Policy-Target"), Some("Db-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:DeleteUserPolicy on any user is told the user is missing...
    let (principal, session_data) = user_identity("SVCDUPBROADDEL01", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_policy_parameters(Some("No-Such-User"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = user_identity("SVCDUPNARROWDEL1", "Narrow-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_policy_parameters(Some("No-Such-User"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Both names are required; neither defaults to anything.
    for parameters in [
        delete_user_policy_parameters(Some("Policy-Target"), None),
        delete_user_policy_parameters(None, Some("Keep-Access")),
    ] {
        let (principal, session_data) = user_identity("SVCDUPBROADDEL01", "Broad-Deleter");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // The account root user is implicitly allowed.
    let (principal, session_data) = root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_user_policy_parameters(Some("Root-Target"), Some("Root-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
}
