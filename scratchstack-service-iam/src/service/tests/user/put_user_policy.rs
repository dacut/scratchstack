use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `PutUserPolicy` authorization tests. `Policy-Target` already carries an
/// inline policy, so replacing one can be told apart from adding one; the other targets carry
/// the paths and tags the resource ARN and the `aws:ResourceTag` condition keys are derived
/// from. `Broad-Writer` is also allowed `iam:GetUserPolicy`, so the tests can read back what
/// a write did or did not leave behind.
const PUT_USER_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'put-user-policy-test@example.com', 'put-user-policy-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCPUPBROADWTR01', '%ACCOUNT_ID%', 'broad-writer', 'Broad-Writer', '/'),
    ('SVCPUPPATHWTR001', '%ACCOUNT_ID%', 'path-writer', 'Path-Writer', '/'),
    ('SVCPUPTAGWTR0001', '%ACCOUNT_ID%', 'tag-writer', 'Tag-Writer', '/'),
    ('SVCPUPNARROWWTR1', '%ACCOUNT_ID%', 'narrow-writer', 'Narrow-Writer', '/'),
    ('SVCPUPNOGRANTWR1', '%ACCOUNT_ID%', 'no-grant-writer', 'No-Grant-Writer', '/'),
    ('SVCPUPTGTPOLICY1', '%ACCOUNT_ID%', 'policy-target', 'Policy-Target', '/'),
    ('SVCPUPTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/'),
    ('SVCPUPTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/'),
    ('SVCPUPTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/'),
    ('SVCPUPTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCPUPTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCPUPTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCPUPBROADWTR01', 'allow-put-any-policy', 'Allow-Put-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Action":["iam:PutUserPolicy","iam:GetUserPolicy"],"Resource":"*"}]}'),
    ('SVCPUPPATHWTR001', 'allow-put-division-policy', 'Allow-Put-Division-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutUserPolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/division/*"}]}'),
    ('SVCPUPTAGWTR0001', 'allow-put-engineering-policy', 'Allow-Put-Engineering-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutUserPolicy","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCPUPNARROWWTR1', 'allow-put-target-policy', 'Allow-Put-Target-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutUserPolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/Policy-Target"}]}'),
    ('SVCPUPTGTPOLICY1', 'existing-access', 'Existing-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `PutUserPolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_put_user_policy_authorization() {
    /// The document the tests first write under a policy name.
    const FIRST_DOCUMENT: &str =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}"#;

    /// The document the tests then write under the same policy name, replacing the first.
    const SECOND_DOCUMENT: &str =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}"#;

    let database = TestDatabase::new(PUT_USER_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:PutUserPolicy on any user adds an inline policy to one.
    let (principal, session_data) = database.user_identity("SVCPUPBROADWTR01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_policy_parameters(Some("Policy-Target"), Some("New-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PutUserPolicyResponse"), "unexpected body: {body}");

    // The write was committed rather than rolled back, so the policy can be read back.
    let (principal, session_data) = database.user_identity("SVCPUPBROADWTR01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Policy-Target"), Some("New-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(decoded_policy_document(&body).contains("s3:ListBucket"), "unexpected body: {body}");

    // Writing the same policy name again replaces the document rather than failing.
    let (principal, session_data) = database.user_identity("SVCPUPBROADWTR01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_policy_parameters(Some("Policy-Target"), Some("New-Access"), Some(SECOND_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCPUPBROADWTR01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Policy-Target"), Some("New-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(decoded_policy_document(&body).contains("sqs:SendMessage"), "unexpected body: {body}");
    assert!(!decoded_policy_document(&body).contains("s3:ListBucket"), "unexpected body: {body}");

    // A document that does not parse as a policy is rejected. The caller is allowed the
    // action, so it learns the document is malformed rather than that it was denied.
    let (principal, session_data) = database.user_identity("SVCPUPBROADWTR01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_policy_parameters(Some("Policy-Target"), Some("Bad-Access"), Some("this is not a policy")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedPolicyDocument</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCPUPNOGRANTWR1", "No-Grant-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_policy_parameters(Some("Policy-Target"), Some("Denied-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Writer is not authorized to perform: \
                 iam:PutUserPolicy on resource: arn:aws:iam::{account_id}:user/Policy-Target"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled the transaction back, so nothing was written.
    let (principal, session_data) = database.user_identity("SVCPUPBROADWTR01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Policy-Target"), Some("Denied-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // The resource ARN carries the target user's path, so a grant scoped to a path prefix
    // reaches users under that path...
    let (principal, session_data) = database.user_identity("SVCPUPPATHWTR001", "Path-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_policy_parameters(Some("Division-Target"), Some("Division-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCPUPPATHWTR001", "Path-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_policy_parameters(Some("Policy-Target"), Some("Division-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the user the policy is embedded in back the aws:ResourceTag condition keys.
    let (principal, session_data) = database.user_identity("SVCPUPTAGWTR0001", "Tag-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_policy_parameters(Some("Engineering-Target"), Some("Eng-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCPUPTAGWTR0001", "Tag-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_policy_parameters(Some("Sales-Target"), Some("Sales-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // An inline policy is part of the user carrying it rather than a resource of its own, so
    // PolicyName narrows nothing: a grant naming just the user allows replacing the policies
    // that user already carries as well as adding new ones.
    let (principal, session_data) = database.user_identity("SVCPUPNARROWWTR1", "Narrow-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_policy_parameters(Some("Policy-Target"), Some("Existing-Access"), Some(SECOND_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCPUPBROADWTR01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Policy-Target"), Some("Existing-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(decoded_policy_document(&body).contains("sqs:SendMessage"), "unexpected body: {body}");

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:PutUserPolicy on any user is told the user is missing...
    let (principal, session_data) = database.user_identity("SVCPUPBROADWTR01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_policy_parameters(Some("No-Such-User"), Some("New-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCPUPNARROWWTR1", "Narrow-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_policy_parameters(Some("No-Such-User"), Some("New-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // All three parameters are required; none defaults to anything.
    for parameters in [
        put_user_policy_parameters(None, Some("New-Access"), Some(FIRST_DOCUMENT)),
        put_user_policy_parameters(Some("Policy-Target"), None, Some(FIRST_DOCUMENT)),
        put_user_policy_parameters(Some("Policy-Target"), Some("New-Access"), None),
    ] {
        let (principal, session_data) = database.user_identity("SVCPUPBROADWTR01", "Broad-Writer");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_user_policy_parameters(Some("Root-Target"), Some("Root-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
}
