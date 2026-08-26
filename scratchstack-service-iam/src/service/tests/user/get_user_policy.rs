use {
    crate::service::{ServiceState, tests::*},
    pretty_assertions::assert_eq,
    scratchstack_core::axum::http::StatusCode,
    scratchstack_iam_database::{migrate::MIGRATOR, utils::TempDatabase},
    sqlx::raw_sql,
    std::sync::Arc,
};

/// Seed data for the `GetUserPolicy` authorization tests. `Policy-Holder` carries two inline
/// policies, so a grant reaching the user can be shown to reach both; the other targets carry
/// the paths and tags the resource ARN and the `aws:ResourceTag` condition keys are derived
/// from.
const GET_USER_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.partition(partition) VALUES ('aws');

    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('123456789012', 'get-user-policy-test@example.com', 'get-user-policy-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCGUPBROADRDR01', '123456789012', 'broad-reader', 'Broad-Reader', '/'),
    ('SVCGUPPATHRDR001', '123456789012', 'path-reader', 'Path-Reader', '/'),
    ('SVCGUPTAGRDR0001', '123456789012', 'tag-reader', 'Tag-Reader', '/'),
    ('SVCGUPNARROWRDR1', '123456789012', 'narrow-reader', 'Narrow-Reader', '/'),
    ('SVCGUPNOGRANTRD1', '123456789012', 'no-grant-reader', 'No-Grant-Reader', '/'),
    ('SVCGUPTGTHOLDER1', '123456789012', 'policy-holder', 'Policy-Holder', '/'),
    ('SVCGUPTGTDIVSN01', '123456789012', 'division-target', 'Division-Target', '/division/'),
    ('SVCGUPTGTENGNR01', '123456789012', 'engineering-target', 'Engineering-Target', '/'),
    ('SVCGUPTGTSALES01', '123456789012', 'sales-target', 'Sales-Target', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCGUPTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCGUPTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCGUPBROADRDR01', 'allow-get-any-policy', 'Allow-Get-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUserPolicy","Resource":"*"}]}'),
    ('SVCGUPPATHRDR001', 'allow-get-division-policy', 'Allow-Get-Division-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUserPolicy",
        "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
    ('SVCGUPTAGRDR0001', 'allow-get-engineering-policy', 'Allow-Get-Engineering-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUserPolicy","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCGUPNARROWRDR1', 'allow-get-holder-policy', 'Allow-Get-Holder-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUserPolicy",
        "Resource":"arn:aws:iam::123456789012:user/Policy-Holder"}]}'),
    ('SVCGUPTGTHOLDER1', 'app-access', 'App-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCGUPTGTHOLDER1', 'db-access', 'Db-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"*"}]}'),
    ('SVCGUPTGTDIVSN01', 'division-access', 'Division-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}'),
    ('SVCGUPTGTENGNR01', 'eng-access', 'Eng-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}'),
    ('SVCGUPTGTSALES01', 'sales-access', 'Sales-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ses:SendEmail","Resource":"*"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCGUPROLE000001', '123456789012', 'get-user-policy-role', 'Get-User-Policy-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCGUPROLE000001', 'allow-get-any-policy', 'Allow-Get-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUserPolicy","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `GetUserPolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function is used because the database is
/// stateful and expensive to start.
#[test_log::test(tokio::test)]
async fn test_get_user_policy_authorization() {
    let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
    database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
    let pool =
        database.get_scratchstack_pool().await.expect("Failed to get PostgreSQL connection pool for scratchstack user");

    let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
    MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
    raw_sql(GET_USER_POLICY_TEST_DATA).execute(&mut *c).await.expect("Failed to load test data into database");
    drop(c);

    let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();

    // A caller allowed iam:GetUserPolicy on any user reads an inline policy off one.
    let (principal, session_data) = user_identity("SVCGUPBROADRDR01", "Broad-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Policy-Holder"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>Policy-Holder</UserName>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>App-Access</PolicyName>"), "unexpected body: {body}");

    // The document goes out percent-encoded rather than as the JSON it is stored as, so the
    // raw policy does not appear on the wire at all and a client decodes what it reads back.
    assert!(body.contains("%7B%22Version%22%3A%222012-10-17%22"), "unexpected body: {body}");
    assert!(!body.contains("s3:GetObject"), "unexpected body: {body}");
    assert!(decoded_policy_document(&body).contains("s3:GetObject"), "unexpected body: {body}");

    // Policy names are matched case-insensitively, and the name comes back cased as it was
    // stored rather than as the request spelled it.
    let (principal, session_data) = user_identity("SVCGUPBROADRDR01", "Broad-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Policy-Holder"), Some("app-access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>App-Access</PolicyName>"), "unexpected body: {body}");

    // An inline policy is part of the user carrying it rather than a resource of its own, so
    // PolicyName narrows nothing: a grant naming just the user reaches every inline policy on
    // it.
    for policy_name in ["App-Access", "Db-Access"] {
        let (principal, session_data) = user_identity("SVCGUPNARROWRDR1", "Narrow-Reader");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Policy-Holder"), Some(policy_name)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains(&format!("<PolicyName>{policy_name}</PolicyName>")), "unexpected body: {body}");
    }

    // ...and reaches exactly the user it names, and no other.
    let (principal, session_data) = user_identity("SVCGUPNARROWRDR1", "Narrow-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Engineering-Target"), Some("Eng-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The resource ARN carries the target user's path, so a grant scoped to a path prefix
    // reaches users under that path...
    let (principal, session_data) = user_identity("SVCGUPPATHRDR001", "Path-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Division-Target"), Some("Division-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(decoded_policy_document(&body).contains("sqs:SendMessage"), "unexpected body: {body}");

    // ...and no further.
    let (principal, session_data) = user_identity("SVCGUPPATHRDR001", "Path-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Policy-Holder"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the user the policy is embedded in back the aws:ResourceTag condition keys.
    let (principal, session_data) = user_identity("SVCGUPTAGRDR0001", "Tag-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Engineering-Target"), Some("Eng-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(decoded_policy_document(&body).contains("ec2:DescribeInstances"), "unexpected body: {body}");

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = user_identity("SVCGUPTAGRDR0001", "Tag-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Sales-Target"), Some("Sales-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Neither does a user carrying no tags at all: the condition key is absent.
    let (principal, session_data) = user_identity("SVCGUPTAGRDR0001", "Tag-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Policy-Holder"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = user_identity("SVCGUPNOGRANTRD1", "No-Grant-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Policy-Holder"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/No-Grant-Reader is not authorized to perform: \
                 iam:GetUserPolicy on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Policy-Holder"
        )),
        "unexpected body: {body}"
    );

    // A policy name that is not attached to the user is reported as missing to a caller
    // allowed to read the user's policies.
    let (principal, session_data) = user_identity("SVCGUPBROADRDR01", "Broad-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Policy-Holder"), Some("No-Such-Policy")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:GetUserPolicy on any user is told the user is missing...
    let (principal, session_data) = user_identity("SVCGUPBROADRDR01", "Broad-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("No-Such-User"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = user_identity("SVCGUPNARROWRDR1", "Narrow-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("No-Such-User"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Both names are required; neither defaults to anything.
    for parameters in
        [get_user_policy_parameters(Some("Policy-Holder"), None), get_user_policy_parameters(None, Some("App-Access"))]
    {
        let (principal, session_data) = user_identity("SVCGUPBROADRDR01", "Broad-Reader");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = role_identity("SVCGUPROLE000001", "Get-User-Policy-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Policy-Holder"), Some("Db-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(decoded_policy_document(&body).contains("dynamodb:GetItem"), "unexpected body: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_user_policy_parameters(Some("Sales-Target"), Some("Sales-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(decoded_policy_document(&body).contains("ses:SendEmail"), "unexpected body: {body}");
}
