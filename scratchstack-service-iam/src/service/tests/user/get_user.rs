use {
    crate::service::{ServiceState, tests::*},
    pretty_assertions::assert_eq,
    scratchstack_core::axum::http::StatusCode,
    scratchstack_iam_database::{migrate::MIGRATOR, utils::TempDatabase},
    sqlx::raw_sql,
    std::sync::Arc,
};

/// Seed data for the `GetUser` authorization tests. The users being read carry the paths and
/// tags the resource ARN and the `aws:ResourceTag`/`iam:ResourceTag` condition keys are
/// derived from; the callers carry grants scoped by principal variable, by resource path, and
/// by resource tag.
const GET_USER_TEST_DATA: &str = r#"
    INSERT INTO iam.partition(partition) VALUES ('aws');

    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('123456789012', 'get-user-test@example.com', 'get-user-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCGETUSERSELF01', '123456789012', 'self-user', 'Self-User', '/'),
    ('SVCGETUSERPATH01', '123456789012', 'path-user', 'Path-User', '/'),
    ('SVCGETUSERTAG001', '123456789012', 'tag-user', 'Tag-User', '/'),
    ('SVCGETUSERIAMTG1', '123456789012', 'iam-tag-user', 'Iam-Tag-User', '/'),
    ('SVCGETUSERBROAD1', '123456789012', 'broad-user', 'Broad-User', '/'),
    ('SVCGETUSERNARROW', '123456789012', 'narrow-user', 'Narrow-User', '/'),
    ('SVCGETUSERDIVSN1', '123456789012', 'division-user', 'Division-User', '/division/'),
    ('SVCGETUSERENGNR1', '123456789012', 'engineering-user', 'Engineering-User', '/'),
    ('SVCGETUSERSALES1', '123456789012', 'sales-user', 'Sales-User', '/'),
    ('SVCGETUSRACCT001', '123456789012', 'account-user', 'Account-User', '/'),
    ('SVCGETUSRACCT002', '123456789012', 'other-account-user', 'Other-Account-User', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCGETUSERENGNR1', 'department', 'Department', 'Engineering'),
    ('SVCGETUSERSALES1', 'department', 'Department', 'Sales');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCGETUSERSELF01', 'allow-get-self', 'Allow-Get-Self',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser",
        "Resource":"arn:aws:iam::123456789012:user/${aws:username}"}]}'),
    ('SVCGETUSERPATH01', 'allow-get-division', 'Allow-Get-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser",
        "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
    ('SVCGETUSERTAG001', 'allow-get-engineering', 'Allow-Get-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCGETUSERIAMTG1', 'allow-get-engineering-iam', 'Allow-Get-Engineering-Iam',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/Department":"Engineering"}}}]}'),
    ('SVCGETUSERBROAD1', 'allow-get-any', 'Allow-Get-Any',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}'),
    ('SVCGETUSRACCT001', 'allow-get-in-own-account', 'Allow-Get-In-Own-Account',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceAccount":"123456789012"}}}]}'),
    ('SVCGETUSRACCT002', 'allow-get-in-other-account', 'Allow-Get-In-Other-Account',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceAccount":"210987654321"}}}]}'),
    ('SVCGETUSERNARROW', 'allow-get-broad-user', 'Allow-Get-Broad-User',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser",
        "Resource":"arn:aws:iam::123456789012:user/Broad-User"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCGETUSERROLE01', '123456789012', 'get-user-role', 'Get-User-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCGETUSERROLE01', 'allow-get-any', 'Allow-Get-Any',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}');
"#;

/// End-to-end `GetUser` authorization checks through `serve_request` against an embedded
/// PostgreSQL database. As with the `ListUsers` test, one test function covers every case
/// because the database is stateful and expensive to start.
#[test_log::test(tokio::test)]
async fn test_get_user_authorization() {
    let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
    database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
    let pool =
        database.get_scratchstack_pool().await.expect("Failed to get PostgreSQL connection pool for scratchstack user");

    let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
    MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
    raw_sql(GET_USER_TEST_DATA).execute(&mut *c).await.expect("Failed to load test data into database");
    drop(c);

    let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();

    // An omitted UserName names the calling user. The grant here is scoped to the caller's
    // own ARN through the aws:username policy variable, so it covers exactly that lookup.
    let (principal, session_data) = user_identity("SVCGETUSERSELF01", "Self-User");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Self-User</Arn>")),
        "unexpected body: {body}"
    );

    // The same grant does not reach any other user.
    let (principal, session_data) = user_identity("SVCGETUSERSELF01", "Self-User");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Broad-User"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Self-User is not authorized to perform: \
                 iam:GetUser on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Broad-User"
        )),
        "unexpected body: {body}"
    );

    // The resource ARN carries the target user's path, so a grant scoped to a path prefix
    // reaches users under that path...
    let (principal, session_data) = user_identity("SVCGETUSERPATH01", "Path-User");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Division-User"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/division/Division-User</Arn>")),
        "unexpected body: {body}"
    );
    assert!(body.contains("<Path>/division/</Path>"), "unexpected body: {body}");

    // ...and no further.
    let (principal, session_data) = user_identity("SVCGETUSERPATH01", "Path-User");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Broad-User"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The target user's tags back the aws:ResourceTag condition keys. The policy spells the
    // tag key in lower case while the tag itself is stored as "Department", confirming that
    // tag keys are matched case-insensitively.
    let (principal, session_data) = user_identity("SVCGETUSERTAG001", "Tag-User");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_user_parameters(Some("Engineering-User"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Engineering-User</Arn>")),
        "unexpected body: {body}"
    );

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = user_identity("SVCGETUSERTAG001", "Tag-User");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Sales-User"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Neither does a user carrying no tags at all: the condition key is absent.
    let (principal, session_data) = user_identity("SVCGETUSERTAG001", "Tag-User");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Broad-User"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // IAM's own iam:ResourceTag condition key carries the same values.
    let (principal, session_data) = user_identity("SVCGETUSERIAMTG1", "Iam-Tag-User");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_user_parameters(Some("Engineering-User"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Engineering-User</Arn>")),
        "unexpected body: {body}"
    );

    // The resource ARN carries the account that owns the user being read, which supplies
    // aws:ResourceAccount: a grant scoped to that account reaches the user...
    let (principal, session_data) = user_identity("SVCGETUSRACCT001", "Account-User");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Broad-User"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Broad-User</Arn>")),
        "unexpected body: {body}"
    );

    // ...and one scoped to a different account does not.
    let (principal, session_data) = user_identity("SVCGETUSRACCT002", "Other-Account-User");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Broad-User"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:GetUser on any user is told the user is missing...
    let (principal, session_data) = user_identity("SVCGETUSERBROAD1", "Broad-User");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("No-Such-User"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on specific users learns nothing about it.
    let (principal, session_data) = user_identity("SVCGETUSERNARROW", "Narrow-User");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("No-Such-User"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // An assumed-role session has no user to default UserName to.
    let (principal, session_data) = role_identity("SVCGETUSERROLE01", "Get-User-Role");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    assert!(body.contains("Must specify userName when calling with non-User credentials"), "unexpected body: {body}");

    // Naming the user explicitly works, governed by the role's own policy.
    let (principal, session_data) = role_identity("SVCGETUSERROLE01", "Get-User-Role");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Broad-User"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Broad-User</Arn>")),
        "unexpected body: {body}"
    );

    // The account root user is implicitly allowed, but is not an IAM user either, so it must
    // also name the user explicitly.
    let (principal, session_data) = root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    let (principal, session_data) = root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Sales-User"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Sales-User</Arn>")),
        "unexpected body: {body}"
    );
}
