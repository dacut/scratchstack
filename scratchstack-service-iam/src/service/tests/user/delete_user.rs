use {
    crate::service::{ServiceState, tests::*},
    pretty_assertions::assert_eq,
    scratchstack_core::axum::http::StatusCode,
    scratchstack_iam_database::{migrate::MIGRATOR, utils::TempDatabase},
    sqlx::raw_sql,
    std::sync::Arc,
};

/// Seed data for the `DeleteUser` authorization tests. The users being deleted carry the paths
/// and tags the resource ARN and the `aws:ResourceTag` condition keys are derived from, and
/// `Policy-Holder` owns an inline policy that blocks its deletion.
const DELETE_USER_TEST_DATA: &str = r#"
    INSERT INTO iam.partition(partition) VALUES ('aws');

    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('123456789012', 'delete-user-test@example.com', 'delete-user-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCDELUSERBROAD', '123456789012', 'broad-deleter', 'Broad-Deleter', '/'),
    ('SVCDELUSERPATH1', '123456789012', 'path-deleter', 'Path-Deleter', '/'),
    ('SVCDELUSERTAG01', '123456789012', 'tag-deleter', 'Tag-Deleter', '/'),
    ('SVCDELUSERNARRW', '123456789012', 'narrow-deleter', 'Narrow-Deleter', '/'),
    ('SVCDELUSERTGT01', '123456789012', 'delete-me', 'Delete-Me', '/'),
    ('SVCDELUSERTGT02', '123456789012', 'delete-me-too', 'Delete-Me-Too', '/'),
    ('SVCDELUSERTGT03', '123456789012', 'division-target', 'Division-Target', '/division/'),
    ('SVCDELUSERTGT04', '123456789012', 'engineering-target', 'Engineering-Target', '/'),
    ('SVCDELUSERTGT05', '123456789012', 'sales-target', 'Sales-Target', '/'),
    ('SVCDELUSERTGT06', '123456789012', 'policy-holder', 'Policy-Holder', '/'),
    ('SVCDELUSERTGT07', '123456789012', 'root-target', 'Root-Target', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCDELUSERTGT04', 'department', 'Department', 'Engineering'),
    ('SVCDELUSERTGT05', 'department', 'Department', 'Sales');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDELUSERBROAD', 'allow-delete-any', 'Allow-Delete-Any',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:DeleteUser","iam:GetUser"],
        "Resource":"*"}]}'),
    ('SVCDELUSERPATH1', 'allow-delete-in-division', 'Allow-Delete-In-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUser",
        "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
    ('SVCDELUSERTAG01', 'allow-delete-engineering', 'Allow-Delete-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUser","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCDELUSERNARRW', 'allow-delete-one-user', 'Allow-Delete-One-User',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUser",
        "Resource":"arn:aws:iam::123456789012:user/Delete-Me-Too"}]}'),
    ('SVCDELUSERTGT06', 'keep-me', 'Keep-Me',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `DeleteUser` through `serve_request` against an
/// embedded PostgreSQL database. A single test function is used because the database is
/// stateful and expensive to start.
#[test_log::test(tokio::test)]
async fn test_delete_user_authorization() {
    let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
    database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
    let pool =
        database.get_scratchstack_pool().await.expect("Failed to get PostgreSQL connection pool for scratchstack user");

    let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
    MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
    raw_sql(DELETE_USER_TEST_DATA).execute(&mut *c).await.expect("Failed to load test data into database");
    drop(c);

    let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();

    // A caller allowed iam:DeleteUser on any user deletes one.
    let (principal, session_data) = user_identity("SVCDELUSERBROAD", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_user_parameters(Some("Delete-Me"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DeleteUserResponse"), "unexpected body: {body}");

    // The delete was committed rather than rolled back, so the user is gone. The same caller
    // is allowed iam:GetUser, so it is told the user no longer exists.
    let (principal, session_data) = user_identity("SVCDELUSERBROAD", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Delete-Me"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // Deleting it a second time reports that it no longer exists.
    let (principal, session_data) = user_identity("SVCDELUSERBROAD", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_user_parameters(Some("Delete-Me"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // The resource ARN carries the target user's path, so a grant scoped to a path prefix
    // reaches users under that path...
    let (principal, session_data) = user_identity("SVCDELUSERPATH1", "Path-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_user_parameters(Some("Division-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = user_identity("SVCDELUSERPATH1", "Path-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_user_parameters(Some("Delete-Me-Too"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The target user's own tags back the aws:ResourceTag condition keys, unlike CreateUser
    // where the tags come from the request.
    let (principal, session_data) = user_identity("SVCDELUSERTAG01", "Tag-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_user_parameters(Some("Engineering-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = user_identity("SVCDELUSERTAG01", "Tag-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_user_parameters(Some("Sales-Target"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled the transaction back, so the user is still there to be deleted by a
    // caller that is allowed to.
    let (principal, session_data) = user_identity("SVCDELUSERBROAD", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_user_parameters(Some("Sales-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user that still owns dependent resources cannot be deleted; the caller is allowed the
    // action, so it learns the delete conflicts rather than that it was denied.
    let (principal, session_data) = user_identity("SVCDELUSERBROAD", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_user_parameters(Some("Policy-Holder"))).await;
    assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
    assert!(body.contains("<Code>DeleteConflict</Code>"), "unexpected body: {body}");

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:DeleteUser on any user is told the user is missing...
    let (principal, session_data) = user_identity("SVCDELUSERBROAD", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_user_parameters(Some("No-Such-User"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = user_identity("SVCDELUSERNARRW", "Narrow-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_user_parameters(Some("No-Such-User"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Unlike GetUser, an omitted UserName does not default to the calling user: DeleteUser
    // requires the name, so a caller cannot delete itself by leaving it off.
    let (principal, session_data) = user_identity("SVCDELUSERBROAD", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_user_parameters(None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // The narrow grant reaches exactly the user it names.
    let (principal, session_data) = user_identity("SVCDELUSERNARRW", "Narrow-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_user_parameters(Some("Delete-Me-Too"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &delete_user_parameters(Some("Root-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
}
