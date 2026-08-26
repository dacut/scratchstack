use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `DeleteRole` authorization tests. `Broad-Deleter` may delete any role;
/// `Path-Deleter` only roles under `/division/`; `No-Grant-Deleter` none at all. `Held-Role`
/// carries an inline policy, so it stands for a role that still owns something.
const DELETE_ROLE_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'delete-role-test@example.com', 'delete-role-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCDELROLEBROAD', '%ACCOUNT_ID%', 'broad-deleter', 'Broad-Deleter', '/'),
    ('SVCDELROLEPATH1', '%ACCOUNT_ID%', 'path-deleter', 'Path-Deleter', '/'),
    ('SVCDELROLENONE1', '%ACCOUNT_ID%', 'no-grant-deleter', 'No-Grant-Deleter', '/');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCDELROLEPLAIN', '%ACCOUNT_ID%', 'plain-role', 'Plain-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCDELROLEDIVSN', '%ACCOUNT_ID%', 'division-role', 'Division-Role', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCDELROLEKEEP1', '%ACCOUNT_ID%', 'kept-role', 'Kept-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCDELROLEHELD1', '%ACCOUNT_ID%', 'held-role', 'Held-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCDELROLETAGGD', '%ACCOUNT_ID%', 'tagged-role', 'Tagged-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCDELROLETAGGD', 'department', 'Department', 'Engineering');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDELROLEHELD1', 'held-policy', 'Held-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDELROLEBROAD', 'allow-delete-any', 'Allow-Delete-Any',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:DeleteRole","iam:GetRole"],
        "Resource":"*"}]}'),
    ('SVCDELROLEPATH1', 'allow-delete-in-division', 'Allow-Delete-In-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteRole",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/division/*"}]}');
"#;

/// End-to-end authorization checks for `DeleteRole` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_delete_role_authorization() {
    let database = TestDatabase::new(DELETE_ROLE_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:DeleteRole on any role deletes one.
    let (principal, session_data) = database.user_identity("SVCDELROLEBROAD", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_role_parameters(Some("Plain-Role"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DeleteRoleResponse"), "unexpected body: {body}");

    // The role is gone, so the delete was committed rather than rolled back.
    let (principal, session_data) = database.user_identity("SVCDELROLEBROAD", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Plain-Role"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");

    // Deleting it again reports that it does not exist.
    let (principal, session_data) = database.user_identity("SVCDELROLEBROAD", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_role_parameters(Some("Plain-Role"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A role that still owns an inline policy cannot be deleted, and the attempt says so rather
    // than deleting the policy along with it.
    let (principal, session_data) = database.user_identity("SVCDELROLEBROAD", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_role_parameters(Some("Held-Role"))).await;
    assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
    assert!(body.contains("<Code>DeleteConflict</Code>"), "unexpected body: {body}");

    // That rejection rolled its transaction back, so the role is still there.
    let (principal, session_data) = database.user_identity("SVCDELROLEBROAD", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Held-Role"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A role's tags are read before it is deleted, so a policy may be conditioned on them; the
    // delete takes the role and its tags together.
    let (principal, session_data) = database.user_identity("SVCDELROLEBROAD", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_role_parameters(Some("Tagged-Role"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The role's path is part of the ARN being authorized, so a grant scoped to a path prefix
    // reaches roles under that path...
    let (principal, session_data) = database.user_identity("SVCDELROLEPATH1", "Path-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_role_parameters(Some("Division-Role"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further: the same caller cannot delete a role at the root path.
    let (principal, session_data) = database.user_identity("SVCDELROLEPATH1", "Path-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_role_parameters(Some("Kept-Role"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Path-Deleter is not authorized to perform: \
                 iam:DeleteRole on resource: arn:aws:iam::{account_id}:role/Kept-Role"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled its transaction back, so the role survives it.
    let (principal, session_data) = database.user_identity("SVCDELROLEBROAD", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Kept-Role"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCDELROLENONE1", "No-Grant-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_role_parameters(Some("Kept-Role"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A malformed role name is rejected before the request is authorized.
    let (principal, session_data) = database.user_identity("SVCDELROLENONE1", "No-Grant-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_role_parameters(Some("bad role!"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // RoleName is required: nothing is deleted by a request that names no role.
    let (principal, session_data) = database.user_identity("SVCDELROLEBROAD", "Broad-Deleter");
    let (status, body) = call(&svc_state, principal, session_data, &delete_role_parameters(None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &delete_role_parameters(Some("Kept-Role"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
}
