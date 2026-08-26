use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `UpdateRole` authorization tests. `Broad-Updater` may update any role;
/// `Tag-Updater` only roles tagged `Department=Engineering`; `No-Grant-Updater` none at all.
const UPDATE_ROLE_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'update-role-test@example.com', 'update-role-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCUPDROLEBROAD', '%ACCOUNT_ID%', 'broad-updater', 'Broad-Updater', '/'),
    ('SVCUPDROLETAG01', '%ACCOUNT_ID%', 'tag-updater', 'Tag-Updater', '/'),
    ('SVCUPDROLENONE1', '%ACCOUNT_ID%', 'no-grant-updater', 'No-Grant-Updater', '/');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document, description, max_session_duration) VALUES
    ('SVCUPDROLEPLAIN', '%ACCOUNT_ID%', 'plain-role', 'Plain-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}',
        'Runs the nightly batch.', 7200),
    ('SVCUPDROLETAGGD', '%ACCOUNT_ID%', 'tagged-role', 'Tagged-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}',
        NULL, NULL);

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCUPDROLETAGGD', 'department', 'Department', 'Engineering');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCUPDROLEBROAD', 'allow-update-any', 'Allow-Update-Any',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:UpdateRole","iam:GetRole"],
        "Resource":"*"}]}'),
    ('SVCUPDROLETAG01', 'allow-update-engineering', 'Allow-Update-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateRole","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}');
"#;

/// End-to-end authorization checks for `UpdateRole` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_update_role_authorization() {
    let database = TestDatabase::new(UPDATE_ROLE_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:UpdateRole on any role changes both fields at once.
    let (principal, session_data) = database.user_identity("SVCUPDROLEBROAD", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_parameters(Some("Plain-Role"), Some("Runs the hourly batch."), Some(10800)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UpdateRoleResponse"), "unexpected body: {body}");

    // The change is visible, so it was committed rather than rolled back.
    let (principal, session_data) = database.user_identity("SVCUPDROLEBROAD", "Broad-Updater");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Plain-Role"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Description>Runs the hourly batch.</Description>"), "unexpected body: {body}");
    assert!(body.contains("<MaxSessionDuration>10800</MaxSessionDuration>"), "unexpected body: {body}");

    // A field the request leaves out is left alone rather than cleared: changing the duration
    // keeps the description the role already had.
    let (principal, session_data) = database.user_identity("SVCUPDROLEBROAD", "Broad-Updater");
    let (status, body) =
        call(&svc_state, principal, session_data, &update_role_parameters(Some("Plain-Role"), None, Some(14400))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCUPDROLEBROAD", "Broad-Updater");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Plain-Role"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Description>Runs the hourly batch.</Description>"), "unexpected body: {body}");
    assert!(body.contains("<MaxSessionDuration>14400</MaxSessionDuration>"), "unexpected body: {body}");

    // A request supplying neither field changes nothing and still succeeds -- but is still
    // authorized, and still has to name a role that exists.
    let (principal, session_data) = database.user_identity("SVCUPDROLEBROAD", "Broad-Updater");
    let (status, body) =
        call(&svc_state, principal, session_data, &update_role_parameters(Some("Plain-Role"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The role's own tags back the aws:ResourceTag condition keys, which the role has to be read
    // to know: the request names only the role.
    let (principal, session_data) = database.user_identity("SVCUPDROLETAG01", "Tag-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_parameters(Some("Tagged-Role"), Some("Owned by engineering."), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // An untagged role leaves the condition key absent, so the grant does not apply.
    let (principal, session_data) = database.user_identity("SVCUPDROLETAG01", "Tag-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_parameters(Some("Plain-Role"), Some("Should not be applied."), None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Tag-Updater is not authorized to perform: \
                 iam:UpdateRole on resource: arn:aws:iam::{account_id}:role/Plain-Role"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled its transaction back, so the description is the one set before it.
    let (principal, session_data) = database.user_identity("SVCUPDROLEBROAD", "Broad-Updater");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Plain-Role"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Description>Runs the hourly batch.</Description>"), "unexpected body: {body}");

    // A caller allowed the action broadly is told a role does not exist.
    let (principal, session_data) = database.user_identity("SVCUPDROLEBROAD", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_parameters(Some("No-Such-Role"), Some("Nowhere to put this."), None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A session duration outside the window IAM allows is rejected before the request is
    // authorized, so the caller learns the request was invalid rather than that it was denied.
    let (principal, session_data) = database.user_identity("SVCUPDROLENONE1", "No-Grant-Updater");
    let (status, body) =
        call(&svc_state, principal, session_data, &update_role_parameters(Some("Plain-Role"), None, Some(60))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCUPDROLENONE1", "No-Grant-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_parameters(Some("Plain-Role"), Some("Should not be applied."), None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // RoleName is required: a request that names no role cannot be read as an UpdateRole request.
    let (principal, session_data) = database.user_identity("SVCUPDROLEBROAD", "Broad-Updater");
    let (status, body) =
        call(&svc_state, principal, session_data, &update_role_parameters(None, Some("Nobody's description."), None))
            .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_parameters(Some("Plain-Role"), Some("Set by the root user."), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCUPDROLEBROAD", "Broad-Updater");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Plain-Role"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Description>Set by the root user.</Description>"), "unexpected body: {body}");
}
