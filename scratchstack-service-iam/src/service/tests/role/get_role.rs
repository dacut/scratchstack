use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The trust policy the seeded roles carry.
const TRUST_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

/// Seed data for the `GetRole` authorization tests. `Broad-Reader` may read any role;
/// `Path-Reader` only roles under `/division/`; `Tag-Reader` only roles tagged
/// `Department=Engineering`; `No-Grant-Reader` none at all. The roles differ in path, tags, and
/// whether they carry a permissions boundary, so that what `GetRole` reports about each can be
/// checked.
const GET_ROLE_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'get-role-test@example.com', 'get-role-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCGETROLEBROAD', '%ACCOUNT_ID%', 'broad-reader', 'Broad-Reader', '/'),
    ('SVCGETROLEPATH1', '%ACCOUNT_ID%', 'path-reader', 'Path-Reader', '/'),
    ('SVCGETROLETAG01', '%ACCOUNT_ID%', 'tag-reader', 'Tag-Reader', '/'),
    ('SVCGETROLENONE1', '%ACCOUNT_ID%', 'no-grant-reader', 'No-Grant-Reader', '/');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCGETROLEBND01', '%ACCOUNT_ID%', 'boundary-policy', 'Boundary-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCGETROLEBND01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document, description, max_session_duration,
        permissions_boundary_managed_policy_id) VALUES
    ('SVCGETROLEPLAIN', '%ACCOUNT_ID%', 'plain-role', 'Plain-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}',
        'Runs the nightly batch.', 7200, NULL),
    ('SVCGETROLEDIVSN', '%ACCOUNT_ID%', 'division-role', 'Division-Role', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}',
        NULL, NULL, NULL),
    ('SVCGETROLETAGGD', '%ACCOUNT_ID%', 'tagged-role', 'Tagged-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}',
        NULL, NULL, 'SVCGETROLEBND01');

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCGETROLETAGGD', 'department', 'Department', 'Engineering');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCGETROLEBROAD', 'allow-get-any', 'Allow-Get-Any',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","Resource":"*"}]}'),
    ('SVCGETROLEPATH1', 'allow-get-in-division', 'Allow-Get-In-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/division/*"}]}'),
    ('SVCGETROLETAG01', 'allow-get-engineering', 'Allow-Get-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/department":"Engineering"}}}]}');
"#;

/// End-to-end authorization checks for `GetRole` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account.
#[test_log::test(tokio::test)]
async fn test_get_role_authorization() {
    let database = TestDatabase::new(GET_ROLE_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:GetRole on any role reads one, and is told everything the role
    // carries.
    let (principal, session_data) = database.user_identity("SVCGETROLEBROAD", "Broad-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Plain-Role"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains(&format!("<Arn>arn:aws:iam::{account_id}:role/Plain-Role</Arn>")), "unexpected body: {body}");
    assert!(body.contains("<RoleName>Plain-Role</RoleName>"), "unexpected body: {body}");
    assert!(body.contains("<Path>/</Path>"), "unexpected body: {body}");
    assert!(body.contains("<Description>Runs the nightly batch.</Description>"), "unexpected body: {body}");
    assert!(body.contains("<MaxSessionDuration>7200</MaxSessionDuration>"), "unexpected body: {body}");

    // The trust policy comes back percent-encoded, as IAM reports every policy document.
    assert_eq!(decoded_trust_policy_document(&body), TRUST_POLICY);

    // Role names are matched case-insensitively, and the role is reported under the casing it
    // was created with rather than the one the request spelled.
    let (principal, session_data) = database.user_identity("SVCGETROLEBROAD", "Broad-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("PLAIN-ROLE"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<RoleName>Plain-Role</RoleName>"), "unexpected body: {body}");

    // A role's tags and permissions boundary are reported alongside it.
    let (principal, session_data) = database.user_identity("SVCGETROLEBROAD", "Broad-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Tagged-Role"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Department</Key>"), "unexpected body: {body}");
    assert!(body.contains("<Value>Engineering</Value>"), "unexpected body: {body}");
    assert!(
        body.contains(&format!(
            "<PermissionsBoundaryArn>arn:aws:iam::{account_id}:policy/Boundary-Policy</PermissionsBoundaryArn>"
        )),
        "unexpected body: {body}"
    );

    // The role's path is part of the ARN being authorized, so a grant scoped to a path prefix
    // reaches roles under that path...
    let (principal, session_data) = database.user_identity("SVCGETROLEPATH1", "Path-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Division-Role"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Path>/division/</Path>"), "unexpected body: {body}");

    // ...and no further: the same caller cannot read a role at the root path. The denial names
    // the role by the ARN it actually carries, path included.
    let (principal, session_data) = database.user_identity("SVCGETROLEPATH1", "Path-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Plain-Role"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Path-Reader is not authorized to perform: \
                 iam:GetRole on resource: arn:aws:iam::{account_id}:role/Plain-Role"
        )),
        "unexpected body: {body}"
    );

    // The role's own tags back the iam:ResourceTag condition keys, which the role has to be read
    // to know: the request names only the role.
    let (principal, session_data) = database.user_identity("SVCGETROLETAG01", "Tag-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Tagged-Role"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<RoleName>Tagged-Role</RoleName>"), "unexpected body: {body}");

    // An untagged role leaves the condition key absent, so the grant does not apply.
    let (principal, session_data) = database.user_identity("SVCGETROLETAG01", "Tag-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Plain-Role"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller allowed the action broadly is told a role does not exist...
    let (principal, session_data) = database.user_identity("SVCGETROLEBROAD", "Broad-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("No-Such-Role"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while one allowed it only on particular roles learns nothing at all about a role it
    // could not have read either way. A missing role has no path to read, so the ARN authorized
    // is the one it would carry at the root path.
    let (principal, session_data) = database.user_identity("SVCGETROLEPATH1", "Path-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("No-Such-Role"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCGETROLENONE1", "No-Grant-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Plain-Role"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A malformed role name is rejected before the request is authorized, so the caller learns
    // the request was invalid rather than that it was denied.
    let (principal, session_data) = database.user_identity("SVCGETROLENONE1", "No-Grant-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("bad role!"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // Unlike GetUser, an omitted RoleName does not default to anything: there is no role the
    // request could mean, so it cannot be read as a GetRole request at all.
    let (principal, session_data) = database.user_identity("SVCGETROLEBROAD", "Broad-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Plain-Role"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<RoleName>Plain-Role</RoleName>"), "unexpected body: {body}");
}
