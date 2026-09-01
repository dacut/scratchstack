use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// A trust policy to replace the one a target role was seeded with.
const NEW_TRUST_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

/// Seed data for the `UpdateAssumeRolePolicy` authorization tests. The targets carry the paths,
/// tags, and permissions boundary the resource ARN and the condition keys are derived from.
const UPDATE_ASSUME_ROLE_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'update-arp-test@example.com', 'update-arp-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCUARPBROADWR01', '%ACCOUNT_ID%', 'broad-writer', 'Broad-Writer', '/'),
    ('SVCUARPPATHWR001', '%ACCOUNT_ID%', 'path-writer', 'Path-Writer', '/'),
    ('SVCUARPTAGWR0001', '%ACCOUNT_ID%', 'tag-writer', 'Tag-Writer', '/'),
    ('SVCUARPIAMTAGWR1', '%ACCOUNT_ID%', 'iam-tag-writer', 'Iam-Tag-Writer', '/'),
    ('SVCUARPPBWR00001', '%ACCOUNT_ID%', 'boundary-writer', 'Boundary-Writer', '/'),
    ('SVCUARPNOGRANT01', '%ACCOUNT_ID%', 'no-grant-writer', 'No-Grant-Writer', '/');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCUARPBOUNDARY1', '%ACCOUNT_ID%', 'boundary-policy', 'Boundary-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCUARPBOUNDARY1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document, permissions_boundary_managed_policy_id) VALUES
    ('SVCUARPTGTBOUND1', '%ACCOUNT_ID%', 'bounded-target', 'Bounded-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        'SVCUARPBOUNDARY1'),
    ('SVCUARPTGTDIVSN1', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        NULL),
    ('SVCUARPTGTENGNR1', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        NULL),
    ('SVCUARPTGTSALES1', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        NULL);

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCUARPTGTENGNR1', 'department', 'Department', 'Engineering'),
    ('SVCUARPTGTSALES1', 'department', 'Department', 'Sales');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCUARPBROADWR01', 'allow-update-any', 'Allow-Update-Any',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateAssumeRolePolicy",
        "Resource":"*"}]}'),
    ('SVCUARPPATHWR001', 'allow-update-division', 'Allow-Update-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateAssumeRolePolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/division/*"}]}'),
    ('SVCUARPTAGWR0001', 'allow-update-engineering', 'Allow-Update-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateAssumeRolePolicy","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCUARPIAMTAGWR1', 'allow-update-engineering-iam', 'Allow-Update-Engineering-Iam',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateAssumeRolePolicy","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCUARPPBWR00001', 'allow-update-bounded', 'Allow-Update-Bounded',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateAssumeRolePolicy","Resource":"*",
        "Condition":{"StringEquals":
            {"iam:PermissionsBoundary":"arn:aws:iam::%ACCOUNT_ID%:policy/Boundary-Policy"}}}]}');
"#;

/// End-to-end authorization checks for `UpdateAssumeRolePolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case so that they share one
/// seeded account, rather than seeding one apiece.
#[test_log::test(tokio::test)]
async fn test_update_assume_role_policy_authorization() {
    let database = TestDatabase::new(UPDATE_ASSUME_ROLE_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:UpdateAssumeRolePolicy on any role replaces a trust policy.
    let (principal, session_data) = database.user_identity("SVCUARPBROADWR01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_assume_role_policy_parameters(Some("Engineering-Target"), Some(NEW_TRUST_POLICY)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The replacement stuck: the root user reads the role back and sees the new trust policy,
    // percent-encoded the way every operation reporting a role does.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_role_parameters(Some("Engineering-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("lambda.amazonaws.com"), "unexpected body: {body}");

    // The resource ARN carries the target role's path, so a grant scoped to a path prefix reaches
    // roles under that path...
    let (principal, session_data) = database.user_identity("SVCUARPPATHWR001", "Path-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_assume_role_policy_parameters(Some("Division-Target"), Some(NEW_TRUST_POLICY)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCUARPPATHWR001", "Path-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_assume_role_policy_parameters(Some("Sales-Target"), Some(NEW_TRUST_POLICY)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The role's tags back aws:ResourceTag/${TagKey}...
    let (principal, session_data) = database.user_identity("SVCUARPTAGWR0001", "Tag-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_assume_role_policy_parameters(Some("Engineering-Target"), Some(NEW_TRUST_POLICY)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and a role tagged otherwise does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCUARPTAGWR0001", "Tag-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_assume_role_policy_parameters(Some("Sales-Target"), Some(NEW_TRUST_POLICY)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // IAM's own iam:ResourceTag/${TagKey} spelling carries the same values.
    let (principal, session_data) = database.user_identity("SVCUARPIAMTAGWR1", "Iam-Tag-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_assume_role_policy_parameters(Some("Engineering-Target"), Some(NEW_TRUST_POLICY)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCUARPIAMTAGWR1", "Iam-Tag-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_assume_role_policy_parameters(Some("Sales-Target"), Some(NEW_TRUST_POLICY)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");

    // Rewriting a role's trust policy changes who can reach it, so IAM reports the permissions
    // boundary set on the role: a grant conditioned on iam:PermissionsBoundary reaches a role
    // under that boundary...
    let (principal, session_data) = database.user_identity("SVCUARPPBWR00001", "Boundary-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_assume_role_policy_parameters(Some("Bounded-Target"), Some(NEW_TRUST_POLICY)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and not a role carrying no boundary at all, whose key is absent rather than different.
    let (principal, session_data) = database.user_identity("SVCUARPPBWR00001", "Boundary-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_assume_role_policy_parameters(Some("Engineering-Target"), Some(NEW_TRUST_POLICY)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCUARPNOGRANT01", "No-Grant-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_assume_role_policy_parameters(Some("Engineering-Target"), Some(NEW_TRUST_POLICY)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Writer is not authorized to perform: \
                 iam:UpdateAssumeRolePolicy on resource: arn:aws:iam::{account_id}:role/Engineering-Target"
        )),
        "unexpected body: {body}"
    );

    // A role that does not exist is reported as NoSuchEntity to a caller allowed to write it.
    let (principal, session_data) = database.user_identity("SVCUARPBROADWR01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_assume_role_policy_parameters(Some("No-Such-Role"), Some(NEW_TRUST_POLICY)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A document that is not a policy at all is reported as MalformedPolicyDocument, after
    // authorization rather than before it.
    let (principal, session_data) = database.user_identity("SVCUARPBROADWR01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_assume_role_policy_parameters(Some("Engineering-Target"), Some("not a policy")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedPolicyDocument</Code>"), "unexpected body: {body}");

    // A request missing a required parameter is rejected before it is authorized.
    let (principal, session_data) = database.user_identity("SVCUARPNOGRANT01", "No-Grant-Writer");
    let (status, body) =
        call(&svc_state, principal, session_data, &update_assume_role_policy_parameters(None, Some(NEW_TRUST_POLICY)))
            .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_assume_role_policy_parameters(Some("Sales-Target"), Some(NEW_TRUST_POLICY)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
}
