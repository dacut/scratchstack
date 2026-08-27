use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The trust policy the seeded roles carry.
const TRUST_POLICY: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}"#;

/// Seed data for the `UpdateRoleDescription` authorization tests. The callers carry grants scoped
/// by the path of the role being retitled, by that role's tags, by the role itself, and by the
/// permissions boundary set on it -- which IAM lists for this action, unlike for tagging.
/// `Update-Role-Only` is allowed `iam:UpdateRole` and not `iam:UpdateRoleDescription`, so the two
/// actions can be seen not to imply one another.
const UPDATE_ROLE_DESCRIPTION_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'update-role-description-test@example.com', 'update-role-description-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCURDBROADUPD01', '%ACCOUNT_ID%', 'broad-updater', 'Broad-Updater', '/'),
    ('SVCURDPATHUPD001', '%ACCOUNT_ID%', 'path-updater', 'Path-Updater', '/'),
    ('SVCURDTAGUPD0001', '%ACCOUNT_ID%', 'tag-updater', 'Tag-Updater', '/'),
    ('SVCURDBOUNDUPD01', '%ACCOUNT_ID%', 'boundary-updater', 'Boundary-Updater', '/'),
    ('SVCURDNARROWUP01', '%ACCOUNT_ID%', 'narrow-updater', 'Narrow-Updater', '/'),
    ('SVCURDROLEONLY01', '%ACCOUNT_ID%', 'update-role-only', 'Update-Role-Only', '/'),
    ('SVCURDNOGRANTUP1', '%ACCOUNT_ID%', 'no-grant-updater', 'No-Grant-Updater', '/');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCURDPOLBOUND01', '%ACCOUNT_ID%', 'boundary-policy', 'Boundary-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCURDPOLBOUND01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document, description, permissions_boundary_managed_policy_id) VALUES
    ('SVCURDTGTPLAIN01', '%ACCOUNT_ID%', 'update-target', 'Update-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        'Runs the nightly batch.', NULL),
    ('SVCURDTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        NULL, NULL),
    ('SVCURDTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        NULL, NULL),
    ('SVCURDTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        NULL, NULL),
    ('SVCURDTGTBOUND01', '%ACCOUNT_ID%', 'bounded-target', 'Bounded-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        NULL, 'SVCURDPOLBOUND01'),
    ('SVCURDTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        NULL, NULL),
    ('SVCURDROLE000001', '%ACCOUNT_ID%', 'update-role-description-role', 'Update-Role-Description-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        NULL, NULL);

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCURDTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCURDTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCURDBROADUPD01', 'allow-retitle-any-role', 'Allow-Retitle-Any-Role',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:UpdateRoleDescription","iam:GetRole"],
        "Resource":"*"}]}'),
    ('SVCURDPATHUPD001', 'allow-retitle-division', 'Allow-Retitle-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateRoleDescription",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/division/*"}]}'),
    ('SVCURDTAGUPD0001', 'allow-retitle-engineering', 'Allow-Retitle-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateRoleDescription","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCURDBOUNDUPD01', 'allow-retitle-under-boundary', 'Allow-Retitle-Under-Boundary',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateRoleDescription","Resource":"*",
        "Condition":{"StringEquals":{"iam:PermissionsBoundary":
        "arn:aws:iam::%ACCOUNT_ID%:policy/Boundary-Policy"}}}]}'),
    ('SVCURDNARROWUP01', 'allow-retitle-target', 'Allow-Retitle-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateRoleDescription",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/Update-Target"}]}'),
    ('SVCURDROLEONLY01', 'allow-update-role-only', 'Allow-Update-Role-Only',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateRole","Resource":"*"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCURDROLE000001', 'allow-retitle-any-role', 'Allow-Retitle-Any-Role',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateRoleDescription",
        "Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `UpdateRoleDescription` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_update_role_description_authorization() {
    let database = TestDatabase::new(UPDATE_ROLE_DESCRIPTION_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:UpdateRoleDescription on any role replaces the description on one,
    // and the response reports the role as it stands afterwards.
    let (principal, session_data) = database.user_identity("SVCURDBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("Update-Target"), Some("Runs the hourly batch.")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UpdateRoleDescriptionResponse"), "unexpected body: {body}");
    assert!(body.contains("<Description>Runs the hourly batch.</Description>"), "unexpected body: {body}");
    assert!(body.contains("<RoleName>Update-Target</RoleName>"), "unexpected body: {body}");

    // The role the response carries reports its trust policy percent-encoded, the way every
    // other operation reporting a role does.
    assert_eq!(decoded_trust_policy_document(&body), TRUST_POLICY);

    // The write was committed rather than rolled back.
    let (principal, session_data) = database.user_identity("SVCURDBROADUPD01", "Broad-Updater");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Update-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Description>Runs the hourly batch.</Description>"), "unexpected body: {body}");
    assert!(!body.contains("nightly"), "unexpected body: {body}");

    // An empty description clears it rather than being rejected.
    let (principal, session_data) = database.user_identity("SVCURDBROADUPD01", "Broad-Updater");
    let (status, body) =
        call(&svc_state, principal, session_data, &update_role_description_parameters(Some("Update-Target"), Some("")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCURDBROADUPD01", "Broad-Updater");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Update-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("hourly"), "unexpected body: {body}");

    // The role name is matched case-insensitively, as it is everywhere else.
    let (principal, session_data) = database.user_identity("SVCURDBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("UPDATE-TARGET"), Some("Cased.")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<RoleName>Update-Target</RoleName>"), "unexpected body: {body}");

    // iam:UpdateRole does not imply iam:UpdateRoleDescription: they are distinct actions, and a
    // grant of the broader one does not carry the narrower.
    let (principal, session_data) = database.user_identity("SVCURDROLEONLY01", "Update-Role-Only");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("Update-Target"), Some("Not allowed.")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The resource ARN carries the target role's path, so a grant scoped to a path prefix
    // reaches roles under that path...
    let (principal, session_data) = database.user_identity("SVCURDPATHUPD001", "Path-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("Division-Target"), Some("In the division.")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCURDPATHUPD001", "Path-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("Update-Target"), Some("Out of reach.")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the role back the aws:ResourceTag condition keys.
    let (principal, session_data) = database.user_identity("SVCURDTAGUPD0001", "Tag-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("Engineering-Target"), Some("Owned by engineering.")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A role carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCURDTAGUPD0001", "Tag-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("Sales-Target"), Some("Not owned by engineering.")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The boundary set on the role backs iam:PermissionsBoundary, which IAM lists for this
    // action, so a grant confined to roles under a boundary reaches one carrying it...
    let (principal, session_data) = database.user_identity("SVCURDBOUNDUPD01", "Boundary-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("Bounded-Target"), Some("Under the boundary.")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and not a role under no boundary, which supplies no key for the condition to match.
    let (principal, session_data) = database.user_identity("SVCURDBOUNDUPD01", "Boundary-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("Sales-Target"), Some("Under no boundary.")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single role reaches it and no other.
    let (principal, session_data) = database.user_identity("SVCURDNARROWUP01", "Narrow-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("Update-Target"), Some("Narrowly retitled.")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCURDNARROWUP01", "Narrow-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("Sales-Target"), Some("Out of reach.")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCURDNOGRANTUP1", "No-Grant-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("Update-Target"), Some("Denied.")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Updater is not authorized to perform: \
                 iam:UpdateRoleDescription on resource: arn:aws:iam::{account_id}:role/Update-Target"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled the transaction back, so the description is the one the last allowed
    // caller wrote.
    let (principal, session_data) = database.user_identity("SVCURDBROADUPD01", "Broad-Updater");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Update-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Description>Narrowly retitled.</Description>"), "unexpected body: {body}");

    // A role that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:UpdateRoleDescription on any role is told the role is missing...
    let (principal, session_data) = database.user_identity("SVCURDBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("No-Such-Role"), Some("Nowhere.")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific role learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCURDNARROWUP01", "Narrow-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("No-Such-Role"), Some("Nowhere.")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // RoleName and Description are both required; Description is not optional here as it is on
    // UpdateRole, since replacing it is the whole of what this does.
    for parameters in [
        update_role_description_parameters(None, Some("Orphaned.")),
        update_role_description_parameters(Some("Update-Target"), None),
    ] {
        let (principal, session_data) = database.user_identity("SVCURDBROADUPD01", "Broad-Updater");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // A role name that is not a role name is rejected before the request is authorized.
    let (principal, session_data) = database.user_identity("SVCURDBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("Bad Role Name"), Some("Malformed.")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCURDROLE000001", "Update-Role-Description-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("Sales-Target"), Some("Retitled from a session.")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_role_description_parameters(Some("Root-Target"), Some("Retitled by root.")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
}
