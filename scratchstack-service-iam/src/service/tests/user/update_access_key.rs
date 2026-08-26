use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `UpdateAccessKey` authorization tests. Every target carries an active key
/// of its own, so a state change that reaches past the user it was authorized against would be
/// visible. The callers carry grants scoped by the path of the user carrying the key, by that
/// user's tags, and by the user itself.
const UPDATE_ACCESS_KEY_TEST_DATA: &str = r#"
    INSERT INTO iam.partition(partition) VALUES ('aws');

    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('123456789012', 'update-access-key-test@example.com', 'update-access-key-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCUAKBROADUPD01', '123456789012', 'broad-updater', 'Broad-Updater', '/'),
    ('SVCUAKPATHUPD001', '123456789012', 'path-updater', 'Path-Updater', '/'),
    ('SVCUAKTAGUPD0001', '123456789012', 'tag-updater', 'Tag-Updater', '/'),
    ('SVCUAKNARROWUP01', '123456789012', 'narrow-updater', 'Narrow-Updater', '/'),
    ('SVCUAKNOGRANTU01', '123456789012', 'no-grant-updater', 'No-Grant-Updater', '/'),
    ('SVCUAKSELFUPD001', '123456789012', 'self-updater', 'Self-Updater', '/'),
    ('SVCUAKTGTPLAIN01', '123456789012', 'key-target', 'Key-Target', '/'),
    ('SVCUAKTGTOTHER01', '123456789012', 'other-target', 'Other-Target', '/'),
    ('SVCUAKTGTDIVSN01', '123456789012', 'division-target', 'Division-Target', '/division/'),
    ('SVCUAKTGTENGNR01', '123456789012', 'engineering-target', 'Engineering-Target', '/'),
    ('SVCUAKTGTSALES01', '123456789012', 'sales-target', 'Sales-Target', '/'),
    ('SVCUAKTGTROOT001', '123456789012', 'root-target', 'Root-Target', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCUAKTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCUAKTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.user_credentials(access_key_id, user_id, secret_key, enabled) VALUES
    ('UAKTARGETKEY0001', 'SVCUAKTGTPLAIN01', 'update-target-secret', TRUE),
    ('UAKOTHERKEY00001', 'SVCUAKTGTOTHER01', 'update-other-secret', TRUE),
    ('UAKDIVISIONKEY01', 'SVCUAKTGTDIVSN01', 'update-division-secret', TRUE),
    ('UAKENGINEERKY001', 'SVCUAKTGTENGNR01', 'update-engineering-secret', TRUE),
    ('UAKSALESKEY00001', 'SVCUAKTGTSALES01', 'update-sales-secret', TRUE),
    ('UAKROOTKEY000001', 'SVCUAKTGTROOT001', 'update-root-secret', TRUE),
    ('UAKSELFKEY000001', 'SVCUAKSELFUPD001', 'update-self-secret', TRUE);

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCUAKBROADUPD01', 'allow-update-any-key', 'Allow-Update-Any-Key',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateAccessKey","Resource":"*"}]}'),
    ('SVCUAKPATHUPD001', 'allow-update-division-keys', 'Allow-Update-Division-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateAccessKey",
        "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
    ('SVCUAKTAGUPD0001', 'allow-update-engineering-keys', 'Allow-Update-Engineering-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateAccessKey","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCUAKNARROWUP01', 'allow-update-target-keys', 'Allow-Update-Target-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateAccessKey",
        "Resource":"arn:aws:iam::123456789012:user/Key-Target"}]}'),
    ('SVCUAKSELFUPD001', 'allow-update-own-keys', 'Allow-Update-Own-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateAccessKey",
        "Resource":"arn:aws:iam::123456789012:user/Self-Updater"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCUAKROLE000001', '123456789012', 'update-access-key-role', 'Update-Access-Key-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCUAKROLE000001', 'allow-update-any-key', 'Allow-Update-Any-Key',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateAccessKey","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `UpdateAccessKey` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one database, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_update_access_key_authorization() {
    const TARGET_KEY: &str = "AKIAUAKTARGETKEY0001";
    const OTHER_TARGET_KEY: &str = "AKIAUAKOTHERKEY00001";

    let database = TestDatabase::new(UPDATE_ACCESS_KEY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();

    // A caller allowed iam:UpdateAccessKey on any user deactivates one of that user's keys.
    let (principal, session_data) = user_identity("SVCUAKBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_access_key_parameters(Some("Key-Target"), Some(TARGET_KEY), Some("Inactive")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UpdateAccessKeyResponse"), "unexpected body: {body}");

    // The key is still there, and is now inactive: deactivating revokes the credential without
    // discarding it, which is what tells it apart from deleting it.
    let (principal, session_data) = root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Key-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains(&format!("<AccessKeyId>{TARGET_KEY}</AccessKeyId>")), "unexpected body: {body}");
    assert!(body.contains("<Status>Inactive</Status>"), "unexpected body: {body}");

    // Naming the state it is already in succeeds and changes nothing, and the key can be
    // activated again afterwards.
    for status_value in ["Inactive", "Active"] {
        let (principal, session_data) = user_identity("SVCUAKBROADUPD01", "Broad-Updater");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &update_access_key_parameters(Some("Key-Target"), Some(TARGET_KEY), Some(status_value)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    }

    let (principal, session_data) = root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Key-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Status>Active</Status>"), "unexpected body: {body}");

    // A key belonging to another user is reported missing rather than updated, even for a
    // caller allowed the action on every user: the key must belong to the user the request
    // names, which is the user the request was authorized against.
    let (principal, session_data) = user_identity("SVCUAKBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_access_key_parameters(Some("Key-Target"), Some(OTHER_TARGET_KEY), Some("Inactive")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // That other user's key is untouched.
    let (principal, session_data) = root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Other-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Status>Active</Status>"), "unexpected body: {body}");

    // An omitted UserName names the calling user, which is what Self-Updater is granted its
    // keys on.
    let (principal, session_data) = user_identity("SVCUAKSELFUPD001", "Self-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_access_key_parameters(None, Some("AKIAUAKSELFKEY000001"), Some("Inactive")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The resource ARN carries the path of the user carrying the key, so a grant scoped to a
    // path prefix reaches users under that path...
    let (principal, session_data) = user_identity("SVCUAKPATHUPD001", "Path-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_access_key_parameters(Some("Division-Target"), Some("AKIAUAKDIVISIONKEY01"), Some("Inactive")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = user_identity("SVCUAKPATHUPD001", "Path-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_access_key_parameters(Some("Key-Target"), Some(TARGET_KEY), Some("Inactive")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the user carrying the key back the aws:ResourceTag condition keys.
    let (principal, session_data) = user_identity("SVCUAKTAGUPD0001", "Tag-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_access_key_parameters(Some("Engineering-Target"), Some("AKIAUAKENGINEERKY001"), Some("Inactive")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = user_identity("SVCUAKTAGUPD0001", "Tag-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_access_key_parameters(Some("Sales-Target"), Some("AKIAUAKSALESKEY00001"), Some("Inactive")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled its transaction back, so that key is still active.
    let (principal, session_data) = root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Sales-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Status>Active</Status>"), "unexpected body: {body}");

    // A grant naming a single user reaches every key that user carries -- there is no naming
    // an access key in a resource ARN -- and reaches no other user.
    let (principal, session_data) = user_identity("SVCUAKNARROWUP01", "Narrow-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_access_key_parameters(Some("Key-Target"), Some(TARGET_KEY), Some("Inactive")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = user_identity("SVCUAKNARROWUP01", "Narrow-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_access_key_parameters(Some("Other-Target"), Some(OTHER_TARGET_KEY), Some("Inactive")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = user_identity("SVCUAKNOGRANTU01", "No-Grant-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_access_key_parameters(Some("Other-Target"), Some(OTHER_TARGET_KEY), Some("Inactive")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/No-Grant-Updater is not authorized to perform: \
                 iam:UpdateAccessKey on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Other-Target"
        )),
        "unexpected body: {body}"
    );

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:UpdateAccessKey on any user is told the key is missing...
    let (principal, session_data) = user_identity("SVCUAKBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_access_key_parameters(Some("No-Such-User"), Some(OTHER_TARGET_KEY), Some("Inactive")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = user_identity("SVCUAKNARROWUP01", "Narrow-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_access_key_parameters(Some("No-Such-User"), Some(OTHER_TARGET_KEY), Some("Inactive")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // AccessKeyId and Status are both required, and a Status naming no state this service
    // knows never becomes a value the request can carry; all three are malformed input rather
    // than validation failures.
    for parameters in [
        update_access_key_parameters(Some("Key-Target"), None, Some("Inactive")),
        update_access_key_parameters(Some("Key-Target"), Some(TARGET_KEY), None),
        update_access_key_parameters(Some("Key-Target"), Some(TARGET_KEY), Some("Disabled")),
    ] {
        let (principal, session_data) = user_identity("SVCUAKBROADUPD01", "Broad-Updater");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // Expired is a state a credential can be in but not one this operation can assign, so a
    // request naming it is a validation failure rather than malformed input -- and it is the
    // update that says so, after the request is authorized.
    let (principal, session_data) = user_identity("SVCUAKBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_access_key_parameters(Some("Key-Target"), Some(TARGET_KEY), Some("Expired")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    let (principal, session_data) = user_identity("SVCUAKNOGRANTU01", "No-Grant-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_access_key_parameters(Some("Key-Target"), Some(TARGET_KEY), Some("Expired")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // An access key id too short to be one, or carrying characters an id never carries, is
    // rejected before the request is authorized, so even a caller with no grant is told the id
    // is malformed rather than denied.
    for access_key_id in ["AKIA123", "AKIA/UAK/TARGET/KEY"] {
        let (principal, session_data) = user_identity("SVCUAKNOGRANTU01", "No-Grant-Updater");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &update_access_key_parameters(Some("Key-Target"), Some(access_key_id), Some("Inactive")),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // Credentials that identify no IAM user have nothing for an omitted UserName to name, so
    // they must name the user outright.
    for (principal, session_data) in [role_identity("SVCUAKROLE000001", "Update-Access-Key-Role"), root_identity()] {
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &update_access_key_parameters(None, Some(OTHER_TARGET_KEY), Some("Inactive")),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
        assert!(
            body.contains("Must specify userName when calling with non-User credentials"),
            "unexpected body: {body}"
        );
    }

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = role_identity("SVCUAKROLE000001", "Update-Access-Key-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_access_key_parameters(Some("Other-Target"), Some(OTHER_TARGET_KEY), Some("Inactive")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_access_key_parameters(Some("Root-Target"), Some("AKIAUAKROOTKEY000001"), Some("Inactive")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Root-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Status>Inactive</Status>"), "unexpected body: {body}");
}
