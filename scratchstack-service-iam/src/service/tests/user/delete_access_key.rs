use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `DeleteAccessKey` authorization tests. Every target carries a key of its
/// own, so a delete that reaches past the user it was authorized against would be visible;
/// `Key-Target` carries two, so one can be deleted and the other shown to survive. The callers
/// carry grants scoped by the path of the user carrying the key, by that user's tags, and by
/// the user itself.
const DELETE_ACCESS_KEY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'delete-access-key-test@example.com', 'delete-access-key-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCDAKBROADDEL01', '%ACCOUNT_ID%', 'broad-deleter', 'Broad-Deleter', '/'),
    ('SVCDAKPATHDEL001', '%ACCOUNT_ID%', 'path-deleter', 'Path-Deleter', '/'),
    ('SVCDAKTAGDEL0001', '%ACCOUNT_ID%', 'tag-deleter', 'Tag-Deleter', '/'),
    ('SVCDAKNARROWDL01', '%ACCOUNT_ID%', 'narrow-deleter', 'Narrow-Deleter', '/'),
    ('SVCDAKNOGRANTD01', '%ACCOUNT_ID%', 'no-grant-deleter', 'No-Grant-Deleter', '/'),
    ('SVCDAKSELFDEL001', '%ACCOUNT_ID%', 'self-deleter', 'Self-Deleter', '/'),
    ('SVCDAKTGTPLAIN01', '%ACCOUNT_ID%', 'key-target', 'Key-Target', '/'),
    ('SVCDAKTGTOTHER01', '%ACCOUNT_ID%', 'other-target', 'Other-Target', '/'),
    ('SVCDAKTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/'),
    ('SVCDAKTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/'),
    ('SVCDAKTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/'),
    ('SVCDAKTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCDAKTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCDAKTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.user_credentials(access_key_id, user_id, secret_key, enabled) VALUES
    ('DAKTARGETKEY0001', 'SVCDAKTGTPLAIN01', 'delete-target-secret-1', TRUE),
    ('DAKTARGETKEY0002', 'SVCDAKTGTPLAIN01', 'delete-target-secret-2', TRUE),
    ('DAKOTHERKEY00001', 'SVCDAKTGTOTHER01', 'delete-other-secret', TRUE),
    ('DAKDIVISIONKEY01', 'SVCDAKTGTDIVSN01', 'delete-division-secret', TRUE),
    ('DAKENGINEERKY001', 'SVCDAKTGTENGNR01', 'delete-engineering-secret', TRUE),
    ('DAKSALESKEY00001', 'SVCDAKTGTSALES01', 'delete-sales-secret', TRUE),
    ('DAKROOTKEY000001', 'SVCDAKTGTROOT001', 'delete-root-secret', TRUE),
    ('DAKSELFKEY000001', 'SVCDAKSELFDEL001', 'delete-self-secret', TRUE);

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDAKBROADDEL01', 'allow-delete-any-key', 'Allow-Delete-Any-Key',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteAccessKey","Resource":"*"}]}'),
    ('SVCDAKPATHDEL001', 'allow-delete-division-keys', 'Allow-Delete-Division-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteAccessKey",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/division/*"}]}'),
    ('SVCDAKTAGDEL0001', 'allow-delete-engineering-keys', 'Allow-Delete-Engineering-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteAccessKey","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCDAKNARROWDL01', 'allow-delete-target-keys', 'Allow-Delete-Target-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteAccessKey",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/Key-Target"}]}'),
    ('SVCDAKSELFDEL001', 'allow-delete-own-keys', 'Allow-Delete-Own-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteAccessKey",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/Self-Deleter"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCDAKROLE000001', '%ACCOUNT_ID%', 'delete-access-key-role', 'Delete-Access-Key-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDAKROLE000001', 'allow-delete-any-key', 'Allow-Delete-Any-Key',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteAccessKey","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `DeleteAccessKey` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_delete_access_key_authorization() {
    const TARGET_KEY: &str = "AKIADAKTARGETKEY0001";
    const OTHER_TARGET_KEY: &str = "AKIADAKOTHERKEY00001";

    let database = TestDatabase::new(DELETE_ACCESS_KEY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:DeleteAccessKey on any user deletes one of that user's keys.
    let (principal, session_data) = database.user_identity("SVCDAKBROADDEL01", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_access_key_parameters(Some("Key-Target"), Some(TARGET_KEY)))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DeleteAccessKeyResponse"), "unexpected body: {body}");

    // The key is gone and the user's other key is untouched: AccessKeyId names one key, not
    // the set of them.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Key-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains(TARGET_KEY), "unexpected body: {body}");
    assert!(body.contains("<AccessKeyId>AKIADAKTARGETKEY0002</AccessKeyId>"), "unexpected body: {body}");

    // Deleting it again reports it missing rather than succeeding silently.
    let (principal, session_data) = database.user_identity("SVCDAKBROADDEL01", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_access_key_parameters(Some("Key-Target"), Some(TARGET_KEY)))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A key belonging to another user is reported missing rather than deleted, even for a
    // caller allowed the action on every user: the key must belong to the user the request
    // names, which is the user the request was authorized against.
    let (principal, session_data) = database.user_identity("SVCDAKBROADDEL01", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_access_key_parameters(Some("Key-Target"), Some(OTHER_TARGET_KEY)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // That other user still carries its key.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Other-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains(&format!("<AccessKeyId>{OTHER_TARGET_KEY}</AccessKeyId>")), "unexpected body: {body}");

    // An omitted UserName names the calling user, which is what Self-Deleter is granted its
    // keys on.
    let (principal, session_data) = database.user_identity("SVCDAKSELFDEL001", "Self-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_access_key_parameters(None, Some("AKIADAKSELFKEY000001")))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The resource ARN carries the path of the user carrying the key, so a grant scoped to a
    // path prefix reaches users under that path...
    let (principal, session_data) = database.user_identity("SVCDAKPATHDEL001", "Path-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_access_key_parameters(Some("Division-Target"), Some("AKIADAKDIVISIONKEY01")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCDAKPATHDEL001", "Path-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_access_key_parameters(Some("Key-Target"), Some("AKIADAKTARGETKEY0002")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the user carrying the key back the aws:ResourceTag condition keys.
    let (principal, session_data) = database.user_identity("SVCDAKTAGDEL0001", "Tag-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_access_key_parameters(Some("Engineering-Target"), Some("AKIADAKENGINEERKY001")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCDAKTAGDEL0001", "Tag-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_access_key_parameters(Some("Sales-Target"), Some("AKIADAKSALESKEY00001")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled its transaction back, so that key is still there to sign with.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Sales-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<AccessKeyId>AKIADAKSALESKEY00001</AccessKeyId>"), "unexpected body: {body}");

    // A grant naming a single user reaches every key that user carries -- there is no naming
    // an access key in a resource ARN -- and reaches no other user.
    let (principal, session_data) = database.user_identity("SVCDAKNARROWDL01", "Narrow-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_access_key_parameters(Some("Key-Target"), Some("AKIADAKTARGETKEY0002")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCDAKNARROWDL01", "Narrow-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_access_key_parameters(Some("Other-Target"), Some(OTHER_TARGET_KEY)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCDAKNOGRANTD01", "No-Grant-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_access_key_parameters(Some("Other-Target"), Some(OTHER_TARGET_KEY)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Deleter is not authorized to perform: \
                 iam:DeleteAccessKey on resource: arn:aws:iam::{account_id}:user/Other-Target"
        )),
        "unexpected body: {body}"
    );

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:DeleteAccessKey on any user is told the key is missing...
    let (principal, session_data) = database.user_identity("SVCDAKBROADDEL01", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_access_key_parameters(Some("No-Such-User"), Some(OTHER_TARGET_KEY)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCDAKNARROWDL01", "Narrow-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_access_key_parameters(Some("No-Such-User"), Some(OTHER_TARGET_KEY)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // AccessKeyId is required, and there is nothing for it to default to.
    let (principal, session_data) = database.user_identity("SVCDAKBROADDEL01", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_access_key_parameters(Some("Key-Target"), None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // An access key id too short to be one, or carrying characters an id never carries, is
    // rejected before the request is authorized, so even a caller with no grant is told the id
    // is malformed rather than denied.
    for access_key_id in ["AKIA123", "AKIA/DAK/TARGET/KEY"] {
        let (principal, session_data) = database.user_identity("SVCDAKNOGRANTD01", "No-Grant-Deleter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &delete_access_key_parameters(Some("Other-Target"), Some(access_key_id)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // The AKIA prefix, on the other hand, is checked by the delete itself, after the request
    // is authorized: an id shaped like one but naming another kind of credential reaches an
    // allowed caller as a validation failure...
    let (principal, session_data) = database.user_identity("SVCDAKBROADDEL01", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_access_key_parameters(Some("Other-Target"), Some("ASIADAKOTHERKEY00001")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // ...and a caller with no grant is denied before it gets that far.
    let (principal, session_data) = database.user_identity("SVCDAKNOGRANTD01", "No-Grant-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_access_key_parameters(Some("Other-Target"), Some("ASIADAKOTHERKEY00001")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Credentials that identify no IAM user have nothing for an omitted UserName to name, so
    // they must name the user outright.
    for (principal, session_data) in
        [database.role_identity("SVCDAKROLE000001", "Delete-Access-Key-Role"), database.root_identity()]
    {
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_access_key_parameters(None, Some(OTHER_TARGET_KEY)))
                .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
        assert!(
            body.contains("Must specify userName when calling with non-User credentials"),
            "unexpected body: {body}"
        );
    }

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCDAKROLE000001", "Delete-Access-Key-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_access_key_parameters(Some("Other-Target"), Some(OTHER_TARGET_KEY)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_access_key_parameters(Some("Root-Target"), Some("AKIADAKROOTKEY000001")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Root-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains("<ListAccessKeysResult><AccessKeyMetadata/></ListAccessKeysResult>"),
        "unexpected body: {body}"
    );
}
