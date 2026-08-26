use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `CreateAccessKey` authorization tests. No target carries a key to begin
/// with, so a key found on one afterwards is the one the test created. The callers carry
/// grants scoped by the path of the user receiving the key, by that user's tags, and by the
/// user itself; `Self-Creator` is granted a key on itself, which is what an omitted `UserName`
/// resolves to.
const CREATE_ACCESS_KEY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'create-access-key-test@example.com', 'create-access-key-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCCAKBROADCRT01', '%ACCOUNT_ID%', 'broad-creator', 'Broad-Creator', '/'),
    ('SVCCAKPATHCRT001', '%ACCOUNT_ID%', 'path-creator', 'Path-Creator', '/'),
    ('SVCCAKTAGCRT0001', '%ACCOUNT_ID%', 'tag-creator', 'Tag-Creator', '/'),
    ('SVCCAKNARROWCR01', '%ACCOUNT_ID%', 'narrow-creator', 'Narrow-Creator', '/'),
    ('SVCCAKNOGRANTC01', '%ACCOUNT_ID%', 'no-grant-creator', 'No-Grant-Creator', '/'),
    ('SVCCAKSELFCRT001', '%ACCOUNT_ID%', 'self-creator', 'Self-Creator', '/'),
    ('SVCCAKTGTPLAIN01', '%ACCOUNT_ID%', 'key-target', 'Key-Target', '/'),
    ('SVCCAKTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/'),
    ('SVCCAKTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/'),
    ('SVCCAKTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/'),
    ('SVCCAKTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCCAKTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCCAKTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCCAKBROADCRT01', 'allow-create-any-key', 'Allow-Create-Any-Key',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateAccessKey","Resource":"*"}]}'),
    ('SVCCAKPATHCRT001', 'allow-create-division-keys', 'Allow-Create-Division-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateAccessKey",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/division/*"}]}'),
    ('SVCCAKTAGCRT0001', 'allow-create-engineering-keys', 'Allow-Create-Engineering-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateAccessKey","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCCAKNARROWCR01', 'allow-create-target-keys', 'Allow-Create-Target-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateAccessKey",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/Key-Target"}]}'),
    ('SVCCAKSELFCRT001', 'allow-create-own-keys', 'Allow-Create-Own-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateAccessKey",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/Self-Creator"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCCAKROLE000001', '%ACCOUNT_ID%', 'create-access-key-role', 'Create-Access-Key-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCCAKROLE000001', 'allow-create-any-key', 'Allow-Create-Any-Key',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateAccessKey","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `CreateAccessKey` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_create_access_key_authorization() {
    let database = TestDatabase::new(CREATE_ACCESS_KEY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:CreateAccessKey on any user creates a key for one, and is handed the
    // secret along with it. A new key is active, so it can be signed with immediately.
    let (principal, session_data) = database.user_identity("SVCCAKBROADCRT01", "Broad-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_access_key_parameters(Some("Key-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>Key-Target</UserName>"), "unexpected body: {body}");
    assert!(body.contains("<Status>Active</Status>"), "unexpected body: {body}");
    assert!(body.contains("<SecretAccessKey>"), "unexpected body: {body}");

    // The id is shaped as IAM spells an access key id: the AKIA prefix and sixteen further
    // characters.
    let created = access_key_id(&body);
    assert!(created.starts_with("AKIA"), "unexpected access key id: {created}");
    assert_eq!(created.len(), 20, "unexpected access key id: {created}");

    // The key was committed, so the root user -- implicitly allowed everything -- reads it back
    // from the user. It reads back without the secret: the secret is reported by the creation
    // and by nothing afterwards.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Key-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains(&format!("<AccessKeyId>{created}</AccessKeyId>")), "unexpected body: {body}");
    assert!(!body.contains("SecretAccessKey"), "unexpected body: {body}");

    // An omitted UserName names the calling user, which is what Self-Creator is granted keys
    // on...
    let (principal, session_data) = database.user_identity("SVCCAKSELFCRT001", "Self-Creator");
    let (status, body) = call(&svc_state, principal, session_data, &create_access_key_parameters(None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>Self-Creator</UserName>"), "unexpected body: {body}");

    // ...and only on the calling user: the default is a convenience, not a widening of the
    // grant.
    let (principal, session_data) = database.user_identity("SVCCAKSELFCRT001", "Self-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_access_key_parameters(Some("Key-Target"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The resource ARN carries the receiving user's path, so a grant scoped to a path prefix
    // reaches users under that path...
    let (principal, session_data) = database.user_identity("SVCCAKPATHCRT001", "Path-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_access_key_parameters(Some("Division-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>Division-Target</UserName>"), "unexpected body: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCCAKPATHCRT001", "Path-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_access_key_parameters(Some("Key-Target"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the user receiving the key back the aws:ResourceTag condition keys.
    let (principal, session_data) = database.user_identity("SVCCAKTAGCRT0001", "Tag-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_access_key_parameters(Some("Engineering-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCCAKTAGCRT0001", "Tag-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_access_key_parameters(Some("Sales-Target"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Neither does a user carrying no tags at all: the condition key is absent.
    let (principal, session_data) = database.user_identity("SVCCAKTAGCRT0001", "Tag-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_access_key_parameters(Some("Key-Target"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled its transaction back, so no key was minted for that user: a caller
    // denied the action does not leave a usable credential behind.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Sales-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains("<ListAccessKeysResult><AccessKeyMetadata/></ListAccessKeysResult>"),
        "unexpected body: {body}"
    );

    // A grant naming a single user reaches keys minted for that user, and reaches no other
    // user.
    let (principal, session_data) = database.user_identity("SVCCAKNARROWCR01", "Narrow-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_access_key_parameters(Some("Key-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCCAKNARROWCR01", "Narrow-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_access_key_parameters(Some("Engineering-Target"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCCAKNOGRANTC01", "No-Grant-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_access_key_parameters(Some("Key-Target"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Creator is not authorized to perform: \
                 iam:CreateAccessKey on resource: arn:aws:iam::{account_id}:user/Key-Target"
        )),
        "unexpected body: {body}"
    );

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:CreateAccessKey on any user is told the user is missing...
    let (principal, session_data) = database.user_identity("SVCCAKBROADCRT01", "Broad-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_access_key_parameters(Some("No-Such-User"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCCAKNARROWCR01", "Narrow-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_access_key_parameters(Some("No-Such-User"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A user name that cannot name a user is rejected before the request is authorized, so
    // even a caller with no grant is told the name is malformed rather than denied.
    let (principal, session_data) = database.user_identity("SVCCAKNOGRANTC01", "No-Grant-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_access_key_parameters(Some("Not/A/User-Name"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // Credentials that identify no IAM user have nothing for an omitted UserName to name, so
    // they must name the user outright.
    for (principal, session_data) in
        [database.role_identity("SVCCAKROLE000001", "Create-Access-Key-Role"), database.root_identity()]
    {
        let (status, body) = call(&svc_state, principal, session_data, &create_access_key_parameters(None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
        assert!(
            body.contains("Must specify userName when calling with non-User credentials"),
            "unexpected body: {body}"
        );
    }

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCCAKROLE000001", "Create-Access-Key-Role");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_access_key_parameters(Some("Key-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &create_access_key_parameters(Some("Root-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    let created = access_key_id(&body);

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Root-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains(&format!("<AccessKeyId>{created}</AccessKeyId>")), "unexpected body: {body}");
}
