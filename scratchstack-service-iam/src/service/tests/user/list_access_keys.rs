use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `ListAccessKeys` authorization tests. `Key-Holder` carries several keys,
/// one of them deactivated, so a listing can be paged through and shown to report the state of
/// each key; `Empty-Target` carries none, so a user without keys can be told apart from one
/// that does not exist. The remaining targets carry the paths and tags the resource ARN and the
/// `aws:ResourceTag` condition keys are derived from.
const LIST_ACCESS_KEYS_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'list-access-keys-test@example.com', 'list-access-keys-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCLAKBROADLST01', '%ACCOUNT_ID%', 'broad-lister', 'Broad-Lister', '/'),
    ('SVCLAKPATHLST001', '%ACCOUNT_ID%', 'path-lister', 'Path-Lister', '/'),
    ('SVCLAKTAGLST0001', '%ACCOUNT_ID%', 'tag-lister', 'Tag-Lister', '/'),
    ('SVCLAKNARROWLS01', '%ACCOUNT_ID%', 'narrow-lister', 'Narrow-Lister', '/'),
    ('SVCLAKNOGRANTL01', '%ACCOUNT_ID%', 'no-grant-lister', 'No-Grant-Lister', '/'),
    ('SVCLAKSELFLST001', '%ACCOUNT_ID%', 'self-lister', 'Self-Lister', '/'),
    ('SVCLAKTGTHOLDER1', '%ACCOUNT_ID%', 'key-holder', 'Key-Holder', '/'),
    ('SVCLAKTGTEMPTY01', '%ACCOUNT_ID%', 'empty-target', 'Empty-Target', '/'),
    ('SVCLAKTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/'),
    ('SVCLAKTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/'),
    ('SVCLAKTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/'),
    ('SVCLAKTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCLAKTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCLAKTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.user_credentials(access_key_id, user_id, secret_key, enabled) VALUES
    ('LAKHOLDERKEY0001', 'SVCLAKTGTHOLDER1', 'list-holder-secret-1', TRUE),
    ('LAKHOLDERKEY0002', 'SVCLAKTGTHOLDER1', 'list-holder-secret-2', FALSE),
    ('LAKHOLDERKEY0003', 'SVCLAKTGTHOLDER1', 'list-holder-secret-3', TRUE),
    ('LAKDIVISIONKEY01', 'SVCLAKTGTDIVSN01', 'list-division-secret', TRUE),
    ('LAKENGINEERKY001', 'SVCLAKTGTENGNR01', 'list-engineering-secret', TRUE),
    ('LAKSALESKEY00001', 'SVCLAKTGTSALES01', 'list-sales-secret', TRUE),
    ('LAKROOTKEY000001', 'SVCLAKTGTROOT001', 'list-root-secret', TRUE),
    ('LAKSELFKEY000001', 'SVCLAKSELFLST001', 'list-self-secret', TRUE);

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLAKBROADLST01', 'allow-list-any-keys', 'Allow-List-Any-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAccessKeys","Resource":"*"}]}'),
    ('SVCLAKPATHLST001', 'allow-list-division-keys', 'Allow-List-Division-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAccessKeys",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/division/*"}]}'),
    ('SVCLAKTAGLST0001', 'allow-list-engineering-keys', 'Allow-List-Engineering-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAccessKeys","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCLAKNARROWLS01', 'allow-list-holder-keys', 'Allow-List-Holder-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAccessKeys",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/Key-Holder"}]}'),
    ('SVCLAKSELFLST001', 'allow-list-own-keys', 'Allow-List-Own-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAccessKeys",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/Self-Lister"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCLAKROLE000001', '%ACCOUNT_ID%', 'list-access-keys-role', 'List-Access-Keys-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLAKROLE000001', 'allow-list-any-keys', 'Allow-List-Any-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAccessKeys","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `ListAccessKeys` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case so that they share one
/// seeded account, rather than seeding one apiece.
#[test_log::test(tokio::test)]
async fn test_list_access_keys_authorization() {
    let database = TestDatabase::new(LIST_ACCESS_KEYS_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:ListAccessKeys on any user reads the keys on one, ordered by id,
    // each with the user it belongs to and the state it is in.
    let (principal, session_data) = database.user_identity("SVCLAKBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Key-Holder"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<AccessKeyId>AKIALAKHOLDERKEY0001</AccessKeyId>"), "unexpected body: {body}");
    assert!(body.contains("<AccessKeyId>AKIALAKHOLDERKEY0002</AccessKeyId>"), "unexpected body: {body}");
    assert!(body.contains("<AccessKeyId>AKIALAKHOLDERKEY0003</AccessKeyId>"), "unexpected body: {body}");
    assert!(body.contains("<UserName>Key-Holder</UserName>"), "unexpected body: {body}");
    assert_eq!(access_key_id(&body), "AKIALAKHOLDERKEY0001", "unexpected body: {body}");

    // A deactivated key is reported alongside the active ones, as inactive: the listing says
    // which keys exist, not which of them can be signed with.
    assert!(body.contains("<Status>Active</Status>"), "unexpected body: {body}");
    assert!(body.contains("<Status>Inactive</Status>"), "unexpected body: {body}");

    // The secret is not among what is reported: it is handed out by CreateAccessKey and by
    // nothing afterwards, so a caller allowed to list a user's keys cannot sign as that user.
    assert!(!body.contains("SecretAccessKey"), "unexpected body: {body}");

    // A user carrying no keys at all is an empty listing rather than a missing user.
    let (principal, session_data) = database.user_identity("SVCLAKBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Empty-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains("<ListAccessKeysResult><AccessKeyMetadata/></ListAccessKeysResult>"),
        "unexpected body: {body}"
    );

    // MaxItems bounds a page, and a bounded page reports the marker the next one continues
    // from...
    let (principal, session_data) = database.user_identity("SVCLAKBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Key-Holder"), Some(2), None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<IsTruncated>true</IsTruncated>"), "unexpected body: {body}");
    assert!(body.contains("<AccessKeyId>AKIALAKHOLDERKEY0001</AccessKeyId>"), "unexpected body: {body}");
    assert!(body.contains("<AccessKeyId>AKIALAKHOLDERKEY0002</AccessKeyId>"), "unexpected body: {body}");
    assert!(!body.contains("AKIALAKHOLDERKEY0003"), "unexpected body: {body}");
    let marker = pagination_marker(&body);

    // ...which reports the rest, and reports itself as the last page.
    let (principal, session_data) = database.user_identity("SVCLAKBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_access_keys_parameters(Some("Key-Holder"), Some(2), Some(&marker)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<AccessKeyId>AKIALAKHOLDERKEY0003</AccessKeyId>"), "unexpected body: {body}");
    assert!(!body.contains("AKIALAKHOLDERKEY0001"), "unexpected body: {body}");
    assert!(!body.contains("<IsTruncated>"), "unexpected body: {body}");

    // An omitted UserName names the calling user, which is what Self-Lister is granted its
    // keys on.
    let (principal, session_data) = database.user_identity("SVCLAKSELFLST001", "Self-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<AccessKeyId>AKIALAKSELFKEY000001</AccessKeyId>"), "unexpected body: {body}");

    // The resource ARN carries the path of the user carrying the keys, so a grant scoped to a
    // path prefix reaches users under that path...
    let (principal, session_data) = database.user_identity("SVCLAKPATHLST001", "Path-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Division-Target"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<AccessKeyId>AKIALAKDIVISIONKEY01</AccessKeyId>"), "unexpected body: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCLAKPATHLST001", "Path-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Key-Holder"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the user carrying the keys back the aws:ResourceTag condition keys.
    let (principal, session_data) = database.user_identity("SVCLAKTAGLST0001", "Tag-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Engineering-Target"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<AccessKeyId>AKIALAKENGINEERKY001</AccessKeyId>"), "unexpected body: {body}");

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCLAKTAGLST0001", "Tag-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Sales-Target"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Neither does a user carrying no tags at all: the condition key is absent.
    let (principal, session_data) = database.user_identity("SVCLAKTAGLST0001", "Tag-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Key-Holder"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single user reaches every key that user carries -- there is no naming
    // an access key in a resource ARN -- and reaches no other user.
    let (principal, session_data) = database.user_identity("SVCLAKNARROWLS01", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Key-Holder"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<AccessKeyId>AKIALAKHOLDERKEY0001</AccessKeyId>"), "unexpected body: {body}");
    assert!(body.contains("<AccessKeyId>AKIALAKHOLDERKEY0002</AccessKeyId>"), "unexpected body: {body}");
    assert!(body.contains("<AccessKeyId>AKIALAKHOLDERKEY0003</AccessKeyId>"), "unexpected body: {body}");

    let (principal, session_data) = database.user_identity("SVCLAKNARROWLS01", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Engineering-Target"), None, None))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCLAKNOGRANTL01", "No-Grant-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Key-Holder"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Lister is not authorized to perform: \
                 iam:ListAccessKeys on resource: arn:aws:iam::{account_id}:user/Key-Holder"
        )),
        "unexpected body: {body}"
    );

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:ListAccessKeys on any user is told the user is missing...
    let (principal, session_data) = database.user_identity("SVCLAKBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("No-Such-User"), None, None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCLAKNARROWLS01", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("No-Such-User"), None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A MaxItems outside the range a page may take is rejected, and so is a marker that is not
    // shaped like a pagination token; both are settled before the request is authorized.
    for parameters in [
        list_access_keys_parameters(Some("Key-Holder"), Some(0), None),
        list_access_keys_parameters(Some("Key-Holder"), Some(1001), None),
        list_access_keys_parameters(Some("Key-Holder"), None, Some("")),
    ] {
        let (principal, session_data) = database.user_identity("SVCLAKBROADLST01", "Broad-Lister");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // A marker this service did not issue is the caller's to fix rather than ours, so it is
    // reported as invalid input rather than as an internal failure -- a client-side pagination
    // token passed back in place of the marker it wraps lands here.
    let (principal, session_data) = database.user_identity("SVCLAKBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_access_keys_parameters(Some("Key-Holder"), None, Some(FOREIGN_PAGINATION_TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>InvalidInput</Code>"), "unexpected body: {body}");

    // A MaxItems that is not a number at all never becomes a value the request can carry, so
    // it is reported as malformed input rather than as a validation failure.
    let (principal, session_data) = database.user_identity("SVCLAKBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        "Action=ListAccessKeys&Version=2010-05-08&UserName=Key-Holder&MaxItems=many",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // Credentials that identify no IAM user have nothing for an omitted UserName to name, so
    // they must name the user outright.
    for (principal, session_data) in
        [database.role_identity("SVCLAKROLE000001", "List-Access-Keys-Role"), database.root_identity()]
    {
        let (status, body) =
            call(&svc_state, principal, session_data, &list_access_keys_parameters(None, None, None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
        assert!(
            body.contains("Must specify userName when calling with non-User credentials"),
            "unexpected body: {body}"
        );
    }

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCLAKROLE000001", "List-Access-Keys-Role");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Key-Holder"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<AccessKeyId>AKIALAKHOLDERKEY0001</AccessKeyId>"), "unexpected body: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Root-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<AccessKeyId>AKIALAKROOTKEY000001</AccessKeyId>"), "unexpected body: {body}");
}
