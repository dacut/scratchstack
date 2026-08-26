use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `TagUser` authorization tests. `Tag-Target` already carries a tag, so
/// replacing one can be told apart from adding one; the other targets carry the paths and tags
/// the resource ARN and the `aws:ResourceTag` condition keys are derived from. `Broad-Tagger`
/// is also allowed `iam:GetUser`, so the tests can read back what a request did or did not
/// leave on a user. The remaining callers carry grants scoped by the target's path, by the
/// tags the request asks to apply, by the tag keys it may name at all, and by the tags the
/// target already carries.
const TAG_USER_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'tag-user-test@example.com', 'tag-user-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCTUSBROADTAG01', '%ACCOUNT_ID%', 'broad-tagger', 'Broad-Tagger', '/'),
    ('SVCTUSPATHTAG001', '%ACCOUNT_ID%', 'path-tagger', 'Path-Tagger', '/'),
    ('SVCTUSREQTAG0001', '%ACCOUNT_ID%', 'request-tag-tagger', 'Request-Tag-Tagger', '/'),
    ('SVCTUSKEYSTAG001', '%ACCOUNT_ID%', 'tag-key-tagger', 'Tag-Key-Tagger', '/'),
    ('SVCTUSRESTAG0001', '%ACCOUNT_ID%', 'resource-tag-tagger', 'Resource-Tag-Tagger', '/'),
    ('SVCTUSNARROWTAG1', '%ACCOUNT_ID%', 'narrow-tagger', 'Narrow-Tagger', '/'),
    ('SVCTUSNOGRANTTG1', '%ACCOUNT_ID%', 'no-grant-tagger', 'No-Grant-Tagger', '/'),
    ('SVCTUSTGTPLAIN01', '%ACCOUNT_ID%', 'tag-target', 'Tag-Target', '/'),
    ('SVCTUSTGTREQST01', '%ACCOUNT_ID%', 'request-target', 'Request-Target', '/'),
    ('SVCTUSTGTKEYS001', '%ACCOUNT_ID%', 'keys-target', 'Keys-Target', '/'),
    ('SVCTUSTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/'),
    ('SVCTUSTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/'),
    ('SVCTUSTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/'),
    ('SVCTUSTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCTUSTGTPLAIN01', 'env', 'Env', 'Staging'),
    ('SVCTUSTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCTUSTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCTUSBROADTAG01', 'allow-tag-any-user', 'Allow-Tag-Any-User',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:TagUser","iam:GetUser"],
        "Resource":"*"}]}'),
    ('SVCTUSPATHTAG001', 'allow-tag-division-user', 'Allow-Tag-Division-User',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagUser",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/division/*"}]}'),
    ('SVCTUSREQTAG0001', 'allow-tag-engineering', 'Allow-Tag-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagUser","Resource":"*",
        "Condition":{"StringEquals":{"aws:RequestTag/department":"Engineering"}}}]}'),
    ('SVCTUSKEYSTAG001', 'allow-tag-with-known-keys', 'Allow-Tag-With-Known-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagUser","Resource":"*",
        "Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["Department","Project"]}}}]}'),
    ('SVCTUSRESTAG0001', 'allow-tag-engineering-user', 'Allow-Tag-Engineering-User',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagUser","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCTUSNARROWTAG1', 'allow-tag-target-user', 'Allow-Tag-Target-User',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagUser",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/Tag-Target"}]}');
"#;

/// End-to-end authorization checks for `TagUser` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_tag_user_authorization() {
    let database = TestDatabase::new(TAG_USER_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:TagUser on any user adds a tag to one.
    let (principal, session_data) = database.user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_user_parameters(Some("Tag-Target"), &[("Team", "Platform")]))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<TagUserResponse"), "unexpected body: {body}");

    // The write was committed rather than rolled back, and it added the tag alongside the one
    // the user was already carrying rather than replacing the lot.
    let (principal, session_data) = database.user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Tag-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Team</Key><Value>Platform</Value>"), "unexpected body: {body}");
    assert!(body.contains("<Key>Env</Key><Value>Staging</Value>"), "unexpected body: {body}");

    // A tag whose key is already on the user replaces that tag's value.
    let (principal, session_data) = database.user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_user_parameters(Some("Tag-Target"), &[("Env", "Production")]))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Tag-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Env</Key><Value>Production</Value>"), "unexpected body: {body}");
    assert!(!body.contains("<Value>Staging</Value>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCTUSNOGRANTTG1", "No-Grant-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_user_parameters(Some("Tag-Target"), &[("Denied", "Yes")])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Tagger is not authorized to perform: \
                 iam:TagUser on resource: arn:aws:iam::{account_id}:user/Tag-Target"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled the transaction back, so the tag was not applied.
    let (principal, session_data) = database.user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Tag-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<Key>Denied</Key>"), "unexpected body: {body}");

    // The resource ARN carries the target user's path, so a grant scoped to a path prefix
    // reaches users under that path...
    let (principal, session_data) = database.user_identity("SVCTUSPATHTAG001", "Path-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_user_parameters(Some("Division-Target"), &[("Team", "Division")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCTUSPATHTAG001", "Path-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_user_parameters(Some("Tag-Target"), &[("Team", "Other")])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags the request asks to apply back the aws:RequestTag condition keys. The policy
    // spells the tag key in lower case while the request spells it "Department", confirming
    // that tag keys are matched case-insensitively.
    let (principal, session_data) = database.user_identity("SVCTUSREQTAG0001", "Request-Tag-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_user_parameters(Some("Request-Target"), &[("Department", "Engineering")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A request asking for the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCTUSREQTAG0001", "Request-Tag-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_user_parameters(Some("Request-Target"), &[("Department", "Sales")]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Neither does a request naming some other tag entirely: the condition key is absent, so
    // the grant does not apply rather than matching an empty value. The tag the user is
    // already carrying is a different condition key and does not stand in for it.
    let (principal, session_data) = database.user_identity("SVCTUSREQTAG0001", "Request-Tag-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_user_parameters(Some("Request-Target"), &[("Team", "Platform")]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant conditioned on aws:TagKeys limits which tags the request may name at all,
    // whatever values it asks to give them.
    let (principal, session_data) = database.user_identity("SVCTUSKEYSTAG001", "Tag-Key-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_user_parameters(Some("Keys-Target"), &[("Department", "Engineering"), ("Project", "Scratchstack")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // One tag key outside the set the policy lists is enough to fail, even alongside keys
    // that are in it.
    let (principal, session_data) = database.user_identity("SVCTUSKEYSTAG001", "Tag-Key-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_user_parameters(Some("Keys-Target"), &[("Department", "Engineering"), ("CostCenter", "1234")]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags the target user already carries back the aws:ResourceTag condition keys, which
    // is a different question from what the request asks to apply: this grant limits which
    // users may be tagged rather than what they may be tagged with.
    let (principal, session_data) = database.user_identity("SVCTUSRESTAG0001", "Resource-Tag-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_user_parameters(Some("Engineering-Target"), &[("Team", "Platform")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user carrying the tag with a different value does not satisfy the condition, and
    // neither does one carrying no such tag at all.
    for user_name in ["Sales-Target", "Tag-Target"] {
        let (principal, session_data) = database.user_identity("SVCTUSRESTAG0001", "Resource-Tag-Tagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &tag_user_parameters(Some(user_name), &[("Team", "Other")]))
                .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
    }

    // Being allowed to tag a user carries being allowed to overwrite the tags that grant is
    // conditioned on: the request is authorized against the tags as they stand, so the caller
    // can move the user out of its own grant's reach...
    let (principal, session_data) = database.user_identity("SVCTUSRESTAG0001", "Resource-Tag-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_user_parameters(Some("Engineering-Target"), &[("Department", "Sales")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and cannot reach it afterwards.
    let (principal, session_data) = database.user_identity("SVCTUSRESTAG0001", "Resource-Tag-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_user_parameters(Some("Engineering-Target"), &[("Team", "Other")]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single user reaches every tag on it: the tag key narrows nothing.
    let (principal, session_data) = database.user_identity("SVCTUSNARROWTAG1", "Narrow-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_user_parameters(Some("Tag-Target"), &[("Narrow", "Yes")])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:TagUser on any user is told the user is missing...
    let (principal, session_data) = database.user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_user_parameters(Some("No-Such-User"), &[("Team", "Platform")]))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCTUSNARROWTAG1", "Narrow-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_user_parameters(Some("No-Such-User"), &[("Team", "Platform")]))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Two tags with the same key ask for two values for one tag, which is the caller's error
    // rather than a silent last-one-wins. The keys here differ only in case, which IAM treats
    // as the same key.
    let (principal, session_data) = database.user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_user_parameters(Some("Tag-Target"), &[("Department", "Engineering"), ("department", "Sales")]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(
        body.contains(
            "<Code>InvalidInput</Code><Message>Duplicate tag keys found. \
                 Please note that Tag keys are case insensitive.</Message>"
        ),
        "unexpected body: {body}"
    );

    // A request naming no tags at all has nothing to apply and is rejected rather than
    // succeeding silently.
    let (principal, session_data) = database.user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
    let (status, body) = call(&svc_state, principal, session_data, &tag_user_parameters(Some("Tag-Target"), &[])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // UserName is required; it does not default to the calling user.
    let (principal, session_data) = database.user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_user_parameters(None, &[("Team", "Platform")])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_user_parameters(Some("Root-Target"), &[("Root", "Tag")])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
}
