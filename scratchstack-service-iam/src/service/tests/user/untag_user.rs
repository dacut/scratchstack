use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `UntagUser` authorization tests. Every target carries the tags a request
/// asks to remove, and `Broad-Untagger` is also allowed `iam:GetUser`, so the tests can read
/// back what a request did or did not remove. The remaining callers carry grants scoped by the
/// target's path, by the tag keys the request may name at all, and by the tags the target
/// already carries -- the last of which governs a request that removes that very tag.
const UNTAG_USER_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'untag-user-test@example.com', 'untag-user-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCUTSBROADUTG01', '%ACCOUNT_ID%', 'broad-untagger', 'Broad-Untagger', '/'),
    ('SVCUTSPATHUTG001', '%ACCOUNT_ID%', 'path-untagger', 'Path-Untagger', '/'),
    ('SVCUTSKEYSUTG001', '%ACCOUNT_ID%', 'tag-key-untagger', 'Tag-Key-Untagger', '/'),
    ('SVCUTSRESUTG0001', '%ACCOUNT_ID%', 'resource-tag-untagger', 'Resource-Tag-Untagger', '/'),
    ('SVCUTSNARROWUTG1', '%ACCOUNT_ID%', 'narrow-untagger', 'Narrow-Untagger', '/'),
    ('SVCUTSNOGRANTUT1', '%ACCOUNT_ID%', 'no-grant-untagger', 'No-Grant-Untagger', '/'),
    ('SVCUTSTGTPLAIN01', '%ACCOUNT_ID%', 'untag-target', 'Untag-Target', '/'),
    ('SVCUTSTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/'),
    ('SVCUTSTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/'),
    ('SVCUTSTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/'),
    ('SVCUTSTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCUTSTGTPLAIN01', 'department', 'Department', 'Engineering'),
    ('SVCUTSTGTPLAIN01', 'project', 'Project', 'Scratchstack'),
    ('SVCUTSTGTPLAIN01', 'keep', 'Keep', 'Yes'),
    ('SVCUTSTGTDIVSN01', 'project', 'Project', 'Division'),
    ('SVCUTSTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCUTSTGTENGNR01', 'costcenter', 'CostCenter', '1234'),
    ('SVCUTSTGTSALES01', 'department', 'Department', 'Sales'),
    ('SVCUTSTGTROOT001', 'root', 'Root', 'Tag');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCUTSBROADUTG01', 'allow-untag-any-user', 'Allow-Untag-Any-User',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:UntagUser","iam:GetUser"],
        "Resource":"*"}]}'),
    ('SVCUTSPATHUTG001', 'allow-untag-division-user', 'Allow-Untag-Division-User',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UntagUser",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/division/*"}]}'),
    ('SVCUTSKEYSUTG001', 'allow-untag-known-keys', 'Allow-Untag-Known-Keys',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UntagUser","Resource":"*",
        "Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["Project"]}}}]}'),
    ('SVCUTSRESUTG0001', 'allow-untag-engineering-user', 'Allow-Untag-Engineering-User',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UntagUser","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCUTSNARROWUTG1', 'allow-untag-target-user', 'Allow-Untag-Target-User',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UntagUser",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/Untag-Target"}]}');
"#;

/// End-to-end authorization checks for `UntagUser` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_untag_user_authorization() {
    let database = TestDatabase::new(UNTAG_USER_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:UntagUser on any user removes a tag from one.
    let (principal, session_data) = database.user_identity("SVCUTSBROADUTG01", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_user_parameters(Some("Untag-Target"), &["Department"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UntagUserResponse"), "unexpected body: {body}");

    // The delete was committed rather than rolled back, and it removed the tag the request
    // named and no others.
    let (principal, session_data) = database.user_identity("SVCUTSBROADUTG01", "Broad-Untagger");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Untag-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<Key>Department</Key>"), "unexpected body: {body}");
    assert!(body.contains("<Key>Project</Key><Value>Scratchstack</Value>"), "unexpected body: {body}");
    assert!(body.contains("<Key>Keep</Key><Value>Yes</Value>"), "unexpected body: {body}");

    // A key the user is not carrying is not an error: the request asks for the user to be left
    // without that tag, and it already is.
    let (principal, session_data) = database.user_identity("SVCUTSBROADUTG01", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_user_parameters(Some("Untag-Target"), &["No-Such-Tag"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCUTSNOGRANTUT1", "No-Grant-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_user_parameters(Some("Untag-Target"), &["Keep"])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Untagger is not authorized to perform: \
                 iam:UntagUser on resource: arn:aws:iam::{account_id}:user/Untag-Target"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled the transaction back, so the tag is still there.
    let (principal, session_data) = database.user_identity("SVCUTSBROADUTG01", "Broad-Untagger");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Untag-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Keep</Key><Value>Yes</Value>"), "unexpected body: {body}");

    // The resource ARN carries the target user's path, so a grant scoped to a path prefix
    // reaches users under that path...
    let (principal, session_data) = database.user_identity("SVCUTSPATHUTG001", "Path-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_user_parameters(Some("Division-Target"), &["Project"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCUTSPATHUTG001", "Path-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_user_parameters(Some("Untag-Target"), &["Keep"])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The request names tag keys and no values, so aws:TagKeys is the condition key that
    // governs which tags a caller may remove.
    let (principal, session_data) = database.user_identity("SVCUTSKEYSUTG001", "Tag-Key-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_user_parameters(Some("Untag-Target"), &["Project"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCUTSBROADUTG01", "Broad-Untagger");
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Untag-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<Key>Project</Key>"), "unexpected body: {body}");

    // One tag key outside the set the policy lists is enough to fail, even alongside keys
    // that are in it.
    let (principal, session_data) = database.user_identity("SVCUTSKEYSUTG001", "Tag-Key-Untagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &untag_user_parameters(Some("Engineering-Target"), &["Project", "CostCenter"]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags the target user carries back the aws:ResourceTag condition keys, which limits
    // which users a caller may untag rather than which tags it may take off them.
    let (principal, session_data) = database.user_identity("SVCUTSRESUTG0001", "Resource-Tag-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_user_parameters(Some("Engineering-Target"), &["CostCenter"]))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCUTSRESUTG0001", "Resource-Tag-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_user_parameters(Some("Sales-Target"), &["Department"])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags are the ones the user carries before the removal, so a grant conditioned on a
    // tag reaches the request that takes that very tag off...
    let (principal, session_data) = database.user_identity("SVCUTSRESUTG0001", "Resource-Tag-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_user_parameters(Some("Engineering-Target"), &["Department"]))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and does not reach the user afterwards.
    let (principal, session_data) = database.user_identity("SVCUTSRESUTG0001", "Resource-Tag-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_user_parameters(Some("Engineering-Target"), &["No-Such-Tag"]))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single user reaches every tag on it: the tag key narrows nothing.
    let (principal, session_data) = database.user_identity("SVCUTSNARROWUTG1", "Narrow-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_user_parameters(Some("Untag-Target"), &["Keep"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:UntagUser on any user is told the user is missing...
    let (principal, session_data) = database.user_identity("SVCUTSBROADUTG01", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_user_parameters(Some("No-Such-User"), &["Department"])).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCUTSNARROWUTG1", "Narrow-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_user_parameters(Some("No-Such-User"), &["Department"])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A request naming no tag keys at all has nothing to remove and is rejected rather than
    // succeeding silently.
    let (principal, session_data) = database.user_identity("SVCUTSBROADUTG01", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_user_parameters(Some("Untag-Target"), &[])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // UserName is required; it does not default to the calling user.
    let (principal, session_data) = database.user_identity("SVCUTSBROADUTG01", "Broad-Untagger");
    let (status, body) = call(&svc_state, principal, session_data, &untag_user_parameters(None, &["Department"])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_user_parameters(Some("Root-Target"), &["Root"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
}
