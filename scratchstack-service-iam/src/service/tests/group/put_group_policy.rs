use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `PutGroupPolicy` authorization tests. IAM defines no condition key for this
/// action and an inline policy is not a resource of its own, so the group's ARN is all a grant
/// has to work with: the callers are scoped by the group's path, by the group itself, and not at
/// all. There is deliberately no caller scoped by policy name, because no such scoping exists.
const PUT_GROUP_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'put-group-policy-test@example.com', 'put-group-policy-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCPGPBROADPUT01', '%ACCOUNT_ID%', 'broad-writer', 'Broad-Writer', '/'),
    ('SVCPGPPATHPUT001', '%ACCOUNT_ID%', 'path-writer', 'Path-Writer', '/'),
    ('SVCPGPNARROWPT01', '%ACCOUNT_ID%', 'narrow-writer', 'Narrow-Writer', '/'),
    ('SVCPGPNOGRANTP01', '%ACCOUNT_ID%', 'no-grant-writer', 'No-Grant-Writer', '/');

    INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) VALUES
    ('SVCPGPTGTPLAIN01', '%ACCOUNT_ID%', 'plain-group', 'Plain-Group', '/'),
    ('SVCPGPTGTDIVSN01', '%ACCOUNT_ID%', 'division-group', 'Division-Group', '/division/'),
    ('SVCPGPTGTNARRW01', '%ACCOUNT_ID%', 'narrow-group', 'Narrow-Group', '/'),
    ('SVCPGPTGTOTHER01', '%ACCOUNT_ID%', 'other-group', 'Other-Group', '/'),
    ('SVCPGPTGTROLE001', '%ACCOUNT_ID%', 'role-group', 'Role-Group', '/'),
    ('SVCPGPTGTROOT001', '%ACCOUNT_ID%', 'root-group', 'Root-Group', '/');

    INSERT INTO iam.group_inline_policies(group_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCPGPTGTPLAIN01', 'existing-policy', 'Existing-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCPGPBROADPUT01', 'allow-write-any-group-policy', 'Allow-Write-Any-Group-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutGroupPolicy","Resource":"*"}]}'),
    ('SVCPGPPATHPUT001', 'allow-write-on-division', 'Allow-Write-On-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutGroupPolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/division/*"}]}'),
    ('SVCPGPNARROWPT01', 'allow-write-on-target', 'Allow-Write-On-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutGroupPolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/Narrow-Group"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCPGPROLE000001', '%ACCOUNT_ID%', 'put-group-policy-role', 'Put-Group-Policy-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCPGPROLE000001', 'allow-write-any-group-policy', 'Allow-Write-Any-Group-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutGroupPolicy","Resource":"*"}]}');
"#;

/// A well-formed policy document, and a second one that differs from it, for the cases that check
/// what a write actually stored.
const POLICY_DOCUMENT: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}"#;
const REPLACEMENT_DOCUMENT: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}"#;

/// End-to-end authorization checks for `PutGroupPolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_put_group_policy_authorization() {
    let database = TestDatabase::new(PUT_GROUP_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:PutGroupPolicy on any group writes an inline policy on one, and the
    // document is stored as it was given -- plain JSON, once the query string carrying it has
    // been decoded.
    let (principal, session_data) = database.user_identity("SVCPGPBROADPUT01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_group_policy_parameters(Some("Plain-Group"), Some("New-Policy"), Some(POLICY_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PutGroupPolicyResponse"), "unexpected body: {body}");
    assert_eq!(
        database.group_inline_policy_document("Plain-Group", "New-Policy").await.as_deref(),
        Some(POLICY_DOCUMENT)
    );

    // A policy of the same name is replaced rather than added alongside, and the replacement is
    // what the group carries afterwards.
    let (principal, session_data) = database.user_identity("SVCPGPBROADPUT01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_group_policy_parameters(Some("Plain-Group"), Some("New-Policy"), Some(REPLACEMENT_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(
        database.group_inline_policy_document("Plain-Group", "New-Policy").await.as_deref(),
        Some(REPLACEMENT_DOCUMENT)
    );

    // PolicyName narrows nothing: a caller allowed to write one inline policy on a group is
    // allowed to overwrite the ones already there, whoever wrote them.
    let (principal, session_data) = database.user_identity("SVCPGPBROADPUT01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_group_policy_parameters(Some("Plain-Group"), Some("Existing-Policy"), Some(POLICY_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(
        database.group_inline_policy_document("Plain-Group", "Existing-Policy").await.as_deref(),
        Some(POLICY_DOCUMENT)
    );

    // The resource ARN carries the group's path, so a grant scoped to a path prefix reaches
    // groups under that path...
    let (principal, session_data) = database.user_identity("SVCPGPPATHPUT001", "Path-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_group_policy_parameters(Some("Division-Group"), Some("Divisional-Policy"), Some(POLICY_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCPGPPATHPUT001", "Path-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_group_policy_parameters(Some("Other-Group"), Some("Divisional-Policy"), Some(POLICY_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled its transaction back, so nothing was written.
    assert!(database.group_inline_policy_document("Other-Group", "Divisional-Policy").await.is_none());

    // A grant naming a single group reaches every inline policy on it -- any name, any document,
    // since there is no condition key to confine either -- and reaches no other group.
    for policy_name in ["First-Policy", "Second-Policy"] {
        let (principal, session_data) = database.user_identity("SVCPGPNARROWPT01", "Narrow-Writer");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &put_group_policy_parameters(Some("Narrow-Group"), Some(policy_name), Some(POLICY_DOCUMENT)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    }

    let (principal, session_data) = database.user_identity("SVCPGPNARROWPT01", "Narrow-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_group_policy_parameters(Some("Other-Group"), Some("First-Policy"), Some(POLICY_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied -- named by the
    // group, since the inline policy is not a resource of its own.
    let (principal, session_data) = database.user_identity("SVCPGPNOGRANTP01", "No-Grant-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_group_policy_parameters(Some("Plain-Group"), Some("Sneaky-Policy"), Some(POLICY_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Writer is not authorized to perform: \
                 iam:PutGroupPolicy on resource: arn:aws:iam::{account_id}:group/Plain-Group"
        )),
        "unexpected body: {body}"
    );

    // A group that does not exist is still authorized against the ARN the request names, so a
    // caller allowed the action on any group is told the group is missing...
    let (principal, session_data) = database.user_identity("SVCPGPBROADPUT01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_group_policy_parameters(Some("No-Such-Group"), Some("New-Policy"), Some(POLICY_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific group learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCPGPNARROWPT01", "Narrow-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_group_policy_parameters(Some("No-Such-Group"), Some("New-Policy"), Some(POLICY_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A document that does not parse as a policy is reported as MalformedPolicyDocument, once the
    // caller is allowed to have asked -- the parse is settled after authorization, so an
    // unauthorized caller is not told which of its documents was bad.
    let (principal, session_data) = database.user_identity("SVCPGPBROADPUT01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_group_policy_parameters(Some("Plain-Group"), Some("Bad-Policy"), Some("this is not a policy")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedPolicyDocument</Code>"), "unexpected body: {body}");

    // That rolled its transaction back, so nothing was written under that name.
    assert!(database.group_inline_policy_document("Plain-Group", "Bad-Policy").await.is_none());

    // GroupName, PolicyName, and PolicyDocument are all required.
    for parameters in [
        put_group_policy_parameters(None, Some("New-Policy"), Some(POLICY_DOCUMENT)),
        put_group_policy_parameters(Some("Plain-Group"), None, Some(POLICY_DOCUMENT)),
        put_group_policy_parameters(Some("Plain-Group"), Some("New-Policy"), None),
    ] {
        let (principal, session_data) = database.user_identity("SVCPGPBROADPUT01", "Broad-Writer");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // A name that cannot name a group or a policy is rejected before the request is authorized,
    // so even a caller with no grant is told the name is malformed rather than denied.
    for parameters in [
        put_group_policy_parameters(Some("Not/A/Group-Name"), Some("New-Policy"), Some(POLICY_DOCUMENT)),
        put_group_policy_parameters(Some("Plain-Group"), Some("Not A Policy Name"), Some(POLICY_DOCUMENT)),
    ] {
        let (principal, session_data) = database.user_identity("SVCPGPNOGRANTP01", "No-Grant-Writer");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // Both names are matched case-insensitively, and a policy name that differs only in casing
    // replaces the policy already there rather than adding a second one.
    let (principal, session_data) = database.user_identity("SVCPGPBROADPUT01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_group_policy_parameters(Some("pLaIn-gRoUp"), Some("nEw-pOlIcY"), Some(POLICY_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(
        database.group_inline_policy_document("Plain-Group", "New-Policy").await.as_deref(),
        Some(POLICY_DOCUMENT)
    );

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCPGPROLE000001", "Put-Group-Policy-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_group_policy_parameters(Some("Role-Group"), Some("Role-Written"), Some(POLICY_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(
        database.group_inline_policy_document("Role-Group", "Role-Written").await.as_deref(),
        Some(POLICY_DOCUMENT)
    );

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_group_policy_parameters(Some("Root-Group"), Some("Root-Written"), Some(POLICY_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(
        database.group_inline_policy_document("Root-Group", "Root-Written").await.as_deref(),
        Some(POLICY_DOCUMENT)
    );
}
