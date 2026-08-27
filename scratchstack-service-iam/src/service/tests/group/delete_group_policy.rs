use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `DeleteGroupPolicy` authorization tests. Every group starts carrying the
/// inline policies the cases below take away, so each caller has something to delete and a policy
/// that was never there can be told apart from a group that does not exist. IAM defines no
/// condition key for this action, so the callers are scoped by the group's path, by the group
/// itself, and not at all.
const DELETE_GROUP_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'delete-group-policy-test@example.com', 'delete-group-policy-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCDGLBROADDEL01', '%ACCOUNT_ID%', 'broad-deleter', 'Broad-Deleter', '/'),
    ('SVCDGLPATHDEL001', '%ACCOUNT_ID%', 'path-deleter', 'Path-Deleter', '/'),
    ('SVCDGLNARROWDL01', '%ACCOUNT_ID%', 'narrow-deleter', 'Narrow-Deleter', '/'),
    ('SVCDGLNOGRANTD01', '%ACCOUNT_ID%', 'no-grant-deleter', 'No-Grant-Deleter', '/');

    INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) VALUES
    ('SVCDGLTGTPLAIN01', '%ACCOUNT_ID%', 'plain-group', 'Plain-Group', '/'),
    ('SVCDGLTGTDIVSN01', '%ACCOUNT_ID%', 'division-group', 'Division-Group', '/division/'),
    ('SVCDGLTGTNARRW01', '%ACCOUNT_ID%', 'narrow-group', 'Narrow-Group', '/'),
    ('SVCDGLTGTOTHER01', '%ACCOUNT_ID%', 'other-group', 'Other-Group', '/'),
    ('SVCDGLTGTBARE001', '%ACCOUNT_ID%', 'bare-group', 'Bare-Group', '/'),
    ('SVCDGLTGTCASE001', '%ACCOUNT_ID%', 'case-group', 'Case-Group', '/'),
    ('SVCDGLTGTROLE001', '%ACCOUNT_ID%', 'role-group', 'Role-Group', '/'),
    ('SVCDGLTGTROOT001', '%ACCOUNT_ID%', 'root-group', 'Root-Group', '/');

    INSERT INTO iam.group_inline_policies(group_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDGLTGTPLAIN01', 'first-policy', 'First-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDGLTGTPLAIN01', 'second-policy', 'Second-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}'),
    ('SVCDGLTGTDIVSN01', 'divisional-policy', 'Divisional-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDGLTGTNARRW01', 'first-policy', 'First-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDGLTGTNARRW01', 'second-policy', 'Second-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}'),
    ('SVCDGLTGTOTHER01', 'first-policy', 'First-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDGLTGTCASE001', 'cased-policy', 'Cased-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDGLTGTROLE001', 'role-policy', 'Role-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDGLTGTROOT001', 'root-policy', 'Root-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDGLBROADDEL01', 'allow-delete-any-group-policy', 'Allow-Delete-Any-Group-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteGroupPolicy","Resource":"*"}]}'),
    ('SVCDGLPATHDEL001', 'allow-delete-on-division', 'Allow-Delete-On-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteGroupPolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/division/*"}]}'),
    ('SVCDGLNARROWDL01', 'allow-delete-on-target', 'Allow-Delete-On-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteGroupPolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/Narrow-Group"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCDGLROLE000001', '%ACCOUNT_ID%', 'delete-group-policy-role', 'Delete-Group-Policy-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDGLROLE000001', 'allow-delete-any-group-policy', 'Allow-Delete-Any-Group-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteGroupPolicy","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `DeleteGroupPolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_delete_group_policy_authorization() {
    let database = TestDatabase::new(DELETE_GROUP_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:DeleteGroupPolicy on any group deletes an inline policy from one,
    // leaving the group's other policies alone.
    let (principal, session_data) = database.user_identity("SVCDGLBROADDEL01", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_group_policy_parameters(Some("Plain-Group"), Some("First-Policy")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DeleteGroupPolicyResponse"), "unexpected body: {body}");
    assert!(database.group_inline_policy_document("Plain-Group", "First-Policy").await.is_none());
    assert!(database.group_inline_policy_document("Plain-Group", "Second-Policy").await.is_some());

    // Deleting a policy the group does not carry is reported as NoSuchEntity, whether it was just
    // deleted or was never there.
    for (group_name, policy_name) in [("Plain-Group", "First-Policy"), ("Bare-Group", "First-Policy")] {
        let (principal, session_data) = database.user_identity("SVCDGLBROADDEL01", "Broad-Deleter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &delete_group_policy_parameters(Some(group_name), Some(policy_name)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");
    }

    // The resource ARN carries the group's path, so a grant scoped to a path prefix reaches
    // groups under that path...
    let (principal, session_data) = database.user_identity("SVCDGLPATHDEL001", "Path-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_group_policy_parameters(Some("Division-Group"), Some("Divisional-Policy")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCDGLPATHDEL001", "Path-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_group_policy_parameters(Some("Other-Group"), Some("First-Policy")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled its transaction back, so that policy is still there.
    assert!(database.group_inline_policy_document("Other-Group", "First-Policy").await.is_some());

    // A grant naming a single group reaches every inline policy on it -- PolicyName narrows
    // nothing -- and reaches no other group.
    for policy_name in ["First-Policy", "Second-Policy"] {
        let (principal, session_data) = database.user_identity("SVCDGLNARROWDL01", "Narrow-Deleter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &delete_group_policy_parameters(Some("Narrow-Group"), Some(policy_name)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    }

    let (principal, session_data) = database.user_identity("SVCDGLNARROWDL01", "Narrow-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_group_policy_parameters(Some("Other-Group"), Some("First-Policy")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied -- named by the
    // group, since the inline policy is not a resource of its own.
    let (principal, session_data) = database.user_identity("SVCDGLNOGRANTD01", "No-Grant-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_group_policy_parameters(Some("Other-Group"), Some("First-Policy")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Deleter is not authorized to perform: \
                 iam:DeleteGroupPolicy on resource: arn:aws:iam::{account_id}:group/Other-Group"
        )),
        "unexpected body: {body}"
    );

    // A group that does not exist is still authorized against the ARN the request names, so a
    // caller allowed the action on any group is told the group is missing...
    let (principal, session_data) = database.user_identity("SVCDGLBROADDEL01", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_group_policy_parameters(Some("No-Such-Group"), Some("First-Policy")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific group learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCDGLNARROWDL01", "Narrow-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_group_policy_parameters(Some("No-Such-Group"), Some("First-Policy")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // GroupName and PolicyName are both required.
    for parameters in [
        delete_group_policy_parameters(None, Some("First-Policy")),
        delete_group_policy_parameters(Some("Other-Group"), None),
    ] {
        let (principal, session_data) = database.user_identity("SVCDGLBROADDEL01", "Broad-Deleter");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // A name that cannot name a group or a policy is rejected before the request is authorized,
    // so even a caller with no grant is told the name is malformed rather than denied.
    for parameters in [
        delete_group_policy_parameters(Some("Not/A/Group-Name"), Some("First-Policy")),
        delete_group_policy_parameters(Some("Other-Group"), Some("Not A Policy Name")),
    ] {
        let (principal, session_data) = database.user_identity("SVCDGLNOGRANTD01", "No-Grant-Deleter");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // Both names are matched case-insensitively.
    let (principal, session_data) = database.user_identity("SVCDGLBROADDEL01", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_group_policy_parameters(Some("cAsE-gRoUp"), Some("cAsEd-pOlIcY")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(database.group_inline_policy_document("Case-Group", "Cased-Policy").await.is_none());

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCDGLROLE000001", "Delete-Group-Policy-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_group_policy_parameters(Some("Role-Group"), Some("Role-Policy")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(database.group_inline_policy_document("Role-Group", "Role-Policy").await.is_none());

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_group_policy_parameters(Some("Root-Group"), Some("Root-Policy")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(database.group_inline_policy_document("Root-Group", "Root-Policy").await.is_none());
}
