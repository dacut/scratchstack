use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The trust policy the seeded roles carry.
const TRUST_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

/// Seed data for the `ListRoles` authorization tests. `Broad-Lister` may list roles;
/// `Account-Lister` only when `aws:ResourceAccount` is its own account, and `Other-Account-Lister`
/// only when it is a different one; `Path-Lister` is granted the action on a single role ARN,
/// which `iam:ListRoles` does not honor. The roles are spread across two paths so that
/// `PathPrefix` has something to filter, and are named so that the order they page in is the
/// order they are written here.
const LIST_ROLES_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'list-roles-test@example.com', 'list-roles-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCLSTROLEBROAD', '%ACCOUNT_ID%', 'broad-lister', 'Broad-Lister', '/'),
    ('SVCLSTROLEACCT1', '%ACCOUNT_ID%', 'account-lister', 'Account-Lister', '/'),
    ('SVCLSTROLEOTHR1', '%ACCOUNT_ID%', 'other-account-lister', 'Other-Account-Lister', '/'),
    ('SVCLSTROLEPATH1', '%ACCOUNT_ID%', 'path-lister', 'Path-Lister', '/'),
    ('SVCLSTROLENONE1', '%ACCOUNT_ID%', 'no-grant-lister', 'No-Grant-Lister', '/');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCLSTROLEALPHA', '%ACCOUNT_ID%', 'alpha-role', 'Alpha-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCLSTROLEBRAVO', '%ACCOUNT_ID%', 'bravo-role', 'Bravo-Role', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCLSTROLECHRLI', '%ACCOUNT_ID%', 'charlie-role', 'Charlie-Role', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCLSTROLEALPHA', 'department', 'Department', 'Engineering');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLSTROLEBROAD', 'allow-list-roles', 'Allow-List-Roles',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRoles","Resource":"*"}]}'),
    ('SVCLSTROLEACCT1', 'allow-own-account', 'Allow-Own-Account',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRoles","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceAccount":"%ACCOUNT_ID%"}}}]}'),
    ('SVCLSTROLEOTHR1', 'allow-other-account', 'Allow-Other-Account',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRoles","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceAccount":"210987654321"}}}]}'),
    ('SVCLSTROLEPATH1', 'allow-list-one-role', 'Allow-List-One-Role',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRoles",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/Alpha-Role"}]}');
"#;

/// End-to-end authorization checks for `ListRoles` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account.
#[test_log::test(tokio::test)]
async fn test_list_roles_authorization() {
    let database = TestDatabase::new(LIST_ROLES_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:ListRoles is told about every role in its own account.
    let (principal, session_data) = database.user_identity("SVCLSTROLEBROAD", "Broad-Lister");
    let (status, body) = call(&svc_state, principal, session_data, &list_roles_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<RoleName>Alpha-Role</RoleName>"), "unexpected body: {body}");
    assert!(body.contains("<RoleName>Bravo-Role</RoleName>"), "unexpected body: {body}");
    assert!(body.contains("<RoleName>Charlie-Role</RoleName>"), "unexpected body: {body}");
    assert!(body.contains(&format!("<Arn>arn:aws:iam::{account_id}:role/Alpha-Role</Arn>")), "unexpected body: {body}");

    // Each role reports its trust policy percent-encoded, as IAM reports every policy document.
    assert_eq!(decoded_trust_policy_document(&body), TRUST_POLICY);

    // The listing does not report tags, which is what ListRoles does on AWS, even though
    // Alpha-Role carries one: a caller wanting them asks GetRole or ListRoleTags for a
    // particular role.
    assert!(!body.contains("<Key>Department</Key>"), "unexpected body: {body}");

    // A path prefix confines the listing to the roles under it...
    let (principal, session_data) = database.user_identity("SVCLSTROLEBROAD", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_roles_parameters(Some("/division/"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<RoleName>Bravo-Role</RoleName>"), "unexpected body: {body}");
    assert!(body.contains("<RoleName>Charlie-Role</RoleName>"), "unexpected body: {body}");
    assert!(!body.contains("<RoleName>Alpha-Role</RoleName>"), "unexpected body: {body}");

    // ...and a prefix matching nothing reports an empty listing rather than an error.
    let (principal, session_data) = database.user_identity("SVCLSTROLEBROAD", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_roles_parameters(Some("/nowhere/"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<RoleName>"), "unexpected body: {body}");

    // A truncated listing reports a marker, which the next call hands back to continue from
    // where the first left off.
    let (principal, session_data) = database.user_identity("SVCLSTROLEBROAD", "Broad-Lister");
    let (status, body) = call(&svc_state, principal, session_data, &list_roles_parameters(None, Some(2), None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<IsTruncated>true</IsTruncated>"), "unexpected body: {body}");
    assert!(body.contains("<RoleName>Alpha-Role</RoleName>"), "unexpected body: {body}");
    assert!(body.contains("<RoleName>Bravo-Role</RoleName>"), "unexpected body: {body}");
    assert!(!body.contains("<RoleName>Charlie-Role</RoleName>"), "unexpected body: {body}");
    let marker = pagination_marker(&body);

    let (principal, session_data) = database.user_identity("SVCLSTROLEBROAD", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_roles_parameters(None, Some(2), Some(&marker))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<RoleName>Charlie-Role</RoleName>"), "unexpected body: {body}");

    // A listing that is not truncated reports no IsTruncated at all, rather than reporting it
    // false: the element and the marker are written together or not at all, which is what the
    // tag listings do too. ListPolicies and ListUsers differ, and always report it.
    assert!(!body.contains("<IsTruncated>"), "unexpected body: {body}");
    assert!(!body.contains("<RoleName>Alpha-Role</RoleName>"), "unexpected body: {body}");

    // A marker this service did not issue is the caller's error, not ours.
    let (principal, session_data) = database.user_identity("SVCLSTROLEBROAD", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_roles_parameters(None, None, Some(FOREIGN_PAGINATION_TOKEN)))
            .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");

    // The listing covers the caller's own account, so aws:ResourceAccount is that account: a
    // grant conditioned on it applies...
    let (principal, session_data) = database.user_identity("SVCLSTROLEACCT1", "Account-Lister");
    let (status, body) = call(&svc_state, principal, session_data, &list_roles_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<RoleName>Alpha-Role</RoleName>"), "unexpected body: {body}");

    // ...and one naming a different account does not.
    let (principal, session_data) = database.user_identity("SVCLSTROLEOTHR1", "Other-Account-Lister");
    let (status, body) = call(&svc_state, principal, session_data, &list_roles_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // iam:ListRoles supports no resource-level permissions, so a grant naming a particular role
    // reaches nothing: the action has to be granted on "*". The denial names the resource as "*"
    // rather than as any one role, which is what the caller has to grant.
    let (principal, session_data) = database.user_identity("SVCLSTROLEPATH1", "Path-Lister");
    let (status, body) = call(&svc_state, principal, session_data, &list_roles_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Path-Lister is not authorized to perform: \
                 iam:ListRoles on resource: *"
        )),
        "unexpected body: {body}"
    );

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCLSTROLENONE1", "No-Grant-Lister");
    let (status, body) = call(&svc_state, principal, session_data, &list_roles_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A malformed path prefix is rejected before the request is authorized, so the caller learns
    // the request was invalid rather than that it was denied.
    let (principal, session_data) = database.user_identity("SVCLSTROLENONE1", "No-Grant-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_roles_parameters(Some("no-leading-slash"), None, None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &list_roles_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<RoleName>Alpha-Role</RoleName>"), "unexpected body: {body}");
}
