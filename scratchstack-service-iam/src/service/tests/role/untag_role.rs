use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `UntagRole` authorization tests. `Untag-Target` starts out carrying several
/// tags so that a removal can be seen to take one and leave the rest. The callers carry grants
/// scoped by the keys the request asks to remove (`aws:TagKeys`), by the path of the role losing
/// them, by the tags that role already carries, and by the role itself.
const UNTAG_ROLE_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'untag-role-test@example.com', 'untag-role-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCUTRBROADUNT01', '%ACCOUNT_ID%', 'broad-untagger', 'Broad-Untagger', '/'),
    ('SVCUTRKEYUNT0001', '%ACCOUNT_ID%', 'key-untagger', 'Key-Untagger', '/'),
    ('SVCUTRPATHUNT001', '%ACCOUNT_ID%', 'path-untagger', 'Path-Untagger', '/'),
    ('SVCUTRRESUNT0001', '%ACCOUNT_ID%', 'resource-untagger', 'Resource-Untagger', '/'),
    ('SVCUTRNARROWUN01', '%ACCOUNT_ID%', 'narrow-untagger', 'Narrow-Untagger', '/'),
    ('SVCUTRNOGRANTUN1', '%ACCOUNT_ID%', 'no-grant-untagger', 'No-Grant-Untagger', '/');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCUTRTGTPLAIN01', '%ACCOUNT_ID%', 'untag-target', 'Untag-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCUTRTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCUTRTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCUTRTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCUTRTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCUTRROLE000001', '%ACCOUNT_ID%', 'untag-role-role', 'Untag-Role-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCUTRTGTPLAIN01', 'env', 'Env', 'Staging'),
    ('SVCUTRTGTPLAIN01', 'team', 'Team', 'Platform'),
    ('SVCUTRTGTPLAIN01', 'owner', 'Owner', 'Infra'),
    ('SVCUTRTGTPLAIN01', 'cased', 'Cased', 'Yes'),
    ('SVCUTRTGTPLAIN01', 'narrow', 'Narrow', 'Yes'),
    ('SVCUTRTGTPLAIN01', 'session', 'Session', 'Yes'),
    ('SVCUTRTGTDIVSN01', 'env', 'Env', 'Division'),
    ('SVCUTRTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCUTRTGTENGNR01', 'env', 'Env', 'Engineering'),
    ('SVCUTRTGTSALES01', 'department', 'Department', 'Sales'),
    ('SVCUTRTGTSALES01', 'env', 'Env', 'Sales'),
    ('SVCUTRTGTROOT001', 'env', 'Env', 'Root');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCUTRBROADUNT01', 'allow-untag-any-role', 'Allow-Untag-Any-Role',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:UntagRole","iam:GetRole"],
        "Resource":"*"}]}'),
    ('SVCUTRKEYUNT0001', 'allow-untag-env-only', 'Allow-Untag-Env-Only',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UntagRole","Resource":"*",
        "Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["Env"]}}}]}'),
    ('SVCUTRPATHUNT001', 'allow-untag-division', 'Allow-Untag-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UntagRole",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/division/*"}]}'),
    ('SVCUTRRESUNT0001', 'allow-untag-engineering', 'Allow-Untag-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UntagRole","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCUTRNARROWUN01', 'allow-untag-target', 'Allow-Untag-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UntagRole",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/Untag-Target"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCUTRROLE000001', 'allow-untag-any-role', 'Allow-Untag-Any-Role',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UntagRole","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `UntagRole` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_untag_role_authorization() {
    let database = TestDatabase::new(UNTAG_ROLE_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:UntagRole on any role removes one tag from it.
    let (principal, session_data) = database.user_identity("SVCUTRBROADUNT01", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("Untag-Target"), &["Owner"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UntagRoleResponse"), "unexpected body: {body}");

    // Only the named key went, and the removal was committed rather than rolled back.
    let (principal, session_data) = database.user_identity("SVCUTRBROADUNT01", "Broad-Untagger");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Untag-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<Key>Owner</Key>"), "unexpected body: {body}");
    assert!(body.contains("<Key>Env</Key><Value>Staging</Value>"), "unexpected body: {body}");
    assert!(body.contains("<Key>Team</Key><Value>Platform</Value>"), "unexpected body: {body}");

    // A key the role does not carry is not an error: the request asks for the role to be left
    // without that tag, and it already is.
    let (principal, session_data) = database.user_identity("SVCUTRBROADUNT01", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("Untag-Target"), &["Owner"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // Both the role name and the tag keys are matched case-insensitively.
    let (principal, session_data) = database.user_identity("SVCUTRBROADUNT01", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("UNTAG-TARGET"), &["CASED"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCUTRBROADUNT01", "Broad-Untagger");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Untag-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<Key>Cased</Key>"), "unexpected body: {body}");

    // The keys being removed back aws:TagKeys, so a grant confined to one key admits a request
    // naming only that key...
    let (principal, session_data) = database.user_identity("SVCUTRKEYUNT0001", "Key-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("Sales-Target"), &["Env"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and refuses one that also names a key it does not, since every key in the request has
    // to be one the grant allows.
    let (principal, session_data) = database.user_identity("SVCUTRKEYUNT0001", "Key-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("Sales-Target"), &["Env", "Department"]))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled the transaction back, so neither key was removed -- not even the one the
    // grant would have allowed on its own.
    let (principal, session_data) = database.user_identity("SVCUTRBROADUNT01", "Broad-Untagger");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Sales-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Department</Key><Value>Sales</Value>"), "unexpected body: {body}");

    // The resource ARN carries the target role's path, so a grant scoped to a path prefix
    // reaches roles under that path...
    let (principal, session_data) = database.user_identity("SVCUTRPATHUNT001", "Path-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("Division-Target"), &["Env"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCUTRPATHUNT001", "Path-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("Untag-Target"), &["Env"])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags the role carries back the aws:ResourceTag condition keys, and they are the tags
    // as they stand before the removal -- so a grant conditioned on a role's tag reaches the
    // request that removes that very tag.
    let (principal, session_data) = database.user_identity("SVCUTRRESUNT0001", "Resource-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("Engineering-Target"), &["Department"]))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // Having removed it, the same caller can no longer reach that role at all.
    let (principal, session_data) = database.user_identity("SVCUTRRESUNT0001", "Resource-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("Engineering-Target"), &["Env"])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single role reaches every tag on it and no other role.
    let (principal, session_data) = database.user_identity("SVCUTRNARROWUN01", "Narrow-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("Untag-Target"), &["Narrow"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCUTRNARROWUN01", "Narrow-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("Sales-Target"), &["Env"])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCUTRNOGRANTUN1", "No-Grant-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("Untag-Target"), &["Env"])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Untagger is not authorized to perform: \
                 iam:UntagRole on resource: arn:aws:iam::{account_id}:role/Untag-Target"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled the transaction back, so the tag is still there.
    let (principal, session_data) = database.user_identity("SVCUTRBROADUNT01", "Broad-Untagger");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Untag-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Env</Key><Value>Staging</Value>"), "unexpected body: {body}");

    // A role that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:UntagRole on any role is told the role is missing...
    let (principal, session_data) = database.user_identity("SVCUTRBROADUNT01", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("No-Such-Role"), &["Env"])).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific role learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCUTRNARROWUN01", "Narrow-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("No-Such-Role"), &["Env"])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // RoleName is required.
    let (principal, session_data) = database.user_identity("SVCUTRBROADUNT01", "Broad-Untagger");
    let (status, body) = call(&svc_state, principal, session_data, &untag_role_parameters(None, &["Env"])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // A role name that is not a role name is rejected before the request is authorized.
    let (principal, session_data) = database.user_identity("SVCUTRBROADUNT01", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("Bad Role Name"), &["Env"])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // At least one tag key is required, settled after authorization.
    let (principal, session_data) = database.user_identity("SVCUTRBROADUNT01", "Broad-Untagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("Untag-Target"), &[])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCUTRROLE000001", "Untag-Role-Role");
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("Untag-Target"), &["Session"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &untag_role_parameters(Some("Root-Target"), &["Env"])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
}
