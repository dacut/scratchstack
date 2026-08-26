use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `DeleteRolePolicy` authorization tests. `Policy-Target` carries several
/// inline policies, so a delete can be shown to remove one and leave the rest; the other targets
/// carry the paths and tags the resource ARN and the `iam:ResourceTag` condition keys are derived
/// from. `Broad-Deleter` is also allowed `iam:ListRolePolicies`, so the tests can see what a
/// delete did or did not leave behind.
const DELETE_ROLE_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'delete-role-policy-test@example.com', 'delete-role-policy-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCDRPBROADDEL01', '%ACCOUNT_ID%', 'broad-deleter', 'Broad-Deleter', '/'),
    ('SVCDRPPATHDEL001', '%ACCOUNT_ID%', 'path-deleter', 'Path-Deleter', '/'),
    ('SVCDRPTAGDEL0001', '%ACCOUNT_ID%', 'tag-deleter', 'Tag-Deleter', '/'),
    ('SVCDRPNARROWDEL1', '%ACCOUNT_ID%', 'narrow-deleter', 'Narrow-Deleter', '/'),
    ('SVCDRPNOGRANTDL1', '%ACCOUNT_ID%', 'no-grant-deleter', 'No-Grant-Deleter', '/');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCDRPTGTPOLICY1', '%ACCOUNT_ID%', 'policy-target', 'Policy-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCDRPTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCDRPTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCDRPTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCDRPTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCDRPTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCDRPTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDRPTGTPOLICY1', 'app-access', 'App-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDRPTGTPOLICY1', 'db-access', 'Db-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"*"}]}'),
    ('SVCDRPTGTPOLICY1', 'narrow-access', 'Narrow-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}'),
    ('SVCDRPTGTPOLICY1', 'cased-access', 'Cased-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}'),
    ('SVCDRPTGTDIVSN01', 'division-access', 'Division-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}'),
    ('SVCDRPTGTENGNR01', 'eng-access', 'Eng-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}'),
    ('SVCDRPTGTSALES01', 'sales-access', 'Sales-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ses:SendEmail","Resource":"*"}]}'),
    ('SVCDRPTGTROOT001', 'root-access', 'Root-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDRPBROADDEL01', 'allow-delete-any-policy', 'Allow-Delete-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Action":["iam:DeleteRolePolicy","iam:ListRolePolicies"],"Resource":"*"}]}'),
    ('SVCDRPPATHDEL001', 'allow-delete-division-policy', 'Allow-Delete-Division-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteRolePolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/division/*"}]}'),
    ('SVCDRPTAGDEL0001', 'allow-delete-engineering-policy', 'Allow-Delete-Engineering-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteRolePolicy","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCDRPNARROWDEL1', 'allow-delete-target-policy', 'Allow-Delete-Target-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteRolePolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/Policy-Target"}]}');
"#;

/// End-to-end authorization checks for `DeleteRolePolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_delete_role_policy_authorization() {
    let database = TestDatabase::new(DELETE_ROLE_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:DeleteRolePolicy on any role removes an inline policy from one.
    let (principal, session_data) = database.user_identity("SVCDRPBROADDEL01", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_policy_parameters(Some("Policy-Target"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DeleteRolePolicyResponse"), "unexpected body: {body}");

    // The delete was committed rather than rolled back, and it took only the policy it named.
    assert_eq!(database.role_inline_policy_document("Policy-Target", "App-Access").await, None);
    let (principal, session_data) = database.user_identity("SVCDRPBROADDEL01", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(Some("Policy-Target"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("App-Access"), "unexpected body: {body}");
    assert!(body.contains("<member>Db-Access</member>"), "unexpected body: {body}");

    // Deleting the same policy again reports it missing rather than succeeding silently.
    let (principal, session_data) = database.user_identity("SVCDRPBROADDEL01", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_policy_parameters(Some("Policy-Target"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // Policy names are matched case-insensitively, so a differently-cased name reaches the
    // policy the role actually carries.
    let (principal, session_data) = database.user_identity("SVCDRPBROADDEL01", "Broad-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_policy_parameters(Some("POLICY-TARGET"), Some("CASED-ACCESS")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(database.role_inline_policy_document("Policy-Target", "Cased-Access").await, None);

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCDRPNOGRANTDL1", "No-Grant-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_policy_parameters(Some("Policy-Target"), Some("Db-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Deleter is not authorized to perform: \
                 iam:DeleteRolePolicy on resource: arn:aws:iam::{account_id}:role/Policy-Target"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled the transaction back, so the policy is still there.
    assert!(database.role_inline_policy_document("Policy-Target", "Db-Access").await.is_some());

    // The resource ARN carries the target role's path, so a grant scoped to a path prefix
    // reaches roles under that path...
    let (principal, session_data) = database.user_identity("SVCDRPPATHDEL001", "Path-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_policy_parameters(Some("Division-Target"), Some("Division-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCDRPPATHDEL001", "Path-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_policy_parameters(Some("Policy-Target"), Some("Db-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the role the policy is embedded in back the iam:ResourceTag condition keys.
    let (principal, session_data) = database.user_identity("SVCDRPTAGDEL0001", "Tag-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_policy_parameters(Some("Engineering-Target"), Some("Eng-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A role carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCDRPTAGDEL0001", "Tag-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_policy_parameters(Some("Sales-Target"), Some("Sales-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
    assert!(database.role_inline_policy_document("Sales-Target", "Sales-Access").await.is_some());

    // An inline policy is part of the role carrying it rather than a resource of its own, so
    // PolicyName narrows nothing: a grant naming just the role reaches every policy on it.
    let (principal, session_data) = database.user_identity("SVCDRPNARROWDEL1", "Narrow-Deleter");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_policy_parameters(Some("Policy-Target"), Some("Narrow-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(database.role_inline_policy_document("Policy-Target", "Narrow-Access").await, None);

    // A role that does not exist has no path to read, so the ARN authorized is the one it would
    // carry at the root path. A caller allowed iam:DeleteRolePolicy on any role is told the role
    // is missing...
    let (principal, session_data) = database.user_identity("SVCDRPBROADDEL01", "Broad-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_role_policy_parameters(Some("No-Such-Role"), Some("Any")))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific role learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCDRPNARROWDEL1", "Narrow-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_role_policy_parameters(Some("No-Such-Role"), Some("Any")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A malformed role name is rejected before the request is authorized, so the caller learns
    // the request was invalid rather than that it was denied.
    let (principal, session_data) = database.user_identity("SVCDRPNOGRANTDL1", "No-Grant-Deleter");
    let (status, body) =
        call(&svc_state, principal, session_data, &delete_role_policy_parameters(Some("bad role!"), Some("Any"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // Both parameters are required; neither defaults to anything.
    for parameters in [
        delete_role_policy_parameters(None, Some("Db-Access")),
        delete_role_policy_parameters(Some("Policy-Target"), None),
    ] {
        let (principal, session_data) = database.user_identity("SVCDRPBROADDEL01", "Broad-Deleter");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &delete_role_policy_parameters(Some("Root-Target"), Some("Root-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(database.role_inline_policy_document("Root-Target", "Root-Access").await, None);
}
