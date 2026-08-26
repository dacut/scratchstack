use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `PutRolePolicy` authorization tests. `Policy-Target` already carries an
/// inline policy, so replacing one can be told apart from adding one; the other targets carry the
/// paths and tags the resource ARN and the `iam:ResourceTag` condition keys are derived from.
/// `Broad-Writer` is also allowed `iam:ListRolePolicies`, so the tests can see what a write did
/// or did not leave behind through the API as well as in the database.
const PUT_ROLE_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'put-role-policy-test@example.com', 'put-role-policy-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCPRPBROADWTR01', '%ACCOUNT_ID%', 'broad-writer', 'Broad-Writer', '/'),
    ('SVCPRPPATHWTR001', '%ACCOUNT_ID%', 'path-writer', 'Path-Writer', '/'),
    ('SVCPRPTAGWTR0001', '%ACCOUNT_ID%', 'tag-writer', 'Tag-Writer', '/'),
    ('SVCPRPNARROWWTR1', '%ACCOUNT_ID%', 'narrow-writer', 'Narrow-Writer', '/'),
    ('SVCPRPNOGRANTWR1', '%ACCOUNT_ID%', 'no-grant-writer', 'No-Grant-Writer', '/');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCPRPTGTPOLICY1', '%ACCOUNT_ID%', 'policy-target', 'Policy-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCPRPTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCPRPTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCPRPTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCPRPTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCPRPTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCPRPTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCPRPTGTPOLICY1', 'existing-access', 'Existing-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCPRPBROADWTR01', 'allow-put-any-policy', 'Allow-Put-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Action":["iam:PutRolePolicy","iam:ListRolePolicies"],"Resource":"*"}]}'),
    ('SVCPRPPATHWTR001', 'allow-put-division-policy', 'Allow-Put-Division-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutRolePolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/division/*"}]}'),
    ('SVCPRPTAGWTR0001', 'allow-put-engineering-policy', 'Allow-Put-Engineering-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutRolePolicy","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCPRPNARROWWTR1', 'allow-put-target-policy', 'Allow-Put-Target-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutRolePolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/Policy-Target"}]}');
"#;

/// End-to-end authorization checks for `PutRolePolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_put_role_policy_authorization() {
    /// The document the tests first write under a policy name.
    const FIRST_DOCUMENT: &str =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}"#;

    /// The document the tests then write under the same policy name, replacing the first.
    const SECOND_DOCUMENT: &str =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}"#;

    let database = TestDatabase::new(PUT_ROLE_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:PutRolePolicy on any role adds an inline policy to one.
    let (principal, session_data) = database.user_identity("SVCPRPBROADWTR01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_policy_parameters(Some("Policy-Target"), Some("New-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PutRolePolicyResponse"), "unexpected body: {body}");

    // The write was committed rather than rolled back: the policy is listed, and the document
    // stored under it is the one that was written.
    let (principal, session_data) = database.user_identity("SVCPRPBROADWTR01", "Broad-Writer");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(Some("Policy-Target"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<member>New-Access</member>"), "unexpected body: {body}");
    assert_eq!(
        database.role_inline_policy_document("Policy-Target", "New-Access").await.as_deref(),
        Some(FIRST_DOCUMENT)
    );

    // Writing the same policy name again replaces the document rather than failing.
    let (principal, session_data) = database.user_identity("SVCPRPBROADWTR01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_policy_parameters(Some("Policy-Target"), Some("New-Access"), Some(SECOND_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(
        database.role_inline_policy_document("Policy-Target", "New-Access").await.as_deref(),
        Some(SECOND_DOCUMENT)
    );

    // A document that does not parse as a policy is rejected. The caller is allowed the action,
    // so it learns the document is malformed rather than that it was denied.
    let (principal, session_data) = database.user_identity("SVCPRPBROADWTR01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_policy_parameters(Some("Policy-Target"), Some("Bad-Access"), Some("this is not a policy")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedPolicyDocument</Code>"), "unexpected body: {body}");
    assert_eq!(database.role_inline_policy_document("Policy-Target", "Bad-Access").await, None);

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCPRPNOGRANTWR1", "No-Grant-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_policy_parameters(Some("Policy-Target"), Some("Denied-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Writer is not authorized to perform: \
                 iam:PutRolePolicy on resource: arn:aws:iam::{account_id}:role/Policy-Target"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled the transaction back, so nothing was written.
    assert_eq!(database.role_inline_policy_document("Policy-Target", "Denied-Access").await, None);

    // The resource ARN carries the target role's path, so a grant scoped to a path prefix reaches
    // roles under that path...
    let (principal, session_data) = database.user_identity("SVCPRPPATHWTR001", "Path-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_policy_parameters(Some("Division-Target"), Some("Division-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCPRPPATHWTR001", "Path-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_policy_parameters(Some("Policy-Target"), Some("Division-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the role the policy is embedded in back the iam:ResourceTag condition keys,
    // which the role has to be read to know: the request names only the role.
    let (principal, session_data) = database.user_identity("SVCPRPTAGWTR0001", "Tag-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_policy_parameters(Some("Engineering-Target"), Some("Eng-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A role carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCPRPTAGWTR0001", "Tag-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_policy_parameters(Some("Sales-Target"), Some("Sales-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // An inline policy is part of the role carrying it rather than a resource of its own, so
    // PolicyName narrows nothing: a grant naming just the role allows replacing the policies that
    // role already carries as well as adding new ones.
    let (principal, session_data) = database.user_identity("SVCPRPNARROWWTR1", "Narrow-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_policy_parameters(Some("Policy-Target"), Some("Existing-Access"), Some(SECOND_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(
        database.role_inline_policy_document("Policy-Target", "Existing-Access").await.as_deref(),
        Some(SECOND_DOCUMENT)
    );

    // Role and policy names are both matched case-insensitively, so a differently-cased name
    // replaces the policy already there rather than adding a second one.
    let (principal, session_data) = database.user_identity("SVCPRPBROADWTR01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_policy_parameters(Some("POLICY-TARGET"), Some("EXISTING-ACCESS"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(
        database.role_inline_policy_document("Policy-Target", "Existing-Access").await.as_deref(),
        Some(FIRST_DOCUMENT)
    );

    // A role that does not exist has no path to read, so the ARN authorized is the one it would
    // carry at the root path. A caller allowed iam:PutRolePolicy on any role is told the role is
    // missing...
    let (principal, session_data) = database.user_identity("SVCPRPBROADWTR01", "Broad-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_policy_parameters(Some("No-Such-Role"), Some("New-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific role learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCPRPNARROWWTR1", "Narrow-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_policy_parameters(Some("No-Such-Role"), Some("New-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A malformed role name is rejected before the request is authorized, so the caller learns
    // the request was invalid rather than that it was denied.
    let (principal, session_data) = database.user_identity("SVCPRPNOGRANTWR1", "No-Grant-Writer");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &put_role_policy_parameters(Some("bad role!"), Some("New-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // All three parameters are required; none defaults to anything.
    for parameters in [
        put_role_policy_parameters(None, Some("New-Access"), Some(FIRST_DOCUMENT)),
        put_role_policy_parameters(Some("Policy-Target"), None, Some(FIRST_DOCUMENT)),
        put_role_policy_parameters(Some("Policy-Target"), Some("New-Access"), None),
    ] {
        let (principal, session_data) = database.user_identity("SVCPRPBROADWTR01", "Broad-Writer");
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
        &put_role_policy_parameters(Some("Root-Target"), Some("Root-Access"), Some(FIRST_DOCUMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(
        database.role_inline_policy_document("Root-Target", "Root-Access").await.as_deref(),
        Some(FIRST_DOCUMENT)
    );
}
