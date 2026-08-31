use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `GetRolePolicy` authorization tests. `Policy-Holder` carries two inline
/// policies, so a grant reaching the role can be shown to reach both; the other targets carry the
/// paths, tags, and permissions boundary the resource ARN and the condition keys are derived
/// from.
const GET_ROLE_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'get-role-policy-test@example.com', 'get-role-policy-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCGRPBROADRDR01', '%ACCOUNT_ID%', 'broad-reader', 'Broad-Reader', '/'),
    ('SVCGRPPATHRDR001', '%ACCOUNT_ID%', 'path-reader', 'Path-Reader', '/'),
    ('SVCGRPTAGRDR0001', '%ACCOUNT_ID%', 'tag-reader', 'Tag-Reader', '/'),
    ('SVCGRPIAMTAGRDR1', '%ACCOUNT_ID%', 'iam-tag-reader', 'Iam-Tag-Reader', '/'),
    ('SVCGRPPBRDR00001', '%ACCOUNT_ID%', 'boundary-reader', 'Boundary-Reader', '/'),
    ('SVCGRPNARROWRDR1', '%ACCOUNT_ID%', 'narrow-reader', 'Narrow-Reader', '/'),
    ('SVCGRPNOGRANTRD1', '%ACCOUNT_ID%', 'no-grant-reader', 'No-Grant-Reader', '/');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCGRPBOUNDARY01', '%ACCOUNT_ID%', 'boundary-policy', 'Boundary-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCGRPBOUNDARY01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document, permissions_boundary_managed_policy_id) VALUES
    ('SVCGRPTGTHOLDER1', '%ACCOUNT_ID%', 'policy-holder', 'Policy-Holder', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        'SVCGRPBOUNDARY01'),
    ('SVCGRPTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        NULL),
    ('SVCGRPTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        NULL),
    ('SVCGRPTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        NULL);

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCGRPTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCGRPTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCGRPBROADRDR01', 'allow-get-any-policy', 'Allow-Get-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRolePolicy","Resource":"*"}]}'),
    ('SVCGRPPATHRDR001', 'allow-get-division-policy', 'Allow-Get-Division-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRolePolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/division/*"}]}'),
    ('SVCGRPTAGRDR0001', 'allow-get-engineering-policy', 'Allow-Get-Engineering-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRolePolicy","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCGRPIAMTAGRDR1', 'allow-get-engineering-iam', 'Allow-Get-Engineering-Iam',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRolePolicy","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCGRPPBRDR00001', 'allow-get-bounded-policy', 'Allow-Get-Bounded-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRolePolicy","Resource":"*",
        "Condition":{"StringEquals":
            {"iam:PermissionsBoundary":"arn:aws:iam::%ACCOUNT_ID%:policy/Boundary-Policy"}}}]}'),
    ('SVCGRPNARROWRDR1', 'allow-get-holder-policy', 'Allow-Get-Holder-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRolePolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/Policy-Holder"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCGRPTGTHOLDER1', 'app-access', 'App-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCGRPTGTHOLDER1', 'db-access', 'Db-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"*"}]}'),
    ('SVCGRPTGTDIVSN01', 'division-access', 'Division-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}'),
    ('SVCGRPTGTENGNR01', 'eng-access', 'Eng-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}'),
    ('SVCGRPTGTSALES01', 'sales-access', 'Sales-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ses:SendEmail","Resource":"*"}]}');
"#;

/// Build the query parameters for a `GetRolePolicy` request, naming a role and a policy or
/// leaving either off.
fn get_role_policy_parameters(role_name: Option<&str>, policy_name: Option<&str>) -> String {
    role_policy_parameters("GetRolePolicy", role_name, policy_name, None)
}

/// End-to-end authorization checks for `GetRolePolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case so that they share one
/// seeded account, rather than seeding one apiece.
#[test_log::test(tokio::test)]
async fn test_get_role_policy_authorization() {
    let database = TestDatabase::new(GET_ROLE_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:GetRolePolicy on any role reads an inline policy off one.
    let (principal, session_data) = database.user_identity("SVCGRPBROADRDR01", "Broad-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_role_policy_parameters(Some("Policy-Holder"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<RoleName>Policy-Holder</RoleName>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>App-Access</PolicyName>"), "unexpected body: {body}");

    // The document goes out percent-encoded rather than as the JSON it is stored as, so the raw
    // policy does not appear on the wire at all and a client decodes what it reads back.
    assert!(body.contains("%7B%22Version%22%3A%222012-10-17%22"), "unexpected body: {body}");
    assert!(!body.contains("s3:GetObject"), "unexpected body: {body}");
    assert!(decoded_policy_document(&body).contains("s3:GetObject"), "unexpected body: {body}");

    // Policy names are matched case-insensitively, and the name comes back cased as it was
    // stored rather than as the request spelled it.
    let (principal, session_data) = database.user_identity("SVCGRPBROADRDR01", "Broad-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_role_policy_parameters(Some("Policy-Holder"), Some("app-access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>App-Access</PolicyName>"), "unexpected body: {body}");

    // An inline policy is part of the role carrying it rather than a resource of its own, so
    // PolicyName narrows nothing: a grant naming just the role reaches every inline policy on it.
    for policy_name in ["App-Access", "Db-Access"] {
        let (principal, session_data) = database.user_identity("SVCGRPNARROWRDR1", "Narrow-Reader");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_role_policy_parameters(Some("Policy-Holder"), Some(policy_name)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains(&format!("<PolicyName>{policy_name}</PolicyName>")), "unexpected body: {body}");
    }

    // ...and reaches exactly the role it names, and no other.
    let (principal, session_data) = database.user_identity("SVCGRPNARROWRDR1", "Narrow-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_role_policy_parameters(Some("Engineering-Target"), Some("Eng-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The resource ARN carries the target role's path, so a grant scoped to a path prefix
    // reaches roles under that path...
    let (principal, session_data) = database.user_identity("SVCGRPPATHRDR001", "Path-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_role_policy_parameters(Some("Division-Target"), Some("Division-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(decoded_policy_document(&body).contains("sqs:SendMessage"), "unexpected body: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCGRPPATHRDR001", "Path-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_role_policy_parameters(Some("Policy-Holder"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The role's tags back aws:ResourceTag/${TagKey}...
    let (principal, session_data) = database.user_identity("SVCGRPTAGRDR0001", "Tag-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_role_policy_parameters(Some("Engineering-Target"), Some("Eng-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(decoded_policy_document(&body).contains("ec2:DescribeInstances"), "unexpected body: {body}");

    // ...and a role tagged otherwise does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCGRPTAGRDR0001", "Tag-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_role_policy_parameters(Some("Sales-Target"), Some("Sales-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // IAM's own iam:ResourceTag/${TagKey} spelling carries the same values.
    let (principal, session_data) = database.user_identity("SVCGRPIAMTAGRDR1", "Iam-Tag-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_role_policy_parameters(Some("Engineering-Target"), Some("Eng-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCGRPIAMTAGRDR1", "Iam-Tag-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_role_policy_parameters(Some("Sales-Target"), Some("Sales-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Reading an inline policy off a role does not report the permissions boundary set on it.
    // IAM lists iam:PermissionsBoundary for the operations that change what a role may do, and
    // for GetRole, but not for this one -- so a grant written against it never matches, even
    // though Policy-Holder does carry exactly the boundary the condition names. Supplying the key
    // here would make a StringNotEquals deny guard fire where IAM leaves it dormant.
    let (principal, session_data) = database.user_identity("SVCGRPPBRDR00001", "Boundary-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_role_policy_parameters(Some("Policy-Holder"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCGRPNOGRANTRD1", "No-Grant-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_role_policy_parameters(Some("Policy-Holder"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Reader is not authorized to perform: \
                 iam:GetRolePolicy on resource: arn:aws:iam::{account_id}:role/Policy-Holder"
        )),
        "unexpected body: {body}"
    );

    // A role that does not exist is reported as NoSuchEntity to a caller allowed to read it.
    let (principal, session_data) = database.user_identity("SVCGRPBROADRDR01", "Broad-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_role_policy_parameters(Some("No-Such-Role"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // As is an inline policy the role does not carry.
    let (principal, session_data) = database.user_identity("SVCGRPBROADRDR01", "Broad-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_role_policy_parameters(Some("Policy-Holder"), Some("No-Such-Policy")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A request missing a required parameter is rejected before it is authorized.
    let (principal, session_data) = database.user_identity("SVCGRPNOGRANTRD1", "No-Grant-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_role_policy_parameters(None, Some("App-Access"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_role_policy_parameters(Some("Policy-Holder"), Some("Db-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(decoded_policy_document(&body).contains("dynamodb:GetItem"), "unexpected body: {body}");
}
