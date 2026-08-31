use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `GetGroupPolicy` authorization tests. `Policy-Holder` carries two inline
/// policies, so a grant reaching the group can be shown to reach both; `Division-Target` carries
/// the path the resource ARN is derived from.
const GET_GROUP_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'get-group-policy-test@example.com', 'get-group-policy-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCGGPPBROADRD01', '%ACCOUNT_ID%', 'broad-reader', 'Broad-Reader', '/'),
    ('SVCGGPPPATHRD001', '%ACCOUNT_ID%', 'path-reader', 'Path-Reader', '/'),
    ('SVCGGPPTAGRD0001', '%ACCOUNT_ID%', 'tag-reader', 'Tag-Reader', '/'),
    ('SVCGGPPNARROWR01', '%ACCOUNT_ID%', 'narrow-reader', 'Narrow-Reader', '/'),
    ('SVCGGPPNOGRANT01', '%ACCOUNT_ID%', 'no-grant-reader', 'No-Grant-Reader', '/');

    INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) VALUES
    ('SVCGGPPTGTHOLD01', '%ACCOUNT_ID%', 'policy-holder', 'Policy-Holder', '/'),
    ('SVCGGPPTGTDIVS01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCGGPPBROADRD01', 'allow-get-any-policy', 'Allow-Get-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetGroupPolicy","Resource":"*"}]}'),
    ('SVCGGPPPATHRD001', 'allow-get-division-policy', 'Allow-Get-Division-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetGroupPolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/division/*"}]}'),
    ('SVCGGPPTAGRD0001', 'allow-get-tagged-policy', 'Allow-Get-Tagged-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetGroupPolicy","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCGGPPNARROWR01', 'allow-get-holder-policy', 'Allow-Get-Holder-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetGroupPolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/Policy-Holder"}]}');

    INSERT INTO iam.group_inline_policies(group_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCGGPPTGTHOLD01', 'app-access', 'App-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCGGPPTGTHOLD01', 'db-access', 'Db-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"*"}]}'),
    ('SVCGGPPTGTDIVS01', 'division-access', 'Division-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}');
"#;

/// Build the query parameters for a `GetGroupPolicy` request, naming a group and a policy or
/// leaving either off.
fn get_group_policy_parameters(group_name: Option<&str>, policy_name: Option<&str>) -> String {
    group_policy_parameters("GetGroupPolicy", group_name, policy_name, None)
}

/// End-to-end authorization checks for `GetGroupPolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case so that they share one
/// seeded account, rather than seeding one apiece.
#[test_log::test(tokio::test)]
async fn test_get_group_policy_authorization() {
    let database = TestDatabase::new(GET_GROUP_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:GetGroupPolicy on any group reads an inline policy off one.
    let (principal, session_data) = database.user_identity("SVCGGPPBROADRD01", "Broad-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_group_policy_parameters(Some("Policy-Holder"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<GroupName>Policy-Holder</GroupName>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>App-Access</PolicyName>"), "unexpected body: {body}");

    // The document goes out percent-encoded rather than as the JSON it is stored as, so the raw
    // policy does not appear on the wire at all and a client decodes what it reads back.
    assert!(body.contains("%7B%22Version%22%3A%222012-10-17%22"), "unexpected body: {body}");
    assert!(!body.contains("s3:GetObject"), "unexpected body: {body}");
    assert!(decoded_policy_document(&body).contains("s3:GetObject"), "unexpected body: {body}");

    // Policy names are matched case-insensitively, and the name comes back cased as it was
    // stored rather than as the request spelled it.
    let (principal, session_data) = database.user_identity("SVCGGPPBROADRD01", "Broad-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_group_policy_parameters(Some("Policy-Holder"), Some("app-access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>App-Access</PolicyName>"), "unexpected body: {body}");

    // An inline policy is part of the group carrying it rather than a resource of its own, so
    // PolicyName narrows nothing: a grant naming just the group reaches every inline policy on
    // it.
    for policy_name in ["App-Access", "Db-Access"] {
        let (principal, session_data) = database.user_identity("SVCGGPPNARROWR01", "Narrow-Reader");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_group_policy_parameters(Some("Policy-Holder"), Some(policy_name)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains(&format!("<PolicyName>{policy_name}</PolicyName>")), "unexpected body: {body}");
    }

    // The resource ARN carries the target group's path, so a grant scoped to a path prefix
    // reaches groups under that path...
    let (principal, session_data) = database.user_identity("SVCGGPPPATHRD001", "Path-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_group_policy_parameters(Some("Division-Target"), Some("Division-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(decoded_policy_document(&body).contains("sqs:SendMessage"), "unexpected body: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCGGPPPATHRD001", "Path-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_group_policy_parameters(Some("Policy-Holder"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The group ARN is the whole of what a policy can condition on. A group is not taggable --
    // IAM has no group-tagging operation -- and is not a principal, so no tag or boundary key is
    // reported and a grant written against one never matches.
    let (principal, session_data) = database.user_identity("SVCGGPPTAGRD0001", "Tag-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_group_policy_parameters(Some("Policy-Holder"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCGGPPNOGRANT01", "No-Grant-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_group_policy_parameters(Some("Policy-Holder"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Reader is not authorized to perform: \
                 iam:GetGroupPolicy on resource: arn:aws:iam::{account_id}:group/Policy-Holder"
        )),
        "unexpected body: {body}"
    );

    // A group that does not exist is reported as NoSuchEntity to a caller allowed to read it.
    let (principal, session_data) = database.user_identity("SVCGGPPBROADRD01", "Broad-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_group_policy_parameters(Some("No-Such-Group"), Some("App-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // As is an inline policy the group does not carry.
    let (principal, session_data) = database.user_identity("SVCGGPPBROADRD01", "Broad-Reader");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_group_policy_parameters(Some("Policy-Holder"), Some("No-Such-Policy")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A request missing a required parameter is rejected before it is authorized.
    let (principal, session_data) = database.user_identity("SVCGGPPNOGRANT01", "No-Grant-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_group_policy_parameters(None, Some("App-Access"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &get_group_policy_parameters(Some("Policy-Holder"), Some("Db-Access")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(decoded_policy_document(&body).contains("dynamodb:GetItem"), "unexpected body: {body}");
}
