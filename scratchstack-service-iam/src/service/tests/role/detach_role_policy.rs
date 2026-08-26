use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `DetachRolePolicy` authorization tests. `Detach-Target` starts out carrying
/// several managed policies so that a detachment can be seen to remove one and leave the rest;
/// the callers carry grants scoped by the policy being detached (`iam:PolicyARN`), by the path of
/// the role losing it, by that role's tags, and by the role itself.
const DETACH_ROLE_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'detach-role-policy-test@example.com', 'detach-role-policy-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCDTRBROADDET01', '%ACCOUNT_ID%', 'broad-detacher', 'Broad-Detacher', '/'),
    ('SVCDTRSAFEDET001', '%ACCOUNT_ID%', 'safe-detacher', 'Safe-Detacher', '/'),
    ('SVCDTRPATHDET001', '%ACCOUNT_ID%', 'path-detacher', 'Path-Detacher', '/'),
    ('SVCDTRTAGDET0001', '%ACCOUNT_ID%', 'tag-detacher', 'Tag-Detacher', '/'),
    ('SVCDTRNARROWD001', '%ACCOUNT_ID%', 'narrow-detacher', 'Narrow-Detacher', '/'),
    ('SVCDTRNOGRANTD01', '%ACCOUNT_ID%', 'no-grant-detacher', 'No-Grant-Detacher', '/');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCDTRTGTPLAIN01', '%ACCOUNT_ID%', 'detach-target', 'Detach-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCDTRTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCDTRTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCDTRTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCDTRTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCDTRROLE000001', '%ACCOUNT_ID%', 'detach-role-policy-role', 'Detach-Role-Policy-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCDTRTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCDTRTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCDTRPOLSAFE001', '%ACCOUNT_ID%', 'safe-policy', 'Safe-Policy', '/safe/', 1, false, 1),
    ('SVCDTRPOLAPP0001', '%ACCOUNT_ID%', 'app-policy', 'App-Policy', '/', 1, false, 1),
    ('SVCDTRPOLDB00001', '%ACCOUNT_ID%', 'db-policy', 'Db-Policy', '/', 1, false, 1),
    ('SVCDTRPOLNARROW1', '%ACCOUNT_ID%', 'narrow-policy', 'Narrow-Policy', '/', 1, false, 1),
    ('SVCDTRPOLCASED01', '%ACCOUNT_ID%', 'cased-policy', 'Cased-Policy', '/', 1, false, 1),
    ('SVCDTRPOLDIVSN01', '%ACCOUNT_ID%', 'division-policy', 'Division-Policy', '/', 1, false, 1),
    ('SVCDTRPOLENG0001', '%ACCOUNT_ID%', 'eng-policy', 'Eng-Policy', '/', 1, false, 1),
    ('SVCDTRPOLSALES01', '%ACCOUNT_ID%', 'sales-policy', 'Sales-Policy', '/', 1, false, 1),
    ('SVCDTRPOLROOT001', '%ACCOUNT_ID%', 'root-policy', 'Root-Policy', '/', 1, false, 1),
    ('SVCDTRPOLSESS001', '%ACCOUNT_ID%', 'session-policy', 'Session-Policy', '/', 1, false, 1),
    ('SVCDTRPOLUNATT01', '%ACCOUNT_ID%', 'unattached-policy', 'Unattached-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCDTRPOLSAFE001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCDTRPOLAPP0001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}'),
    ('SVCDTRPOLDB00001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"*"}]}'),
    ('SVCDTRPOLNARROW1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}'),
    ('SVCDTRPOLCASED01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ses:SendEmail","Resource":"*"}]}'),
    ('SVCDTRPOLDIVSN01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}'),
    ('SVCDTRPOLENG0001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeVolumes","Resource":"*"}]}'),
    ('SVCDTRPOLSALES01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ses:SendRawEmail","Resource":"*"}]}'),
    ('SVCDTRPOLROOT001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}'),
    ('SVCDTRPOLSESS001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"logs:PutLogEvents","Resource":"*"}]}'),
    ('SVCDTRPOLUNATT01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}]}');

    INSERT INTO iam.role_attached_policies(role_id, managed_policy_id) VALUES
    ('SVCDTRTGTPLAIN01', 'SVCDTRPOLSAFE001'),
    ('SVCDTRTGTPLAIN01', 'SVCDTRPOLAPP0001'),
    ('SVCDTRTGTPLAIN01', 'SVCDTRPOLDB00001'),
    ('SVCDTRTGTPLAIN01', 'SVCDTRPOLNARROW1'),
    ('SVCDTRTGTPLAIN01', 'SVCDTRPOLCASED01'),
    ('SVCDTRTGTPLAIN01', 'SVCDTRPOLSESS001'),
    ('SVCDTRTGTDIVSN01', 'SVCDTRPOLDIVSN01'),
    ('SVCDTRTGTENGNR01', 'SVCDTRPOLENG0001'),
    ('SVCDTRTGTSALES01', 'SVCDTRPOLSALES01'),
    ('SVCDTRTGTROOT001', 'SVCDTRPOLROOT001');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDTRBROADDET01', 'allow-detach-any-policy', 'Allow-Detach-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:DetachRolePolicy",
        "iam:ListAttachedRolePolicies"],"Resource":"*"}]}'),
    ('SVCDTRSAFEDET001', 'allow-detach-safe-policies', 'Allow-Detach-Safe-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DetachRolePolicy","Resource":"*",
        "Condition":{"ArnLike":{"iam:PolicyARN":"arn:aws:iam::%ACCOUNT_ID%:policy/safe/*"}}}]}'),
    ('SVCDTRPATHDET001', 'allow-detach-from-division', 'Allow-Detach-From-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DetachRolePolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/division/*"}]}'),
    ('SVCDTRTAGDET0001', 'allow-detach-from-engineering', 'Allow-Detach-From-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DetachRolePolicy","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCDTRNARROWD001', 'allow-detach-from-target', 'Allow-Detach-From-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DetachRolePolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/Detach-Target"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCDTRROLE000001', 'allow-detach-any-policy', 'Allow-Detach-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DetachRolePolicy","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `DetachRolePolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_detach_role_policy_authorization() {
    let database = TestDatabase::new(DETACH_ROLE_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let app_policy_arn = database.arn("policy/App-Policy");
    let cased_policy_arn = database.arn("policy/Cased-Policy");
    let db_policy_arn = database.arn("policy/Db-Policy");
    let narrow_policy_arn = database.arn("policy/Narrow-Policy");
    let safe_policy_arn = database.arn("policy/safe/Safe-Policy");
    let unattached_policy_arn = database.arn("policy/Unattached-Policy");

    // A caller allowed iam:DetachRolePolicy on any role removes one managed policy from a role.
    let (principal, session_data) = database.user_identity("SVCDTRBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("Detach-Target"), Some(app_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<DetachRolePolicyResponse"), "unexpected body: {body}");

    // Only the named policy went: the rest of the attachments are untouched.
    let (principal, session_data) = database.user_identity("SVCDTRBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_role_policies_parameters(Some("Detach-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("App-Policy"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>Db-Policy</PolicyName>"), "unexpected body: {body}");
    assert_eq!(body.matches("<member>").count(), 5, "unexpected body: {body}");

    // The managed policy itself is untouched; only the attachment is gone, so it can be read
    // back and attached again.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_parameters(Some(app_policy_arn.as_str()))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>App-Policy</PolicyName>"), "unexpected body: {body}");

    // Detaching a policy the role does not carry is NoSuchEntity rather than a silent success:
    // this is the one place detaching differs from attaching, which is idempotent.
    let (principal, session_data) = database.user_identity("SVCDTRBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("Detach-Target"), Some(app_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A policy that exists but was never attached to this role is reported the same way.
    let (principal, session_data) = database.user_identity("SVCDTRBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("Detach-Target"), Some(unattached_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // The role name is matched case-insensitively, as it is everywhere else.
    let (principal, session_data) = database.user_identity("SVCDTRBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("DETACH-TARGET"), Some(cased_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCDTRBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_role_policies_parameters(Some("Detach-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("Cased-Policy"), "unexpected body: {body}");

    // The policy being detached backs iam:PolicyARN, so a grant confined to a policy path
    // reaches the policies under it...
    let (principal, session_data) = database.user_identity("SVCDTRSAFEDET001", "Safe-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("Detach-Target"), Some(safe_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further, however broadly the roles it may detach them from are named.
    let (principal, session_data) = database.user_identity("SVCDTRSAFEDET001", "Safe-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("Detach-Target"), Some(db_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The resource ARN carries the losing role's path, so a grant scoped to a path prefix
    // reaches roles under that path...
    let (principal, session_data) = database.user_identity("SVCDTRPATHDET001", "Path-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("Division-Target"), Some(database.arn("policy/Division-Policy").as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCDTRPATHDET001", "Path-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("Detach-Target"), Some(db_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the role losing the policy back the aws:ResourceTag condition keys.
    let (principal, session_data) = database.user_identity("SVCDTRTAGDET0001", "Tag-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("Engineering-Target"), Some(database.arn("policy/Eng-Policy").as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A role carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCDTRTAGDET0001", "Tag-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("Sales-Target"), Some(database.arn("policy/Sales-Policy").as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single role and no policy reaches every policy attached to it -- which is
    // why detaching is worth confining too: a caller able to detach can strip a role of the very
    // grants that hold it in check -- and reaches no other role.
    let (principal, session_data) = database.user_identity("SVCDTRNARROWD001", "Narrow-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("Detach-Target"), Some(narrow_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCDTRNARROWD001", "Narrow-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("Sales-Target"), Some(database.arn("policy/Sales-Policy").as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCDTRNOGRANTD01", "No-Grant-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("Detach-Target"), Some(db_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Detacher is not authorized to perform: \
                 iam:DetachRolePolicy on resource: arn:aws:iam::{account_id}:role/Detach-Target"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled back with the transaction: the policy is still attached.
    let (principal, session_data) = database.user_identity("SVCDTRBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_role_policies_parameters(Some("Detach-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Db-Policy</PolicyName>"), "unexpected body: {body}");

    // A role that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:DetachRolePolicy on any role is told the role is missing...
    let (principal, session_data) = database.user_identity("SVCDTRBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("No-Such-Role"), Some(db_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific role learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCDTRNARROWD001", "Narrow-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("No-Such-Role"), Some(db_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // RoleName and PolicyArn are both required.
    for parameters in [
        detach_role_policy_parameters(None, Some(db_policy_arn.as_str())),
        detach_role_policy_parameters(Some("Detach-Target"), None),
    ] {
        let (principal, session_data) = database.user_identity("SVCDTRBROADDET01", "Broad-Detacher");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // A role name that is not a role name is rejected before the request is authorized.
    let (principal, session_data) = database.user_identity("SVCDTRBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("Bad Role Name"), Some(db_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A policy ARN too short to be one is rejected before the request is authorized; one long
    // enough to reach the detachment is rejected by it, after.
    for policy_arn in ["arn:aws:iam::1:p", "not-an-arn-but-long-enough-to-pass"] {
        let (principal, session_data) = database.user_identity("SVCDTRBROADDET01", "Broad-Detacher");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &detach_role_policy_parameters(Some("Detach-Target"), Some(policy_arn)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCDTRROLE000001", "Detach-Role-Policy-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("Detach-Target"), Some(database.arn("policy/Session-Policy").as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &detach_role_policy_parameters(Some("Root-Target"), Some(database.arn("policy/Root-Policy").as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // Everything the target started with has now been detached but Db-Policy.
    let (principal, session_data) = database.user_identity("SVCDTRBROADDET01", "Broad-Detacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_role_policies_parameters(Some("Detach-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "<AttachedPolicies>\
                 <member><PolicyArn>arn:aws:iam::{account_id}:policy/Db-Policy</PolicyArn>\
                 <PolicyName>Db-Policy</PolicyName></member>\
                 </AttachedPolicies>"
        )),
        "unexpected body: {body}"
    );
}
