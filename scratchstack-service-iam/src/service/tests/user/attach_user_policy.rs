use {
    crate::service::{ServiceState, tests::*},
    pretty_assertions::assert_eq,
    scratchstack_core::axum::http::StatusCode,
    scratchstack_iam_database::{migrate::MIGRATOR, utils::TempDatabase},
    sqlx::raw_sql,
    std::sync::Arc,
};

/// Seed data for the `AttachUserPolicy` authorization tests. The callers carry grants scoped by
/// the policy being attached (`iam:PolicyARN`), by the path of the user receiving it, by that
/// user's tags, and by the user itself; the managed policies give those grants something to
/// distinguish, with `Safe-Policy` under a path of its own and `Aws-Managed-Policy` owned by
/// the AWS account rather than by this one.
const ATTACH_USER_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.partition(partition) VALUES ('aws');

    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('123456789012', 'attach-user-policy-test@example.com', 'attach-user-policy-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCAUPBROADATT01', '123456789012', 'broad-attacher', 'Broad-Attacher', '/'),
    ('SVCAUPSAFEATT001', '123456789012', 'safe-attacher', 'Safe-Attacher', '/'),
    ('SVCAUPAWSATT0001', '123456789012', 'aws-attacher', 'Aws-Attacher', '/'),
    ('SVCAUPPATHATT001', '123456789012', 'path-attacher', 'Path-Attacher', '/'),
    ('SVCAUPTAGATT0001', '123456789012', 'tag-attacher', 'Tag-Attacher', '/'),
    ('SVCAUPNARROWA001', '123456789012', 'narrow-attacher', 'Narrow-Attacher', '/'),
    ('SVCAUPNOGRANTA01', '123456789012', 'no-grant-attacher', 'No-Grant-Attacher', '/'),
    ('SVCAUPTGTPLAIN01', '123456789012', 'attach-target', 'Attach-Target', '/'),
    ('SVCAUPTGTDIVSN01', '123456789012', 'division-target', 'Division-Target', '/division/'),
    ('SVCAUPTGTENGNR01', '123456789012', 'engineering-target', 'Engineering-Target', '/'),
    ('SVCAUPTGTSALES01', '123456789012', 'sales-target', 'Sales-Target', '/'),
    ('SVCAUPTGTROOT001', '123456789012', 'root-target', 'Root-Target', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCAUPTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCAUPTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCAUPPOLSAFE001', '123456789012', 'safe-policy', 'Safe-Policy', '/safe/', 1, false, 1),
    ('SVCAUPPOLADMIN01', '123456789012', 'admin-policy', 'Admin-Policy', '/', 1, false, 1),
    ('SVCAUPPOLEXTRA01', '123456789012', 'extra-policy', 'Extra-Policy', '/', 1, false, 1),
    ('SVCAUPPOLAWSMG01', '000000000000', 'aws-managed-policy', 'Aws-Managed-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCAUPPOLSAFE001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCAUPPOLADMIN01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'),
    ('SVCAUPPOLEXTRA01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}'),
    ('SVCAUPPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCAUPBROADATT01', 'allow-attach-any-policy', 'Allow-Attach-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"*"}]}'),
    ('SVCAUPSAFEATT001', 'allow-attach-safe-policies', 'Allow-Attach-Safe-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"*",
        "Condition":{"ArnLike":{"iam:PolicyARN":"arn:aws:iam::123456789012:policy/safe/*"}}}]}'),
    ('SVCAUPAWSATT0001', 'allow-attach-aws-policies', 'Allow-Attach-Aws-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"*",
        "Condition":{"ArnLike":{"iam:PolicyARN":"arn:aws:iam::aws:policy/*"}}}]}'),
    ('SVCAUPPATHATT001', 'allow-attach-to-division', 'Allow-Attach-To-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachUserPolicy",
        "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
    ('SVCAUPTAGATT0001', 'allow-attach-to-engineering', 'Allow-Attach-To-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCAUPNARROWA001', 'allow-attach-to-target', 'Allow-Attach-To-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachUserPolicy",
        "Resource":"arn:aws:iam::123456789012:user/Attach-Target"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCAUPROLE000001', '123456789012', 'attach-user-policy-role', 'Attach-User-Policy-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCAUPROLE000001', 'allow-attach-any-policy', 'Allow-Attach-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `AttachUserPolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function is used because the database is
/// stateful and expensive to start.
#[test_log::test(tokio::test)]
async fn test_attach_user_policy_authorization() {
    const ADMIN_POLICY_ARN: &str = "arn:aws:iam::123456789012:policy/Admin-Policy";
    const EXTRA_POLICY_ARN: &str = "arn:aws:iam::123456789012:policy/Extra-Policy";
    const SAFE_POLICY_ARN: &str = "arn:aws:iam::123456789012:policy/safe/Safe-Policy";
    const AWS_MANAGED_POLICY_ARN: &str = "arn:aws:iam::aws:policy/Aws-Managed-Policy";

    let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
    database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
    let pool =
        database.get_scratchstack_pool().await.expect("Failed to get PostgreSQL connection pool for scratchstack user");

    let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
    MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
    raw_sql(ATTACH_USER_POLICY_TEST_DATA).execute(&mut *c).await.expect("Failed to load test data into database");
    drop(c);

    let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();

    // A caller allowed iam:AttachUserPolicy on any user attaches a managed policy to one.
    let (principal, session_data) = user_identity("SVCAUPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Attach-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<AttachUserPolicyResponse"), "unexpected body: {body}");

    // The attachment took: the root user, implicitly allowed everything, reads it back.
    let (principal, session_data) = root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Attach-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains(&format!("<PolicyArn>{ADMIN_POLICY_ARN}</PolicyArn>")), "unexpected body: {body}");

    // Attaching a policy the user already carries succeeds and changes nothing.
    let (principal, session_data) = user_identity("SVCAUPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Attach-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Attach-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(body.matches("<member>").count(), 1, "unexpected body: {body}");

    // The policy being attached backs iam:PolicyARN, so a grant confined to a policy path
    // reaches the policies under it...
    let (principal, session_data) = user_identity("SVCAUPSAFEATT001", "Safe-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Attach-Target"), Some(SAFE_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further, however broadly the users it may attach them to are named.
    let (principal, session_data) = user_identity("SVCAUPSAFEATT001", "Safe-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Attach-Target"), Some(EXTRA_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // An AWS-owned policy is named through the aws account alias, and iam:PolicyARN carries
    // the ARN as the request spelled it, so that is what the condition compares.
    let (principal, session_data) = user_identity("SVCAUPAWSATT0001", "Aws-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Attach-Target"), Some(AWS_MANAGED_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The same policy named through the numeric account this implementation stores it under is
    // a different string, and the condition compares the string it was given.
    let (principal, session_data) = user_identity("SVCAUPAWSATT0001", "Aws-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(
            Some("Attach-Target"),
            Some("arn:aws:iam::000000000000:policy/Aws-Managed-Policy"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    let (principal, session_data) = user_identity("SVCAUPAWSATT0001", "Aws-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Attach-Target"), Some(EXTRA_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // All three attachments are in place, ordered by policy name. The AWS-owned policy is
    // reported under the numeric account behind the alias, which is how it is stored.
    let (principal, session_data) = root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Attach-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(
            "<AttachedPolicies>\
                 <member><PolicyArn>arn:aws:iam::123456789012:policy/Admin-Policy</PolicyArn>\
                 <PolicyName>Admin-Policy</PolicyName></member>\
                 <member><PolicyArn>arn:aws:iam::000000000000:policy/Aws-Managed-Policy</PolicyArn>\
                 <PolicyName>Aws-Managed-Policy</PolicyName></member>\
                 <member><PolicyArn>arn:aws:iam::123456789012:policy/safe/Safe-Policy</PolicyArn>\
                 <PolicyName>Safe-Policy</PolicyName></member>\
                 </AttachedPolicies>"
        ),
        "unexpected body: {body}"
    );

    // The resource ARN carries the receiving user's path, so a grant scoped to a path prefix
    // reaches users under that path...
    let (principal, session_data) = user_identity("SVCAUPPATHATT001", "Path-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Division-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = user_identity("SVCAUPPATHATT001", "Path-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Attach-Target"), Some(EXTRA_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the receiving user back the aws:ResourceTag condition keys.
    let (principal, session_data) = user_identity("SVCAUPTAGATT0001", "Tag-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Engineering-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = user_identity("SVCAUPTAGATT0001", "Tag-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Sales-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single user and no policy reaches every policy in the account -- which
    // is what makes iam:AttachUserPolicy a privilege escalation unless iam:PolicyARN confines
    // it -- and reaches no other user.
    let (principal, session_data) = user_identity("SVCAUPNARROWA001", "Narrow-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Attach-Target"), Some(EXTRA_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = user_identity("SVCAUPNARROWA001", "Narrow-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Sales-Target"), Some(EXTRA_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = user_identity("SVCAUPNOGRANTA01", "No-Grant-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Attach-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/No-Grant-Attacher is not authorized to perform: \
                 iam:AttachUserPolicy on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Attach-Target"
        )),
        "unexpected body: {body}"
    );

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:AttachUserPolicy on any user is told the user is missing...
    let (principal, session_data) = user_identity("SVCAUPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("No-Such-User"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = user_identity("SVCAUPNARROWA001", "Narrow-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("No-Such-User"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A policy that does not exist is reported the same way, once the caller is allowed to
    // have asked.
    let (principal, session_data) = user_identity("SVCAUPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Attach-Target"), Some("arn:aws:iam::123456789012:policy/No-Such-Policy")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // UserName and PolicyArn are both required.
    for parameters in [
        attach_user_policy_parameters(None, Some(ADMIN_POLICY_ARN)),
        attach_user_policy_parameters(Some("Attach-Target"), None),
    ] {
        let (principal, session_data) = user_identity("SVCAUPBROADATT01", "Broad-Attacher");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // A policy ARN too short to be one is rejected before the request is authorized; one long
    // enough to reach the attachment is rejected by it, after.
    for policy_arn in ["arn:aws:iam::1:p", "not-an-arn-but-long-enough-to-pass"] {
        let (principal, session_data) = user_identity("SVCAUPBROADATT01", "Broad-Attacher");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &attach_user_policy_parameters(Some("Attach-Target"), Some(policy_arn)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // A caller whose grant is confined by iam:PolicyARN never gets that far: a value that is
    // not an ARN at all matches none of the ARNs the policy lists, so it is denied rather than
    // told the ARN is malformed.
    let (principal, session_data) = user_identity("SVCAUPSAFEATT001", "Safe-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Attach-Target"), Some("not-an-arn-but-long-enough-to-pass")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = role_identity("SVCAUPROLE000001", "Attach-User-Policy-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Division-Target"), Some(SAFE_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_user_policy_parameters(Some("Root-Target"), Some(ADMIN_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
}
