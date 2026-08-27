use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `AttachGroupPolicy` authorization tests. The group is the resource and the
/// policy is named by `iam:PolicyARN`, so the callers are scoped by each half separately and by
/// neither: by the path of the group receiving the policy, by the group itself, by the policy
/// being attached, and not at all.
const ATTACH_GROUP_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'attach-group-policy-test@example.com', 'attach-group-policy-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCAGPBROADATT01', '%ACCOUNT_ID%', 'broad-attacher', 'Broad-Attacher', '/'),
    ('SVCAGPSAFEATT001', '%ACCOUNT_ID%', 'safe-attacher', 'Safe-Attacher', '/'),
    ('SVCAGPPATHATT001', '%ACCOUNT_ID%', 'path-attacher', 'Path-Attacher', '/'),
    ('SVCAGPNARROWAT01', '%ACCOUNT_ID%', 'narrow-attacher', 'Narrow-Attacher', '/'),
    ('SVCAGPNOGRANTA01', '%ACCOUNT_ID%', 'no-grant-attacher', 'No-Grant-Attacher', '/');

    INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) VALUES
    ('SVCAGPTGTPLAIN01', '%ACCOUNT_ID%', 'plain-group', 'Plain-Group', '/'),
    ('SVCAGPTGTDIVSN01', '%ACCOUNT_ID%', 'division-group', 'Division-Group', '/division/'),
    ('SVCAGPTGTNARRW01', '%ACCOUNT_ID%', 'narrow-group', 'Narrow-Group', '/'),
    ('SVCAGPTGTOTHER01', '%ACCOUNT_ID%', 'other-group', 'Other-Group', '/'),
    ('SVCAGPTGTROLE001', '%ACCOUNT_ID%', 'role-group', 'Role-Group', '/'),
    ('SVCAGPTGTROOT001', '%ACCOUNT_ID%', 'root-group', 'Root-Group', '/');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCAGPPOLSAFE001', '%ACCOUNT_ID%', 'safe-policy', 'Safe-Policy', '/safe/', 1, false, 1),
    ('SVCAGPPOLWIDE001', '%ACCOUNT_ID%', 'wide-policy', 'Wide-Policy', '/', 1, false, 1),
    ('SVCAGPPOLAWSMG01', '000000000000', 'group-aws-managed', 'Group-Aws-Managed', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCAGPPOLSAFE001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCAGPPOLWIDE001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'),
    ('SVCAGPPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCAGPBROADATT01', 'allow-attach-anything', 'Allow-Attach-Anything',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachGroupPolicy","Resource":"*"}]}'),
    ('SVCAGPSAFEATT001', 'allow-attach-safe-policies', 'Allow-Attach-Safe-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachGroupPolicy",
        "Resource":"*","Condition":{"ArnLike":{"iam:PolicyARN":"arn:aws:iam::%ACCOUNT_ID%:policy/safe/*"}}}]}'),
    ('SVCAGPPATHATT001', 'allow-attach-on-division', 'Allow-Attach-On-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachGroupPolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/division/*"}]}'),
    ('SVCAGPNARROWAT01', 'allow-attach-on-target', 'Allow-Attach-On-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachGroupPolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:group/Narrow-Group"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCAGPROLE000001', '%ACCOUNT_ID%', 'attach-group-policy-role', 'Attach-Group-Policy-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCAGPROLE000001', 'allow-attach-anything', 'Allow-Attach-Anything',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachGroupPolicy","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `AttachGroupPolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_attach_group_policy_authorization() {
    const AWS_MANAGED_POLICY_ARN: &str = "arn:aws:iam::aws:policy/Group-Aws-Managed";

    let database = TestDatabase::new(ATTACH_GROUP_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let safe_policy_arn = database.arn("policy/safe/Safe-Policy");
    let wide_policy_arn = database.arn("policy/Wide-Policy");

    // A caller allowed iam:AttachGroupPolicy on any group attaches a policy to one.
    let (principal, session_data) = database.user_identity("SVCAGPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("Plain-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<AttachGroupPolicyResponse"), "unexpected body: {body}");
    assert_eq!(database.group_attached_policy_names("Plain-Group").await, vec!["Wide-Policy"]);

    // The attachment is idempotent, so attaching a policy the group already carries succeeds and
    // adds nothing.
    let (principal, session_data) = database.user_identity("SVCAGPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("Plain-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(database.group_attached_policy_names("Plain-Group").await, vec!["Wide-Policy"]);

    // A group may carry more than one managed policy.
    let (principal, session_data) = database.user_identity("SVCAGPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("Plain-Group"), Some(safe_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(database.group_attached_policy_names("Plain-Group").await, vec!["Safe-Policy", "Wide-Policy"]);

    // The policy being attached backs iam:PolicyARN, so a grant confined to a policy path reaches
    // the policies under it...
    let (principal, session_data) = database.user_identity("SVCAGPSAFEATT001", "Safe-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("Other-Group"), Some(safe_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further, however broadly the groups it may attach them to are named. This is what
    // keeps such a caller from handing a group -- and so every member of it -- more than the
    // policies it was trusted with.
    let (principal, session_data) = database.user_identity("SVCAGPSAFEATT001", "Safe-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("Other-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The denial rolled its transaction back, so only the allowed policy is attached.
    assert_eq!(database.group_attached_policy_names("Other-Group").await, vec!["Safe-Policy"]);

    // An AWS-owned policy is named through the aws account alias, and can be attached like any
    // other.
    let (principal, session_data) = database.user_identity("SVCAGPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("Other-Group"), Some(AWS_MANAGED_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(database.group_attached_policy_names("Other-Group").await, vec!["Group-Aws-Managed", "Safe-Policy"]);

    // The resource ARN carries the receiving group's path, so a grant scoped to a path prefix
    // reaches groups under that path...
    let (principal, session_data) = database.user_identity("SVCAGPPATHATT001", "Path-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("Division-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCAGPPATHATT001", "Path-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("Plain-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single group and no policy reaches every policy in the account -- so such
    // a caller can hand that group whatever it likes -- and reaches no other group.
    let (principal, session_data) = database.user_identity("SVCAGPNARROWAT01", "Narrow-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("Narrow-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCAGPNARROWAT01", "Narrow-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("Other-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied -- named by the
    // group, since that is the resource the action acts on.
    let (principal, session_data) = database.user_identity("SVCAGPNOGRANTA01", "No-Grant-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("Plain-Group"), Some(safe_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Attacher is not authorized to perform: \
                 iam:AttachGroupPolicy on resource: arn:aws:iam::{account_id}:group/Plain-Group"
        )),
        "unexpected body: {body}"
    );

    // A group that does not exist is still authorized against the ARN the request names, so a
    // caller allowed the action on any group is told the group is missing...
    let (principal, session_data) = database.user_identity("SVCAGPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("No-Such-Group"), Some(safe_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...and so is a policy that does not exist, once the caller is allowed to have asked.
    let (principal, session_data) = database.user_identity("SVCAGPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("Plain-Group"), Some(database.arn("policy/No-Such-Policy").as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A caller allowed the action only on a specific group learns nothing about either.
    let (principal, session_data) = database.user_identity("SVCAGPNARROWAT01", "Narrow-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("No-Such-Group"), Some(safe_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // GroupName and PolicyArn are both required.
    for parameters in [
        attach_group_policy_parameters(None, Some(safe_policy_arn.as_str())),
        attach_group_policy_parameters(Some("Plain-Group"), None),
    ] {
        let (principal, session_data) = database.user_identity("SVCAGPBROADATT01", "Broad-Attacher");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // A policy ARN too short to be one is rejected before the request is authorized; one long
    // enough to reach the attachment -- whether it is not an ARN at all, or an ARN naming
    // something that is not a policy -- is rejected by it, after.
    for policy_arn in [
        "arn:aws:iam::1:p".to_string(),
        "not-an-arn-but-long-enough-to-pass".to_string(),
        database.arn("group/Plain-Group"),
    ] {
        let (principal, session_data) = database.user_identity("SVCAGPBROADATT01", "Broad-Attacher");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &attach_group_policy_parameters(Some("Plain-Group"), Some(policy_arn.as_str())),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // A group name that cannot name a group is rejected the same way, before authorization.
    let (principal, session_data) = database.user_identity("SVCAGPNOGRANTA01", "No-Grant-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("Not/A/Group-Name"), Some(safe_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCAGPROLE000001", "Attach-Group-Policy-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("Role-Group"), Some(safe_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(database.group_attached_policy_names("Role-Group").await, vec!["Safe-Policy"]);

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_group_policy_parameters(Some("Root-Group"), Some(wide_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(database.group_attached_policy_names("Root-Group").await, vec!["Wide-Policy"]);
}
