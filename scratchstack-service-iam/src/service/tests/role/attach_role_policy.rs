use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `AttachRolePolicy` authorization tests. The callers carry grants scoped by
/// the policy being attached (`iam:PolicyARN`), by the path of the role receiving it, by that
/// role's tags, and by the role itself; the managed policies give those grants something to
/// distinguish, with `Safe-Policy` under a path of its own and `Aws-Managed-Role-Policy` owned by
/// the AWS account rather than by this one.
const ATTACH_ROLE_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'attach-role-policy-test@example.com', 'attach-role-policy-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCARPBROADATT01', '%ACCOUNT_ID%', 'broad-attacher', 'Broad-Attacher', '/'),
    ('SVCARPSAFEATT001', '%ACCOUNT_ID%', 'safe-attacher', 'Safe-Attacher', '/'),
    ('SVCARPAWSATT0001', '%ACCOUNT_ID%', 'aws-attacher', 'Aws-Attacher', '/'),
    ('SVCARPPATHATT001', '%ACCOUNT_ID%', 'path-attacher', 'Path-Attacher', '/'),
    ('SVCARPTAGATT0001', '%ACCOUNT_ID%', 'tag-attacher', 'Tag-Attacher', '/'),
    ('SVCARPNARROWA001', '%ACCOUNT_ID%', 'narrow-attacher', 'Narrow-Attacher', '/'),
    ('SVCARPNOGRANTA01', '%ACCOUNT_ID%', 'no-grant-attacher', 'No-Grant-Attacher', '/'),
    ('SVCARPBOUNDATT01', '%ACCOUNT_ID%', 'boundary-attacher', 'Boundary-Attacher', '/'),
    ('SVCARPGUARDATT01', '%ACCOUNT_ID%', 'guard-attacher', 'Guard-Attacher', '/');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCARPTGTPLAIN01', '%ACCOUNT_ID%', 'attach-target', 'Attach-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCARPTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCARPTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCARPTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCARPTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCARPROLE000001', '%ACCOUNT_ID%', 'attach-role-policy-role', 'Attach-Role-Policy-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCARPTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCARPTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCARPPOLSAFE001', '%ACCOUNT_ID%', 'safe-policy', 'Safe-Policy', '/safe/', 1, false, 1),
    ('SVCARPPOLADMIN01', '%ACCOUNT_ID%', 'admin-policy', 'Admin-Policy', '/', 1, false, 1),
    ('SVCARPPOLEXTRA01', '%ACCOUNT_ID%', 'extra-policy', 'Extra-Policy', '/', 1, false, 1),
    ('SVCARPPOLAWSMG01', '000000000000', 'aws-managed-role-policy', 'Aws-Managed-Role-Policy', '/', 1, false, 1),
    ('SVCARPPOLBOUND01', '%ACCOUNT_ID%', 'boundary-policy', 'Boundary-Policy', '/', 1, false, 1),
    ('SVCARPPOLBOUND02', '%ACCOUNT_ID%', 'other-boundary-policy', 'Other-Boundary-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCARPPOLSAFE001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCARPPOLADMIN01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'),
    ('SVCARPPOLEXTRA01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}'),
    ('SVCARPPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}'),
    ('SVCARPPOLBOUND01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}'),
    ('SVCARPPOLBOUND02', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"}]}');

    -- These roles carry a permissions boundary, so they are created after the managed policies
    -- serving as one.
    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document, permissions_boundary_managed_policy_id) VALUES
    ('SVCARPTGTBOUND01', '%ACCOUNT_ID%', 'bounded-target', 'Bounded-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        'SVCARPPOLBOUND01'),
    ('SVCARPTGTBOUND02', '%ACCOUNT_ID%', 'other-bounded-target', 'Other-Bounded-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}',
        'SVCARPPOLBOUND02');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCARPBROADATT01', 'allow-attach-any-policy', 'Allow-Attach-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:AttachRolePolicy",
        "iam:ListAttachedRolePolicies"],"Resource":"*"}]}'),
    ('SVCARPSAFEATT001', 'allow-attach-safe-policies', 'Allow-Attach-Safe-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"*",
        "Condition":{"ArnLike":{"iam:PolicyARN":"arn:aws:iam::%ACCOUNT_ID%:policy/safe/*"}}}]}'),
    ('SVCARPAWSATT0001', 'allow-attach-aws-policies', 'Allow-Attach-Aws-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"*",
        "Condition":{"ArnLike":{"iam:PolicyARN":"arn:aws:iam::aws:policy/*"}}}]}'),
    ('SVCARPPATHATT001', 'allow-attach-to-division', 'Allow-Attach-To-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachRolePolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/division/*"}]}'),
    ('SVCARPTAGATT0001', 'allow-attach-to-engineering', 'Allow-Attach-To-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCARPNARROWA001', 'allow-attach-to-target', 'Allow-Attach-To-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachRolePolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/Attach-Target"}]}'),
    ('SVCARPBOUNDATT01', 'allow-attach-under-boundary', 'Allow-Attach-Under-Boundary',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"*",
        "Condition":{"StringEquals":{"iam:PermissionsBoundary":
        "arn:aws:iam::%ACCOUNT_ID%:policy/Boundary-Policy"}}}]}'),
    ('SVCARPGUARDATT01', 'deny-attach-outside-boundary', 'Deny-Attach-Outside-Boundary',
        '{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"*"},
        {"Effect":"Deny","Action":"iam:AttachRolePolicy","Resource":"*",
        "Condition":{"StringNotEquals":{"iam:PermissionsBoundary":
        "arn:aws:iam::%ACCOUNT_ID%:policy/Boundary-Policy"}}}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCARPROLE000001', 'allow-attach-any-policy', 'Allow-Attach-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `AttachRolePolicy` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case: the cases run in order
/// against one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_attach_role_policy_authorization() {
    const AWS_MANAGED_POLICY_ARN: &str = "arn:aws:iam::aws:policy/Aws-Managed-Role-Policy";

    let database = TestDatabase::new(ATTACH_ROLE_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let admin_policy_arn = database.arn("policy/Admin-Policy");
    let extra_policy_arn = database.arn("policy/Extra-Policy");
    let safe_policy_arn = database.arn("policy/safe/Safe-Policy");

    // A caller allowed iam:AttachRolePolicy on any role attaches a managed policy to one.
    let (principal, session_data) = database.user_identity("SVCARPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Attach-Target"), Some(admin_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<AttachRolePolicyResponse"), "unexpected body: {body}");

    // The attachment took: the root user, implicitly allowed everything, reads it back.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_role_policies_parameters(Some("Attach-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains(&format!("<PolicyArn>{admin_policy_arn}</PolicyArn>")), "unexpected body: {body}");

    // Attaching a policy the role already carries succeeds and changes nothing.
    let (principal, session_data) = database.user_identity("SVCARPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Attach-Target"), Some(admin_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_role_policies_parameters(Some("Attach-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(body.matches("<member>").count(), 1, "unexpected body: {body}");

    // The role name is matched case-insensitively, as it is everywhere else.
    let (principal, session_data) = database.user_identity("SVCARPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("ATTACH-TARGET"), Some(safe_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_role_policies_parameters(Some("Attach-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(body.matches("<member>").count(), 2, "unexpected body: {body}");

    // The policy being attached backs iam:PolicyARN, so a grant confined to a policy path
    // reaches the policies under it...
    let (principal, session_data) = database.user_identity("SVCARPSAFEATT001", "Safe-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Division-Target"), Some(safe_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further, however broadly the roles it may attach them to are named.
    let (principal, session_data) = database.user_identity("SVCARPSAFEATT001", "Safe-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Attach-Target"), Some(extra_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Managed policies are not shared across accounts, so a policy another account owns is
    // reported the way one that does not exist is -- after authorization, since the caller here
    // is allowed to attach any policy.
    let (principal, session_data) = database.user_identity("SVCARPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(
            Some("Attach-Target"),
            Some("arn:aws:iam::210987654321:policy/Other-Account-Policy"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(
        body.contains("<Message>Policy arn:aws:iam::210987654321:policy/Other-Account-Policy was not found.</Message>"),
        "unexpected body: {body}"
    );

    // An AWS-owned policy is named through the aws account alias, and iam:PolicyARN carries the
    // ARN as the request spelled it, so that is what the condition compares.
    let (principal, session_data) = database.user_identity("SVCARPAWSATT0001", "Aws-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Attach-Target"), Some(AWS_MANAGED_POLICY_ARN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The same policy named through the numeric account this implementation stores it under is a
    // different string, and the condition compares the string it was given.
    let (principal, session_data) = database.user_identity("SVCARPAWSATT0001", "Aws-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(
            Some("Attach-Target"),
            Some("arn:aws:iam::000000000000:policy/Aws-Managed-Role-Policy"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // All three attachments are in place, ordered by policy name. The AWS-owned policy is
    // reported under the numeric account behind the alias, which is how it is stored.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_role_policies_parameters(Some("Attach-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "<AttachedPolicies>\
                 <member><PolicyArn>arn:aws:iam::{account_id}:policy/Admin-Policy</PolicyArn>\
                 <PolicyName>Admin-Policy</PolicyName></member>\
                 <member><PolicyArn>arn:aws:iam::000000000000:policy/Aws-Managed-Role-Policy</PolicyArn>\
                 <PolicyName>Aws-Managed-Role-Policy</PolicyName></member>\
                 <member><PolicyArn>arn:aws:iam::{account_id}:policy/safe/Safe-Policy</PolicyArn>\
                 <PolicyName>Safe-Policy</PolicyName></member>\
                 </AttachedPolicies>"
        )),
        "unexpected body: {body}"
    );

    // The resource ARN carries the receiving role's path, so a grant scoped to a path prefix
    // reaches roles under that path...
    let (principal, session_data) = database.user_identity("SVCARPPATHATT001", "Path-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Division-Target"), Some(admin_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCARPPATHATT001", "Path-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Attach-Target"), Some(extra_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the receiving role back the aws:ResourceTag condition keys.
    let (principal, session_data) = database.user_identity("SVCARPTAGATT0001", "Tag-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Engineering-Target"), Some(admin_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A role carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCARPTAGATT0001", "Tag-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Sales-Target"), Some(admin_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single role and no policy reaches every policy in the account -- which is
    // what makes iam:AttachRolePolicy a privilege escalation unless iam:PolicyARN confines it,
    // and the permissions land with anyone who can assume the role -- and reaches no other role.
    let (principal, session_data) = database.user_identity("SVCARPNARROWA001", "Narrow-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Attach-Target"), Some(extra_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCARPNARROWA001", "Narrow-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Sales-Target"), Some(extra_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The boundary set on the receiving role backs the iam:PermissionsBoundary condition key,
    // so a grant confined to roles under a particular boundary reaches one that carries it...
    let (principal, session_data) = database.user_identity("SVCARPBOUNDATT01", "Boundary-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Bounded-Target"), Some(extra_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and not one carrying a different boundary, which is what keeps a delegated
    // administrator from raising a role above itself.
    let (principal, session_data) = database.user_identity("SVCARPBOUNDATT01", "Boundary-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Other-Bounded-Target"), Some(extra_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A role under no boundary at all supplies no key, so the condition does not match rather
    // than matching an empty string: an unbounded role is out of reach too.
    let (principal, session_data) = database.user_identity("SVCARPBOUNDATT01", "Boundary-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Attach-Target"), Some(extra_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The key works as a deny guard too. A caller allowed the action broadly, but denied it
    // wherever the boundary is not the expected one, reaches a role carrying that boundary...
    let (principal, session_data) = database.user_identity("SVCARPGUARDATT01", "Guard-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Bounded-Target"), Some(admin_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and is stopped by its own guard on a role carrying a different one.
    let (principal, session_data) = database.user_identity("SVCARPGUARDATT01", "Guard-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Other-Bounded-Target"), Some(admin_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A role under no boundary supplies no key, and StringNotEquals does not match a key that
    // is absent, so the deny does not fire and the broad allow stands. This is IAM's behaviour
    // and is the reason such a guard has to be written with a Null condition or an IfExists
    // operator to cover unbounded roles; asserting it here keeps the omission from being read
    // as a missing key.
    let (principal, session_data) = database.user_identity("SVCARPGUARDATT01", "Guard-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Root-Target"), Some(admin_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCARPNOGRANTA01", "No-Grant-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Attach-Target"), Some(admin_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Attacher is not authorized to perform: \
                 iam:AttachRolePolicy on resource: arn:aws:iam::{account_id}:role/Attach-Target"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled back with the transaction: the role carries what it carried before.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_role_policies_parameters(Some("Attach-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(body.matches("<member>").count(), 4, "unexpected body: {body}");

    // A role that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:AttachRolePolicy on any role is told the role is missing...
    let (principal, session_data) = database.user_identity("SVCARPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("No-Such-Role"), Some(admin_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific role learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCARPNARROWA001", "Narrow-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("No-Such-Role"), Some(admin_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A policy that does not exist is reported the same way, once the caller is allowed to have
    // asked.
    let (principal, session_data) = database.user_identity("SVCARPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Attach-Target"), Some(database.arn("policy/No-Such-Policy").as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // RoleName and PolicyArn are both required.
    for parameters in [
        attach_role_policy_parameters(None, Some(admin_policy_arn.as_str())),
        attach_role_policy_parameters(Some("Attach-Target"), None),
    ] {
        let (principal, session_data) = database.user_identity("SVCARPBROADATT01", "Broad-Attacher");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // A role name that is not a role name is rejected before the request is authorized.
    let (principal, session_data) = database.user_identity("SVCARPBROADATT01", "Broad-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Bad Role Name"), Some(admin_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A policy ARN too short to be one is rejected before the request is authorized; one long
    // enough to reach the attachment is rejected by it, after.
    for policy_arn in ["arn:aws:iam::1:p", "not-an-arn-but-long-enough-to-pass"] {
        let (principal, session_data) = database.user_identity("SVCARPBROADATT01", "Broad-Attacher");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &attach_role_policy_parameters(Some("Attach-Target"), Some(policy_arn)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // A caller whose grant is confined by iam:PolicyARN never gets that far: a value that is not
    // an ARN at all matches none of the ARNs the policy lists, so it is denied rather than told
    // the ARN is malformed.
    let (principal, session_data) = database.user_identity("SVCARPSAFEATT001", "Safe-Attacher");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Attach-Target"), Some("not-an-arn-but-long-enough-to-pass")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCARPROLE000001", "Attach-Role-Policy-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Engineering-Target"), Some(safe_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &attach_role_policy_parameters(Some("Root-Target"), Some(admin_policy_arn.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
}
