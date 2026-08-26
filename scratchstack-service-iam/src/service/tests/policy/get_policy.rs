use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The ARN of the AWS-managed policy this test seeds, spelled with the numeric account the
/// database stores AWS-managed policies under.
const AWS_MANAGED_POLICY_ARN: &str = "arn:aws:iam::000000000000:policy/Get-Policy-Aws-Managed";

/// The same policy, spelled with the `aws` account alias IAM uses for AWS-managed policies.
const AWS_MANAGED_POLICY_ALIAS_ARN: &str = "arn:aws:iam::aws:policy/Get-Policy-Aws-Managed";

/// A policy in an account that is not the caller's, seeded so that a caller trying to read across
/// accounts has something real to fail to reach.
const FOREIGN_POLICY_ARN: &str = "arn:aws:iam::310987654321:policy/Foreign-Policy";

/// Seed data for the `GetPolicy` authorization tests. The callers carry grants scoped by the
/// policy being read and by that policy's tags; the managed policies give those grants something
/// to distinguish, with `Safe-Policy` under a path of its own, one policy owned by the AWS
/// account rather than by this one, and one owned by an unrelated account.
const GET_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'get-policy-test@example.com', 'get-policy-test'),
    ('310987654321', 'get-policy-foreign@example.com', 'get-policy-foreign');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCGETPOLBROAD01', '%ACCOUNT_ID%', 'broad-reader', 'Broad-Reader', '/'),
    ('SVCGETPOLNARROW1', '%ACCOUNT_ID%', 'narrow-reader', 'Narrow-Reader', '/'),
    ('SVCGETPOLTAG0001', '%ACCOUNT_ID%', 'tag-reader', 'Tag-Reader', '/'),
    ('SVCGETPOLNONE001', '%ACCOUNT_ID%', 'no-grant-reader', 'No-Grant-Reader', '/'),
    ('SVCGETPOLATTACH1', '%ACCOUNT_ID%', 'attached-user', 'Attached-User', '/'),
    ('SVCGETPOLAWSATT1', '%ACCOUNT_ID%', 'aws-policy-user', 'Aws-Policy-User', '/'),
    ('SVCGETPOLFRGNUSR', '310987654321', 'foreign-user', 'Foreign-User', '/');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version, description) VALUES
    ('SVCGETPOLADMIN01', '%ACCOUNT_ID%', 'admin-policy', 'Admin-Policy', '/', 1, false, 1, 'Grants everything.'),
    ('SVCGETPOLSAFE001', '%ACCOUNT_ID%', 'safe-policy', 'Safe-Policy', '/safe/', 1, false, 1, NULL),
    ('SVCGETPOLAWSMG01', '000000000000', 'get-policy-aws-managed', 'Get-Policy-Aws-Managed', '/', 1, false, 1, NULL),
    ('SVCGETPOLFOREGN1', '310987654321', 'foreign-policy', 'Foreign-Policy', '/', 1, false, 1, NULL);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCGETPOLADMIN01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'),
    ('SVCGETPOLSAFE001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCGETPOLAWSMG01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}'),
    ('SVCGETPOLFOREGN1', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}');

    INSERT INTO iam.managed_policy_tags(managed_policy_id, key_lower, key_cased, value) VALUES
    ('SVCGETPOLADMIN01', 'department', 'Department', 'Engineering');

    -- The AWS-managed policy is carried by a user in this account and by one in an unrelated
    -- account, so the count reported to this account has something to leave out.
    INSERT INTO iam.user_attached_policies(user_id, managed_policy_id) VALUES
    ('SVCGETPOLATTACH1', 'SVCGETPOLADMIN01'),
    ('SVCGETPOLAWSATT1', 'SVCGETPOLAWSMG01'),
    ('SVCGETPOLFRGNUSR', 'SVCGETPOLAWSMG01');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCGETPOLBROAD01', 'allow-get-any-policy', 'Allow-Get-Any-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetPolicy","Resource":"*"}]}'),
    ('SVCGETPOLNARROW1', 'allow-get-admin-policy', 'Allow-Get-Admin-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetPolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:policy/Admin-Policy"}]}'),
    ('SVCGETPOLTAG0001', 'allow-get-engineering-policies', 'Allow-Get-Engineering-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetPolicy","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/department":"Engineering"}}}]}');
"#;

/// End-to-end authorization checks for `GetPolicy` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account.
#[test_log::test(tokio::test)]
async fn test_get_policy_authorization() {
    let database = TestDatabase::new(GET_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();
    let admin_policy = database.arn("policy/Admin-Policy");
    let safe_policy = database.arn("policy/safe/Safe-Policy");

    // A caller allowed iam:GetPolicy on any policy reads one, and is told everything the policy
    // records: where it lives, which version is its default, what is attached to it, and its tags.
    let (principal, session_data) = database.user_identity("SVCGETPOLBROAD01", "Broad-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&admin_policy))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains(&format!("<Arn>{admin_policy}</Arn>")), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>Admin-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyId>ANPASVCGETPOLADMIN01</PolicyId>"), "unexpected body: {body}");
    assert!(body.contains("<Path>/</Path>"), "unexpected body: {body}");
    assert!(body.contains("<DefaultVersionId>v1</DefaultVersionId>"), "unexpected body: {body}");
    assert!(body.contains("<AttachmentCount>1</AttachmentCount>"), "unexpected body: {body}");
    assert!(
        body.contains("<PermissionsBoundaryUsageCount>0</PermissionsBoundaryUsageCount>"),
        "unexpected body: {body}"
    );
    assert!(body.contains("<Description>Grants everything.</Description>"), "unexpected body: {body}");
    assert!(body.contains("<Key>Department</Key>"), "unexpected body: {body}");
    assert!(body.contains("<Value>Engineering</Value>"), "unexpected body: {body}");

    // GetPolicy reports the policy's metadata, not the document itself; that is what
    // GetPolicyVersion is for.
    assert!(!body.contains("<PolicyDocument>"), "unexpected body: {body}");

    // A policy's path is part of the ARN naming it, so it is named through the path it lives
    // under...
    let (principal, session_data) = database.user_identity("SVCGETPOLBROAD01", "Broad-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&safe_policy))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Path>/safe/</Path>"), "unexpected body: {body}");

    // ...and the same name under another path names nothing.
    let (principal, session_data) = database.user_identity("SVCGETPOLBROAD01", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_parameters(Some(&database.arn("policy/Safe-Policy"))))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // Policy names are compared case-insensitively, and the response reports the policy under the
    // spelling it was created with rather than the one the request used.
    let (principal, session_data) = database.user_identity("SVCGETPOLBROAD01", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_parameters(Some(&database.arn("policy/ADMIN-POLICY"))))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Admin-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(body.contains(&format!("<Arn>{admin_policy}</Arn>")), "unexpected body: {body}");

    // A grant naming one policy reaches that policy...
    let (principal, session_data) = database.user_identity("SVCGETPOLNARROW1", "Narrow-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&admin_policy))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no other.
    let (principal, session_data) = database.user_identity("SVCGETPOLNARROW1", "Narrow-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&safe_policy))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Narrow-Reader is not authorized to perform: \
                 iam:GetPolicy on resource: {safe_policy}"
        )),
        "unexpected body: {body}"
    );

    // The policy is read before the request is authorized, so a grant conditioned on the tags the
    // policy carries can be evaluated at all.
    let (principal, session_data) = database.user_identity("SVCGETPOLTAG0001", "Tag-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&admin_policy))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A policy without that tag leaves the condition key absent, so the grant does not apply.
    let (principal, session_data) = database.user_identity("SVCGETPOLTAG0001", "Tag-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&safe_policy))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCGETPOLNONE001", "No-Grant-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&admin_policy))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller allowed the action broadly is told that a policy does not exist...
    let missing_policy = database.arn("policy/Missing-Policy");
    let (principal, session_data) = database.user_identity("SVCGETPOLBROAD01", "Broad-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&missing_policy))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Message>Policy {missing_policy} was not found.</Message>")),
        "unexpected body: {body}"
    );

    // ...while one allowed it only on particular policies learns nothing at all.
    let (principal, session_data) = database.user_identity("SVCGETPOLNARROW1", "Narrow-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&missing_policy))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // AWS-managed policies belong to no customer account, and every account can read them. They
    // can be named through the numeric account they are stored under...
    let (principal, session_data) = database.user_identity("SVCGETPOLBROAD01", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_parameters(Some(AWS_MANAGED_POLICY_ARN))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Get-Policy-Aws-Managed</PolicyName>"), "unexpected body: {body}");
    assert!(body.contains(&format!("<Arn>{AWS_MANAGED_POLICY_ARN}</Arn>")), "unexpected body: {body}");

    // The counts an AWS-managed policy reports are the asking account's own: two users carry this
    // policy, but only one of them is in this account, and that is the one that is counted.
    assert!(body.contains("<AttachmentCount>1</AttachmentCount>"), "unexpected body: {body}");
    assert!(
        body.contains("<PermissionsBoundaryUsageCount>0</PermissionsBoundaryUsageCount>"),
        "unexpected body: {body}"
    );

    // ...or through the `aws` account alias IAM spells them with, which names the same policy and
    // is reported back the way the request spelled it. Which spelling the request used does not
    // change the counts: they are the asking account's either way.
    let (principal, session_data) = database.user_identity("SVCGETPOLBROAD01", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_parameters(Some(AWS_MANAGED_POLICY_ALIAS_ARN))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains(&format!("<Arn>{AWS_MANAGED_POLICY_ALIAS_ARN}</Arn>")), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>Get-Policy-Aws-Managed</PolicyName>"), "unexpected body: {body}");
    assert!(body.contains("<AttachmentCount>1</AttachmentCount>"), "unexpected body: {body}");

    // A managed policy is not shared across customer accounts, so a policy in another account is
    // reported as no policy at all -- to a caller allowed the action on every resource, which
    // would otherwise be handed another account's policy by naming its ARN.
    let (principal, session_data) = database.user_identity("SVCGETPOLBROAD01", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_parameters(Some(FOREIGN_POLICY_ARN))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Message>Policy {FOREIGN_POLICY_ARN} was not found.</Message>")),
        "unexpected body: {body}"
    );
    assert!(!body.contains("<PolicyId>"), "unexpected body: {body}");

    // An ARN that is not a policy ARN is rejected before the request is authorized, so a caller
    // with no grant sees the same rejection as one with a grant.
    for (policy_arn, message) in [
        (database.arn("user/Broad-Reader"), "Policy ARN must have a resource that starts with"),
        ("arn:aws:iam:us-east-1:123456789012:policy/Admin-Policy".to_string(), "Policy ARN must not have a region"),
        ("arn:aws:s3:::my-bucket-with-a-long-name".to_string(), "Invalid policy ARN"),
        ("not-an-arn-but-long-enough-to-pass".to_string(), "Invalid policy ARN"),
    ] {
        let (principal, session_data) = database.user_identity("SVCGETPOLNONE001", "No-Grant-Reader");
        let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&policy_arn))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response for {policy_arn}: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body for {policy_arn}: {body}");
        assert!(body.contains(message), "unexpected body for {policy_arn}: {body}");
    }

    // An ARN too short to be one is rejected on its length, before anything tries to read it.
    let (principal, session_data) = database.user_identity("SVCGETPOLBROAD01", "Broad-Reader");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_parameters(Some("arn:aws:iam::1:p"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A request leaving off the ARN never becomes a request at all.
    let (principal, session_data) = database.user_identity("SVCGETPOLBROAD01", "Broad-Reader");
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // The account root user is implicitly allowed, and carries no policies of its own.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_policy_parameters(Some(&safe_policy))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Safe-Policy</PolicyName>"), "unexpected body: {body}");
}
