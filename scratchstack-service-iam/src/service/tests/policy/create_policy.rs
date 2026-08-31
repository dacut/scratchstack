use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// A well-formed policy document, for the requests whose subject is something other than the
/// document itself.
const POLICY_DOCUMENT: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;

/// Seed data for the `CreatePolicy` authorization tests. The callers carry grants scoped by the
/// path the new policy is created under and by the tags the request asks to apply, through
/// `aws:RequestTag`, `aws:ResourceTag`, and `iam:ResourceTag` alike -- the last of these being one
/// the IAM documentation does not list for CreatePolicy but the service supplies anyway.
/// `Create-Only-Creator` is allowed `iam:CreatePolicy` and nothing else, so it shows that tagging
/// a policy at creation is gated separately. `Broad-Creator` is allowed to read policies as well,
/// so that what a request left behind can be read back.
const CREATE_POLICY_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'create-policy-test@example.com', 'create-policy-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCCREPOLBROAD01', '%ACCOUNT_ID%', 'broad-creator', 'Broad-Creator', '/'),
    ('SVCCREPOLPATH001', '%ACCOUNT_ID%', 'path-creator', 'Path-Creator', '/'),
    ('SVCCREPOLTAG0001', '%ACCOUNT_ID%', 'tag-creator', 'Tag-Creator', '/'),
    ('SVCCREPOLRTAG001', '%ACCOUNT_ID%', 'resource-tag-creator', 'Resource-Tag-Creator', '/'),
    ('SVCCREPOLITAG001', '%ACCOUNT_ID%', 'iam-resource-tag-creator', 'Iam-Resource-Tag-Creator', '/'),
    ('SVCCREPOLONLY001', '%ACCOUNT_ID%', 'create-only-creator', 'Create-Only-Creator', '/'),
    ('SVCCREPOLNONE001', '%ACCOUNT_ID%', 'no-grant-creator', 'No-Grant-Creator', '/');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCCREPOLBROAD01', 'allow-create-any', 'Allow-Create-Any',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Action":["iam:CreatePolicy","iam:TagPolicy","iam:GetPolicy"],"Resource":"*"}]}'),
    ('SVCCREPOLPATH001', 'allow-create-in-division', 'Allow-Create-In-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreatePolicy",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:policy/division/*"}]}'),
    ('SVCCREPOLTAG0001', 'allow-create-engineering', 'Allow-Create-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreatePolicy","iam:TagPolicy"],
        "Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/department":"Engineering"}}}]}'),
    ('SVCCREPOLRTAG001', 'allow-create-engineering-resource', 'Allow-Create-Engineering-Resource',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreatePolicy","iam:TagPolicy"],
        "Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCCREPOLITAG001', 'allow-create-engineering-iam-resource', 'Allow-Create-Engineering-Iam-Resource',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreatePolicy","iam:TagPolicy"],
        "Resource":"*","Condition":{"StringEquals":{"iam:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCCREPOLONLY001', 'allow-create-only', 'Allow-Create-Only',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreatePolicy","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `CreatePolicy` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_create_policy_authorization() {
    let database = TestDatabase::new(CREATE_POLICY_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:CreatePolicy on any policy creates one at the root path. The document
    // it carries becomes the policy's first version, which is also its default.
    let (principal, session_data) = database.user_identity("SVCCREPOLBROAD01", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(Some("New-Policy"), Some(POLICY_DOCUMENT), None, None, &[]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:policy/New-Policy</Arn>")),
        "unexpected body: {body}"
    );
    assert!(body.contains("<PolicyName>New-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(body.contains("<Path>/</Path>"), "unexpected body: {body}");
    assert!(body.contains("<DefaultVersionId>v1</DefaultVersionId>"), "unexpected body: {body}");
    assert!(body.contains("<AttachmentCount>0</AttachmentCount>"), "unexpected body: {body}");
    assert!(body.contains("<IsAttachable>true</IsAttachable>"), "unexpected body: {body}");

    // The policy is now readable, so the create was committed rather than rolled back.
    let (principal, session_data) = database.user_identity("SVCCREPOLBROAD01", "Broad-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_parameters(Some(&database.arn("policy/New-Policy"))))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>New-Policy</PolicyName>"), "unexpected body: {body}");

    // A second policy of the same name collides with the one just created. That is the caller's
    // error rather than ours, so it is reported as an entity that already exists.
    let (principal, session_data) = database.user_identity("SVCCREPOLBROAD01", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(Some("New-Policy"), Some(POLICY_DOCUMENT), None, None, &[]),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
    assert!(body.contains("<Code>EntityAlreadyExists</Code>"), "unexpected body: {body}");
    assert!(
        body.contains("<Message>A policy called New-Policy already exists. Duplicate names are not allowed.</Message>"),
        "unexpected body: {body}"
    );

    // Policy names are compared case-insensitively, so a name differing only in case collides with
    // the policy just created too...
    let (principal, session_data) = database.user_identity("SVCCREPOLBROAD01", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(Some("NEW-POLICY"), Some(POLICY_DOCUMENT), None, None, &[]),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
    assert!(body.contains("<Code>EntityAlreadyExists</Code>"), "unexpected body: {body}");

    // ...and a name is taken account-wide rather than per path, so the same name under another
    // path collides as well.
    let (principal, session_data) = database.user_identity("SVCCREPOLBROAD01", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(Some("New-Policy"), Some(POLICY_DOCUMENT), Some("/elsewhere/"), None, &[]),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
    assert!(body.contains("<Code>EntityAlreadyExists</Code>"), "unexpected body: {body}");

    // The path the request asks for is part of the ARN being authorized, so a grant scoped to a
    // path prefix reaches policies created under that path...
    let (principal, session_data) = database.user_identity("SVCCREPOLPATH001", "Path-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(Some("Division-Policy"), Some(POLICY_DOCUMENT), Some("/division/"), None, &[]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:policy/division/Division-Policy</Arn>")),
        "unexpected body: {body}"
    );
    assert!(body.contains("<Path>/division/</Path>"), "unexpected body: {body}");

    // ...and no further: the same caller cannot create a policy at the root path.
    let (principal, session_data) = database.user_identity("SVCCREPOLPATH001", "Path-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(Some("Root-Policy"), Some(POLICY_DOCUMENT), None, None, &[]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Path-Creator is not authorized to perform: \
                 iam:CreatePolicy on resource: arn:aws:iam::{account_id}:policy/Root-Policy"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled the transaction back, so nothing was created.
    let (principal, session_data) = database.user_identity("SVCCREPOLBROAD01", "Broad-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_parameters(Some(&database.arn("policy/Root-Policy"))))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // The tags the request asks to apply back the aws:RequestTag condition keys. The policy
    // spells the tag key in lower case while the request spells it "Department", confirming that
    // tag keys are matched case-insensitively.
    let (principal, session_data) = database.user_identity("SVCCREPOLTAG0001", "Tag-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(
            Some("Tagged-Policy"),
            Some(POLICY_DOCUMENT),
            None,
            None,
            &[("Department", "Engineering")],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Department</Key>"), "unexpected body: {body}");
    assert!(body.contains("<Value>Engineering</Value>"), "unexpected body: {body}");

    // A request asking for the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCCREPOLTAG0001", "Tag-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(Some("Sales-Policy"), Some(POLICY_DOCUMENT), None, None, &[("Department", "Sales")]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Neither does a request asking for no tags at all: the condition key is absent, so the grant
    // does not apply rather than matching an empty value.
    let (principal, session_data) = database.user_identity("SVCCREPOLTAG0001", "Tag-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(Some("Bare-Policy"), Some(POLICY_DOCUMENT), None, None, &[]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // CreatePolicy reports the tags the request asks for through aws:ResourceTag as well as
    // aws:RequestTag, even though the policy does not exist yet -- confirmed against the service,
    // as it is for CreateUser and CreateRole.
    let (principal, session_data) = database.user_identity("SVCCREPOLRTAG001", "Resource-Tag-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(
            Some("Resource-Tagged-Policy"),
            Some(POLICY_DOCUMENT),
            None,
            None,
            &[("Department", "Engineering")],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Department</Key>"), "unexpected body: {body}");
    assert!(body.contains("<Value>Engineering</Value>"), "unexpected body: {body}");

    // The value still has to match.
    let (principal, session_data) = database.user_identity("SVCCREPOLRTAG001", "Resource-Tag-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(
            Some("Resource-Sales-Policy"),
            Some(POLICY_DOCUMENT),
            None,
            None,
            &[("Department", "Sales")],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // CreatePolicy also supplies IAM's own iam:ResourceTag/${TagKey} spelling, so a grant written
    // against it is satisfied too.
    //
    // The IAM documentation lists the iam: condition keys for CreateUser and CreateRole but not
    // for CreatePolicy. The service does not agree with its own documentation, and this follows
    // the service: verified against live IAM that a grant conditioned on iam:ResourceTag allows
    // CreatePolicy when the requested tag matches and denies it when it does not. An absent key
    // could not produce that, since StringEquals on a key that is not there never matches. The
    // scratchstack-e2e suite re-checks this against live IAM in tests/test_authz_policy.py.
    let (principal, session_data) = database.user_identity("SVCCREPOLITAG001", "Iam-Resource-Tag-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(
            Some("Iam-Resource-Tagged-Policy"),
            Some(POLICY_DOCUMENT),
            None,
            None,
            &[("Department", "Engineering")],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Department</Key>"), "unexpected body: {body}");

    // The value still has to match, which is what shows the key is being compared rather than
    // ignored: a request the condition does not name is denied.
    let (principal, session_data) = database.user_identity("SVCCREPOLITAG001", "Iam-Resource-Tag-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(
            Some("Iam-Resource-Sales-Policy"),
            Some(POLICY_DOCUMENT),
            None,
            None,
            &[("Department", "Sales")],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Tagging a policy is a separate action from creating one, so a caller allowed only
    // iam:CreatePolicy can create a policy...
    let (principal, session_data) = database.user_identity("SVCCREPOLONLY001", "Create-Only-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(Some("Plain-Policy"), Some(POLICY_DOCUMENT), None, None, &[]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...but not a tagged one, and the denial names the action actually missing.
    let (principal, session_data) = database.user_identity("SVCCREPOLONLY001", "Create-Only-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(
            Some("Tagged-Denied-Policy"),
            Some(POLICY_DOCUMENT),
            None,
            None,
            &[("Department", "Engineering")],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Create-Only-Creator is not authorized to perform: \
                 iam:TagPolicy on resource: arn:aws:iam::{account_id}:policy/Tagged-Denied-Policy"
        )),
        "unexpected body: {body}"
    );

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCCREPOLNONE001", "No-Grant-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(Some("Ungranted-Policy"), Some(POLICY_DOCUMENT), None, None, &[]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The description the request carries is stored with the policy and reported back.
    let (principal, session_data) = database.user_identity("SVCCREPOLBROAD01", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(
            Some("Described-Policy"),
            Some(POLICY_DOCUMENT),
            None,
            Some("Grants read access to objects."),
            &[],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Description>Grants read access to objects.</Description>"), "unexpected body: {body}");

    // A document that is not a policy at all is the caller's error, and is reported as one --
    // after authorization, since the caller here is allowed to create policies.
    let (principal, session_data) = database.user_identity("SVCCREPOLBROAD01", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(Some("Broken-Policy"), Some("not a policy document"), None, None, &[]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedPolicyDocument</Code>"), "unexpected body: {body}");

    // The rejection rolled its transaction back, so nothing was created under that name.
    let (principal, session_data) = database.user_identity("SVCCREPOLBROAD01", "Broad-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_policy_parameters(Some(&database.arn("policy/Broken-Policy"))))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");

    // A name outside the character set IAM allows is rejected before the request is authorized,
    // so a caller with no grant sees the same rejection as one with a grant.
    let (principal, session_data) = database.user_identity("SVCCREPOLNONE001", "No-Grant-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(Some("Bad Name"), Some(POLICY_DOCUMENT), None, None, &[]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A path that does not begin and end with a slash is rejected the same way.
    let (principal, session_data) = database.user_identity("SVCCREPOLBROAD01", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(Some("Bad-Path-Policy"), Some(POLICY_DOCUMENT), Some("division"), None, &[]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A request leaving off a parameter the operation requires never becomes a request at all.
    for parameters in [
        create_policy_parameters(None, Some(POLICY_DOCUMENT), None, None, &[]),
        create_policy_parameters(Some("Nameless-Policy"), None, None, None, &[]),
    ] {
        let (principal, session_data) = database.user_identity("SVCCREPOLBROAD01", "Broad-Creator");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
    }

    // The account root user is implicitly allowed, and carries no policies of its own.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_policy_parameters(Some("Root-Created-Policy"), Some(POLICY_DOCUMENT), None, None, &[("Owner", "Root")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:policy/Root-Created-Policy</Arn>")),
        "unexpected body: {body}"
    );
    assert!(body.contains("<Key>Owner</Key>"), "unexpected body: {body}");
}
