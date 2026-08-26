use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The trust policy the roles created here carry: the one a service-linked role is given, which
/// is what a caller creating a role for a service would actually pass.
const TRUST_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

/// Seed data for the `CreateRole` authorization tests. The callers carry grants scoped by the
/// path the new role is created under, by the tags the request asks to apply, and by the
/// permissions boundary it asks to attach; `Boundary-Policy` is the managed policy the
/// boundary-scoped grant names. `Create-Only-Creator` is allowed `iam:CreateRole` and nothing
/// else, so it shows that tagging a role at creation is gated separately while attaching a
/// permissions boundary is not. `Broad-Creator` may also read roles, so that a case can check
/// whether the role a rejected request named was left behind.
const CREATE_ROLE_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'create-role-test@example.com', 'create-role-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCCREROLEBROAD', '%ACCOUNT_ID%', 'broad-creator', 'Broad-Creator', '/'),
    ('SVCCREROLEPATH1', '%ACCOUNT_ID%', 'path-creator', 'Path-Creator', '/'),
    ('SVCCREROLETAG01', '%ACCOUNT_ID%', 'tag-creator', 'Tag-Creator', '/'),
    ('SVCCREROLEPB001', '%ACCOUNT_ID%', 'boundary-creator', 'Boundary-Creator', '/'),
    ('SVCCREROLEONLY1', '%ACCOUNT_ID%', 'create-only-creator', 'Create-Only-Creator', '/'),
    ('SVCCREROLENONE1', '%ACCOUNT_ID%', 'no-grant-creator', 'No-Grant-Creator', '/');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCCREROLEBND01', '%ACCOUNT_ID%', 'boundary-policy', 'Boundary-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCCREROLEBND01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCCREROLEBROAD', 'allow-create-any', 'Allow-Create-Any',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Action":["iam:CreateRole","iam:TagRole","iam:GetRole"],"Resource":"*"}]}'),
    ('SVCCREROLEPATH1', 'allow-create-in-division', 'Allow-Create-In-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateRole",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/division/*"}]}'),
    ('SVCCREROLETAG01', 'allow-create-engineering', 'Allow-Create-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateRole","iam:TagRole"],
        "Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/department":"Engineering"}}}]}'),
    ('SVCCREROLEPB001', 'allow-create-with-boundary', 'Allow-Create-With-Boundary',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateRole","Resource":"*",
        "Condition":{"StringEquals":
            {"iam:PermissionsBoundary":"arn:aws:iam::%ACCOUNT_ID%:policy/Boundary-Policy"}}}]}'),
    ('SVCCREROLEONLY1', 'allow-create-only', 'Allow-Create-Only',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateRole","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `CreateRole` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_create_role_authorization() {
    let database = TestDatabase::new(CREATE_ROLE_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:CreateRole on any role creates one at the root path.
    let (principal, session_data) = database.user_identity("SVCCREROLEBROAD", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("New-Role"), Some(TRUST_POLICY), None, None, None, &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains(&format!("<Arn>arn:aws:iam::{account_id}:role/New-Role</Arn>")), "unexpected body: {body}");
    assert!(body.contains("<Path>/</Path>"), "unexpected body: {body}");
    assert!(body.contains("<RoleName>New-Role</RoleName>"), "unexpected body: {body}");

    // The trust policy comes back percent-encoded, as IAM reports every policy document, and
    // decodes to exactly what the request supplied.
    assert_eq!(decoded_trust_policy_document(&body), TRUST_POLICY);

    // The name is taken now, so the create was committed rather than rolled back.
    let (principal, session_data) = database.user_identity("SVCCREROLEBROAD", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("New-Role"), Some(TRUST_POLICY), None, None, None, &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
    assert!(body.contains("<Code>EntityAlreadyExists</Code>"), "unexpected body: {body}");

    // Role names are compared case-insensitively, so a name differing only in case collides
    // with the role just created.
    let (principal, session_data) = database.user_identity("SVCCREROLEBROAD", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("NEW-ROLE"), Some(TRUST_POLICY), None, None, None, &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
    assert!(body.contains("<Code>EntityAlreadyExists</Code>"), "unexpected body: {body}");

    // The description and the maximum session duration the request asks for are reported back.
    let (principal, session_data) = database.user_identity("SVCCREROLEBROAD", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(
            Some("Described-Role"),
            Some(TRUST_POLICY),
            None,
            Some("Runs the nightly batch."),
            Some(7200),
            &[],
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Description>Runs the nightly batch.</Description>"), "unexpected body: {body}");
    assert!(body.contains("<MaxSessionDuration>7200</MaxSessionDuration>"), "unexpected body: {body}");

    // The path the request asks for is part of the ARN being authorized, so a grant scoped to
    // a path prefix reaches roles created under that path...
    let (principal, session_data) = database.user_identity("SVCCREROLEPATH1", "Path-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("Division-Role"), Some(TRUST_POLICY), Some("/division/"), None, None, &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:role/division/Division-Role</Arn>")),
        "unexpected body: {body}"
    );
    assert!(body.contains("<Path>/division/</Path>"), "unexpected body: {body}");

    // ...and no further: the same caller cannot create a role at the root path.
    let (principal, session_data) = database.user_identity("SVCCREROLEPATH1", "Path-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("Root-Role"), Some(TRUST_POLICY), None, None, None, &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Path-Creator is not authorized to perform: \
                 iam:CreateRole on resource: arn:aws:iam::{account_id}:role/Root-Role"
        )),
        "unexpected body: {body}"
    );

    // A denial rolls the transaction back, so nothing was created.
    let (principal, session_data) = database.user_identity("SVCCREROLEBROAD", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("Root-Role"), Some(TRUST_POLICY), None, None, None, &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The tags the request asks to apply back the aws:RequestTag condition keys. The policy
    // spells the tag key in lower case while the request spells it "Department", confirming
    // that tag keys are matched case-insensitively.
    let (principal, session_data) = database.user_identity("SVCCREROLETAG01", "Tag-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(
            Some("Tagged-Role"),
            Some(TRUST_POLICY),
            None,
            None,
            None,
            &[("Department", "Engineering")],
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Department</Key>"), "unexpected body: {body}");
    assert!(body.contains("<Value>Engineering</Value>"), "unexpected body: {body}");

    // A request asking for the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCCREROLETAG01", "Tag-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(
            Some("Sales-Role"),
            Some(TRUST_POLICY),
            None,
            None,
            None,
            &[("Department", "Sales")],
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Neither does a request asking for no tags at all: the condition key is absent, so the
    // grant does not apply rather than matching an empty value.
    let (principal, session_data) = database.user_identity("SVCCREROLETAG01", "Tag-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("Bare-Role"), Some(TRUST_POLICY), None, None, None, &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Tagging a role is a separate action from creating one, so a caller allowed only
    // iam:CreateRole can create a role...
    let (principal, session_data) = database.user_identity("SVCCREROLEONLY1", "Create-Only-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("Plain-Role"), Some(TRUST_POLICY), None, None, None, &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...but not a tagged one, and the denial names the action actually missing.
    let (principal, session_data) = database.user_identity("SVCCREROLEONLY1", "Create-Only-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(
            Some("Tagged-Denied-Role"),
            Some(TRUST_POLICY),
            None,
            None,
            None,
            &[("Department", "Engineering")],
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Create-Only-Creator is not authorized to perform: \
                 iam:TagRole on resource: arn:aws:iam::{account_id}:role/Tagged-Denied-Role"
        )),
        "unexpected body: {body}"
    );

    // The permissions boundary the request asks for backs iam:PermissionsBoundary, which is
    // what lets a policy require that roles be created only under a boundary.
    let boundary = format!("arn:aws:iam::{account_id}:policy/Boundary-Policy");
    let (principal, session_data) = database.user_identity("SVCCREROLEPB001", "Boundary-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("Bounded-Role"), Some(TRUST_POLICY), None, None, None, &[], Some(&boundary)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<PermissionsBoundaryArn>{boundary}</PermissionsBoundaryArn>")),
        "unexpected body: {body}"
    );

    // Omitting the boundary leaves the condition key absent, so the grant does not apply.
    let (principal, session_data) = database.user_identity("SVCCREROLEPB001", "Boundary-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("Unbounded-Role"), Some(TRUST_POLICY), None, None, None, &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A permissions boundary needs no second action: a caller allowed iam:CreateRole alone can
    // attach one, as it can on CreateUser.
    let (principal, session_data) = database.user_identity("SVCCREROLEONLY1", "Create-Only-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("Plain-Bounded-Role"), Some(TRUST_POLICY), None, None, None, &[], Some(&boundary)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<PermissionsBoundaryArn>{boundary}</PermissionsBoundaryArn>")),
        "unexpected body: {body}"
    );

    // A boundary naming a policy that does not exist is reported as such.
    let missing_boundary = format!("arn:aws:iam::{account_id}:policy/No-Such-Policy");
    let (principal, session_data) = database.user_identity("SVCCREROLEBROAD", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(
            Some("Missing-Boundary-Role"),
            Some(TRUST_POLICY),
            None,
            None,
            None,
            &[],
            Some(&missing_boundary),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // A trust policy that is not a policy document at all is the caller's error, and is reported
    // as one -- after authorization, since the caller here is allowed to create roles. A role
    // carrying it could never be assumed, so it is rejected rather than stored.
    let (principal, session_data) = database.user_identity("SVCCREROLEBROAD", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("Broken-Trust-Role"), Some("not a policy document"), None, None, None, &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedPolicyDocument</Code>"), "unexpected body: {body}");

    // The rejection rolled its transaction back, so nothing was created under that name.
    let (principal, session_data) = database.user_identity("SVCCREROLEBROAD", "Broad-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &get_role_parameters(Some("Broken-Trust-Role"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");

    // A session duration outside the window IAM allows is rejected before the request is
    // authorized, so the caller learns the request was invalid rather than that it was denied.
    let (principal, session_data) = database.user_identity("SVCCREROLENONE1", "No-Grant-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("Long-Session-Role"), Some(TRUST_POLICY), None, None, Some(86400), &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A malformed role name is rejected the same way.
    let (principal, session_data) = database.user_identity("SVCCREROLENONE1", "No-Grant-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("bad role!"), Some(TRUST_POLICY), None, None, None, &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A request that names no trust policy at all cannot be read as a CreateRole request.
    let (principal, session_data) = database.user_identity("SVCCREROLEBROAD", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("No-Trust-Role"), None, None, None, None, &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCCREROLENONE1", "No-Grant-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("Denied-Role"), Some(TRUST_POLICY), None, None, None, &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_role_parameters(Some("Root-Made-Role"), Some(TRUST_POLICY), None, None, None, &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:role/Root-Made-Role</Arn>")),
        "unexpected body: {body}"
    );
}
