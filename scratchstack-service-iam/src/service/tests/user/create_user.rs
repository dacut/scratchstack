use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `CreateUser` authorization tests. The callers carry grants scoped by the
/// path the new user is created under, by the tags the request asks to apply -- through the
/// request-tag keys and through the resource-tag keys alike -- by the tag keys it may name at
/// all, and by the permissions boundary it asks to attach; `Boundary-Policy` is the managed
/// policy the boundary-scoped grant names. `Create-Only-Creator` is allowed `iam:CreateUser` and
/// nothing else, so it shows that tagging a user at creation is gated separately while attaching
/// a permissions boundary is not.
const CREATE_USER_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'create-user-test@example.com', 'create-user-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCCREUSERBROAD', '%ACCOUNT_ID%', 'broad-creator', 'Broad-Creator', '/'),
    ('SVCCREUSERPATH1', '%ACCOUNT_ID%', 'path-creator', 'Path-Creator', '/'),
    ('SVCCREUSERTAG01', '%ACCOUNT_ID%', 'tag-creator', 'Tag-Creator', '/'),
    ('SVCCREUSERRTAG1', '%ACCOUNT_ID%', 'resource-tag-creator', 'Resource-Tag-Creator', '/'),
    ('SVCCREUSERITAG1', '%ACCOUNT_ID%', 'iam-resource-tag-creator', 'Iam-Resource-Tag-Creator', '/'),
    ('SVCCREUSERKEYS1', '%ACCOUNT_ID%', 'tag-key-creator', 'Tag-Key-Creator', '/'),
    ('SVCCREUSERPB001', '%ACCOUNT_ID%', 'boundary-creator', 'Boundary-Creator', '/'),
    ('SVCCREUSERNONE1', '%ACCOUNT_ID%', 'no-grant-creator', 'No-Grant-Creator', '/'),
    ('SVCCREUSERONLY1', '%ACCOUNT_ID%', 'create-only-creator', 'Create-Only-Creator', '/'),
    ('SVCCREUSERARN01', '%ACCOUNT_ID%', 'arn-boundary-creator', 'Arn-Boundary-Creator', '/'),
    ('SVCCREUSEREXIST', '%ACCOUNT_ID%', 'existing-user', 'Existing-User', '/');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCCREUSERBND01', '%ACCOUNT_ID%', 'boundary-policy', 'Boundary-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCCREUSERBND01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCCREUSERBROAD', 'allow-create-any', 'Allow-Create-Any',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateUser","iam:TagUser"],
        "Resource":"*"}]}'),
    ('SVCCREUSERPATH1', 'allow-create-in-division', 'Allow-Create-In-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateUser",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/division/*"}]}'),
    ('SVCCREUSERTAG01', 'allow-create-engineering', 'Allow-Create-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateUser","iam:TagUser"],
        "Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/department":"Engineering"}}}]}'),
    ('SVCCREUSERRTAG1', 'allow-create-engineering-resource', 'Allow-Create-Engineering-Resource',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateUser","iam:TagUser"],
        "Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCCREUSERITAG1', 'allow-create-engineering-iam-resource', 'Allow-Create-Engineering-Iam-Resource',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateUser","iam:TagUser"],
        "Resource":"*","Condition":{"StringEquals":{"iam:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCCREUSERKEYS1', 'allow-create-with-known-tags', 'Allow-Create-With-Known-Tags',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateUser","iam:TagUser"],
        "Resource":"*","Condition":{"ForAllValues:StringEquals":
            {"aws:TagKeys":["Department","Project"]}}}]}'),
    ('SVCCREUSERPB001', 'allow-create-with-boundary', 'Allow-Create-With-Boundary',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateUser","Resource":"*",
        "Condition":{"StringEquals":
            {"iam:PermissionsBoundary":"arn:aws:iam::%ACCOUNT_ID%:policy/Boundary-Policy"}}}]}'),
    ('SVCCREUSERONLY1', 'allow-create-only', 'Allow-Create-Only',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateUser","Resource":"*"}]}'),
    ('SVCCREUSERARN01', 'allow-create-with-arn-boundary', 'Allow-Create-With-Arn-Boundary',
        '{"Version":"2012-10-17","Statement":[{"Sid":"VisualEditor0","Effect":"Allow","Action":"iam:CreateUser",
        "Resource":"*","Condition":{"ArnEquals":
            {"iam:PermissionsBoundary":"arn:aws:iam::%ACCOUNT_ID%:policy/Boundary-Policy"}}}]}');
"#;

/// End-to-end authorization checks for `CreateUser` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_create_user_authorization() {
    let database = TestDatabase::new(CREATE_USER_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:CreateUser on any user creates one at the root path.
    let (principal, session_data) = database.user_identity("SVCCREUSERBROAD", "Broad-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_user_parameters("New-User", None, &[], None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains(&format!("<Arn>arn:aws:iam::{account_id}:user/New-User</Arn>")), "unexpected body: {body}");
    assert!(body.contains("<Path>/</Path>"), "unexpected body: {body}");
    assert!(body.contains("<UserName>New-User</UserName>"), "unexpected body: {body}");

    // The user is now readable, so the create was committed rather than rolled back.
    let (principal, session_data) = database.user_identity("SVCCREUSERBROAD", "Broad-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_user_parameters("New-User", None, &[], None)).await;
    assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
    assert!(body.contains("<Code>EntityAlreadyExists</Code>"), "unexpected body: {body}");

    // User names are compared case-insensitively, so a name differing only in case collides
    // with the user just created.
    let (principal, session_data) = database.user_identity("SVCCREUSERBROAD", "Broad-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_user_parameters("NEW-USER", None, &[], None)).await;
    assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
    assert!(body.contains("<Code>EntityAlreadyExists</Code>"), "unexpected body: {body}");

    // The path the request asks for is part of the ARN being authorized, so a grant scoped to
    // a path prefix reaches users created under that path...
    let (principal, session_data) = database.user_identity("SVCCREUSERPATH1", "Path-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters("Division-User", Some("/division/"), &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:user/division/Division-User</Arn>")),
        "unexpected body: {body}"
    );
    assert!(body.contains("<Path>/division/</Path>"), "unexpected body: {body}");

    // ...and no further: the same caller cannot create a user at the root path.
    let (principal, session_data) = database.user_identity("SVCCREUSERPATH1", "Path-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_user_parameters("Root-User", None, &[], None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Path-Creator is not authorized to perform: \
                 iam:CreateUser on resource: arn:aws:iam::{account_id}:user/Root-User"
        )),
        "unexpected body: {body}"
    );

    // A denial rolls the transaction back, so nothing was created.
    let (principal, session_data) = database.user_identity("SVCCREUSERBROAD", "Broad-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_user_parameters("Root-User", None, &[], None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The tags the request asks to apply back the aws:RequestTag condition keys. The policy
    // spells the tag key in lower case while the request spells it "Department", confirming
    // that tag keys are matched case-insensitively.
    let (principal, session_data) = database.user_identity("SVCCREUSERTAG01", "Tag-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters("Tagged-User", None, &[("Department", "Engineering")], None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Department</Key>"), "unexpected body: {body}");
    assert!(body.contains("<Value>Engineering</Value>"), "unexpected body: {body}");

    // A request asking for the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCCREUSERTAG01", "Tag-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters("Sales-User", None, &[("Department", "Sales")], None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Neither does a request asking for no tags at all: the condition key is absent, so the
    // grant does not apply rather than matching an empty value.
    let (principal, session_data) = database.user_identity("SVCCREUSERTAG01", "Tag-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_user_parameters("Bare-User", None, &[], None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // CreateUser reports the tags the request asks for through the resource-tag condition keys
    // as well as the request-tag ones, even though the user does not exist yet -- confirmed
    // against the service. A grant conditioned on aws:ResourceTag therefore governs creating a
    // user just as it governs tagging one that already exists. Supplying only the request-tag
    // keys would leave this grant dormant and deny the request.
    let (principal, session_data) = database.user_identity("SVCCREUSERRTAG1", "Resource-Tag-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters("Resource-Tagged-User", None, &[("Department", "Engineering")], None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Department</Key>"), "unexpected body: {body}");
    assert!(body.contains("<Value>Engineering</Value>"), "unexpected body: {body}");

    // The value still has to match: the keys carry what the request asked for, not a wildcard.
    let (principal, session_data) = database.user_identity("SVCCREUSERRTAG1", "Resource-Tag-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters("Resource-Sales-User", None, &[("Department", "Sales")], None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A request naming no tags leaves the key absent, so the grant does not apply rather than
    // matching an empty value.
    let (principal, session_data) = database.user_identity("SVCCREUSERRTAG1", "Resource-Tag-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_user_parameters("Resource-Bare-User", None, &[], None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // IAM's own iam:ResourceTag spelling of the same key behaves identically, so a policy
    // written against either one governs user creation.
    let (principal, session_data) = database.user_identity("SVCCREUSERITAG1", "Iam-Resource-Tag-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters("Iam-Resource-Tagged-User", None, &[("Department", "Engineering")], None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Department</Key>"), "unexpected body: {body}");

    let (principal, session_data) = database.user_identity("SVCCREUSERITAG1", "Iam-Resource-Tag-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters("Iam-Resource-Sales-User", None, &[("Department", "Sales")], None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant conditioned on aws:TagKeys limits which tags the request may name at all,
    // whatever values it asks to give them: every tag key the request carries has to be one
    // the policy lists.
    let (principal, session_data) = database.user_identity("SVCCREUSERKEYS1", "Tag-Key-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters(
            "Known-Tags-User",
            None,
            &[("Department", "Engineering"), ("Project", "Scratchstack")],
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Project</Key>"), "unexpected body: {body}");

    // One tag key outside the set the policy lists is enough to fail, even alongside keys
    // that are in it.
    let (principal, session_data) = database.user_identity("SVCCREUSERKEYS1", "Tag-Key-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters(
            "Extra-Tag-User",
            None,
            &[("Department", "Engineering"), ("Cost-Center", "1234")],
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A request naming no tags at all satisfies ForAllValues vacuously: there is no tag key
    // the policy would have to allow.
    let (principal, session_data) = database.user_identity("SVCCREUSERKEYS1", "Tag-Key-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_user_parameters("Untagged-User", None, &[], None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // Two tags with the same key ask for two values for one tag. That is the caller's error,
    // not ours, so it is reported as invalid input rather than an internal failure. The keys
    // here differ only in case, which IAM treats as the same key.
    let (principal, session_data) = database.user_identity("SVCCREUSERBROAD", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters("Dupe-Tag-User", None, &[("Department", "Engineering"), ("department", "Sales")], None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");

    // Verified against the live service: this is the error element AWS returns, verbatim.
    assert!(
        body.contains(
            "<Error><Type>Sender</Type><Code>InvalidInput</Code><Message>Duplicate tag keys found. \
                 Please note that Tag keys are case insensitive.</Message></Error>"
        ),
        "unexpected body: {body}"
    );

    // The rejection rolled the transaction back, so the name is still free.
    let (principal, session_data) = database.user_identity("SVCCREUSERBROAD", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters("Dupe-Tag-User", None, &[("Department", "Engineering")], None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The permissions boundary the request asks for backs iam:PermissionsBoundary, which is
    // what lets a policy require that users be created only under a boundary.
    let boundary = format!("arn:aws:iam::{account_id}:policy/Boundary-Policy");
    let (principal, session_data) = database.user_identity("SVCCREUSERPB001", "Boundary-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_user_parameters("Bounded-User", None, &[], Some(&boundary)))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<PermissionsBoundaryArn>{boundary}</PermissionsBoundaryArn>")),
        "unexpected body: {body}"
    );

    // Omitting the boundary leaves the condition key absent, so the grant does not apply.
    let (principal, session_data) = database.user_identity("SVCCREUSERPB001", "Boundary-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_user_parameters("Unbounded-User", None, &[], None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Naming a different boundary does not satisfy the condition either.
    let other_boundary = format!("arn:aws:iam::{account_id}:policy/Other-Policy");
    let (principal, session_data) = database.user_identity("SVCCREUSERPB001", "Boundary-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters("Other-Bounded-User", None, &[], Some(&other_boundary)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Tagging a user is a separate action from creating one, so a caller allowed only
    // iam:CreateUser can create a user...
    let (principal, session_data) = database.user_identity("SVCCREUSERONLY1", "Create-Only-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_user_parameters("Plain-User", None, &[], None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...but not a tagged one, and the denial names the action actually missing.
    let (principal, session_data) = database.user_identity("SVCCREUSERONLY1", "Create-Only-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters("Tagged-Denied-User", None, &[("Department", "Engineering")], None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Create-Only-Creator is not authorized to perform: \
                 iam:TagUser on resource: arn:aws:iam::{account_id}:user/Tagged-Denied-User"
        )),
        "unexpected body: {body}"
    );

    // A permissions boundary, by contrast, needs no second action: the same caller can attach
    // one under iam:CreateUser alone, as the service allows.
    let (principal, session_data) = database.user_identity("SVCCREUSERONLY1", "Create-Only-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters("Plain-Bounded-User", None, &[], Some(&boundary)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<PermissionsBoundaryArn>{boundary}</PermissionsBoundaryArn>")),
        "unexpected body: {body}"
    );

    // The denials rolled their transactions back, so neither user was created.
    let (principal, session_data) = database.user_identity("SVCCREUSERBROAD", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters("Tagged-Denied-User", None, &[("Department", "Engineering")], None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The boundary condition works with the ArnEquals operator as well as StringEquals, which
    // is what the console's policy editor emits for an ARN-valued key. Aspen treats ArnEquals
    // and ArnLike identically, as AWS documents them to be.
    let (principal, session_data) = database.user_identity("SVCCREUSERARN01", "Arn-Boundary-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters("Arn-Bounded-User", None, &[], Some(&boundary)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<PermissionsBoundaryArn>{boundary}</PermissionsBoundaryArn>")),
        "unexpected body: {body}"
    );

    // A different boundary does not satisfy it.
    let (principal, session_data) = database.user_identity("SVCCREUSERARN01", "Arn-Boundary-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters("Arn-Other-Bounded-User", None, &[], Some(&other_boundary)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Nor does omitting the boundary: the condition key is absent, which an ARN operator
    // treats as a null that only its IfExists variant would accept. This is the case that
    // matters, since a policy written this way exists to stop unbounded users being created.
    let (principal, session_data) = database.user_identity("SVCCREUSERARN01", "Arn-Boundary-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_user_parameters("Arn-Unbounded-User", None, &[], None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is refused.
    let (principal, session_data) = database.user_identity("SVCCREUSERNONE1", "No-Grant-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_user_parameters("Denied-User", None, &[], None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A malformed user name is rejected before the request is authorized, so the caller
    // learns the request was invalid rather than that it was denied.
    let (principal, session_data) = database.user_identity("SVCCREUSERNONE1", "No-Grant-Creator");
    let (status, body) =
        call(&svc_state, principal, session_data, &create_user_parameters("bad%20name%21", None, &[], None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // A permissions boundary naming a policy that does not exist is reported as such.
    let missing_boundary = format!("arn:aws:iam::{account_id}:policy/No-Such-Policy");
    let (principal, session_data) = database.user_identity("SVCCREUSERBROAD", "Broad-Creator");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &create_user_parameters("Missing-Boundary-User", None, &[], Some(&missing_boundary)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &create_user_parameters("Root-Made-User", None, &[], None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:user/Root-Made-User</Arn>")),
        "unexpected body: {body}"
    );
}
