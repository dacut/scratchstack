use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `ListRolePolicies` authorization tests. `Policy-Holder` carries several
/// inline policies, so a listing can be paged through and shown to report names and nothing else;
/// `Empty-Target` carries none, so a role without inline policies can be told apart from one that
/// does not exist. The remaining targets carry the paths and tags the resource ARN and the
/// `iam:ResourceTag` condition keys are derived from.
const LIST_ROLE_POLICIES_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'list-role-policies-test@example.com', 'list-role-policies-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCLRPBROADLST01', '%ACCOUNT_ID%', 'broad-lister', 'Broad-Lister', '/'),
    ('SVCLRPPATHLST001', '%ACCOUNT_ID%', 'path-lister', 'Path-Lister', '/'),
    ('SVCLRPTAGLST0001', '%ACCOUNT_ID%', 'tag-lister', 'Tag-Lister', '/'),
    ('SVCLRPNARROWLS01', '%ACCOUNT_ID%', 'narrow-lister', 'Narrow-Lister', '/'),
    ('SVCLRPNOGRANTL01', '%ACCOUNT_ID%', 'no-grant-lister', 'No-Grant-Lister', '/');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path,
        assume_role_policy_document) VALUES
    ('SVCLRPTGTHOLDER1', '%ACCOUNT_ID%', 'policy-holder', 'Policy-Holder', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCLRPTGTEMPTY01', '%ACCOUNT_ID%', 'empty-target', 'Empty-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCLRPTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCLRPTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCLRPTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCLRPTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'),
    ('SVCLRPSESSROLE01', '%ACCOUNT_ID%', 'list-role-policies-role', 'List-Role-Policies-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCLRPTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCLRPTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLRPTGTHOLDER1', 'app-access', 'App-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLRPTGTHOLDER1', 'db-access', 'Db-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"*"}]}'),
    ('SVCLRPTGTHOLDER1', 'zz-access', 'Zz-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}'),
    ('SVCLRPTGTDIVSN01', 'division-access', 'Division-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}'),
    ('SVCLRPTGTENGNR01', 'eng-access', 'Eng-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}'),
    ('SVCLRPTGTSALES01', 'sales-access', 'Sales-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ses:SendEmail","Resource":"*"}]}'),
    ('SVCLRPTGTROOT001', 'root-access', 'Root-Access',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}'),
    ('SVCLRPSESSROLE01', 'allow-list-any-policies', 'Allow-List-Any-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRolePolicies","Resource":"*"}]}');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLRPBROADLST01', 'allow-list-any-policies', 'Allow-List-Any-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRolePolicies","Resource":"*"}]}'),
    ('SVCLRPPATHLST001', 'allow-list-division-policies', 'Allow-List-Division-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRolePolicies",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/division/*"}]}'),
    ('SVCLRPTAGLST0001', 'allow-list-engineering-policies', 'Allow-List-Engineering-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRolePolicies","Resource":"*",
        "Condition":{"StringEquals":{"iam:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCLRPNARROWLS01', 'allow-list-holder-policies', 'Allow-List-Holder-Policies',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRolePolicies",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/Policy-Holder"}]}');
"#;

/// End-to-end authorization checks for `ListRolePolicies` through `serve_request` against an
/// embedded PostgreSQL database. A single test function covers every case so that they share one
/// seeded account, rather than seeding one apiece.
#[test_log::test(tokio::test)]
async fn test_list_role_policies_authorization() {
    let database = TestDatabase::new(LIST_ROLE_POLICIES_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:ListRolePolicies on any role reads the names of the inline policies on
    // one, ordered by name.
    let (principal, session_data) = database.user_identity("SVCLRPBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(Some("Policy-Holder"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(
            "<PolicyNames><member>App-Access</member><member>Db-Access</member>\
                 <member>Zz-Access</member></PolicyNames>"
        ),
        "unexpected body: {body}"
    );

    // The names come back cased as they were stored, and they are all that comes back: the
    // documents themselves are read with GetRolePolicy, which is granted separately. Nor is the
    // role's trust policy reported here.
    assert!(!body.contains("PolicyDocument"), "unexpected body: {body}");
    assert!(!body.contains("s3:GetObject"), "unexpected body: {body}");
    assert!(!body.contains("AssumeRolePolicyDocument"), "unexpected body: {body}");

    // Role names are matched case-insensitively.
    let (principal, session_data) = database.user_identity("SVCLRPBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(Some("POLICY-HOLDER"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<member>App-Access</member>"), "unexpected body: {body}");

    // A role carrying no inline policies at all is an empty listing rather than a missing role.
    let (principal, session_data) = database.user_identity("SVCLRPBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(Some("Empty-Target"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains("<ListRolePoliciesResult><PolicyNames/></ListRolePoliciesResult>"),
        "unexpected body: {body}"
    );

    // MaxItems bounds a page, and a bounded page reports the marker the next one continues
    // from...
    let (principal, session_data) = database.user_identity("SVCLRPBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(Some("Policy-Holder"), Some(2), None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<IsTruncated>true</IsTruncated>"), "unexpected body: {body}");
    assert!(
        body.contains("<PolicyNames><member>App-Access</member><member>Db-Access</member></PolicyNames>"),
        "unexpected body: {body}"
    );
    assert!(!body.contains("Zz-Access"), "unexpected body: {body}");
    let marker = pagination_marker(&body);

    // ...which reports the rest, and reports itself as the last page by leaving IsTruncated off.
    let (principal, session_data) = database.user_identity("SVCLRPBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_role_policies_parameters(Some("Policy-Holder"), Some(2), Some(&marker)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<member>Zz-Access</member>"), "unexpected body: {body}");
    assert!(!body.contains("App-Access"), "unexpected body: {body}");
    assert!(!body.contains("<IsTruncated>"), "unexpected body: {body}");

    // The resource ARN carries the target role's path, so a grant scoped to a path prefix
    // reaches roles under that path...
    let (principal, session_data) = database.user_identity("SVCLRPPATHLST001", "Path-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(Some("Division-Target"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<member>Division-Access</member>"), "unexpected body: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCLRPPATHLST001", "Path-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(Some("Policy-Holder"), None, None))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the role carrying the policies back the iam:ResourceTag condition keys.
    let (principal, session_data) = database.user_identity("SVCLRPTAGLST0001", "Tag-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_role_policies_parameters(Some("Engineering-Target"), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<member>Eng-Access</member>"), "unexpected body: {body}");

    // A role carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCLRPTAGLST0001", "Tag-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(Some("Sales-Target"), None, None))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // Neither does a role carrying no tags at all: the condition key is absent.
    let (principal, session_data) = database.user_identity("SVCLRPTAGLST0001", "Tag-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(Some("Policy-Holder"), None, None))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single role reaches every inline policy on it -- there is no naming an
    // inline policy in a resource ARN -- and reaches no other role.
    let (principal, session_data) = database.user_identity("SVCLRPNARROWLS01", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(Some("Policy-Holder"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<member>App-Access</member>"), "unexpected body: {body}");
    assert!(body.contains("<member>Db-Access</member>"), "unexpected body: {body}");
    assert!(body.contains("<member>Zz-Access</member>"), "unexpected body: {body}");

    let (principal, session_data) = database.user_identity("SVCLRPNARROWLS01", "Narrow-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_role_policies_parameters(Some("Engineering-Target"), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCLRPNOGRANTL01", "No-Grant-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(Some("Policy-Holder"), None, None))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Lister is not authorized to perform: \
                 iam:ListRolePolicies on resource: arn:aws:iam::{account_id}:role/Policy-Holder"
        )),
        "unexpected body: {body}"
    );

    // A role that does not exist has no path to read, so the ARN authorized is the one it would
    // carry at the root path. A caller allowed iam:ListRolePolicies on any role is told the role
    // is missing...
    let (principal, session_data) = database.user_identity("SVCLRPBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(Some("No-Such-Role"), None, None))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific role learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCLRPNARROWLS01", "Narrow-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(Some("No-Such-Role"), None, None))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // RoleName is required; it does not default to anything.
    let (principal, session_data) = database.user_identity("SVCLRPBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(None, None, None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // A malformed role name, a MaxItems outside the range a page may take, and a marker that is
    // not shaped like a pagination token are all settled before the request is authorized.
    for parameters in [
        list_role_policies_parameters(Some("bad role!"), None, None),
        list_role_policies_parameters(Some("Policy-Holder"), Some(0), None),
        list_role_policies_parameters(Some("Policy-Holder"), Some(1001), None),
        list_role_policies_parameters(Some("Policy-Holder"), None, Some("")),
    ] {
        let (principal, session_data) = database.user_identity("SVCLRPNOGRANTL01", "No-Grant-Lister");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // A marker this service did not issue is the caller's to fix rather than ours, so it is
    // reported as invalid input rather than as an internal failure -- a client-side pagination
    // token passed back in place of the marker it wraps lands here.
    let (principal, session_data) = database.user_identity("SVCLRPBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_role_policies_parameters(Some("Policy-Holder"), None, Some(FOREIGN_PAGINATION_TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>InvalidInput</Code>"), "unexpected body: {body}");

    // A MaxItems that is not a number at all never becomes a value the request can carry, so it
    // is reported as malformed input rather than as a validation failure.
    let (principal, session_data) = database.user_identity("SVCLRPBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        "Action=ListRolePolicies&Version=2010-05-08&RoleName=Policy-Holder&MaxItems=many",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCLRPSESSROLE01", "List-Role-Policies-Role");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(Some("Policy-Holder"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<member>App-Access</member>"), "unexpected body: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_role_policies_parameters(Some("Root-Target"), None, None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<member>Root-Access</member>"), "unexpected body: {body}");
}
