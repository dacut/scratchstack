use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `ListAttachedUserPolicies` authorization tests. `Attachment-Holder`
/// carries three managed policies, one of them under a path of its own so the `PathPrefix`
/// filter has something to select on; `Empty-Target` carries none, so a user without
/// attachments can be told apart from one that does not exist. The remaining targets carry the
/// paths and tags the resource ARN and the `aws:ResourceTag` condition keys are derived from.
const LIST_ATTACHED_USER_POLICIES_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'list-attached-user-policies-test@example.com', 'list-attached-user-policies-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCLAPBROADLST01', '%ACCOUNT_ID%', 'broad-lister', 'Broad-Lister', '/'),
    ('SVCLAPPATHLST001', '%ACCOUNT_ID%', 'path-lister', 'Path-Lister', '/'),
    ('SVCLAPTAGLST0001', '%ACCOUNT_ID%', 'tag-lister', 'Tag-Lister', '/'),
    ('SVCLAPNARROWLS01', '%ACCOUNT_ID%', 'narrow-lister', 'Narrow-Lister', '/'),
    ('SVCLAPNOGRANTL01', '%ACCOUNT_ID%', 'no-grant-lister', 'No-Grant-Lister', '/'),
    ('SVCLAPTGTHOLDER1', '%ACCOUNT_ID%', 'attachment-holder', 'Attachment-Holder', '/'),
    ('SVCLAPTGTEMPTY01', '%ACCOUNT_ID%', 'empty-target', 'Empty-Target', '/'),
    ('SVCLAPTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/'),
    ('SVCLAPTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/'),
    ('SVCLAPTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/'),
    ('SVCLAPTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCLAPTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCLAPTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCLAPPOLAPP0001', '%ACCOUNT_ID%', 'app-policy', 'App-Policy', '/apps/', 1, false, 1),
    ('SVCLAPPOLDB00001', '%ACCOUNT_ID%', 'db-policy', 'Db-Policy', '/', 1, false, 1),
    ('SVCLAPPOLZZ00001', '%ACCOUNT_ID%', 'zz-policy', 'Zz-Policy', '/', 1, false, 1),
    ('SVCLAPPOLDIVSN01', '%ACCOUNT_ID%', 'division-policy', 'Division-Policy', '/', 1, false, 1),
    ('SVCLAPPOLENG0001', '%ACCOUNT_ID%', 'eng-policy', 'Eng-Policy', '/', 1, false, 1),
    ('SVCLAPPOLSALES01', '%ACCOUNT_ID%', 'sales-policy', 'Sales-Policy', '/', 1, false, 1),
    ('SVCLAPPOLROOT001', '%ACCOUNT_ID%', 'root-policy', 'Root-Policy', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCLAPPOLAPP0001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCLAPPOLDB00001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"*"}]}'),
    ('SVCLAPPOLZZ00001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}'),
    ('SVCLAPPOLDIVSN01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}'),
    ('SVCLAPPOLENG0001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}'),
    ('SVCLAPPOLSALES01', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ses:SendEmail","Resource":"*"}]}'),
    ('SVCLAPPOLROOT001', 1,
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*"}]}');

    INSERT INTO iam.user_attached_policies(user_id, managed_policy_id) VALUES
    ('SVCLAPTGTHOLDER1', 'SVCLAPPOLAPP0001'),
    ('SVCLAPTGTHOLDER1', 'SVCLAPPOLDB00001'),
    ('SVCLAPTGTHOLDER1', 'SVCLAPPOLZZ00001'),
    ('SVCLAPTGTDIVSN01', 'SVCLAPPOLDIVSN01'),
    ('SVCLAPTGTENGNR01', 'SVCLAPPOLENG0001'),
    ('SVCLAPTGTSALES01', 'SVCLAPPOLSALES01'),
    ('SVCLAPTGTROOT001', 'SVCLAPPOLROOT001');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLAPBROADLST01', 'allow-list-any-attachments', 'Allow-List-Any-Attachments',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAttachedUserPolicies",
        "Resource":"*"}]}'),
    ('SVCLAPPATHLST001', 'allow-list-division-attachments', 'Allow-List-Division-Attachments',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAttachedUserPolicies",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/division/*"}]}'),
    ('SVCLAPTAGLST0001', 'allow-list-engineering-attachments', 'Allow-List-Engineering-Attachments',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAttachedUserPolicies",
        "Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCLAPNARROWLS01', 'allow-list-holder-attachments', 'Allow-List-Holder-Attachments',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAttachedUserPolicies",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/Attachment-Holder"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCLAPROLE000001', '%ACCOUNT_ID%', 'list-attached-user-policies-role', 'List-Attached-User-Policies-Role',
        '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCLAPROLE000001', 'allow-list-any-attachments', 'Allow-List-Any-Attachments',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAttachedUserPolicies",
        "Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `ListAttachedUserPolicies` through `serve_request` against
/// an embedded PostgreSQL database. A single test function covers every case so that they share
/// one seeded account, rather than seeding one apiece.
#[test_log::test(tokio::test)]
async fn test_list_attached_user_policies_authorization() {
    let database = TestDatabase::new(LIST_ATTACHED_USER_POLICIES_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:ListAttachedUserPolicies on any user reads the managed policies
    // attached to one, ordered by name, each reported by name and ARN.
    let (principal, session_data) = database.user_identity("SVCLAPBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Attachment-Holder"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "<AttachedPolicies>\
                 <member><PolicyArn>arn:aws:iam::{account_id}:policy/apps/App-Policy</PolicyArn>\
                 <PolicyName>App-Policy</PolicyName></member>\
                 <member><PolicyArn>arn:aws:iam::{account_id}:policy/Db-Policy</PolicyArn>\
                 <PolicyName>Db-Policy</PolicyName></member>\
                 <member><PolicyArn>arn:aws:iam::{account_id}:policy/Zz-Policy</PolicyArn>\
                 <PolicyName>Zz-Policy</PolicyName></member>\
                 </AttachedPolicies>"
        )),
        "unexpected body: {body}"
    );

    // Names and ARNs are all that comes back: the documents behind them are read with
    // GetPolicy and GetPolicyVersion, which are granted separately.
    assert!(!body.contains("PolicyDocument"), "unexpected body: {body}");
    assert!(!body.contains("s3:GetObject"), "unexpected body: {body}");

    // A user carrying no attachments at all is an empty listing rather than a missing user.
    let (principal, session_data) = database.user_identity("SVCLAPBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Empty-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains("<ListAttachedUserPoliciesResult><AttachedPolicies/></ListAttachedUserPoliciesResult>"),
        "unexpected body: {body}"
    );

    // PathPrefix filters by the path of the policy rather than of the user...
    let (principal, session_data) = database.user_identity("SVCLAPBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Attachment-Holder"), Some("/apps/"), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>App-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(!body.contains("Db-Policy"), "unexpected body: {body}");
    assert!(!body.contains("Zz-Policy"), "unexpected body: {body}");

    // ...and matches nothing when no attached policy lives under it.
    let (principal, session_data) = database.user_identity("SVCLAPBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Attachment-Holder"), Some("/nowhere/"), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains("<ListAttachedUserPoliciesResult><AttachedPolicies/></ListAttachedUserPoliciesResult>"),
        "unexpected body: {body}"
    );

    // MaxItems bounds a page, and a bounded page reports the marker the next one continues
    // from...
    let (principal, session_data) = database.user_identity("SVCLAPBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Attachment-Holder"), None, Some(2), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<IsTruncated>true</IsTruncated>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>App-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(body.contains("<PolicyName>Db-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(!body.contains("Zz-Policy"), "unexpected body: {body}");
    let marker = pagination_marker(&body);

    // ...which reports the rest, and reports itself as the last page.
    let (principal, session_data) = database.user_identity("SVCLAPBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Attachment-Holder"), None, Some(2), Some(&marker)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Zz-Policy</PolicyName>"), "unexpected body: {body}");
    assert!(!body.contains("App-Policy"), "unexpected body: {body}");
    assert!(!body.contains("<IsTruncated>"), "unexpected body: {body}");

    // The resource ARN carries the target user's path, so a grant scoped to a path prefix
    // reaches users under that path...
    let (principal, session_data) = database.user_identity("SVCLAPPATHLST001", "Path-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Division-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Division-Policy</PolicyName>"), "unexpected body: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCLAPPATHLST001", "Path-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Attachment-Holder"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags on the user carrying the attachments back the aws:ResourceTag condition keys.
    let (principal, session_data) = database.user_identity("SVCLAPTAGLST0001", "Tag-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Engineering-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Eng-Policy</PolicyName>"), "unexpected body: {body}");

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCLAPTAGLST0001", "Tag-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Sales-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single user reaches every policy attached to it -- PathPrefix narrows
    // the listing, not the grant -- and reaches no other user.
    let (principal, session_data) = database.user_identity("SVCLAPNARROWLS01", "Narrow-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Attachment-Holder"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert_eq!(body.matches("<member>").count(), 3, "unexpected body: {body}");

    let (principal, session_data) = database.user_identity("SVCLAPNARROWLS01", "Narrow-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Engineering-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCLAPNOGRANTL01", "No-Grant-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Attachment-Holder"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Lister is not authorized to perform: \
                 iam:ListAttachedUserPolicies on resource: arn:aws:iam::{account_id}:user/Attachment-Holder"
        )),
        "unexpected body: {body}"
    );

    // A user that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:ListAttachedUserPolicies on any user is told the user is missing...
    let (principal, session_data) = database.user_identity("SVCLAPBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("No-Such-User"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCLAPNARROWLS01", "Narrow-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("No-Such-User"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // UserName is required; it does not default to the calling user.
    let (principal, session_data) = database.user_identity("SVCLAPBROADLST01", "Broad-Lister");
    let (status, body) =
        call(&svc_state, principal, session_data, &list_attached_user_policies_parameters(None, None, None, None))
            .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // A MaxItems outside the range a page may take is rejected, and so are a path prefix that
    // is not a path and a marker that is not shaped like a pagination token; all are settled
    // before the request is authorized.
    for parameters in [
        list_attached_user_policies_parameters(Some("Attachment-Holder"), None, Some(0), None),
        list_attached_user_policies_parameters(Some("Attachment-Holder"), None, Some(1001), None),
        list_attached_user_policies_parameters(Some("Attachment-Holder"), Some("apps/"), None, None),
        list_attached_user_policies_parameters(Some("Attachment-Holder"), None, None, Some("")),
    ] {
        let (principal, session_data) = database.user_identity("SVCLAPBROADLST01", "Broad-Lister");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // A marker this service did not issue is the caller's to fix rather than ours, so it is
    // reported as invalid input rather than as an internal failure.
    let (principal, session_data) = database.user_identity("SVCLAPBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Attachment-Holder"), None, None, Some(FOREIGN_PAGINATION_TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>InvalidInput</Code>"), "unexpected body: {body}");

    // A MaxItems that is not a number at all never becomes a value the request can carry, so
    // it is reported as malformed input rather than as a validation failure.
    let (principal, session_data) = database.user_identity("SVCLAPBROADLST01", "Broad-Lister");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        "Action=ListAttachedUserPolicies&Version=2010-05-08&UserName=Attachment-Holder&MaxItems=many",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCLAPROLE000001", "List-Attached-User-Policies-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Attachment-Holder"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>App-Policy</PolicyName>"), "unexpected body: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &list_attached_user_policies_parameters(Some("Root-Target"), None, None, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<PolicyName>Root-Policy</PolicyName>"), "unexpected body: {body}");
}
