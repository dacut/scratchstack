use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// The trust policy the seeded roles carry.
const TRUST_POLICY: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}"#;

/// Seed data for the `TagRole` authorization tests. The callers carry grants scoped by the tags
/// the request asks to write (`aws:RequestTag` and `aws:TagKeys`), by the path of the role being
/// tagged, by the tags that role already carries, and by the role itself. `Tag-Target` starts out
/// carrying a tag so that adding one can be told apart from replacing one.
const TAG_ROLE_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'tag-role-test@example.com', 'tag-role-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCTGRBROADTAG01', '%ACCOUNT_ID%', 'broad-tagger', 'Broad-Tagger', '/'),
    ('SVCTGRVALUETAG01', '%ACCOUNT_ID%', 'value-tagger', 'Value-Tagger', '/'),
    ('SVCTGRKEYTAG0001', '%ACCOUNT_ID%', 'key-tagger', 'Key-Tagger', '/'),
    ('SVCTGRPATHTAG001', '%ACCOUNT_ID%', 'path-tagger', 'Path-Tagger', '/'),
    ('SVCTGRRESTAG0001', '%ACCOUNT_ID%', 'resource-tagger', 'Resource-Tagger', '/'),
    ('SVCTGRNARROWTG01', '%ACCOUNT_ID%', 'narrow-tagger', 'Narrow-Tagger', '/'),
    ('SVCTGRNOGRANTTG1', '%ACCOUNT_ID%', 'no-grant-tagger', 'No-Grant-Tagger', '/');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCTGRTGTPLAIN01', '%ACCOUNT_ID%', 'tag-target', 'Tag-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCTGRTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCTGRTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCTGRTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCTGRTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCTGRROLE000001', '%ACCOUNT_ID%', 'tag-role-role', 'Tag-Role-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_tags(role_id, key_lower, key_cased, value) VALUES
    ('SVCTGRTGTPLAIN01', 'env', 'Env', 'Staging'),
    ('SVCTGRTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCTGRTGTSALES01', 'department', 'Department', 'Sales');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCTGRBROADTAG01', 'allow-tag-any-role', 'Allow-Tag-Any-Role',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:TagRole","iam:GetRole"],
        "Resource":"*"}]}'),
    ('SVCTGRVALUETAG01', 'allow-tag-platform-only', 'Allow-Tag-Platform-Only',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagRole","Resource":"*",
        "Condition":{"StringEquals":{"aws:RequestTag/Team":"Platform"}}}]}'),
    ('SVCTGRKEYTAG0001', 'allow-tag-team-key-only', 'Allow-Tag-Team-Key-Only',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagRole","Resource":"*",
        "Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["Team"]}}}]}'),
    ('SVCTGRPATHTAG001', 'allow-tag-division', 'Allow-Tag-Division',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagRole",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/division/*"}]}'),
    ('SVCTGRRESTAG0001', 'allow-tag-engineering', 'Allow-Tag-Engineering',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagRole","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCTGRNARROWTG01', 'allow-tag-target', 'Allow-Tag-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagRole",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:role/Tag-Target"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCTGRROLE000001', 'allow-tag-any-role', 'Allow-Tag-Any-Role',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagRole","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `TagRole` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_tag_role_authorization() {
    let database = TestDatabase::new(TAG_ROLE_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:TagRole on any role adds a tag to one.
    let (principal, session_data) = database.user_identity("SVCTGRBROADTAG01", "Broad-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(Some("Tag-Target"), &[("Team", "Platform")]))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<TagRoleResponse"), "unexpected body: {body}");

    // The write was committed rather than rolled back, and it added the tag alongside the one
    // the role was already carrying rather than replacing the lot.
    let (principal, session_data) = database.user_identity("SVCTGRBROADTAG01", "Broad-Tagger");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Tag-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Team</Key><Value>Platform</Value>"), "unexpected body: {body}");
    assert!(body.contains("<Key>Env</Key><Value>Staging</Value>"), "unexpected body: {body}");

    // Tagging a role does not disturb its trust policy, which is still reported percent-encoded.
    assert_eq!(decoded_trust_policy_document(&body), TRUST_POLICY);

    // A tag whose key is already on the role replaces that tag's value.
    let (principal, session_data) = database.user_identity("SVCTGRBROADTAG01", "Broad-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(Some("Tag-Target"), &[("Env", "Production")]))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCTGRBROADTAG01", "Broad-Tagger");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Tag-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Key>Env</Key><Value>Production</Value>"), "unexpected body: {body}");
    assert!(!body.contains("<Value>Staging</Value>"), "unexpected body: {body}");

    // The role name is matched case-insensitively, as it is everywhere else.
    let (principal, session_data) = database.user_identity("SVCTGRBROADTAG01", "Broad-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(Some("TAG-TARGET"), &[("Cased", "Yes")])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The tags the request asks to write back aws:RequestTag, so a grant confined to one value
    // admits that value...
    let (principal, session_data) = database.user_identity("SVCTGRVALUETAG01", "Value-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(Some("Sales-Target"), &[("Team", "Platform")]))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and refuses another, whichever role is being tagged.
    let (principal, session_data) = database.user_identity("SVCTGRVALUETAG01", "Value-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(Some("Sales-Target"), &[("Team", "Finance")]))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The keys being written back aws:TagKeys, so a grant confined to one key admits a request
    // writing only that key...
    let (principal, session_data) = database.user_identity("SVCTGRKEYTAG0001", "Key-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(Some("Sales-Target"), &[("Team", "Anything")]))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and refuses one that also writes a key it does not name, since every key in the request
    // has to be one the grant allows.
    let (principal, session_data) = database.user_identity("SVCTGRKEYTAG0001", "Key-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_role_parameters(Some("Sales-Target"), &[("Team", "Anything"), ("Other", "Value")]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The resource ARN carries the target role's path, so a grant scoped to a path prefix
    // reaches roles under that path...
    let (principal, session_data) = database.user_identity("SVCTGRPATHTAG001", "Path-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_role_parameters(Some("Division-Target"), &[("Team", "Division")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and no further.
    let (principal, session_data) = database.user_identity("SVCTGRPATHTAG001", "Path-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(Some("Tag-Target"), &[("Team", "Division")]))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // The tags the role already carries back the aws:ResourceTag condition keys, which are a
    // different set from the ones being written.
    let (principal, session_data) = database.user_identity("SVCTGRRESTAG0001", "Resource-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_role_parameters(Some("Engineering-Target"), &[("Team", "Anything")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A role carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCTGRRESTAG0001", "Resource-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(Some("Sales-Target"), &[("Team", "Anything")]))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller allowed to tag a role reached by a grant conditioned on that role's own tags can
    // rewrite the very tag the grant turns on, moving the role out of its reach.
    let (principal, session_data) = database.user_identity("SVCTGRRESTAG0001", "Resource-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_role_parameters(Some("Engineering-Target"), &[("Department", "Sales")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCTGRRESTAG0001", "Resource-Tagger");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &tag_role_parameters(Some("Engineering-Target"), &[("Team", "Anything")]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A grant naming a single role reaches every tag on it and no other role.
    let (principal, session_data) = database.user_identity("SVCTGRNARROWTG01", "Narrow-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(Some("Tag-Target"), &[("Narrow", "Yes")])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.user_identity("SVCTGRNARROWTG01", "Narrow-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(Some("Sales-Target"), &[("Narrow", "Yes")]))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCTGRNOGRANTTG1", "No-Grant-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(Some("Tag-Target"), &[("Denied", "Yes")])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Tagger is not authorized to perform: \
                 iam:TagRole on resource: arn:aws:iam::{account_id}:role/Tag-Target"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled the transaction back, so the tag was not applied.
    let (principal, session_data) = database.user_identity("SVCTGRBROADTAG01", "Broad-Tagger");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Tag-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<Key>Denied</Key>"), "unexpected body: {body}");

    // A role that does not exist is still authorized against the ARN the request names, so a
    // caller allowed iam:TagRole on any role is told the role is missing...
    let (principal, session_data) = database.user_identity("SVCTGRBROADTAG01", "Broad-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(Some("No-Such-Role"), &[("Team", "Platform")]))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific role learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCTGRNARROWTG01", "Narrow-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(Some("No-Such-Role"), &[("Team", "Platform")]))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // RoleName is required.
    let (principal, session_data) = database.user_identity("SVCTGRBROADTAG01", "Broad-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(None, &[("Team", "Platform")])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // A role name that is not a role name is rejected before the request is authorized.
    let (principal, session_data) = database.user_identity("SVCTGRBROADTAG01", "Broad-Tagger");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(Some("Bad Role Name"), &[("Team", "Platform")]))
            .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

    // At least one tag is required, and two tags sharing a key ask for two values for one tag.
    // Both are settled after authorization, so a caller allowed to have asked is told which, and
    // they are reported differently: an empty list fails validation, while duplicate keys are
    // input the request could not have meant. Tag keys are compared case-insensitively, so the
    // second pair below is one key twice rather than two keys.
    for (tags, code) in
        [(&[][..], "ValidationError"), (&[("Team", "Platform"), ("team", "Finance")][..], "InvalidInput")]
    {
        let (principal, session_data) = database.user_identity("SVCTGRBROADTAG01", "Broad-Tagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &tag_role_parameters(Some("Tag-Target"), tags)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains(&format!("<Code>{code}</Code>")), "unexpected body: {body}");
    }

    // The rejected request wrote nothing.
    let (principal, session_data) = database.user_identity("SVCTGRBROADTAG01", "Broad-Tagger");
    let (status, body) = call(&svc_state, principal, session_data, &get_role_parameters(Some("Tag-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(!body.contains("<Key>Team</Key><Value>Finance</Value>"), "unexpected body: {body}");

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCTGRROLE000001", "Tag-Role-Role");
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(Some("Division-Target"), &[("Session", "Yes")]))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &tag_role_parameters(Some("Root-Target"), &[("Root", "Yes")])).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
}
