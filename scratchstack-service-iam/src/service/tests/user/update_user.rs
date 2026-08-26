use {crate::service::tests::*, pretty_assertions::assert_eq, scratchstack_core::axum::http::StatusCode};

/// Seed data for the `UpdateUser` authorization tests. Renaming or moving a user changes the ARN
/// naming it, so the callers here carry grants scoped by path, by the user's tags, and by the
/// user itself, which is what tells apart a grant reaching the name a user is renamed away from
/// and one reaching the name it is renamed to. `Keep-Target` carries a credential, an inline
/// policy, and a tag, so a rename can be shown to take them with it.
const UPDATE_USER_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'update-user-test@example.com', 'update-user-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCUPUBROADUPD01', '%ACCOUNT_ID%', 'broad-updater', 'Broad-Updater', '/'),
    ('SVCUPUPATHUPD001', '%ACCOUNT_ID%', 'path-updater', 'Path-Updater', '/'),
    ('SVCUPUTAGUPD0001', '%ACCOUNT_ID%', 'tag-updater', 'Tag-Updater', '/'),
    ('SVCUPUNARROWUP01', '%ACCOUNT_ID%', 'narrow-updater', 'Narrow-Updater', '/'),
    ('SVCUPUNOGRANTU01', '%ACCOUNT_ID%', 'no-grant-updater', 'No-Grant-Updater', '/'),
    ('SVCUPUTGTRENAME1', '%ACCOUNT_ID%', 'rename-target', 'Rename-Target', '/'),
    ('SVCUPUTGTMOVE001', '%ACCOUNT_ID%', 'move-target', 'Move-Target', '/'),
    ('SVCUPUTGTBOTH001', '%ACCOUNT_ID%', 'both-target', 'Both-Target', '/'),
    ('SVCUPUTGTQUIET01', '%ACCOUNT_ID%', 'quiet-target', 'Quiet-Target', '/'),
    ('SVCUPUTGTKEEP001', '%ACCOUNT_ID%', 'keep-target', 'Keep-Target', '/'),
    ('SVCUPUTGTEXIST01', '%ACCOUNT_ID%', 'existing-target', 'Existing-Target', '/'),
    ('SVCUPUTGTDIVSN01', '%ACCOUNT_ID%', 'division-target', 'Division-Target', '/division/'),
    ('SVCUPUTGTOUTSD01', '%ACCOUNT_ID%', 'outside-target', 'Outside-Target', '/'),
    ('SVCUPUTGTENGNR01', '%ACCOUNT_ID%', 'engineering-target', 'Engineering-Target', '/'),
    ('SVCUPUTGTSALES01', '%ACCOUNT_ID%', 'sales-target', 'Sales-Target', '/'),
    ('SVCUPUTGTNARROW1', '%ACCOUNT_ID%', 'narrow-target', 'Narrow-Target', '/'),
    ('SVCUPUTGTROLE001', '%ACCOUNT_ID%', 'role-target', 'Role-Target', '/'),
    ('SVCUPUTGTROOT001', '%ACCOUNT_ID%', 'root-target', 'Root-Target', '/');

    INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
    ('SVCUPUTGTENGNR01', 'department', 'Department', 'Engineering'),
    ('SVCUPUTGTSALES01', 'department', 'Department', 'Sales'),
    ('SVCUPUTGTKEEP001', 'project', 'Project', 'Apollo');

    INSERT INTO iam.user_credentials(access_key_id, user_id, secret_key, enabled) VALUES
    ('UPUKEEPKEY000001', 'SVCUPUTGTKEEP001', 'update-keep-secret', TRUE);

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCUPUTGTKEEP001', 'keep-policy', 'Keep-Policy',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
    ('SVCUPUBROADUPD01', 'allow-update-any-user', 'Allow-Update-Any-User',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateUser","Resource":"*"}]}'),
    ('SVCUPUPATHUPD001', 'allow-update-division-users', 'Allow-Update-Division-Users',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateUser",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/division/*"}]}'),
    ('SVCUPUTAGUPD0001', 'allow-update-engineering-users', 'Allow-Update-Engineering-Users',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateUser","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
    ('SVCUPUNARROWUP01', 'allow-update-narrow-target', 'Allow-Update-Narrow-Target',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateUser",
        "Resource":"arn:aws:iam::%ACCOUNT_ID%:user/Narrow-Target"}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCUPUROLE000001', '%ACCOUNT_ID%', 'update-user-role', 'Update-User-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCUPUROLE000001', 'allow-update-any-user', 'Allow-Update-Any-User',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateUser","Resource":"*"}]}');
"#;

/// End-to-end authorization checks for `UpdateUser` through `serve_request` against an embedded
/// PostgreSQL database. A single test function covers every case: the cases run in order against
/// one account, and several of them read the state the cases before them left behind.
#[test_log::test(tokio::test)]
async fn test_update_user_authorization() {
    let database = TestDatabase::new(UPDATE_USER_TEST_DATA).await;
    let svc_state = database.svc_state().clone();
    let account_id = database.account_id();

    // A caller allowed iam:UpdateUser on any user renames one.
    let (principal, session_data) = database.user_identity("SVCUPUBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_user_parameters(Some("Rename-Target"), Some("Renamed"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UpdateUserResponse"), "unexpected body: {body}");

    // The user answers to the new name and no longer to the old one, so the rename was committed
    // rather than rolled back.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Renamed"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains(&format!("<Arn>arn:aws:iam::{account_id}:user/Renamed</Arn>")), "unexpected body: {body}");
    assert!(body.contains("<UserId>AIDASVCUPUTGTRENAME1</UserId>"), "unexpected body: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Rename-Target"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");

    // A path is part of a user's ARN as much as its name is, so moving a user is the same
    // operation as renaming one.
    let (principal, session_data) = database.user_identity("SVCUPUBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_user_parameters(Some("Move-Target"), None, Some("/division/")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Move-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:user/division/Move-Target</Arn>")),
        "unexpected body: {body}"
    );
    assert!(body.contains("<Path>/division/</Path>"), "unexpected body: {body}");

    // Both halves can be replaced at once.
    let (principal, session_data) = database.user_identity("SVCUPUBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_user_parameters(Some("Both-Target"), Some("Both-Renamed"), Some("/moved/")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Both-Renamed"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:user/moved/Both-Renamed</Arn>")),
        "unexpected body: {body}"
    );

    // A request replacing neither half succeeds and changes nothing.
    let (principal, session_data) = database.user_identity("SVCUPUBROADUPD01", "Broad-Updater");
    let (status, body) =
        call(&svc_state, principal, session_data, &update_user_parameters(Some("Quiet-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Quiet-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:user/Quiet-Target</Arn>")),
        "unexpected body: {body}"
    );

    // Names are compared case-insensitively, so a rename that changes only the casing renames the
    // user to itself rather than colliding with it, and the new casing is what is reported back.
    let (principal, session_data) = database.user_identity("SVCUPUBROADUPD01", "Broad-Updater");
    let (status, body) =
        call(&svc_state, principal, session_data, &update_user_parameters(Some("renamed"), Some("RENAMED"), None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Renamed"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<UserName>RENAMED</UserName>"), "unexpected body: {body}");

    // Everything the user carries is keyed on its id rather than on its name, so a rename takes
    // its credentials, inline policies, and tags with it.
    let (principal, session_data) = database.user_identity("SVCUPUBROADUPD01", "Broad-Updater");
    let (status, body) =
        call(&svc_state, principal, session_data, &update_user_parameters(Some("Keep-Target"), Some("Kept"), None))
            .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_access_keys_parameters(Some("Kept"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<AccessKeyId>AKIAUPUKEEPKEY000001</AccessKeyId>"), "unexpected body: {body}");
    // The key is reported against the name the user now answers to.
    assert!(body.contains("<UserName>Kept</UserName>"), "unexpected body: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_user_policies_parameters(Some("Kept"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<member>Keep-Policy</member>"), "unexpected body: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &list_user_tags_parameters(Some("Kept"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Value>Apollo</Value>"), "unexpected body: {body}");

    // A name the account already carries cannot be renamed onto, and the comparison ignores case.
    for new_user_name in ["Existing-Target", "existing-target"] {
        let (principal, session_data) = database.user_identity("SVCUPUBROADUPD01", "Broad-Updater");
        let (status, body) =
            call(&svc_state, principal, session_data, &update_user_parameters(Some("Kept"), Some(new_user_name), None))
                .await;
        assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
        assert!(body.contains("<Code>EntityAlreadyExists</Code>"), "unexpected body: {body}");
    }

    // The collision rolled its transaction back, so the user still answers to the name it had.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Kept"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A grant scoped to a path prefix reaches a user under that path, so long as the request
    // leaves it there.
    let (principal, session_data) = database.user_identity("SVCUPUPATHUPD001", "Path-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_user_parameters(Some("Division-Target"), Some("Division-Renamed"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // Moving that user out from under the path is not something the same grant allows: the ARN
    // the user would carry afterwards is outside it, and it is that ARN the denial names.
    let (principal, session_data) = database.user_identity("SVCUPUPATHUPD001", "Path-Updater");
    let (status, body) =
        call(&svc_state, principal, session_data, &update_user_parameters(Some("Division-Renamed"), None, Some("/")))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/Path-Updater is not authorized to perform: \
                 iam:UpdateUser on resource: arn:aws:iam::{account_id}:user/Division-Renamed"
        )),
        "unexpected body: {body}"
    );

    // The denial rolled its transaction back, so the user is still where it was.
    let (principal, session_data) = database.root_identity();
    let (status, body) =
        call(&svc_state, principal, session_data, &get_user_parameters(Some("Division-Renamed"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(body.contains("<Path>/division/</Path>"), "unexpected body: {body}");

    // Moving a user into the path the grant covers is not allowed either: it is the ARN the user
    // carries now that falls outside it.
    let (principal, session_data) = database.user_identity("SVCUPUPATHUPD001", "Path-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_user_parameters(Some("Outside-Target"), None, Some("/division/")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!("iam:UpdateUser on resource: arn:aws:iam::{account_id}:user/Outside-Target")),
        "unexpected body: {body}"
    );

    // A grant naming a single user covers a request that changes nothing about that user's ARN...
    let (principal, session_data) = database.user_identity("SVCUPUNARROWUP01", "Narrow-Updater");
    let (status, body) =
        call(&svc_state, principal, session_data, &update_user_parameters(Some("Narrow-Target"), None, None)).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // ...and covers no rename away from that name, since the name is what the grant names.
    let (principal, session_data) = database.user_identity("SVCUPUNARROWUP01", "Narrow-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_user_parameters(Some("Narrow-Target"), Some("Narrow-Renamed"), None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!("iam:UpdateUser on resource: arn:aws:iam::{account_id}:user/Narrow-Renamed")),
        "unexpected body: {body}"
    );

    // The tags the user carries back the aws:ResourceTag condition keys. This operation does not
    // change them, so they describe the user under the name it is renamed to as much as under the
    // one it is renamed from.
    let (principal, session_data) = database.user_identity("SVCUPUTAGUPD0001", "Tag-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_user_parameters(Some("Engineering-Target"), Some("Engineering-Renamed"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A user carrying the tag with a different value does not satisfy the condition.
    let (principal, session_data) = database.user_identity("SVCUPUTAGUPD0001", "Tag-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_user_parameters(Some("Sales-Target"), Some("Sales-Renamed"), None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Sales-Target"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // A caller with no grant at all is denied, and is told what it was denied.
    let (principal, session_data) = database.user_identity("SVCUPUNOGRANTU01", "No-Grant-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_user_parameters(Some("Quiet-Target"), Some("Quiet-Renamed"), None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(
        body.contains(&format!(
            "User: arn:aws:iam::{account_id}:user/No-Grant-Updater is not authorized to perform: \
                 iam:UpdateUser on resource: arn:aws:iam::{account_id}:user/Quiet-Target"
        )),
        "unexpected body: {body}"
    );

    // A user that does not exist is still authorized against the ARN the request names -- the
    // root path, since there is no user to read a path from -- so a caller allowed
    // iam:UpdateUser on any user is told the user is missing...
    let (principal, session_data) = database.user_identity("SVCUPUBROADUPD01", "Broad-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_user_parameters(Some("No-Such-User"), Some("Still-No-Such-User"), None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
    assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

    // ...while a caller allowed it only on a specific user learns nothing about it.
    let (principal, session_data) = database.user_identity("SVCUPUNARROWUP01", "Narrow-Updater");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_user_parameters(Some("No-Such-User"), Some("Still-No-Such-User"), None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

    // UserName is required: unlike GetUser, an omitted name does not default to the calling user.
    let (principal, session_data) = database.user_identity("SVCUPUBROADUPD01", "Broad-Updater");
    let (status, body) =
        call(&svc_state, principal, session_data, &update_user_parameters(None, Some("Nameless"), None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
    assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

    // A new name or a new path that is not one is rejected before the request is authorized, so
    // even a caller with no grant is told the request is malformed rather than denied.
    for parameters in [
        update_user_parameters(Some("Quiet-Target"), Some("Bad Name"), None),
        update_user_parameters(Some("Quiet-Target"), None, Some("no-slashes")),
    ] {
        let (principal, session_data) = database.user_identity("SVCUPUNOGRANTU01", "No-Grant-Updater");
        let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
    }

    // An assumed-role session is governed by the role's own policy.
    let (principal, session_data) = database.role_identity("SVCUPUROLE000001", "Update-User-Role");
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_user_parameters(Some("Role-Target"), Some("Role-Renamed"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    // The account root user is implicitly allowed.
    let (principal, session_data) = database.root_identity();
    let (status, body) = call(
        &svc_state,
        principal,
        session_data,
        &update_user_parameters(Some("Root-Target"), Some("Root-Renamed"), Some("/administration/")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let (principal, session_data) = database.root_identity();
    let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Root-Renamed"))).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body.contains(&format!("<Arn>arn:aws:iam::{account_id}:user/administration/Root-Renamed</Arn>")),
        "unexpected body: {body}"
    );
}
