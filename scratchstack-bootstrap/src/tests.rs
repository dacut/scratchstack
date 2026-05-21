use {
    crate::run,
    aws_smithy_types::error::metadata::ProvideErrorMetadata,
    pretty_assertions::assert_eq,
    scratchstack_database::utils::TempDatabase,
    scratchstack_shapes_iam::error_meta::Error as IamError,
    serde_json::Value as JsonValue,
    std::{collections::HashSet, ffi::OsString, future::Future},
};

/// Suite of tests for ssbs.
#[test_log::test(tokio::test)]
async fn test_ssdb_ops() {
    let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
    database.setup().await.expect("Failed to setup database");
    database.start().await.expect("Failed to start database");
    database.bootstrap().await.expect("Failed to bootstrap database");

    test_migrate_database(&database).await;
    test_migrate_database(&database).await;
    test_partition(&database).await;
    test_accounts(&database).await;
    test_users(&database).await;
    test_policies(&database).await;
    test_groups(&database).await;
    test_group_membership(&database).await;
    test_roles(&database).await;
    test_policy_attachments(&database).await;
}

async fn test_migrate_database(database: &TempDatabase) {
    let port = database.port_str();
    let result = database
        .run(["ssbs", "--port", &port, "--username", "scratchstack", "migrate"])
        .await
        .expect("Failed to run migrate");
    assert!(result.contains("Migration completed successfully."));
}

async fn test_partition(database: &TempDatabase) {
    let port = database.port_str();

    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "set-current-partition",
            "--partition",
            "test-partition",
        ])
        .await
        .expect("Failed to run set-current-partition");
    assert!(result.contains(r#""Partition": "test-partition""#));

    let result = database
        .run(["ssbs", "--port", &port, "--username", "scratchstack", "get-current-partition"])
        .await
        .expect("Failed to run get-current-partition");
    assert!(result.contains(r#""Partition": "test-partition""#));
}

async fn test_accounts(database: &TempDatabase) {
    let port = database.port_str();

    let mut account_ids = HashSet::new();

    // Create an account with no email or alias and verify the output contains the expected fields.
    let result = database
        .run(["ssbs", "--port", &port, "--username", "scratchstack", "create-account"])
        .await
        .expect("Failed to run create-account with no email or account-alias");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse create-account output as JSON");
    let account = json.get("Account").expect("Account should be present");
    let account_id1 = account.get("AccountId").expect("AccountId should be present");
    let account_id1_str = account_id1.as_str().expect("AccountId should be a string");
    assert_eq!(account.get("Email"), None);
    assert_eq!(account.get("AccountAlias"), None);
    account_ids.insert(account_id1_str.to_string());

    // Create an account with a specified account ID (and pray we don't hit a collision)
    let result = database
        .run(["ssbs", "--port", &port, "--username", "scratchstack", "create-account", "--account-id", "555566667777"])
        .await
        .expect("Failed to run create-account with specified account-id");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse create-account output as JSON");
    let account = json.get("Account").expect("Account should be present");
    let account_id2 = account.get("AccountId").expect("AccountId should be present");
    let account_id2_str = account_id2.as_str().expect("AccountId should be a string");
    assert_eq!(account_id2_str, "555566667777");
    assert_eq!(account.get("Email"), None);
    assert_eq!(account.get("AccountAlias"), None);
    account_ids.insert(account_id2_str.to_string());

    // Create a 200 accounts for testing list-accounts pagination and verify all account IDs are unique.
    for i in 0..200 {
        let email = format!("account{:05}@example.com", i);
        let alias = format!("account-alias-{:05}", i);
        let result = database
            .run([
                "ssbs",
                "--port",
                &port,
                "--username",
                "scratchstack",
                "create-account",
                "--email",
                &email,
                "--account-alias",
                &alias,
            ])
            .await
            .unwrap_or_else(|_| {
                panic!("Failed to run create-account for account with email {email} and alias {alias}")
            });
        let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse create-account output as JSON");
        let account = json.get("Account").expect("Account should be present");
        let account_id = account.get("AccountId").expect("AccountId should be present");
        let account_id_str = account_id.as_str().expect("AccountId should be a string");
        assert!(account_ids.insert(account_id_str.to_string()), "AccountId should be unique");
        assert_eq!(account.get("Email"), Some(&JsonValue::String(email)));
        assert_eq!(account.get("AccountAlias"), Some(&JsonValue::String(alias)));
    }

    let mut result = database
        .run(["ssbs", "--port", &port, "--username", "scratchstack", "list-accounts"])
        .await
        .expect("Failed to run list-accounts (initial run)");
    loop {
        let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-accounts output as JSON");
        let accounts = json.get("Accounts").expect("Accounts should be present");
        let accounts_array = accounts.as_array().expect("Accounts should be an array");

        for account in accounts_array {
            let account_id = account
                .get("AccountId")
                .expect("AccountId should be present")
                .as_str()
                .expect("AccountId should be a string");

            if account_id != "000000000000" {
                let remove = account_ids.remove(account_id);
                assert!(remove, "Listed AccountId should be one of the created accounts");
            }
        }

        let Some(marker) = json.get("Marker") else {
            break;
        };

        let marker_str =
            marker.as_str().unwrap_or_else(|| panic!("Marker should be a string if present, got {marker:?}"));
        result = database
            .run(["ssbs", "--port", &port, "--username", "scratchstack", "list-accounts", "--marker", marker_str])
            .await
            .expect("Failed to run list-accounts with pagination");
    }

    if !account_ids.is_empty() {
        panic!(
            "All created accounts should have been listed, but the following AccountIds were not found: {:?}",
            account_ids
        );
    }
}

async fn test_users(database: &TempDatabase) {
    let port = database.port_str();

    // Create a user and verify the output.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "test-user",
            "--tags",
            "Key=Environment,Value=Production",
            "Key=Team,Value=Engineering",
        ])
        .await
        .expect("Failed to run create-user for 555566667777/test-user");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse create-user output as JSON");
    let user = json.get("User").expect("User should be present");
    let path = user.get("Path").expect("Path should be present").as_str().expect("Path should be a string");
    assert_eq!(path, "/");
    let user_name =
        user.get("UserName").expect("UserName should be present").as_str().expect("UserName should be a string");
    assert_eq!(user_name, "test-user");
    let arn = user.get("Arn").expect("Arn should be present").as_str().expect("Arn should be a string");
    assert_eq!(arn, "arn:test-partition:iam::555566667777:user/test-user");
    let tags = user.get("Tags").expect("Tags should be present").as_array().expect("Tags should be an array");
    assert_eq!(tags.len(), 2);
    let tag1 = &tags[0];
    let tag1_key = tag1.get("Key").expect("Tag Key should be present").as_str().expect("Tag Key should be a string");
    let tag1_value =
        tag1.get("Value").expect("Tag Value should be present").as_str().expect("Tag Value should be a string");
    assert_eq!(tag1_key, "Environment");
    assert_eq!(tag1_value, "Production");
    let tag2 = &tags[1];
    let tag2_key = tag2.get("Key").expect("Tag Key should be present").as_str().expect("Tag Key should be a string");
    let tag2_value =
        tag2.get("Value").expect("Tag Value should be present").as_str().expect("Tag Value should be a string");
    assert_eq!(tag2_key, "Team");
    assert_eq!(tag2_value, "Engineering");

    // Get the user and verify the output.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "test-user",
        ])
        .await
        .expect("Failed to run get-user for 555566667777/test-user");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse get-user output as JSON");
    let user = json.get("User").expect("User should be present");
    let path = user.get("Path").expect("Path should be present").as_str().expect("Path should be a string");
    assert_eq!(path, "/");
    let user_name =
        user.get("UserName").expect("UserName should be present").as_str().expect("UserName should be a string");
    assert_eq!(user_name, "test-user");
    let arn = user.get("Arn").expect("Arn should be present").as_str().expect("Arn should be a string");
    assert_eq!(arn, "arn:test-partition:iam::555566667777:user/test-user");
    let user_id = user.get("UserId").expect("UserId should be present").as_str().expect("UserId should be a string");
    assert!(user_id.starts_with("AIDA"), "UserId should start with AIDA, got {user_id}");
    let tags = user.get("Tags").expect("Tags should be present").as_array().expect("Tags should be an array");
    assert_eq!(tags.len(), 2);
    assert_eq!(tags[0].get("Key").unwrap().as_str().unwrap(), "Environment");
    assert_eq!(tags[0].get("Value").unwrap().as_str().unwrap(), "Production");
    assert_eq!(tags[1].get("Key").unwrap().as_str().unwrap(), "Team");
    assert_eq!(tags[1].get("Value").unwrap().as_str().unwrap(), "Engineering");

    // Getting a nonexistent user should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "no-such-user",
        ])
        .await
        .expect_err("Getting a nonexistent user should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity error, got: {err}");

    // List the user's tags and verify them.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-user-tags",
            "--account-id",
            "555566667777",
            "--user-name",
            "test-user",
        ])
        .await
        .expect("Failed to run list-user-tags for 555566667777/test-user");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-user-tags output as JSON");
    let tags = json.get("Tags").expect("Tags should be present").as_array().expect("Tags should be an array");
    assert_eq!(tags.len(), 2);
    let tag1 = &tags[0];
    let tag1_key = tag1.get("Key").expect("Tag Key should be present").as_str().expect("Tag Key should be a string");
    let tag1_value =
        tag1.get("Value").expect("Tag Value should be present").as_str().expect("Tag Value should be a string");
    assert_eq!(tag1_key, "Environment");
    assert_eq!(tag1_value, "Production");
    let tag2 = &tags[1];
    let tag2_key = tag2.get("Key").expect("Tag Key should be present").as_str().expect("Tag Key should be a string");
    let tag2_value =
        tag2.get("Value").expect("Tag Value should be present").as_str().expect("Tag Value should be a string");
    assert_eq!(tag2_key, "Team");
    assert_eq!(tag2_value, "Engineering");

    // Tag the user with a new tag and update an existing tag.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "tag-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "test-user",
            "--tags",
            "Key=Environment,Value=Staging",
            "Key=Project,Value=Apollo",
        ])
        .await
        .expect("Failed to run tag-user for 555566667777/test-user");

    // Verify the tags were updated/added.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-user-tags",
            "--account-id",
            "555566667777",
            "--user-name",
            "test-user",
        ])
        .await
        .expect("Failed to run list-user-tags after tag-user");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-user-tags output as JSON");
    let tags = json.get("Tags").expect("Tags should be present").as_array().expect("Tags should be an array");
    assert_eq!(tags.len(), 3, "Expected 3 tags after tag-user (Environment updated, Project added, Team unchanged)");
    // Tags are sorted by key_lower: Environment, Project, Team
    assert_eq!(tags[0].get("Key").unwrap().as_str().unwrap(), "Environment");
    assert_eq!(tags[0].get("Value").unwrap().as_str().unwrap(), "Staging");
    assert_eq!(tags[1].get("Key").unwrap().as_str().unwrap(), "Project");
    assert_eq!(tags[1].get("Value").unwrap().as_str().unwrap(), "Apollo");
    assert_eq!(tags[2].get("Key").unwrap().as_str().unwrap(), "Team");
    assert_eq!(tags[2].get("Value").unwrap().as_str().unwrap(), "Engineering");

    // Untag the user — remove Environment and Project.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "untag-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "test-user",
            "--tag-keys",
            "Environment",
            "Project",
        ])
        .await
        .expect("Failed to run untag-user for 555566667777/test-user");

    // Verify only Team remains.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-user-tags",
            "--account-id",
            "555566667777",
            "--user-name",
            "test-user",
        ])
        .await
        .expect("Failed to run list-user-tags after untag-user");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-user-tags output as JSON");
    let tags = json.get("Tags").expect("Tags should be present").as_array().expect("Tags should be an array");
    assert_eq!(tags.len(), 1, "Expected 1 tag after untag-user");
    assert_eq!(tags[0].get("Key").unwrap().as_str().unwrap(), "Team");
    assert_eq!(tags[0].get("Value").unwrap().as_str().unwrap(), "Engineering");

    // Untagging a nonexistent key should succeed silently.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "untag-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "test-user",
            "--tag-keys",
            "NoSuchKey",
        ])
        .await
        .expect("Untagging a nonexistent key should succeed silently");

    // Tagging a nonexistent user should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "tag-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "no-such-user",
            "--tags",
            "Key=Foo,Value=Bar",
        ])
        .await
        .expect_err("Tagging a nonexistent user should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity error, got: {err}");

    // Untagging a nonexistent user should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "untag-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "no-such-user",
            "--tag-keys",
            "Foo",
        ])
        .await
        .expect_err("Untagging a nonexistent user should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity error, got: {err}");

    // Delete the user.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "test-user",
        ])
        .await
        .expect("Failed to run delete-user for 555566667777/test-user");

    // Deleting the same user again should fail with a NoSuchEntity error.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "test-user",
        ])
        .await
        .expect_err("Deleting a non-existent user should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity error, got: {err}");
    assert!(
        err.message().unwrap_or_default().contains("cannot be found"),
        "Expected 'cannot be found' in error message, got: {err}"
    );

    // Deleting a user that never existed should also fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "no-such-user",
        ])
        .await
        .expect_err("Deleting a user that never existed should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity error, got: {err}");
    assert!(
        err.message().unwrap_or_default().contains("cannot be found"),
        "Expected 'cannot be found' in error message, got: {err}"
    );

    // -- delete-user-permissions-boundary --------------------------------------
    // Create a managed policy and a user that uses it as its permissions boundary.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-policy",
            "--account-id",
            "555566667777",
            "--policy-name",
            "UserPbPolicy",
            "--policy-document",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#,
        ])
        .await
        .expect("Failed to create UserPbPolicy");
    let pb_arn = "arn:test-partition:iam::555566667777:policy/UserPbPolicy";

    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "PbUser",
            "--permissions-boundary",
            pb_arn,
        ])
        .await
        .expect("Failed to create PbUser with permissions boundary");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse create-user output");
    let pb_arn_out = json
        .get("User")
        .and_then(|u| u.get("PermissionsBoundary"))
        .and_then(|p| p.get("PermissionsBoundaryArn"))
        .and_then(JsonValue::as_str)
        .expect("PermissionsBoundary.PermissionsBoundaryArn should be present");
    assert_eq!(pb_arn_out, pb_arn);

    // Clear the boundary.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-user-permissions-boundary",
            "--account-id",
            "555566667777",
            "--user-name",
            "PbUser",
        ])
        .await
        .expect("Failed to delete-user-permissions-boundary on PbUser");

    // Re-running on a user with no PB must still succeed (idempotent).
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-user-permissions-boundary",
            "--account-id",
            "555566667777",
            "--user-name",
            "PbUser",
        ])
        .await
        .expect("delete-user-permissions-boundary must be idempotent");

    // Now we should be able to delete the user and then the (no-longer-PB) policy.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "PbUser",
        ])
        .await
        .expect("Failed to delete PbUser");
    database
        .run(["ssbs", "--port", &port, "--username", "scratchstack", "delete-policy", "--policy-arn", pb_arn])
        .await
        .expect("Failed to delete UserPbPolicy");

    // delete-user-permissions-boundary on a nonexistent user must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-user-permissions-boundary",
            "--account-id",
            "555566667777",
            "--user-name",
            "no-such-user",
        ])
        .await
        .expect_err("delete-user-permissions-boundary on a nonexistent user should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Invalid user name must surface as ValidationError before reaching the database.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-user-permissions-boundary",
            "--account-id",
            "555566667777",
            "--user-name",
            "bad name!",
        ])
        .await
        .expect_err("delete-user-permissions-boundary with an invalid user name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // -- put-user-permissions-boundary -----------------------------------------
    // Create a managed policy and a fresh user with no boundary, then set the boundary via the API.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-policy",
            "--account-id",
            "555566667777",
            "--policy-name",
            "PutUserPbPolicy",
            "--policy-document",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#,
        ])
        .await
        .expect("Failed to create PutUserPbPolicy");
    let pb_arn = "arn:test-partition:iam::555566667777:policy/PutUserPbPolicy";

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "PutPbUser",
        ])
        .await
        .expect("Failed to create PutPbUser");

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-user-permissions-boundary",
            "--account-id",
            "555566667777",
            "--user-name",
            "PutPbUser",
            "--permissions-boundary",
            pb_arn,
        ])
        .await
        .expect("Failed to put-user-permissions-boundary on PutPbUser");

    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "PutPbUser",
        ])
        .await
        .expect("Failed to get-user for PutPbUser after put-user-permissions-boundary");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse get-user output");
    let pb_arn_out = json
        .get("User")
        .and_then(|u| u.get("PermissionsBoundary"))
        .and_then(|p| p.get("PermissionsBoundaryArn"))
        .and_then(JsonValue::as_str)
        .expect("PermissionsBoundary.PermissionsBoundaryArn should be present");
    assert_eq!(pb_arn_out, pb_arn);

    // Re-putting the same boundary must succeed.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-user-permissions-boundary",
            "--account-id",
            "555566667777",
            "--user-name",
            "PutPbUser",
            "--permissions-boundary",
            pb_arn,
        ])
        .await
        .expect("Re-running put-user-permissions-boundary on PutPbUser should succeed");

    // put-user-permissions-boundary on a nonexistent user must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-user-permissions-boundary",
            "--account-id",
            "555566667777",
            "--user-name",
            "no-such-user",
            "--permissions-boundary",
            pb_arn,
        ])
        .await
        .expect_err("put-user-permissions-boundary on a nonexistent user should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // PB ARN pointing to a nonexistent policy must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-user-permissions-boundary",
            "--account-id",
            "555566667777",
            "--user-name",
            "PutPbUser",
            "--permissions-boundary",
            "arn:test-partition:iam::555566667777:policy/NoSuchPolicy",
        ])
        .await
        .expect_err("put-user-permissions-boundary with a nonexistent PB policy should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Malformed PB ARN must surface ValidationError.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-user-permissions-boundary",
            "--account-id",
            "555566667777",
            "--user-name",
            "PutPbUser",
            "--permissions-boundary",
            "not-an-arn-but-long-enough-to-pass",
        ])
        .await
        .expect_err("put-user-permissions-boundary with an invalid PB ARN should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // Invalid user name must surface as ValidationError before reaching the database.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-user-permissions-boundary",
            "--account-id",
            "555566667777",
            "--user-name",
            "bad name!",
            "--permissions-boundary",
            pb_arn,
        ])
        .await
        .expect_err("put-user-permissions-boundary with an invalid user name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // Clean up: clear PB, delete the user and policy.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-user-permissions-boundary",
            "--account-id",
            "555566667777",
            "--user-name",
            "PutPbUser",
        ])
        .await
        .expect("Failed to clear PutPbUser PB during cleanup");
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "PutPbUser",
        ])
        .await
        .expect("Failed to delete PutPbUser during cleanup");
    database
        .run(["ssbs", "--port", &port, "--username", "scratchstack", "delete-policy", "--policy-arn", pb_arn])
        .await
        .expect("Failed to delete PutUserPbPolicy during cleanup");

    // -- put-user-policy ------------------------------------------------------
    // Create a fresh user for inline-policy tests. The user can't be deleted while inline
    // policies exist; the delete-user-policy block below removes them at the end.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "PutPolicyUser",
        ])
        .await
        .expect("Failed to create PutPolicyUser");

    let policy_doc =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
    let policy_doc_replaced =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}"#;
    let policy_doc_with_external_principal = r#"{
        "Version":"2012-10-17",
        "Statement":[{
            "Effect":"Allow",
            "Principal":{"AWS":"arn:aws:iam::999999999999:user/nonexistent"},
            "Action":"sts:AssumeRole",
            "Resource":"*"
        }]
    }"#;

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-user-policy",
            "--account-id",
            "555566667777",
            "--user-name",
            "PutPolicyUser",
            "--policy-name",
            "InlineRead",
            "--policy-document",
            policy_doc,
        ])
        .await
        .expect("Failed to put-user-policy on PutPolicyUser");

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-user-policy",
            "--account-id",
            "555566667777",
            "--user-name",
            "PutPolicyUser",
            "--policy-name",
            "InlineRead",
            "--policy-document",
            policy_doc_replaced,
        ])
        .await
        .expect("Replacing the inline policy on PutPolicyUser must succeed");

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-user-policy",
            "--account-id",
            "555566667777",
            "--user-name",
            "PutPolicyUser",
            "--policy-name",
            "InlineWithMissingPrincipal",
            "--policy-document",
            policy_doc_with_external_principal,
        ])
        .await
        .expect("Policies referencing non-existent principals must still be accepted");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-user-policy",
            "--account-id",
            "555566667777",
            "--user-name",
            "PutPolicyUser",
            "--policy-name",
            "InlineBroken",
            "--policy-document",
            "{ not valid aspen json }",
        ])
        .await
        .expect_err("put-user-policy with malformed JSON should fail");
    assert_eq!(err.code(), Some("MalformedPolicyDocument"), "Expected MalformedPolicyDocument, got: {err}");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-user-policy",
            "--account-id",
            "555566667777",
            "--user-name",
            "no-such-user",
            "--policy-name",
            "AnyName",
            "--policy-document",
            policy_doc,
        ])
        .await
        .expect_err("put-user-policy on a nonexistent user should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-user-policy",
            "--account-id",
            "555566667777",
            "--user-name",
            "bad name!",
            "--policy-name",
            "AnyName",
            "--policy-document",
            policy_doc,
        ])
        .await
        .expect_err("put-user-policy with an invalid user name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // -- delete-user-policy ---------------------------------------------------
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-user-policy",
            "--account-id",
            "555566667777",
            "--user-name",
            "PutPolicyUser",
            "--policy-name",
            "InlineWithMissingPrincipal",
        ])
        .await
        .expect("Failed to delete-user-policy on PutPolicyUser");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-user-policy",
            "--account-id",
            "555566667777",
            "--user-name",
            "PutPolicyUser",
            "--policy-name",
            "NotAttached",
        ])
        .await
        .expect_err("delete-user-policy for a policy that is not attached should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-user-policy",
            "--account-id",
            "555566667777",
            "--user-name",
            "no-such-user",
            "--policy-name",
            "AnyName",
        ])
        .await
        .expect_err("delete-user-policy on a nonexistent user should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-user-policy",
            "--account-id",
            "555566667777",
            "--user-name",
            "bad name!",
            "--policy-name",
            "AnyName",
        ])
        .await
        .expect_err("delete-user-policy with an invalid user name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");
}

async fn test_policies(database: &TempDatabase) {
    let port = database.port_str();

    // Creating a policy with an empty document fails the Smithy shape regex/length constraint,
    // which surfaces as ValidationError. (MalformedPolicyDocument is reserved for documents that
    // pass shape validation but fail Aspen parsing — covered by the database-layer tests.)
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-policy",
            "--account-id",
            "555566667777",
            "--policy-name",
            "empty-doc-policy",
            "--policy-document",
            "",
        ])
        .await
        .expect_err("Creating a policy with an empty document should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError for empty document, got: {err}");

    // -- delete-policy-version -------------------------------------------------
    // Create a policy with two versions: v1 is default, v2 is not.
    let policy_doc_v1 =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
    let policy_doc_v2 =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}"#;
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-policy",
            "--account-id",
            "555566667777",
            "--policy-name",
            "DelVersionPolicy",
            "--policy-document",
            policy_doc_v1,
        ])
        .await
        .expect("Failed to create DelVersionPolicy");
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
            "--policy-document",
            policy_doc_v2,
        ])
        .await
        .expect("Failed to create v2 of DelVersionPolicy");

    // Deleting the default version (v1) must fail with DeleteConflict.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
            "--version-id",
            "v1",
        ])
        .await
        .expect_err("Deleting the default version should fail");
    assert_eq!(err.code(), Some("DeleteConflict"), "Expected DeleteConflict, got: {err}");

    // Deleting a non-default version (v2) must succeed.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
            "--version-id",
            "v2",
        ])
        .await
        .expect("Failed to delete v2 of DelVersionPolicy");

    // Re-deleting v2 must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
            "--version-id",
            "v2",
        ])
        .await
        .expect_err("Re-deleting v2 should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Deleting a version on a non-existent policy must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/NoSuchDelPolicy",
            "--version-id",
            "v1",
        ])
        .await
        .expect_err("Deleting from a non-existent policy should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Wrong path on the ARN should also fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/wrong/DelVersionPolicy",
            "--version-id",
            "v1",
        ])
        .await
        .expect_err("Deleting via wrong path should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // AWS-owned policy: addressing via "aws" in the ARN must map to account 000000000000.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-policy",
            "--account-id",
            "000000000000",
            "--policy-name",
            "AwsDelVersionPolicy",
            "--policy-document",
            policy_doc_v1,
        ])
        .await
        .expect("Failed to create AwsDelVersionPolicy");
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::000000000000:policy/AwsDelVersionPolicy",
            "--policy-document",
            policy_doc_v2,
        ])
        .await
        .expect("Failed to create v2 of AwsDelVersionPolicy");

    // Delete v2 using "aws" in the ARN.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::aws:policy/AwsDelVersionPolicy",
            "--version-id",
            "v2",
        ])
        .await
        .expect("Failed to delete v2 of AwsDelVersionPolicy via 'aws' account");

    // Re-deleting v2 via "aws" must fail with NoSuchEntity, confirming it was actually removed
    // from the 000000000000 account row.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::aws:policy/AwsDelVersionPolicy",
            "--version-id",
            "v2",
        ])
        .await
        .expect_err("Re-deleting v2 via aws should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // -- get-policy ----------------------------------------------------------
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-policy",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
        ])
        .await
        .expect("Failed to get DelVersionPolicy");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse get-policy output as JSON");
    let policy = json.get("Policy").expect("Policy should be present");
    assert_eq!(policy.get("PolicyName").unwrap().as_str(), Some("DelVersionPolicy"));
    assert_eq!(policy.get("Path").unwrap().as_str(), Some("/"));
    assert_eq!(policy.get("DefaultVersionId").unwrap().as_str(), Some("v1"));
    let arn = policy.get("Arn").unwrap().as_str().unwrap();
    assert_eq!(arn, "arn:test-partition:iam::555566667777:policy/DelVersionPolicy");

    // get-policy via the 'aws' account in the ARN should map to 000000000000.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-policy",
            "--policy-arn",
            "arn:test-partition:iam::aws:policy/AwsDelVersionPolicy",
        ])
        .await
        .expect("Failed to get AwsDelVersionPolicy via 'aws' account");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse get-policy output as JSON");
    let policy = json.get("Policy").expect("Policy should be present");
    assert_eq!(policy.get("PolicyName").unwrap().as_str(), Some("AwsDelVersionPolicy"));

    // get-policy with a mismatched path should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-policy",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/wrong/DelVersionPolicy",
        ])
        .await
        .expect_err("Get with mismatched path should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // -- get-policy-version -------------------------------------------------
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
            "--version-id",
            "v1",
        ])
        .await
        .expect("Failed to get v1 of DelVersionPolicy");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse get-policy-version output as JSON");
    let pv = json.get("PolicyVersion").expect("PolicyVersion should be present");
    assert_eq!(pv.get("VersionId").unwrap().as_str(), Some("v1"));
    assert_eq!(pv.get("IsDefaultVersion").unwrap().as_bool(), Some(true));
    assert!(pv.get("Document").is_some(), "Document should be present");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
            "--version-id",
            "v99",
        ])
        .await
        .expect_err("Get nonexistent version should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // -- list-policies ------------------------------------------------------
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-policies",
            "--account-id",
            "555566667777",
            "--scope",
            "Local",
            "--max-items",
            "1000",
        ])
        .await
        .expect("Failed to list local policies for 555566667777");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-policies output as JSON");
    let policies = json.get("Policies").expect("Policies should be present").as_array().expect("Policies as array");
    let names: Vec<&str> = policies.iter().map(|p| p.get("PolicyName").unwrap().as_str().unwrap()).collect();
    assert!(names.contains(&"DelVersionPolicy"), "Expected DelVersionPolicy in local list: {names:?}");
    assert!(!names.contains(&"AwsDelVersionPolicy"), "AwsDelVersionPolicy is not local for 555566667777");

    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-policies",
            "--account-id",
            "555566667777",
            "--scope",
            "AWS",
            "--max-items",
            "1000",
        ])
        .await
        .expect("Failed to list AWS-scope policies for 555566667777");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-policies output as JSON");
    let policies = json.get("Policies").expect("Policies should be present").as_array().expect("Policies as array");
    let names: Vec<&str> = policies.iter().map(|p| p.get("PolicyName").unwrap().as_str().unwrap()).collect();
    assert!(names.contains(&"AwsDelVersionPolicy"), "Expected AwsDelVersionPolicy in AWS-scope list: {names:?}");

    // -- list-policies pagination ------------------------------------------
    // Seed 5 policies under a fresh path so the path-prefix filter gives a deterministic
    // subset, then walk the marker across pages with max-items=2.
    let pagination_doc =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
    for i in 0..5 {
        let name = format!("BsPaginationPolicy{i}");
        database
            .run([
                "ssbs",
                "--port",
                &port,
                "--username",
                "scratchstack",
                "create-policy",
                "--account-id",
                "555566667777",
                "--policy-name",
                &name,
                "--policy-document",
                pagination_doc,
                "--path",
                "/bs-pagination/",
            ])
            .await
            .unwrap_or_else(|e| panic!("Failed to create {name}: {e}"));
    }

    let mut collected: Vec<String> = Vec::new();
    let mut marker: Option<String> = None;
    let mut pages = 0;
    loop {
        pages += 1;
        let mut args: Vec<String> = vec![
            "ssbs".to_string(),
            "--port".to_string(),
            port.clone(),
            "--username".to_string(),
            "scratchstack".to_string(),
            "list-policies".to_string(),
            "--account-id".to_string(),
            "555566667777".to_string(),
            "--scope".to_string(),
            "Local".to_string(),
            "--path-prefix".to_string(),
            "/bs-pagination/".to_string(),
            "--max-items".to_string(),
            "2".to_string(),
        ];
        if let Some(m) = &marker {
            args.push("--marker".to_string());
            args.push(m.clone());
        }
        let result = database.run(args).await.expect("Failed to list paginated policies");
        let json: JsonValue =
            serde_json::from_str(&result).expect("Failed to parse paginated list-policies output as JSON");
        let policies = json.get("Policies").expect("Policies should be present").as_array().expect("Policies as array");
        for p in policies {
            collected.push(p.get("PolicyName").unwrap().as_str().unwrap().to_string());
        }
        match json.get("Marker") {
            Some(m) => marker = Some(m.as_str().expect("Marker is a string").to_string()),
            None => break,
        }
        if pages > 10 {
            panic!("list-policies pagination did not terminate after 10 pages");
        }
    }
    assert_eq!(pages, 3, "Expected 3 pages (2+2+1) for 5 policies with max-items=2; got {pages}");
    assert_eq!(collected.len(), 5, "Expected 5 total policies across pages: {collected:?}");
    let unique: HashSet<&String> = collected.iter().collect();
    assert_eq!(unique.len(), 5, "Pages must not contain duplicates: {collected:?}");
    collected.sort();
    let expected: Vec<String> = (0..5).map(|i| format!("BsPaginationPolicy{i}")).collect();
    assert_eq!(collected, expected, "Union of paginated pages should cover all 5 policies");

    // -- list-policy-versions -----------------------------------------------
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-policy-versions",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
        ])
        .await
        .expect("Failed to list versions of DelVersionPolicy");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-policy-versions output as JSON");
    let versions = json.get("Versions").expect("Versions should be present").as_array().expect("Versions as array");
    // DelVersionPolicy: v1 default, v2 was deleted. Only v1 remains.
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].get("VersionId").unwrap().as_str(), Some("v1"));

    // -- set-default-policy-version + delete blocked then succeeds ----------
    // Add a new version to DelVersionPolicy. Note that the new version is `v(latest_version + 1)`,
    // which is v3 here — the original v2 was deleted earlier but `latest_version` isn't decremented
    // on delete, so the previous create_policy_version left it at 2.
    let policy_doc_new =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}"#;
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
            "--policy-document",
            policy_doc_new,
        ])
        .await
        .expect("Failed to add a new version to DelVersionPolicy");

    // v1 is still default. Setting default to v3 should succeed.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "set-default-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
            "--version-id",
            "v3",
        ])
        .await
        .expect("Failed to set default to v3");

    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-policy",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
        ])
        .await
        .expect("Failed to get DelVersionPolicy");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse get-policy output as JSON");
    assert_eq!(json.get("Policy").unwrap().get("DefaultVersionId").unwrap().as_str(), Some("v3"));

    // Now v1 is no longer the default — deleting it should succeed.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
            "--version-id",
            "v1",
        ])
        .await
        .expect("Failed to delete v1 after flipping default");

    // Setting default to a nonexistent version should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "set-default-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
            "--version-id",
            "v99",
        ])
        .await
        .expect_err("Set default to nonexistent version should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // -- tag-policy / untag-policy ------------------------------------------
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "tag-policy",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
            "--tags",
            "Key=Env,Value=Prod",
            "Key=Owner,Value=Platform",
        ])
        .await
        .expect("Failed to tag DelVersionPolicy");

    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-policy",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
        ])
        .await
        .expect("Failed to get DelVersionPolicy after tagging");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse get-policy output as JSON");
    let tags =
        json.get("Policy").unwrap().get("Tags").expect("Tags should be present").as_array().expect("Tags as array");
    assert_eq!(tags.len(), 2);
    let tag_pairs: Vec<(&str, &str)> = tags
        .iter()
        .map(|t| (t.get("Key").unwrap().as_str().unwrap(), t.get("Value").unwrap().as_str().unwrap()))
        .collect();
    assert!(tag_pairs.contains(&("Env", "Prod")));
    assert!(tag_pairs.contains(&("Owner", "Platform")));

    // untag one of them.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "untag-policy",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
            "--tag-keys",
            "Owner",
        ])
        .await
        .expect("Failed to untag Owner");

    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-policy",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
        ])
        .await
        .expect("Failed to get DelVersionPolicy after untagging");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse get-policy output as JSON");
    let tags =
        json.get("Policy").unwrap().get("Tags").expect("Tags should be present").as_array().expect("Tags as array");
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0].get("Key").unwrap().as_str(), Some("Env"));

    // tag-policy on missing policy should fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "tag-policy",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/NoSuchTagBootstrap",
            "--tags",
            "Key=A,Value=B",
        ])
        .await
        .expect_err("Tag on missing policy should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // -- list-policy-tags ----------------------------------------------------
    // DelVersionPolicy has one tag (Env=Prod) left after the tag/untag section above.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-policy-tags",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
        ])
        .await
        .expect("Failed to list-policy-tags for DelVersionPolicy");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-policy-tags output");
    let tags = json.get("Tags").and_then(JsonValue::as_array).expect("Tags should be an array");
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0].get("Key").and_then(JsonValue::as_str), Some("Env"));
    assert_eq!(tags[0].get("Value").and_then(JsonValue::as_str), Some("Prod"));

    // Create a policy with multiple tags so we can exercise pagination, then clean it up.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-policy",
            "--account-id",
            "555566667777",
            "--policy-name",
            "ListTagsPaginationPolicy",
            "--policy-document",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#,
            "--tags",
            "Key=Alpha,Value=1",
            "Key=Beta,Value=2",
            "Key=Gamma,Value=3",
        ])
        .await
        .expect("Failed to create ListTagsPaginationPolicy");
    let pagination_arn = "arn:test-partition:iam::555566667777:policy/ListTagsPaginationPolicy";

    // Page 1: max-items=1.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-policy-tags",
            "--policy-arn",
            pagination_arn,
            "--max-items",
            "1",
        ])
        .await
        .expect("Failed to list-policy-tags page 1");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse page 1");
    assert_eq!(json.get("Tags").and_then(JsonValue::as_array).map(Vec::len), Some(1));
    assert_eq!(json.get("IsTruncated").and_then(JsonValue::as_bool), Some(true));
    let marker = json.get("Marker").and_then(JsonValue::as_str).expect("Marker should be present").to_string();
    let page1_key = json
        .get("Tags")
        .and_then(JsonValue::as_array)
        .and_then(|a| a.first())
        .and_then(|t| t.get("Key"))
        .and_then(JsonValue::as_str)
        .unwrap()
        .to_string();

    // Page 2: continue from marker.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-policy-tags",
            "--policy-arn",
            pagination_arn,
            "--max-items",
            "1",
            "--marker",
            &marker,
        ])
        .await
        .expect("Failed to list-policy-tags page 2");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse page 2");
    let tags = json.get("Tags").and_then(JsonValue::as_array).expect("Tags should be present");
    assert_eq!(tags.len(), 1);
    let page2_key = tags[0].get("Key").and_then(JsonValue::as_str).unwrap().to_string();
    assert_ne!(page1_key, page2_key, "Pagination produced duplicate tag keys");

    // Clean up.
    database
        .run(["ssbs", "--port", &port, "--username", "scratchstack", "delete-policy", "--policy-arn", pagination_arn])
        .await
        .expect("Failed to delete ListTagsPaginationPolicy during cleanup");

    // list-policy-tags on a nonexistent policy must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-policy-tags",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/NoSuchListTagsPolicy",
        ])
        .await
        .expect_err("list-policy-tags on a nonexistent policy should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Malformed (but long enough) ARN must surface as ValidationError.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-policy-tags",
            "--policy-arn",
            "not-an-arn-but-long-enough-to-pass",
        ])
        .await
        .expect_err("list-policy-tags with a bad ARN should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // ARN below the 20-character minimum is rejected at the Smithy builder.
    let err = database
        .run(["ssbs", "--port", &port, "--username", "scratchstack", "list-policy-tags", "--policy-arn", "short-arn"])
        .await
        .expect_err("list-policy-tags with a short ARN should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // -- delete-policy -------------------------------------------------------
    // Deleting a nonexistent policy must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/NoSuchDelPolicy",
        ])
        .await
        .expect_err("Deleting a nonexistent policy should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Mismatched path must also fail with NoSuchEntity (DelVersionPolicy lives at /, not at
    // /wrong/).
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/wrong/DelVersionPolicy",
        ])
        .await
        .expect_err("Deleting via wrong path should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Unparseable ARN surfaces as ValidationError.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy",
            "--policy-arn",
            "arn:test-partition:s3:::policy/SomePolicy",
        ])
        .await
        .expect_err("Deleting with a non-iam-service ARN should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // A policy with non-default versions remaining cannot be deleted. Use a fresh policy so we
    // don't tangle with the surrounding tests.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-policy",
            "--account-id",
            "555566667777",
            "--policy-name",
            "DelPolicyMultiVersion",
            "--policy-document",
            policy_doc_v1,
        ])
        .await
        .expect("Failed to create DelPolicyMultiVersion");
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelPolicyMultiVersion",
            "--policy-document",
            policy_doc_v2,
        ])
        .await
        .expect("Failed to create v2 of DelPolicyMultiVersion");
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelPolicyMultiVersion",
        ])
        .await
        .expect_err("Deleting a policy with non-default versions should fail");
    assert_eq!(err.code(), Some("DeleteConflict"), "Expected DeleteConflict, got: {err}");

    // After pruning v2, deleting the policy should succeed and remove the remaining default
    // version via FK cascade.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy-version",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelPolicyMultiVersion",
            "--version-id",
            "v2",
        ])
        .await
        .expect("Failed to delete v2 of DelPolicyMultiVersion");
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelPolicyMultiVersion",
        ])
        .await
        .expect("Failed to delete DelPolicyMultiVersion after pruning v2");

    // Successfully delete DelVersionPolicy. It has only v3 (the default) plus the surviving Env
    // tag from the tag-policy/untag-policy steps; managed_policy_tags cascades on delete.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
        ])
        .await
        .expect("Failed to delete DelVersionPolicy");

    // Re-deleting must report NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
        ])
        .await
        .expect_err("Re-deleting DelVersionPolicy should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // GetPolicy must agree that it's gone.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-policy",
            "--policy-arn",
            "arn:test-partition:iam::555566667777:policy/DelVersionPolicy",
        ])
        .await
        .expect_err("Get-policy on deleted DelVersionPolicy should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // AWS-owned policy: deleting via the "aws" alias must hit the 000000000000 row.
    // AwsDelVersionPolicy has only v1 at this point (v2 was deleted above).
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy",
            "--policy-arn",
            "arn:test-partition:iam::aws:policy/AwsDelVersionPolicy",
        ])
        .await
        .expect("Failed to delete AwsDelVersionPolicy via 'aws' account alias");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-policy",
            "--policy-arn",
            "arn:test-partition:iam::000000000000:policy/AwsDelVersionPolicy",
        ])
        .await
        .expect_err("Re-deleting AwsDelVersionPolicy via numeric account should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");
}

async fn test_groups(database: &TempDatabase) {
    let port = database.port_str();

    // Create a group and verify the output.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "Admins",
        ])
        .await
        .expect("Failed to run create-group for 555566667777/Admins");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse create-group output as JSON");
    let group = json.get("Group").expect("Group should be present");
    let path = group.get("Path").expect("Path should be present").as_str().expect("Path should be a string");
    assert_eq!(path, "/");
    let group_name =
        group.get("GroupName").expect("GroupName should be present").as_str().expect("GroupName should be a string");
    assert_eq!(group_name, "Admins");
    let arn = group.get("Arn").expect("Arn should be present").as_str().expect("Arn should be a string");
    assert_eq!(arn, "arn:test-partition:iam::555566667777:group/Admins");
    let group_id =
        group.get("GroupId").expect("GroupId should be present").as_str().expect("GroupId should be a string");
    assert!(group_id.starts_with("AGPA"), "GroupId should start with AGPA, got {group_id}");

    // Create a group with a custom path.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "Developers",
            "--path",
            "/engineering/",
        ])
        .await
        .expect("Failed to run create-group for 555566667777/Developers");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse create-group output as JSON");
    let group = json.get("Group").expect("Group should be present");
    let path = group.get("Path").expect("Path should be present").as_str().expect("Path should be a string");
    assert_eq!(path, "/engineering/");
    let arn = group.get("Arn").expect("Arn should be present").as_str().expect("Arn should be a string");
    assert_eq!(arn, "arn:test-partition:iam::555566667777:group/engineering/Developers");

    // Creating a duplicate group should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "Admins",
        ])
        .await
        .expect_err("Creating a duplicate group should fail");
    assert!(err.code().is_some(), "Expected an error code, got: {err}");

    // Get the group and verify the output.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "Admins",
        ])
        .await
        .expect("Failed to run get-group for 555566667777/Admins");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse get-group output as JSON");
    let group = json.get("Group").expect("Group should be present");
    let group_name =
        group.get("GroupName").expect("GroupName should be present").as_str().expect("GroupName should be a string");
    assert_eq!(group_name, "Admins");
    let path = group.get("Path").expect("Path should be present").as_str().expect("Path should be a string");
    assert_eq!(path, "/");
    let group_id =
        group.get("GroupId").expect("GroupId should be present").as_str().expect("GroupId should be a string");
    assert!(group_id.starts_with("AGPA"), "GroupId should start with AGPA, got {group_id}");

    // Getting a nonexistent group should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "NoSuchGroup",
        ])
        .await
        .expect_err("Getting a nonexistent group should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity error, got: {err}");

    // List groups and verify both are present.
    let result = database
        .run(["ssbs", "--port", &port, "--username", "scratchstack", "list-groups", "--account-id", "555566667777"])
        .await
        .expect("Failed to run list-groups for 555566667777");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-groups output as JSON");
    let groups = json.get("Groups").expect("Groups should be present").as_array().expect("Groups should be an array");
    assert!(groups.len() >= 2, "Expected at least 2 groups, got {}", groups.len());
    let names: Vec<&str> = groups.iter().map(|g| g.get("GroupName").unwrap().as_str().unwrap()).collect();
    assert!(names.contains(&"Admins"), "Expected Admins in group list");
    assert!(names.contains(&"Developers"), "Expected Developers in group list");

    // List groups with path prefix filter.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-groups",
            "--account-id",
            "555566667777",
            "--path-prefix",
            "/engineering/",
        ])
        .await
        .expect("Failed to run list-groups with path prefix");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-groups output as JSON");
    let groups = json.get("Groups").expect("Groups should be present").as_array().expect("Groups should be an array");
    assert_eq!(groups.len(), 1, "Expected exactly 1 group under /engineering/");
    assert_eq!(groups[0].get("GroupName").unwrap().as_str().unwrap(), "Developers");

    // Update/rename a group.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "update-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "Admins",
            "--new-group-name",
            "Administrators",
        ])
        .await
        .expect("Failed to run update-group to rename Admins to Administrators");

    // Verify the rename took effect.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "Administrators",
        ])
        .await
        .expect("Failed to get renamed group Administrators");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse get-group output as JSON");
    let group = json.get("Group").expect("Group should be present");
    assert_eq!(group.get("GroupName").unwrap().as_str().unwrap(), "Administrators");

    // The old name should no longer exist.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "Admins",
        ])
        .await
        .expect_err("Old group name should no longer exist after rename");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity error, got: {err}");

    // Update a nonexistent group should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "update-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "NoSuchGroup",
            "--new-group-name",
            "Whatever",
        ])
        .await
        .expect_err("Updating a nonexistent group should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity error, got: {err}");

    // Delete a group.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "Developers",
        ])
        .await
        .expect("Failed to run delete-group for 555566667777/Developers");

    // Deleting the same group again should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "Developers",
        ])
        .await
        .expect_err("Deleting a non-existent group should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity error, got: {err}");
    assert!(
        err.message().unwrap_or_default().contains("cannot be found"),
        "Expected 'cannot be found' in error message, got: {err}"
    );

    // -- put-group-policy -----------------------------------------------------
    // Create a fresh group for inline-policy tests. The group can't be deleted while inline
    // policies exist; the delete-group-policy block below removes them at the end.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "PutPolicyGroup",
        ])
        .await
        .expect("Failed to create PutPolicyGroup");

    let policy_doc =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
    let policy_doc_replaced =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}"#;
    let policy_doc_with_external_principal = r#"{
        "Version":"2012-10-17",
        "Statement":[{
            "Effect":"Allow",
            "Principal":{"AWS":"arn:aws:iam::999999999999:user/nonexistent"},
            "Action":"sts:AssumeRole",
            "Resource":"*"
        }]
    }"#;

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-group-policy",
            "--account-id",
            "555566667777",
            "--group-name",
            "PutPolicyGroup",
            "--policy-name",
            "InlineRead",
            "--policy-document",
            policy_doc,
        ])
        .await
        .expect("Failed to put-group-policy on PutPolicyGroup");

    // Re-putting the same policy name with a different document must succeed (replacement).
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-group-policy",
            "--account-id",
            "555566667777",
            "--group-name",
            "PutPolicyGroup",
            "--policy-name",
            "InlineRead",
            "--policy-document",
            policy_doc_replaced,
        ])
        .await
        .expect("Replacing the inline policy on PutPolicyGroup must succeed");

    // A policy with a syntactically valid principal pointing at a non-existent account is OK.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-group-policy",
            "--account-id",
            "555566667777",
            "--group-name",
            "PutPolicyGroup",
            "--policy-name",
            "InlineWithMissingPrincipal",
            "--policy-document",
            policy_doc_with_external_principal,
        ])
        .await
        .expect("Policies referencing non-existent principals must still be accepted");

    // Malformed JSON must surface as MalformedPolicyDocument.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-group-policy",
            "--account-id",
            "555566667777",
            "--group-name",
            "PutPolicyGroup",
            "--policy-name",
            "InlineBroken",
            "--policy-document",
            "{ not valid aspen json }",
        ])
        .await
        .expect_err("put-group-policy with malformed JSON should fail");
    assert_eq!(err.code(), Some("MalformedPolicyDocument"), "Expected MalformedPolicyDocument, got: {err}");

    // put-group-policy on a nonexistent group must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-group-policy",
            "--account-id",
            "555566667777",
            "--group-name",
            "no-such-group",
            "--policy-name",
            "AnyName",
            "--policy-document",
            policy_doc,
        ])
        .await
        .expect_err("put-group-policy on a nonexistent group should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Invalid group name must surface as ValidationError before reaching the database.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-group-policy",
            "--account-id",
            "555566667777",
            "--group-name",
            "bad name!",
            "--policy-name",
            "AnyName",
            "--policy-document",
            policy_doc,
        ])
        .await
        .expect_err("put-group-policy with an invalid group name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // -- delete-group-policy --------------------------------------------------
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-group-policy",
            "--account-id",
            "555566667777",
            "--group-name",
            "PutPolicyGroup",
            "--policy-name",
            "InlineWithMissingPrincipal",
        ])
        .await
        .expect("Failed to delete-group-policy on PutPolicyGroup");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-group-policy",
            "--account-id",
            "555566667777",
            "--group-name",
            "PutPolicyGroup",
            "--policy-name",
            "NotAttached",
        ])
        .await
        .expect_err("delete-group-policy for a policy that is not attached should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-group-policy",
            "--account-id",
            "555566667777",
            "--group-name",
            "no-such-group",
            "--policy-name",
            "AnyName",
        ])
        .await
        .expect_err("delete-group-policy on a nonexistent group should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-group-policy",
            "--account-id",
            "555566667777",
            "--group-name",
            "bad name!",
            "--policy-name",
            "AnyName",
        ])
        .await
        .expect_err("delete-group-policy with an invalid group name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");
}

async fn test_group_membership(database: &TempDatabase) {
    let port = database.port_str();

    // Create a user and a group for membership testing.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "member-user",
        ])
        .await
        .expect("Failed to create member-user");

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "MembershipGroup",
        ])
        .await
        .expect("Failed to create MembershipGroup");

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "SecondGroup",
        ])
        .await
        .expect("Failed to create SecondGroup");

    // Add user to group.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "add-user-to-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "MembershipGroup",
            "--user-name",
            "member-user",
        ])
        .await
        .expect("Failed to add member-user to MembershipGroup");

    // Adding the same user again should succeed (idempotent).
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "add-user-to-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "MembershipGroup",
            "--user-name",
            "member-user",
        ])
        .await
        .expect("Adding user to group again should be idempotent");

    // Add user to a second group.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "add-user-to-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "SecondGroup",
            "--user-name",
            "member-user",
        ])
        .await
        .expect("Failed to add member-user to SecondGroup");

    // Adding user to a nonexistent group should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "add-user-to-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "NoSuchGroup",
            "--user-name",
            "member-user",
        ])
        .await
        .expect_err("Adding user to nonexistent group should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity error, got: {err}");

    // Adding a nonexistent user to a group should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "add-user-to-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "MembershipGroup",
            "--user-name",
            "no-such-user",
        ])
        .await
        .expect_err("Adding nonexistent user to group should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity error, got: {err}");

    // List groups for the user.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-groups-for-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "member-user",
        ])
        .await
        .expect("Failed to list groups for member-user");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-groups-for-user output as JSON");
    let groups = json.get("Groups").expect("Groups should be present").as_array().expect("Groups should be an array");
    assert_eq!(groups.len(), 2, "Expected 2 groups for member-user, got {}", groups.len());
    let names: Vec<&str> = groups.iter().map(|g| g.get("GroupName").unwrap().as_str().unwrap()).collect();
    assert!(names.contains(&"MembershipGroup"), "Expected MembershipGroup in list");
    assert!(names.contains(&"SecondGroup"), "Expected SecondGroup in list");

    // List groups for a nonexistent user should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-groups-for-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "no-such-user",
        ])
        .await
        .expect_err("Listing groups for nonexistent user should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity error, got: {err}");

    // Remove user from a group.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "remove-user-from-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "MembershipGroup",
            "--user-name",
            "member-user",
        ])
        .await
        .expect("Failed to remove member-user from MembershipGroup");

    // Verify user is now in only one group.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-groups-for-user",
            "--account-id",
            "555566667777",
            "--user-name",
            "member-user",
        ])
        .await
        .expect("Failed to list groups for member-user after removal");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-groups-for-user output as JSON");
    let groups = json.get("Groups").expect("Groups should be present").as_array().expect("Groups should be an array");
    assert_eq!(groups.len(), 1, "Expected 1 group after removal");
    assert_eq!(groups[0].get("GroupName").unwrap().as_str().unwrap(), "SecondGroup");

    // Removing user who is not a member should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "remove-user-from-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "MembershipGroup",
            "--user-name",
            "member-user",
        ])
        .await
        .expect_err("Removing non-member from group should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity error, got: {err}");

    // Removing user from nonexistent group should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "remove-user-from-group",
            "--account-id",
            "555566667777",
            "--group-name",
            "NoSuchGroup",
            "--user-name",
            "member-user",
        ])
        .await
        .expect_err("Removing user from nonexistent group should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity error, got: {err}");
}

async fn test_roles(database: &TempDatabase) {
    let port = database.port_str();
    let trust_policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

    // Create a role with the minimum set of arguments.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
            "--assume-role-policy-document",
            trust_policy,
        ])
        .await
        .expect("Failed to run create-role for 555566667777/LambdaExecutor");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse create-role output as JSON");
    let role = json.get("Role").expect("Role should be present");
    let path = role.get("Path").expect("Path should be present").as_str().expect("Path should be a string");
    assert_eq!(path, "/");
    let role_name =
        role.get("RoleName").expect("RoleName should be present").as_str().expect("RoleName should be a string");
    assert_eq!(role_name, "LambdaExecutor");
    let arn = role.get("Arn").expect("Arn should be present").as_str().expect("Arn should be a string");
    assert_eq!(arn, "arn:test-partition:iam::555566667777:role/LambdaExecutor");
    let role_id = role.get("RoleId").expect("RoleId should be present").as_str().expect("RoleId should be a string");
    assert!(role_id.starts_with("AROA"), "RoleId should start with AROA, got {role_id}");
    let assume_role_policy_document = role
        .get("AssumeRolePolicyDocument")
        .expect("AssumeRolePolicyDocument should be present")
        .as_str()
        .expect("AssumeRolePolicyDocument should be a string");
    assert_eq!(assume_role_policy_document, trust_policy);

    // Create a role with description, max-session-duration, path, and tags.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "DeployRole",
            "--assume-role-policy-document",
            trust_policy,
            "--description",
            "Deployment automation role.",
            "--max-session-duration",
            "14400",
            "--path",
            "/service-roles/",
            "--tags",
            "Key=Environment,Value=Production",
            "Key=Team,Value=Platform",
        ])
        .await
        .expect("Failed to run create-role for 555566667777/DeployRole");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse create-role output as JSON");
    let role = json.get("Role").expect("Role should be present");
    let path = role.get("Path").expect("Path should be present").as_str().expect("Path should be a string");
    assert_eq!(path, "/service-roles/");
    let arn = role.get("Arn").expect("Arn should be present").as_str().expect("Arn should be a string");
    assert_eq!(arn, "arn:test-partition:iam::555566667777:role/service-roles/DeployRole");
    let description = role
        .get("Description")
        .expect("Description should be present")
        .as_str()
        .expect("Description should be a string");
    assert_eq!(description, "Deployment automation role.");
    let max_session_duration = role
        .get("MaxSessionDuration")
        .expect("MaxSessionDuration should be present")
        .as_i64()
        .expect("MaxSessionDuration should be an integer");
    assert_eq!(max_session_duration, 14400);
    let tags = role.get("Tags").expect("Tags should be present").as_array().expect("Tags should be an array");
    assert_eq!(tags.len(), 2);
    assert_eq!(tags[0].get("Key").unwrap().as_str().unwrap(), "Environment");
    assert_eq!(tags[0].get("Value").unwrap().as_str().unwrap(), "Production");
    assert_eq!(tags[1].get("Key").unwrap().as_str().unwrap(), "Team");
    assert_eq!(tags[1].get("Value").unwrap().as_str().unwrap(), "Platform");

    // Creating a duplicate role should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
            "--assume-role-policy-document",
            trust_policy,
        ])
        .await
        .expect_err("Creating a duplicate role should fail");
    assert!(err.code().is_some(), "Expected an error code, got: {err}");

    // max-session-duration below the AWS minimum should fail validation.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "TooShortRole",
            "--assume-role-policy-document",
            trust_policy,
            "--max-session-duration",
            "60",
        ])
        .await
        .expect_err("max-session-duration below 3600 should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // -- get-role --------------------------------------------------------------
    // Round-trip LambdaExecutor (created above with no PB, no tags).
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
        ])
        .await
        .expect("Failed to get-role LambdaExecutor");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse get-role output");
    let role = json.get("Role").expect("Role should be present");
    assert_eq!(role.get("RoleName").and_then(JsonValue::as_str), Some("LambdaExecutor"));
    assert_eq!(role.get("Path").and_then(JsonValue::as_str), Some("/"));
    assert_eq!(
        role.get("Arn").and_then(JsonValue::as_str),
        Some("arn:test-partition:iam::555566667777:role/LambdaExecutor")
    );
    let role_id = role.get("RoleId").and_then(JsonValue::as_str).expect("RoleId should be a string");
    assert!(role_id.starts_with("AROA"), "RoleId should start with AROA, got {role_id}");
    let trust = role
        .get("AssumeRolePolicyDocument")
        .and_then(JsonValue::as_str)
        .expect("AssumeRolePolicyDocument should be a string");
    assert_eq!(trust, trust_policy);
    assert!(role.get("PermissionsBoundary").is_none(), "Expected no PermissionsBoundary, got {role}");

    // Round-trip DeployRole (created above with description, max-session-duration, path, tags).
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "DeployRole",
        ])
        .await
        .expect("Failed to get-role DeployRole");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse get-role output");
    let role = json.get("Role").expect("Role should be present");
    assert_eq!(role.get("Path").and_then(JsonValue::as_str), Some("/service-roles/"));
    assert_eq!(
        role.get("Arn").and_then(JsonValue::as_str),
        Some("arn:test-partition:iam::555566667777:role/service-roles/DeployRole")
    );
    assert_eq!(role.get("Description").and_then(JsonValue::as_str), Some("Deployment automation role."));
    assert_eq!(role.get("MaxSessionDuration").and_then(JsonValue::as_i64), Some(14400));
    let tags = role.get("Tags").and_then(JsonValue::as_array).expect("Tags should be an array");
    assert_eq!(tags.len(), 2);
    assert_eq!(tags[0].get("Key").and_then(JsonValue::as_str), Some("Environment"));
    assert_eq!(tags[0].get("Value").and_then(JsonValue::as_str), Some("Production"));
    assert_eq!(tags[1].get("Key").and_then(JsonValue::as_str), Some("Team"));
    assert_eq!(tags[1].get("Value").and_then(JsonValue::as_str), Some("Platform"));

    // get-role on a nonexistent role must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "no-such-role",
        ])
        .await
        .expect_err("get-role on a nonexistent role should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // get-role with an invalid role name must surface as ValidationError.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "bad role!",
        ])
        .await
        .expect_err("get-role with an invalid role name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // -- list-roles ------------------------------------------------------------
    // 555566667777 currently has LambdaExecutor (path /) and DeployRole (path /service-roles/).
    let result = database
        .run(["ssbs", "--port", &port, "--username", "scratchstack", "list-roles", "--account-id", "555566667777"])
        .await
        .expect("Failed to list-roles in 555566667777");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-roles output");
    let roles = json.get("Roles").and_then(JsonValue::as_array).expect("Roles should be an array");
    let names: Vec<&str> = roles.iter().filter_map(|r| r.get("RoleName").and_then(JsonValue::as_str)).collect();
    assert!(names.contains(&"LambdaExecutor"), "Expected LambdaExecutor in list-roles, got {names:?}");
    assert!(names.contains(&"DeployRole"), "Expected DeployRole in list-roles, got {names:?}");

    // Filter to /service-roles/ — should return only DeployRole.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-roles",
            "--account-id",
            "555566667777",
            "--path-prefix",
            "/service-roles/",
        ])
        .await
        .expect("Failed to list-roles with /service-roles/ prefix");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-roles output");
    let roles = json.get("Roles").and_then(JsonValue::as_array).expect("Roles should be an array");
    assert_eq!(roles.len(), 1, "Expected exactly 1 role under /service-roles/, got {result}");
    assert_eq!(roles[0].get("RoleName").and_then(JsonValue::as_str), Some("DeployRole"));

    // max-items=1 must produce one page with IsTruncated=true and a Marker. The next page picks
    // up the second role.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-roles",
            "--account-id",
            "555566667777",
            "--max-items",
            "1",
        ])
        .await
        .expect("Failed to list-roles with max-items=1");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-roles output");
    assert_eq!(json.get("Roles").and_then(JsonValue::as_array).map(Vec::len), Some(1));
    assert_eq!(json.get("IsTruncated").and_then(JsonValue::as_bool), Some(true));
    let marker = json.get("Marker").and_then(JsonValue::as_str).expect("Marker should be a string");

    let page2 = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-roles",
            "--account-id",
            "555566667777",
            "--max-items",
            "1",
            "--marker",
            marker,
        ])
        .await
        .expect("Failed to list-roles second page");
    let json: JsonValue = serde_json::from_str(&page2).expect("Failed to parse list-roles page 2");
    let roles = json.get("Roles").and_then(JsonValue::as_array).expect("Roles should be an array");
    assert_eq!(roles.len(), 1, "Expected exactly 1 role on page 2, got {page2}");
    // The two pages together must cover both roles without duplicates.
    let page1_name = serde_json::from_str::<JsonValue>(&result)
        .unwrap()
        .get("Roles")
        .and_then(JsonValue::as_array)
        .and_then(|a| a.first())
        .and_then(|r| r.get("RoleName"))
        .and_then(JsonValue::as_str)
        .unwrap()
        .to_string();
    let page2_name = roles[0].get("RoleName").and_then(JsonValue::as_str).unwrap().to_string();
    assert_ne!(page1_name, page2_name, "Pagination produced duplicate roles");

    // list-roles on an invalid path prefix must surface ValidationError.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-roles",
            "--account-id",
            "555566667777",
            "--path-prefix",
            "no-leading-slash/",
        ])
        .await
        .expect_err("list-roles with an invalid path prefix should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // -- list-role-tags --------------------------------------------------------
    // DeployRole in 555566667777 was created above with two tags (Environment/Team).
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-role-tags",
            "--account-id",
            "555566667777",
            "--role-name",
            "DeployRole",
        ])
        .await
        .expect("Failed to list-role-tags for DeployRole");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-role-tags output");
    let tags = json.get("Tags").and_then(JsonValue::as_array).expect("Tags should be an array");
    assert_eq!(tags.len(), 2);
    assert_eq!(tags[0].get("Key").and_then(JsonValue::as_str), Some("Environment"));
    assert_eq!(tags[0].get("Value").and_then(JsonValue::as_str), Some("Production"));
    assert_eq!(tags[1].get("Key").and_then(JsonValue::as_str), Some("Team"));
    assert_eq!(tags[1].get("Value").and_then(JsonValue::as_str), Some("Platform"));

    // LambdaExecutor has no tags.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-role-tags",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
        ])
        .await
        .expect("Failed to list-role-tags for LambdaExecutor");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-role-tags output");
    let tags = json.get("Tags").and_then(JsonValue::as_array).expect("Tags should be an array");
    assert!(tags.is_empty(), "Expected no tags on LambdaExecutor, got {result}");

    // max-items=1 + marker pagination across DeployRole's two tags.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-role-tags",
            "--account-id",
            "555566667777",
            "--role-name",
            "DeployRole",
            "--max-items",
            "1",
        ])
        .await
        .expect("Failed to list-role-tags page 1");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse page 1");
    assert_eq!(json.get("Tags").and_then(JsonValue::as_array).map(Vec::len), Some(1));
    assert_eq!(json.get("IsTruncated").and_then(JsonValue::as_bool), Some(true));
    let marker = json.get("Marker").and_then(JsonValue::as_str).expect("Marker should be a string").to_string();
    let page1_key = json
        .get("Tags")
        .and_then(JsonValue::as_array)
        .and_then(|a| a.first())
        .and_then(|t| t.get("Key"))
        .and_then(JsonValue::as_str)
        .unwrap()
        .to_string();

    let page2 = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-role-tags",
            "--account-id",
            "555566667777",
            "--role-name",
            "DeployRole",
            "--max-items",
            "1",
            "--marker",
            &marker,
        ])
        .await
        .expect("Failed to list-role-tags page 2");
    let json: JsonValue = serde_json::from_str(&page2).expect("Failed to parse page 2");
    let tags = json.get("Tags").and_then(JsonValue::as_array).expect("Tags should be an array");
    assert_eq!(tags.len(), 1);
    let page2_key = tags[0].get("Key").and_then(JsonValue::as_str).unwrap().to_string();
    assert_ne!(page1_key, page2_key, "Pagination produced duplicate tag keys");

    // list-role-tags on a nonexistent role must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-role-tags",
            "--account-id",
            "555566667777",
            "--role-name",
            "no-such-role",
        ])
        .await
        .expect_err("list-role-tags on a nonexistent role should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Invalid role name must surface ValidationError before reaching the database.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-role-tags",
            "--account-id",
            "555566667777",
            "--role-name",
            "bad role!",
        ])
        .await
        .expect_err("list-role-tags with an invalid role name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // -- tag-role / untag-role -------------------------------------------------
    // LambdaExecutor in 555566667777 has no tags. Tag it with two tags.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "tag-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
            "--tags",
            "Key=Environment,Value=Production",
            "Key=Team,Value=Platform",
        ])
        .await
        .expect("Failed to run tag-role for 555566667777/LambdaExecutor");

    // Verify the tags via list-role-tags.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-role-tags",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
        ])
        .await
        .expect("Failed to run list-role-tags after tag-role");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-role-tags after tag-role");
    let tags = json.get("Tags").and_then(JsonValue::as_array).expect("Tags should be an array");
    assert_eq!(tags.len(), 2);
    // Tags come back ordered by lowercased key.
    assert_eq!(tags[0].get("Key").and_then(JsonValue::as_str), Some("Environment"));
    assert_eq!(tags[0].get("Value").and_then(JsonValue::as_str), Some("Production"));
    assert_eq!(tags[1].get("Key").and_then(JsonValue::as_str), Some("Team"));
    assert_eq!(tags[1].get("Value").and_then(JsonValue::as_str), Some("Platform"));

    // Re-tagging an existing key must update the value (upsert) and a new key adds a tag.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "tag-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
            "--tags",
            "Key=Environment,Value=Staging",
            "Key=Project,Value=Apollo",
        ])
        .await
        .expect("Failed to run tag-role upsert for 555566667777/LambdaExecutor");

    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-role-tags",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
        ])
        .await
        .expect("Failed to run list-role-tags after tag-role upsert");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-role-tags after upsert");
    let tags = json.get("Tags").and_then(JsonValue::as_array).expect("Tags should be an array");
    assert_eq!(tags.len(), 3, "Expected 3 tags after upsert (Environment updated, Project added, Team unchanged)");
    assert_eq!(tags[0].get("Key").and_then(JsonValue::as_str), Some("Environment"));
    assert_eq!(tags[0].get("Value").and_then(JsonValue::as_str), Some("Staging"));
    assert_eq!(tags[1].get("Key").and_then(JsonValue::as_str), Some("Project"));
    assert_eq!(tags[1].get("Value").and_then(JsonValue::as_str), Some("Apollo"));
    assert_eq!(tags[2].get("Key").and_then(JsonValue::as_str), Some("Team"));
    assert_eq!(tags[2].get("Value").and_then(JsonValue::as_str), Some("Platform"));

    // Untag the role — remove Environment and Project.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "untag-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
            "--tag-keys",
            "Environment",
            "Project",
        ])
        .await
        .expect("Failed to run untag-role for 555566667777/LambdaExecutor");

    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-role-tags",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
        ])
        .await
        .expect("Failed to run list-role-tags after untag-role");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse list-role-tags after untag-role");
    let tags = json.get("Tags").and_then(JsonValue::as_array).expect("Tags should be an array");
    assert_eq!(tags.len(), 1, "Expected 1 tag after untag-role");
    assert_eq!(tags[0].get("Key").and_then(JsonValue::as_str), Some("Team"));
    assert_eq!(tags[0].get("Value").and_then(JsonValue::as_str), Some("Platform"));

    // Untagging a key that does not exist must succeed silently.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "untag-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
            "--tag-keys",
            "NoSuchKey",
        ])
        .await
        .expect("Untagging a nonexistent key should succeed silently");

    // Tagging a nonexistent role must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "tag-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "no-such-role",
            "--tags",
            "Key=Foo,Value=Bar",
        ])
        .await
        .expect_err("tag-role on a nonexistent role should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Untagging a nonexistent role must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "untag-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "no-such-role",
            "--tag-keys",
            "Foo",
        ])
        .await
        .expect_err("untag-role on a nonexistent role should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Invalid role name must surface ValidationError before reaching the database.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "tag-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "bad role!",
            "--tags",
            "Key=Foo,Value=Bar",
        ])
        .await
        .expect_err("tag-role with an invalid role name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "untag-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "bad role!",
            "--tag-keys",
            "Foo",
        ])
        .await
        .expect_err("untag-role with an invalid role name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // -- delete-role -----------------------------------------------------------
    // Create a fresh role and delete it. This leaves test_policy_attachments' role landscape
    // untouched.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "DeleteMeCliRole",
            "--assume-role-policy-document",
            trust_policy,
        ])
        .await
        .expect("Failed to create DeleteMeCliRole");

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "DeleteMeCliRole",
        ])
        .await
        .expect("Failed to delete DeleteMeCliRole");

    // Deleting the same role again must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "DeleteMeCliRole",
        ])
        .await
        .expect_err("Re-deleting DeleteMeCliRole should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Deleting a role that never existed must also fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "no-such-role",
        ])
        .await
        .expect_err("Deleting a role that never existed should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Delete a role that has an attached managed policy: must fail with DeleteConflict and the
    // role must still exist afterwards. Use DeployRole (created above) and a managed policy
    // created and attached just for this case.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-policy",
            "--account-id",
            "555566667777",
            "--policy-name",
            "DeleteRoleBlockerPolicy",
            "--policy-document",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#,
        ])
        .await
        .expect("Failed to create DeleteRoleBlockerPolicy");
    let blocker_arn = "arn:test-partition:iam::555566667777:policy/DeleteRoleBlockerPolicy";

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "attach-role-policy",
            "--account-id",
            "555566667777",
            "--role-name",
            "DeployRole",
            "--policy-arn",
            blocker_arn,
        ])
        .await
        .expect("Failed to attach DeleteRoleBlockerPolicy to DeployRole");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "DeployRole",
        ])
        .await
        .expect_err("Deleting a role with an attached managed policy should fail");
    assert_eq!(err.code(), Some("DeleteConflict"), "Expected DeleteConflict, got: {err}");

    // Detach and then delete to leave the test database tidy.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "detach-role-policy",
            "--account-id",
            "555566667777",
            "--role-name",
            "DeployRole",
            "--policy-arn",
            blocker_arn,
        ])
        .await
        .expect("Failed to detach DeleteRoleBlockerPolicy from DeployRole");

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "DeployRole",
        ])
        .await
        .expect("Failed to delete DeployRole after detaching blocker");

    database
        .run(["ssbs", "--port", &port, "--username", "scratchstack", "delete-policy", "--policy-arn", blocker_arn])
        .await
        .expect("Failed to delete DeleteRoleBlockerPolicy");

    // delete-role on an invalid role name must produce a ValidationError before reaching the
    // database.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "bad role!",
        ])
        .await
        .expect_err("delete-role with an invalid role name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // -- delete-role-permissions-boundary --------------------------------------
    // Create a managed policy and a role that uses it as its permissions boundary.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-policy",
            "--account-id",
            "555566667777",
            "--policy-name",
            "RolePbPolicy",
            "--policy-document",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#,
        ])
        .await
        .expect("Failed to create RolePbPolicy");
    let pb_arn = "arn:test-partition:iam::555566667777:policy/RolePbPolicy";

    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "PbRole",
            "--assume-role-policy-document",
            trust_policy,
            "--permissions-boundary",
            pb_arn,
        ])
        .await
        .expect("Failed to create PbRole with permissions boundary");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse create-role output");
    let pb_arn_out = json
        .get("Role")
        .and_then(|r| r.get("PermissionsBoundary"))
        .and_then(|p| p.get("PermissionsBoundaryArn"))
        .and_then(JsonValue::as_str)
        .expect("PermissionsBoundary.PermissionsBoundaryArn should be present");
    assert_eq!(pb_arn_out, pb_arn);

    // Clear the boundary.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role-permissions-boundary",
            "--account-id",
            "555566667777",
            "--role-name",
            "PbRole",
        ])
        .await
        .expect("Failed to delete-role-permissions-boundary on PbRole");

    // Re-running on a role with no PB must still succeed (idempotent).
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role-permissions-boundary",
            "--account-id",
            "555566667777",
            "--role-name",
            "PbRole",
        ])
        .await
        .expect("delete-role-permissions-boundary must be idempotent");

    // Now we should be able to delete the role and then the (no-longer-PB) policy.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "PbRole",
        ])
        .await
        .expect("Failed to delete PbRole");
    database
        .run(["ssbs", "--port", &port, "--username", "scratchstack", "delete-policy", "--policy-arn", pb_arn])
        .await
        .expect("Failed to delete RolePbPolicy");

    // delete-role-permissions-boundary on a nonexistent role must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role-permissions-boundary",
            "--account-id",
            "555566667777",
            "--role-name",
            "no-such-role",
        ])
        .await
        .expect_err("delete-role-permissions-boundary on a nonexistent role should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Invalid role name must surface as ValidationError before reaching the database.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role-permissions-boundary",
            "--account-id",
            "555566667777",
            "--role-name",
            "bad role!",
        ])
        .await
        .expect_err("delete-role-permissions-boundary with an invalid role name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // -- update-role / update-role-description ---------------------------------
    // LambdaExecutor in 555566667777 currently has the "Team=Platform" tag (from tag-role tests)
    // and no description or max_session_duration set.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "update-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
            "--description",
            "Set via update-role.",
            "--max-session-duration",
            "7200",
        ])
        .await
        .expect("Failed to run update-role for LambdaExecutor");

    // Verify both fields were applied via get-role.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
        ])
        .await
        .expect("Failed to get-role for LambdaExecutor after update-role");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse get-role output");
    let role = json.get("Role").expect("Role should be present");
    assert_eq!(role.get("Description").and_then(JsonValue::as_str), Some("Set via update-role."));
    assert_eq!(role.get("MaxSessionDuration").and_then(JsonValue::as_i64), Some(7200));

    // update-role with only --description leaves max_session_duration unchanged.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "update-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
            "--description",
            "Updated description only.",
        ])
        .await
        .expect("Failed to run update-role description only");
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
        ])
        .await
        .expect("Failed to get-role after description-only update");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse get-role output");
    let role = json.get("Role").expect("Role should be present");
    assert_eq!(role.get("Description").and_then(JsonValue::as_str), Some("Updated description only."));
    assert_eq!(role.get("MaxSessionDuration").and_then(JsonValue::as_i64), Some(7200));

    // update-role with neither field must still succeed (no-op) so long as the role exists.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "update-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
        ])
        .await
        .expect("update-role with no field flags must succeed on an existing role");

    // update-role on a nonexistent role must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "update-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "no-such-role",
            "--description",
            "ignored",
        ])
        .await
        .expect_err("update-role on a nonexistent role should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Out-of-range max_session_duration must surface as ValidationError before reaching the
    // database (the Smithy builder rejects the value).
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "update-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
            "--max-session-duration",
            "60",
        ])
        .await
        .expect_err("update-role with max_session_duration below 3600 should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // Invalid role name must surface as ValidationError before reaching the database.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "update-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "bad role!",
            "--description",
            "ignored",
        ])
        .await
        .expect_err("update-role with an invalid role name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // update-role-description replaces the description and prints the updated role.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "update-role-description",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
            "--description",
            "Replaced via update-role-description.",
        ])
        .await
        .expect("Failed to run update-role-description");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse update-role-description output");
    let role = json.get("Role").expect("Role should be present");
    assert_eq!(role.get("RoleName").and_then(JsonValue::as_str), Some("LambdaExecutor"));
    assert_eq!(role.get("Description").and_then(JsonValue::as_str), Some("Replaced via update-role-description."));
    // The max_session_duration set via update-role above must be preserved.
    assert_eq!(role.get("MaxSessionDuration").and_then(JsonValue::as_i64), Some(7200));

    // An empty description string is allowed.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "update-role-description",
            "--account-id",
            "555566667777",
            "--role-name",
            "LambdaExecutor",
            "--description",
            "",
        ])
        .await
        .expect("Failed to run update-role-description with an empty description");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse output");
    let role = json.get("Role").expect("Role should be present");
    assert_eq!(role.get("Description").and_then(JsonValue::as_str), Some(""));

    // update-role-description on a nonexistent role must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "update-role-description",
            "--account-id",
            "555566667777",
            "--role-name",
            "no-such-role",
            "--description",
            "ignored",
        ])
        .await
        .expect_err("update-role-description on a nonexistent role should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Invalid role name must surface as ValidationError before reaching the database.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "update-role-description",
            "--account-id",
            "555566667777",
            "--role-name",
            "bad role!",
            "--description",
            "ignored",
        ])
        .await
        .expect_err("update-role-description with an invalid role name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // -- put-role-permissions-boundary -----------------------------------------
    // Create a managed policy and a fresh role with no boundary, then set the boundary.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-policy",
            "--account-id",
            "555566667777",
            "--policy-name",
            "PutRolePbPolicy",
            "--policy-document",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#,
        ])
        .await
        .expect("Failed to create PutRolePbPolicy");
    let pb_arn = "arn:test-partition:iam::555566667777:policy/PutRolePbPolicy";

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "PutPbRole",
            "--assume-role-policy-document",
            trust_policy,
        ])
        .await
        .expect("Failed to create PutPbRole");

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-role-permissions-boundary",
            "--account-id",
            "555566667777",
            "--role-name",
            "PutPbRole",
            "--permissions-boundary",
            pb_arn,
        ])
        .await
        .expect("Failed to put-role-permissions-boundary on PutPbRole");

    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "get-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "PutPbRole",
        ])
        .await
        .expect("Failed to get-role for PutPbRole after put-role-permissions-boundary");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse get-role output");
    let pb_arn_out = json
        .get("Role")
        .and_then(|r| r.get("PermissionsBoundary"))
        .and_then(|p| p.get("PermissionsBoundaryArn"))
        .and_then(JsonValue::as_str)
        .expect("PermissionsBoundary.PermissionsBoundaryArn should be present");
    assert_eq!(pb_arn_out, pb_arn);

    // Re-putting the same boundary must succeed.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-role-permissions-boundary",
            "--account-id",
            "555566667777",
            "--role-name",
            "PutPbRole",
            "--permissions-boundary",
            pb_arn,
        ])
        .await
        .expect("Re-running put-role-permissions-boundary on PutPbRole should succeed");

    // put-role-permissions-boundary on a nonexistent role must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-role-permissions-boundary",
            "--account-id",
            "555566667777",
            "--role-name",
            "no-such-role",
            "--permissions-boundary",
            pb_arn,
        ])
        .await
        .expect_err("put-role-permissions-boundary on a nonexistent role should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // PB ARN pointing to a nonexistent policy must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-role-permissions-boundary",
            "--account-id",
            "555566667777",
            "--role-name",
            "PutPbRole",
            "--permissions-boundary",
            "arn:test-partition:iam::555566667777:policy/NoSuchPolicy",
        ])
        .await
        .expect_err("put-role-permissions-boundary with a nonexistent PB policy should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Malformed PB ARN must surface ValidationError.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-role-permissions-boundary",
            "--account-id",
            "555566667777",
            "--role-name",
            "PutPbRole",
            "--permissions-boundary",
            "not-an-arn-but-long-enough-to-pass",
        ])
        .await
        .expect_err("put-role-permissions-boundary with an invalid PB ARN should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // Invalid role name must surface as ValidationError before reaching the database.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-role-permissions-boundary",
            "--account-id",
            "555566667777",
            "--role-name",
            "bad role!",
            "--permissions-boundary",
            pb_arn,
        ])
        .await
        .expect_err("put-role-permissions-boundary with an invalid role name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // Clean up: clear PB, delete the role and policy.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role-permissions-boundary",
            "--account-id",
            "555566667777",
            "--role-name",
            "PutPbRole",
        ])
        .await
        .expect("Failed to clear PutPbRole PB during cleanup");
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "PutPbRole",
        ])
        .await
        .expect("Failed to delete PutPbRole during cleanup");
    database
        .run(["ssbs", "--port", &port, "--username", "scratchstack", "delete-policy", "--policy-arn", pb_arn])
        .await
        .expect("Failed to delete PutRolePbPolicy during cleanup");

    // -- put-role-policy ------------------------------------------------------
    // Create a fresh role for inline-policy tests. The role can't be deleted while inline
    // policies exist; the delete-role-policy block below removes them at the end.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-role",
            "--account-id",
            "555566667777",
            "--role-name",
            "PutPolicyRole",
            "--assume-role-policy-document",
            trust_policy,
        ])
        .await
        .expect("Failed to create PutPolicyRole");

    let policy_doc =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
    let policy_doc_replaced =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}"#;
    let policy_doc_with_external_principal = r#"{
        "Version":"2012-10-17",
        "Statement":[{
            "Effect":"Allow",
            "Principal":{"AWS":"arn:aws:iam::999999999999:user/nonexistent"},
            "Action":"sts:AssumeRole",
            "Resource":"*"
        }]
    }"#;

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-role-policy",
            "--account-id",
            "555566667777",
            "--role-name",
            "PutPolicyRole",
            "--policy-name",
            "InlineRead",
            "--policy-document",
            policy_doc,
        ])
        .await
        .expect("Failed to put-role-policy on PutPolicyRole");

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-role-policy",
            "--account-id",
            "555566667777",
            "--role-name",
            "PutPolicyRole",
            "--policy-name",
            "InlineRead",
            "--policy-document",
            policy_doc_replaced,
        ])
        .await
        .expect("Replacing the inline policy on PutPolicyRole must succeed");

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-role-policy",
            "--account-id",
            "555566667777",
            "--role-name",
            "PutPolicyRole",
            "--policy-name",
            "InlineWithMissingPrincipal",
            "--policy-document",
            policy_doc_with_external_principal,
        ])
        .await
        .expect("Policies referencing non-existent principals must still be accepted");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-role-policy",
            "--account-id",
            "555566667777",
            "--role-name",
            "PutPolicyRole",
            "--policy-name",
            "InlineBroken",
            "--policy-document",
            "{ not valid aspen json }",
        ])
        .await
        .expect_err("put-role-policy with malformed JSON should fail");
    assert_eq!(err.code(), Some("MalformedPolicyDocument"), "Expected MalformedPolicyDocument, got: {err}");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-role-policy",
            "--account-id",
            "555566667777",
            "--role-name",
            "no-such-role",
            "--policy-name",
            "AnyName",
            "--policy-document",
            policy_doc,
        ])
        .await
        .expect_err("put-role-policy on a nonexistent role should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "put-role-policy",
            "--account-id",
            "555566667777",
            "--role-name",
            "bad role!",
            "--policy-name",
            "AnyName",
            "--policy-document",
            policy_doc,
        ])
        .await
        .expect_err("put-role-policy with an invalid role name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");

    // -- delete-role-policy ---------------------------------------------------
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role-policy",
            "--account-id",
            "555566667777",
            "--role-name",
            "PutPolicyRole",
            "--policy-name",
            "InlineWithMissingPrincipal",
        ])
        .await
        .expect("Failed to delete-role-policy on PutPolicyRole");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role-policy",
            "--account-id",
            "555566667777",
            "--role-name",
            "PutPolicyRole",
            "--policy-name",
            "NotAttached",
        ])
        .await
        .expect_err("delete-role-policy for a policy that is not attached should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role-policy",
            "--account-id",
            "555566667777",
            "--role-name",
            "no-such-role",
            "--policy-name",
            "AnyName",
        ])
        .await
        .expect_err("delete-role-policy on a nonexistent role should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "delete-role-policy",
            "--account-id",
            "555566667777",
            "--role-name",
            "bad role!",
            "--policy-name",
            "AnyName",
        ])
        .await
        .expect_err("delete-role-policy with an invalid role name should fail");
    assert_eq!(err.code(), Some("ValidationError"), "Expected ValidationError, got: {err}");
}

async fn test_policy_attachments(database: &TempDatabase) {
    let port = database.port_str();

    // Create an account, user, group, and policy for attachment testing.
    let account_result = database
        .run(["ssbs", "--port", &port, "--username", "scratchstack", "create-account", "--account-id", "777788889999"])
        .await
        .expect("Failed to create account 777788889999");
    assert!(account_result.contains("777788889999"), "Account ID should appear in output");

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-user",
            "--account-id",
            "777788889999",
            "--user-name",
            "attach-test-user",
        ])
        .await
        .expect("Failed to create attach-test-user");

    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-group",
            "--account-id",
            "777788889999",
            "--group-name",
            "AttachTestGroup",
        ])
        .await
        .expect("Failed to create AttachTestGroup");

    let policy_result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "create-policy",
            "--account-id",
            "777788889999",
            "--policy-name",
            "AttachTestPolicy",
            "--policy-document",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#,
        ])
        .await
        .expect("Failed to create AttachTestPolicy");
    assert!(policy_result.contains("AttachTestPolicy"), "Policy name should appear in output");

    let policy_arn = "arn:aws:iam::777788889999:policy/AttachTestPolicy";

    // Attach policy to user.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "attach-user-policy",
            "--account-id",
            "777788889999",
            "--user-name",
            "attach-test-user",
            "--policy-arn",
            policy_arn,
        ])
        .await
        .expect("Failed to attach policy to user");
    assert_eq!(result.trim(), "", "attach-user-policy should produce no output");

    // Attaching again should be idempotent.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "attach-user-policy",
            "--account-id",
            "777788889999",
            "--user-name",
            "attach-test-user",
            "--policy-arn",
            policy_arn,
        ])
        .await
        .expect("Second attach-user-policy should succeed (idempotent)");

    // Attach policy to group.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "attach-group-policy",
            "--account-id",
            "777788889999",
            "--group-name",
            "AttachTestGroup",
            "--policy-arn",
            policy_arn,
        ])
        .await
        .expect("Failed to attach policy to group");
    assert_eq!(result.trim(), "", "attach-group-policy should produce no output");

    // Nonexistent group should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "attach-group-policy",
            "--account-id",
            "777788889999",
            "--group-name",
            "NoSuchGroup",
            "--policy-arn",
            policy_arn,
        ])
        .await
        .expect_err("Attaching to nonexistent group should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Nonexistent user should fail.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "attach-user-policy",
            "--account-id",
            "777788889999",
            "--user-name",
            "no-such-user",
            "--policy-arn",
            policy_arn,
        ])
        .await
        .expect_err("Attaching to nonexistent user should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Detach policy from user.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "detach-user-policy",
            "--account-id",
            "777788889999",
            "--user-name",
            "attach-test-user",
            "--policy-arn",
            policy_arn,
        ])
        .await
        .expect("Failed to detach policy from user");
    assert_eq!(result.trim(), "", "detach-user-policy should produce no output");

    // Detaching again should fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "detach-user-policy",
            "--account-id",
            "777788889999",
            "--user-name",
            "attach-test-user",
            "--policy-arn",
            policy_arn,
        ])
        .await
        .expect_err("Second detach-user-policy should fail (not attached)");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Detach policy from group.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "detach-group-policy",
            "--account-id",
            "777788889999",
            "--group-name",
            "AttachTestGroup",
            "--policy-arn",
            policy_arn,
        ])
        .await
        .expect("Failed to detach policy from group");
    assert_eq!(result.trim(), "", "detach-group-policy should produce no output");

    // Detaching again should fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "detach-group-policy",
            "--account-id",
            "777788889999",
            "--group-name",
            "AttachTestGroup",
            "--policy-arn",
            policy_arn,
        ])
        .await
        .expect_err("Second detach-group-policy should fail (not attached)");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Detaching from a nonexistent role should fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "detach-role-policy",
            "--account-id",
            "777788889999",
            "--role-name",
            "no-such-role",
            "--policy-arn",
            policy_arn,
        ])
        .await
        .expect_err("Detaching from nonexistent role should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // After the detach tests above, the user and group have no attached policies. Verify with
    // list-attached-user-policies and list-attached-group-policies.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-attached-user-policies",
            "--account-id",
            "777788889999",
            "--user-name",
            "attach-test-user",
        ])
        .await
        .expect("Failed to list attached user policies");
    let json: JsonValue = serde_json::from_str(&result).expect("Failed to parse attached user policies output");
    let attached_policies = json
        .get("AttachedPolicies")
        .and_then(JsonValue::as_array)
        .expect("Expected AttachedPolicies to exist and be an array");
    assert!(attached_policies.is_empty(), "Expected empty AttachedPolicies, got: {result}");

    // Re-attach the policy and verify list-attached-user-policies now shows it.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "attach-user-policy",
            "--account-id",
            "777788889999",
            "--user-name",
            "attach-test-user",
            "--policy-arn",
            policy_arn,
        ])
        .await
        .expect("Failed to re-attach policy to user");
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-attached-user-policies",
            "--account-id",
            "777788889999",
            "--user-name",
            "attach-test-user",
        ])
        .await
        .expect("Failed to list attached user policies after re-attach");
    assert!(result.contains("AttachTestPolicy"), "Expected AttachTestPolicy in output, got: {result}");
    assert!(
        result.contains(":iam::777788889999:policy/AttachTestPolicy"),
        "Expected policy ARN suffix in output, got: {result}"
    );

    // Listing attached policies for a nonexistent user should fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-attached-user-policies",
            "--account-id",
            "777788889999",
            "--user-name",
            "no-such-user",
        ])
        .await
        .expect_err("Listing attached policies for nonexistent user should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Re-attach the policy to the group and verify list-attached-group-policies shows it.
    database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "attach-group-policy",
            "--account-id",
            "777788889999",
            "--group-name",
            "AttachTestGroup",
            "--policy-arn",
            policy_arn,
        ])
        .await
        .expect("Failed to re-attach policy to group");
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-attached-group-policies",
            "--account-id",
            "777788889999",
            "--group-name",
            "AttachTestGroup",
        ])
        .await
        .expect("Failed to list attached group policies");
    assert!(result.contains("AttachTestPolicy"), "Expected AttachTestPolicy in output, got: {result}");

    // Listing attached policies for a nonexistent group should fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-attached-group-policies",
            "--account-id",
            "777788889999",
            "--group-name",
            "NoSuchGroup",
        ])
        .await
        .expect_err("Listing attached policies for nonexistent group should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // Listing attached policies for a nonexistent role should fail with NoSuchEntity (no
    // create-role CLI command, so this also smoke-tests that list-attached-role-policies is
    // wired up correctly).
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-attached-role-policies",
            "--account-id",
            "777788889999",
            "--role-name",
            "no-such-role",
        ])
        .await
        .expect_err("Listing attached policies for nonexistent role should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");

    // ListEntitiesForPolicy — at this point AttachTestPolicy is attached to both attach-test-user
    // and AttachTestGroup (both re-attached above), so the default response should list both.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-entities-for-policy",
            "--policy-arn",
            policy_arn,
        ])
        .await
        .expect("Failed to list entities for AttachTestPolicy");
    assert!(result.contains("attach-test-user"), "Expected attach-test-user in output, got: {result}");
    assert!(result.contains("AttachTestGroup"), "Expected AttachTestGroup in output, got: {result}");

    // Filter to just users.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-entities-for-policy",
            "--policy-arn",
            policy_arn,
            "--entity-filter",
            "User",
        ])
        .await
        .expect("Failed to list entities for AttachTestPolicy with User filter");
    assert!(result.contains("attach-test-user"), "Expected attach-test-user in User-only output, got: {result}");
    assert!(!result.contains("AttachTestGroup"), "AttachTestGroup must not appear under User filter: {result}");

    // Filter to just groups.
    let result = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-entities-for-policy",
            "--policy-arn",
            policy_arn,
            "--entity-filter",
            "Group",
        ])
        .await
        .expect("Failed to list entities for AttachTestPolicy with Group filter");
    assert!(result.contains("AttachTestGroup"), "Expected AttachTestGroup in Group-only output, got: {result}");
    assert!(!result.contains("attach-test-user"), "attach-test-user must not appear under Group filter: {result}");

    // A nonexistent policy ARN must fail with NoSuchEntity.
    let err = database
        .run([
            "ssbs",
            "--port",
            &port,
            "--username",
            "scratchstack",
            "list-entities-for-policy",
            "--policy-arn",
            "arn:aws:iam::777788889999:policy/NoSuchListEntitiesPolicy",
        ])
        .await
        .expect_err("Listing entities for nonexistent policy should fail");
    assert_eq!(err.code(), Some("NoSuchEntity"), "Expected NoSuchEntity, got: {err}");
}

/// Convert a Vec<String-like> to a Vec<OsString>.
fn cli<I, S>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    args.into_iter().map(Into::into).collect()
}

/// Useful utilities to annotate to the TempDatabase type.
trait TestHarness {
    /// Returns a fake set of environment variables containing PGPASSWORD.
    fn fake_env(&self) -> Vec<(OsString, String)>;

    /// Returns the port that the database is running on as a string for use in
    /// command line arguments.
    fn port_str(&self) -> String;

    /// Runs the given CLI in a harness with the fake environment and stdout captured to a string.
    fn run<I, S>(&self, args: I) -> impl Future<Output = Result<String, IamError>> + Send
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>;
}

impl TestHarness for TempDatabase {
    fn fake_env(&self) -> Vec<(OsString, String)> {
        let result = vec![
            (OsString::from("PGPASSWORD"), self.scratchstack_password().to_string()),
            (OsString::from("BOOTSTRAP_PGPASSWORD"), self.bootstrap_password().to_string()),
        ];

        result
    }

    fn port_str(&self) -> String {
        self.settings().port.to_string()
    }

    fn run<I, S>(&self, args: I) -> impl Future<Output = Result<String, IamError>> + Send
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let vars = self.fake_env();
        let args = cli(args);
        async move {
            let mut result: Vec<u8> = Vec::with_capacity(1024);
            run(args, vars, &mut result).await?;
            String::from_utf8(result).map_err(|e| {
                log::error!("Failed to convert output to UTF-8: {e}");
                IamError::from(
                    scratchstack_shapes_iam::types::error::InternalFailure::builder()
                        .message("An internal error has occurred.")
                        .build(),
                )
            })
        }
    }
}
