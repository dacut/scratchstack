use {
    crate::run,
    anyhow::Result as AnyResult,
    scratchstack_database::utils::TempDatabase,
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

    // Just test that the command runs successfully for now, we'll add more assertions as we implement more user operations.
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
    fn run<I, S>(&self, args: I) -> impl Future<Output = AnyResult<String>> + Send
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

    fn run<I, S>(&self, args: I) -> impl Future<Output = AnyResult<String>> + Send
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let vars = self.fake_env();
        let args = cli(args);
        async move {
            let mut result: Vec<u8> = Vec::with_capacity(1024);
            run(args, vars, &mut result).await?;
            Ok(String::from_utf8(result)?)
        }
    }
}
