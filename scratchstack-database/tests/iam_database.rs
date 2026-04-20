//! Tests for the IAM database model and related functionality.
#![cfg(all(feature = "iam", feature = "utils"))]
#![warn(clippy::all)]
#![allow(clippy::manual_range_contains)]
#![deny(
    missing_docs,
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_html_tags,
    rustdoc::private_intra_doc_links,
    rustdoc::unescaped_backticks
)]
#![cfg_attr(doc, feature(doc_cfg))]

use {
    pretty_assertions::{assert_eq, assert_ne},
    scratchstack_database::{
        Loadable,
        model::iam,
        ops::{
            RequestExecutor,
            iam::{
                CreateAccountRequest, GetCurrentPartitionRequest, ListAccountsFilter, ListAccountsFilterKey,
                ListAccountsRequest, SetCurrentPartitionRequest,
            },
        },
        utils::TempDatabase,
    },
    scratchstack_shapes_iam::{CreateUserInternalRequest, Tag},
};

/// Test all of the features of the database.
///
/// We do this instead of more granular testing because the database we're running against is typically stateful.
#[test_log::test(tokio::test)]
async fn test_database() {
    let iam_data: iam::Database =
        serde_json::from_str(TEST_DATA).expect("Failed to deserialize test data into IAM database model");

    let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
    database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
    let pool =
        database.get_scratchstack_pool().await.expect("Failed to get PostgreSQL connection pool for scratchstack user");

    let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
    iam::MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
    let rows_affected = iam_data.load_into(&mut c).await.expect("Failed to load IAM data into database");
    eprintln!("Loaded {rows_affected} rows of IAM data into database");

    // -- SetCurrentPartition and GetCurrentPartition --------------------------
    test_invalid_set_current_partition(&pool).await;
    test_set_current_partition(&pool).await;
    test_get_current_partition(&pool).await;

    let iam_dump = iam::Database::dump_from(&mut c).await.expect("Failed to dump IAM data from database");
    assert_ne!(iam_data, iam_dump, "Dumped IAM data should not be equal to original IAM data due to created_at fields");
    let iam_dump2 =
        iam::Database::dump_from(&mut c).await.expect("Failed to dump IAM data from database a second time");
    assert_eq!(iam_dump, iam_dump2, "Dumped IAM data should be equal across multiple dumps");

    // -- CreateAccountRequest -------------------------------------------------
    test_create_account_specific_id(&pool).await;
    test_create_account_with_email_and_alias(&pool).await;
    test_create_account_random_id(&pool).await;
    test_create_account_duplicate_id(&pool).await;
    test_create_account_invalid_id(&pool).await;
    test_create_account_invalid_alias_leading_dash(&pool).await;
    test_create_account_alias_too_short(&pool).await;
    test_create_account_organization_id_unsupported(&pool).await;
    test_list_accounts_explicit(&pool).await;
    test_create_350_accounts(&pool).await;
    test_list_350_accounts(&pool).await;
    test_list_accounts_filter_single_account_id(&pool).await;
    test_list_accounts_filter_multiple_account_ids(&pool).await;
    test_list_accounts_filter_by_email(&pool).await;
    test_list_accounts_filter_by_alias(&pool).await;
    test_list_accounts_filter_combined_match(&pool).await;
    test_list_accounts_filter_combined_no_match(&pool).await;
    test_list_accounts_filter_nonexistent(&pool).await;

    // -- CreateUserRequestInternal --------------------------------------------
    test_create_user_simple(&pool).await;
    test_create_user_with_path(&pool).await;
    test_create_user_with_tags(&pool).await;
    test_create_user_with_permissions_boundary(&pool).await;
    test_create_user_duplicate_name(&pool).await;
    test_create_user_invalid_name();
    test_create_user_nonexistent_account(&pool).await;
    test_create_user_nonexistent_permissions_boundary(&pool).await;

    iam::MIGRATOR.undo(&mut *c, 0).await.expect("Failed to undo database migrations");
}

async fn test_set_current_partition(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = SetCurrentPartitionRequest::builder()
        .partition("test-partition")
        .build()
        .expect("Failed to build SetCurrentPartitionRequest");
    assert_eq!(req.partition(), "test-partition");

    let resp = req.execute(&mut tx).await.expect("Failed to set current partition");
    assert_eq!(resp.partition(), "test-partition");
    tx.commit().await.expect("Failed to commit transaction");
}

async fn test_invalid_set_current_partition(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = SetCurrentPartitionRequest::builder()
        .partition("")
        .build()
        .expect("Failed to build SetCurrentPartitionRequest with empty partition ID");
    let result = req.execute(&mut tx).await;
    assert!(result.is_err(), "Setting an invalid partition ID should fail");
    tx.rollback().await.expect("Failed to rollback transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = SetCurrentPartitionRequest::builder()
        .partition("-")
        .build()
        .expect("Failed to build SetCurrentPartitionRequest with invalid partition ID");
    let result = req.execute(&mut tx).await;
    assert!(result.is_err(), "Setting an invalid partition ID should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
}

async fn test_get_current_partition(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");

    let resp = GetCurrentPartitionRequest::default().execute(&mut tx).await.expect("Failed to get current partition");
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(resp.partition(), Some("test-partition"));
}

async fn test_create_account_specific_id(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateAccountRequest {
        organization_id: None,
        account_id: Some("100000000001".to_string()),
        email: None,
        alias: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to create account with specific ID");
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(resp.account_id, "100000000001");
    assert_eq!(resp.organization_id, None);
    assert_eq!(resp.email, None);
    assert_eq!(resp.alias, None);
}

async fn test_create_account_with_email_and_alias(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateAccountRequest {
        organization_id: None,
        account_id: Some("100000000002".to_string()),
        email: Some("admin@example.com".to_string()),
        alias: Some("example-corp".to_string()),
    }
    .execute(&mut tx)
    .await
    .expect("Failed to create account with email and alias");
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(resp.account_id, "100000000002");
    assert_eq!(resp.email.as_deref(), Some("admin@example.com"));
    assert_eq!(resp.alias.as_deref(), Some("example-corp"));
}

async fn test_create_account_random_id(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateAccountRequest {
        organization_id: None,
        account_id: None,
        email: None,
        alias: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to create account with random ID");
    tx.commit().await.expect("Failed to commit transaction");

    // The returned account ID must be a 12-digit string.
    assert_eq!(resp.account_id.len(), 12, "Random account ID must be 12 digits");
    assert!(resp.account_id.chars().all(|c| c.is_ascii_digit()), "Random account ID must be all digits");

    // Verify the account appears in ListAccounts.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let list_resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterKey::AccountId,
            values: vec![resp.account_id.clone()],
        }],
        max_items: None,
        next_token: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(list_resp.accounts.len(), 1);
    assert_eq!(list_resp.accounts[0].account_id, resp.account_id);
}

async fn test_create_account_duplicate_id(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateAccountRequest {
        organization_id: None,
        account_id: Some("100000000001".to_string()),
        email: None,
        alias: None,
    }
    .execute(&mut tx)
    .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a duplicate account ID must fail");
}

async fn test_create_account_invalid_id(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateAccountRequest {
        organization_id: None,
        account_id: Some("12345".to_string()),
        email: None,
        alias: None,
    }
    .execute(&mut tx)
    .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating an account with an invalid ID must fail");
}

async fn test_create_account_invalid_alias_leading_dash(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateAccountRequest {
        organization_id: None,
        account_id: Some("100000000003".to_string()),
        email: None,
        alias: Some("-bad-alias".to_string()),
    }
    .execute(&mut tx)
    .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating an account with an invalid alias must fail");
}

async fn test_create_account_alias_too_short(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateAccountRequest {
        organization_id: None,
        account_id: Some("100000000003".to_string()),
        email: None,
        alias: Some("ab".to_string()),
    }
    .execute(&mut tx)
    .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating an account with a too-short alias must fail");
}

async fn test_create_account_organization_id_unsupported(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateAccountRequest {
        organization_id: Some("o-12345".to_string()),
        account_id: Some("100000000003".to_string()),
        email: None,
        alias: None,
    }
    .execute(&mut tx)
    .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating an account in an organization must fail (unsupported)");
}

async fn test_list_accounts_explicit(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let list_resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterKey::AccountId,
            values: vec!["100000000001".to_string(), "100000000002".to_string()],
        }],
        max_items: None,
        next_token: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(list_resp.accounts.len(), 2);
    assert_eq!(list_resp.accounts[0].account_id, "100000000001");
    assert_eq!(list_resp.accounts[1].account_id, "100000000002");
    assert_eq!(list_resp.accounts[1].email.as_deref(), Some("admin@example.com"));
    assert_eq!(list_resp.accounts[1].alias.as_deref(), Some("example-corp"));
    assert_eq!(list_resp.next_token, None);
}

const BASE_ACCOUNT_ID: u64 = 876_543_210_000;
const N_BULK_ACCOUNTS: u64 = 350;

async fn test_create_350_accounts(pool: &sqlx::PgPool) {
    // Create 350 accounts with sequential IDs, emails, and aliases.
    for i in 0..N_BULK_ACCOUNTS {
        let account_id = format!("{:012}", BASE_ACCOUNT_ID + i);
        let email = format!("{account_id}@example.com");
        let alias = format!("account-{account_id}");

        let mut tx = pool.begin().await.expect("Failed to begin transaction");
        let resp = CreateAccountRequest {
            organization_id: None,
            account_id: Some(account_id.clone()),
            email: Some(email.clone()),
            alias: Some(alias.clone()),
        }
        .execute(&mut tx)
        .await
        .unwrap_or_else(|e| panic!("Failed to create account {account_id}: {e}"));
        tx.commit().await.expect("Failed to commit transaction");

        assert_eq!(resp.account_id, account_id);
        assert_eq!(resp.email.as_deref(), Some(email.as_str()));
        assert_eq!(resp.alias.as_deref(), Some(alias.as_str()));
    }
}

async fn test_list_350_accounts(pool: &sqlx::PgPool) {
    // Paginate through all accounts, collecting every account in the bulk range.
    let mut all_bulk_accounts = Vec::new();
    let mut next_token: Option<String> = None;
    let mut page_count = 0u32;

    loop {
        let mut tx = pool.begin().await.expect("Failed to begin transaction");
        let resp = ListAccountsRequest {
            filters: vec![],
            max_items: Some(100),
            next_token: next_token.clone(),
        }
        .execute(&mut tx)
        .await
        .expect("Failed to list accounts");
        tx.rollback().await.expect("Failed to rollback transaction");

        page_count += 1;
        for account in resp.accounts {
            let id: u64 = account.account_id.parse().unwrap_or(0);
            if id >= BASE_ACCOUNT_ID && id < BASE_ACCOUNT_ID + N_BULK_ACCOUNTS {
                all_bulk_accounts.push(account);
            }
        }

        next_token = resp.next_token;
        if next_token.is_none() {
            break;
        }
    }

    assert!(page_count > 1, "Expected multiple pages, got {page_count}");
    assert_eq!(
        all_bulk_accounts.len(),
        N_BULK_ACCOUNTS as usize,
        "Expected {N_BULK_ACCOUNTS} bulk accounts across all pages, found {}",
        all_bulk_accounts.len(),
    );

    // Spot-check first, middle, and last accounts.
    for offset in [0, N_BULK_ACCOUNTS / 2, N_BULK_ACCOUNTS - 1] {
        let expected_id = format!("{:012}", BASE_ACCOUNT_ID + offset);
        let expected_email = format!("{expected_id}@example.com");
        let expected_alias = format!("account-{expected_id}");

        let account = all_bulk_accounts
            .iter()
            .find(|a| a.account_id == expected_id)
            .unwrap_or_else(|| panic!("Account {expected_id} not found in paginated results"));

        assert_eq!(account.email.as_deref(), Some(expected_email.as_str()), "Email mismatch for {expected_id}");
        assert_eq!(account.alias.as_deref(), Some(expected_alias.as_str()), "Alias mismatch for {expected_id}");
    }
}

/// Return the account ID, email, and alias strings for a bulk account at the given offset.
fn bulk_account(offset: u64) -> (String, String, String) {
    let id = format!("{:012}", BASE_ACCOUNT_ID + offset);
    let email = format!("{id}@example.com");
    let alias = format!("account-{id}");
    (id, email, alias)
}

async fn test_list_accounts_filter_single_account_id(pool: &sqlx::PgPool) {
    let (id, expected_email, expected_alias) = bulk_account(42);

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterKey::AccountId,
            values: vec![id.clone()],
        }],
        max_items: None,
        next_token: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts by single account ID");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), 1, "Expected exactly one account for id {id}");
    assert_eq!(resp.accounts[0].account_id, id);
    assert_eq!(resp.accounts[0].email.as_deref(), Some(expected_email.as_str()));
    assert_eq!(resp.accounts[0].alias.as_deref(), Some(expected_alias.as_str()));
    assert_eq!(resp.next_token, None);
}

async fn test_list_accounts_filter_multiple_account_ids(pool: &sqlx::PgPool) {
    let offsets = [10u64, 100, 200, 300];
    let ids: Vec<String> = offsets.iter().map(|&o| bulk_account(o).0).collect();

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterKey::AccountId,
            values: ids.clone(),
        }],
        max_items: None,
        next_token: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts by multiple account IDs");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), offsets.len(), "Expected {} accounts", offsets.len());
    // Results are ordered by account_id; our offsets are already ascending.
    for (account, &offset) in resp.accounts.iter().zip(offsets.iter()) {
        let (expected_id, expected_email, expected_alias) = bulk_account(offset);
        assert_eq!(account.account_id, expected_id);
        assert_eq!(account.email.as_deref(), Some(expected_email.as_str()));
        assert_eq!(account.alias.as_deref(), Some(expected_alias.as_str()));
    }
    assert_eq!(resp.next_token, None);
}

async fn test_list_accounts_filter_by_email(pool: &sqlx::PgPool) {
    let (expected_id, email, expected_alias) = bulk_account(77);

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterKey::Email,
            values: vec![email.clone()],
        }],
        max_items: None,
        next_token: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts by email");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), 1, "Expected exactly one account for email {email}");
    assert_eq!(resp.accounts[0].account_id, expected_id);
    assert_eq!(resp.accounts[0].email.as_deref(), Some(email.as_str()));
    assert_eq!(resp.accounts[0].alias.as_deref(), Some(expected_alias.as_str()));
    assert_eq!(resp.next_token, None);
}

async fn test_list_accounts_filter_by_alias(pool: &sqlx::PgPool) {
    let (expected_id, expected_email, alias) = bulk_account(155);

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterKey::Alias,
            values: vec![alias.clone()],
        }],
        max_items: None,
        next_token: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts by alias");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), 1, "Expected exactly one account for alias {alias}");
    assert_eq!(resp.accounts[0].account_id, expected_id);
    assert_eq!(resp.accounts[0].email.as_deref(), Some(expected_email.as_str()));
    assert_eq!(resp.accounts[0].alias.as_deref(), Some(alias.as_str()));
    assert_eq!(resp.next_token, None);
}

async fn test_list_accounts_filter_combined_match(pool: &sqlx::PgPool) {
    // AccountId AND Email filters both match the same account — should return it.
    let (id, email, expected_alias) = bulk_account(250);

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![
            ListAccountsFilter {
                name: ListAccountsFilterKey::AccountId,
                values: vec![id.clone()],
            },
            ListAccountsFilter {
                name: ListAccountsFilterKey::Email,
                values: vec![email.clone()],
            },
        ],
        max_items: None,
        next_token: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts with combined matching filters");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), 1, "Expected exactly one account when AccountId and Email both match");
    assert_eq!(resp.accounts[0].account_id, id);
    assert_eq!(resp.accounts[0].email.as_deref(), Some(email.as_str()));
    assert_eq!(resp.accounts[0].alias.as_deref(), Some(expected_alias.as_str()));
    assert_eq!(resp.next_token, None);
}

async fn test_list_accounts_filter_combined_no_match(pool: &sqlx::PgPool) {
    // AccountId and Email filters refer to *different* accounts — the AND should return nothing.
    let (id_a, _, _) = bulk_account(10);
    let (_, email_b, _) = bulk_account(20);

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![
            ListAccountsFilter {
                name: ListAccountsFilterKey::AccountId,
                values: vec![id_a.clone()],
            },
            ListAccountsFilter {
                name: ListAccountsFilterKey::Email,
                values: vec![email_b.clone()],
            },
        ],
        max_items: None,
        next_token: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts with combined non-matching filters");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(
        resp.accounts.len(),
        0,
        "Expected no accounts when AccountId ({id_a}) and Email ({email_b}) refer to different accounts",
    );
    assert_eq!(resp.next_token, None);
}

async fn test_list_accounts_filter_nonexistent(pool: &sqlx::PgPool) {
    // 999999999999 is never created by any test, so this must return no results.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterKey::AccountId,
            values: vec!["999999999999".to_string()],
        }],
        max_items: None,
        next_token: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts with nonexistent account ID filter");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), 0, "Expected no accounts for a nonexistent account ID");
    assert_eq!(resp.next_token, None);
}

/// Create a user with only a name and account — all other fields take defaults.
async fn test_create_user_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateUserInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await
        .expect("Failed to create user");
    tx.commit().await.expect("Failed to commit transaction");

    let user = resp.user.expect("Response should include created user");
    assert_eq!(user.user_name, "alice");
    assert_eq!(user.path, "/");
    assert!(user.user_id.starts_with("AIDA"), "User ID must start with AIDA prefix");
    assert!(user.arn.ends_with(":user/alice"), "ARN must end with :user/alice, got {}", user.arn);
    assert!(user.permissions_boundary.is_none());
    assert!(user.tags.is_empty());
}

/// Create a user at a non-default path.
async fn test_create_user_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateUserInternalRequest::builder()
        .user_name("bob".to_string())
        .path(Some("/engineering/".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await
        .expect("Failed to create user with path");
    tx.commit().await.expect("Failed to commit transaction");

    let user = resp.user.expect("Response should include created user");
    assert_eq!(user.user_name, "bob");
    assert_eq!(user.path, "/engineering/");
}

/// Create a user with tags attached.
async fn test_create_user_with_tags(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateUserInternalRequest::builder()
        .user_name("carol".to_string())
        .account_id("210987654321".to_string())
        .tags(vec![
            Tag::builder()
                .key("Environment".to_string())
                .value("Production".to_string())
                .build()
                .expect("Failed to build Environment tag"),
            Tag::builder()
                .key("Team".to_string())
                .value("Engineering".to_string())
                .build()
                .expect("Failed to build Team tag"),
        ])
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await
        .expect("Failed to create user with tags");
    tx.commit().await.expect("Failed to commit transaction");

    let user = resp.user.expect("Response should include created user");
    assert_eq!(user.user_name, "carol");
}

/// Create a user with an existing managed policy as the permissions boundary.
async fn test_create_user_with_permissions_boundary(pool: &sqlx::PgPool) {
    // The test data has "Example-Managed-Policy-1" in account 123456789012 at path "/".

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateUserInternalRequest::builder()
        .user_name("dave".to_string())
        .account_id("123456789012".to_string())
        .permissions_boundary(Some("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1".to_string()))
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await
        .expect("Failed to create user with permissions boundary");
    tx.commit().await.expect("Failed to commit transaction");

    let user = resp.user.expect("Response should include created user");
    assert_eq!(user.user_name, "dave");
    let pb = user.permissions_boundary.expect("User should have a permissions boundary");
    let pb_arn = pb.permissions_boundary_arn.expect("Permissions boundary should include an ARN");
    assert_eq!(pb_arn, "arn:aws:iam::123456789012:policy/Example-Managed-Policy-1");
}

/// Attempting to create a user whose (lowercased) name already exists in the account must fail.
async fn test_create_user_duplicate_name(pool: &sqlx::PgPool) {
    // "alice" was committed by test_create_user_simple; re-inserting it must fail.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateUserInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a duplicate user name must fail");
}

/// Building a request with an invalid user name must fail before touching the database.
fn test_create_user_invalid_name() {
    // Spaces and `!` are not in the allowed character set.
    let result = CreateUserInternalRequest::builder()
        .user_name("bad name!".to_string())
        .account_id("123456789012".to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid user name must fail");
}

/// Creating a user in an account that does not exist must fail with a FK violation.
async fn test_create_user_nonexistent_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateUserInternalRequest::builder()
        .user_name("eve".to_string())
        .account_id("999999999999".to_string())
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a user in a nonexistent account must fail");
}

/// Specifying a permissions boundary that references a policy that does not exist must fail.
async fn test_create_user_nonexistent_permissions_boundary(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateUserInternalRequest::builder()
        .user_name("frank".to_string())
        .account_id("123456789012".to_string())
        .permissions_boundary(Some("arn:aws:iam::123456789012:policy/NonExistentPolicy".to_string()))
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a user with a nonexistent permissions boundary must fail");
}

const TEST_DATA: &str = include_str!("iam_database.json");
